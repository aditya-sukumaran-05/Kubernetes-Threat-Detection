"""Security validation utilities for Kubernetes telemetry collectors and inference pipeline.

Provides strict input validation for Kubernetes resource identifiers, label selectors,
gadget versions, file paths, and numerical telemetry values to prevent command/flag
injection, directory traversal, and numerical model evasion.
"""

from __future__ import annotations

import math
import os
import re
import tempfile
from pathlib import Path
from typing import Any, Sequence

# Kubernetes DNS-1123 label / resource identifier pattern:
# Allows optional resource type prefix, e.g. "deployment/webapp" or "default"
_K8S_NAME_PATTERN = re.compile(
    r"^(?:[a-z0-9](?:[-a-z0-9]*[a-z0-9])?/)*[a-z0-9](?:[-a-z0-9]*[a-z0-9])?(?:\.[a-z0-9](?:[-a-z0-9]*[a-z0-9])?)*$"
)

# Kubernetes label selector: comma-separated key=value, key!=value, or key in (values)
# Strictly disallows flags (leading -) and shell metacharacters (;, &, |, $, `, <, >, \n)
_K8S_SELECTOR_PATTERN = re.compile(
    r"^[a-zA-Z0-9_.\-/]+(?:\s*(?:=|==|!=|\bin\b|\bnotin\b)\s*\(?[a-zA-Z0-9_.\-/\s,]*\)?)?(?:\s*,\s*[a-zA-Z0-9_.\-/]+(?:\s*(?:=|==|!=|\bin\b|\bnotin\b)\s*\(?[a-zA-Z0-9_.\-/\s,]*\)?)?)*$"
)

# Inspektor Gadget image / tag version, e.g. "v0.55.1" or "0.55.1"
_GADGET_VERSION_PATTERN = re.compile(r"^v?[0-9]+(?:\.[0-9]+)*(?:-[a-zA-Z0-9_.]+)?$")

_SHELL_METACHARS = frozenset(";&|*?`$()<>\\\"'\r\n\t")
_SELECTOR_SHELL_METACHARS = frozenset(";&|*?`$<>\\\"'\r\n\t")


def validate_k8s_name(name: str, field_name: str = "resource name") -> str:
    """Validate a Kubernetes resource name (namespace, pod, deployment, service).

    Guarantees that the name cannot be interpreted as a CLI flag (leading hyphen)
    or contain shell control characters.
    """
    if not isinstance(name, str):
        raise TypeError(f"{field_name} must be a string, got {type(name).__name__}")

    stripped = name.strip()
    if not stripped:
        raise ValueError(f"{field_name} cannot be empty")

    if stripped.startswith("-"):
        raise ValueError(f"{field_name} cannot start with a hyphen (flag injection rejected): {name!r}")

    if any(c in _SHELL_METACHARS for c in stripped):
        raise ValueError(f"{field_name} contains prohibited shell metacharacters: {name!r}")

    if len(stripped) > 253:
        raise ValueError(f"{field_name} exceeds maximum length of 253 characters: {len(stripped)}")

    if not _K8S_NAME_PATTERN.match(stripped):
        raise ValueError(
            f"{field_name} must conform to Kubernetes naming conventions (DNS-1123 label/subdomain): {name!r}"
        )

    return stripped


def validate_k8s_selector(selector: str, field_name: str = "selector") -> str:
    """Validate a Kubernetes label selector string.

    Prevents flag injection and shell command chaining in kubectl and gadget invocations.
    """
    if not isinstance(selector, str):
        raise TypeError(f"{field_name} must be a string, got {type(selector).__name__}")

    stripped = selector.strip()
    if not stripped:
        raise ValueError(f"{field_name} cannot be empty")

    if stripped.startswith("-"):
        raise ValueError(f"{field_name} cannot start with a hyphen (flag injection rejected): {selector!r}")

    if any(c in _SELECTOR_SHELL_METACHARS for c in stripped):
        raise ValueError(f"{field_name} contains prohibited shell metacharacters: {selector!r}")

    if len(stripped) > 512:
        raise ValueError(f"{field_name} exceeds maximum allowed length of 512 characters")

    if not _K8S_SELECTOR_PATTERN.match(stripped):
        raise ValueError(f"{field_name} has invalid label selector syntax: {selector!r}")

    return stripped


def validate_gadget_version(version: str) -> str:
    """Validate an Inspektor Gadget version string (e.g. v0.55.1)."""
    if not isinstance(version, str):
        raise TypeError(f"gadget_version must be a string, got {type(version).__name__}")

    stripped = version.strip()
    if not stripped:
        raise ValueError("gadget_version cannot be empty")

    if stripped.startswith("-"):
        raise ValueError(f"gadget_version cannot start with a hyphen: {version!r}")

    if not _GADGET_VERSION_PATTERN.match(stripped):
        raise ValueError(f"Invalid gadget_version format: {version!r} (expected e.g. 'v0.55.1')")

    return stripped


_PROJECT_ROOT = Path(__file__).resolve().parents[1]


def get_default_allowed_roots() -> list[Path]:
    """Return the set of default approved base directories for output paths."""
    roots: list[Path] = [_PROJECT_ROOT]
    cwd = Path.cwd().resolve()
    if cwd not in roots:
        roots.append(cwd)
    temp_dir = Path(tempfile.gettempdir()).resolve()
    if temp_dir not in roots:
        roots.append(temp_dir)
    return roots


def validate_safe_output_path(
    path: Path | str,
    base_dir: Path | str | None = None,
    allowed_roots: Sequence[Path | str] | None = None,
) -> Path:
    """Validate an output path, ensuring both relative and absolute paths remain within permitted boundaries.

    Security Policy:
    - Rejects empty paths.
    - Relative paths are anchored to base_dir if specified, else Path.cwd().
    - Resolves all symlinks and parent references via Path.resolve(strict=False).
    - If allowed_roots is specified, the resolved path must be contained within at least one allowed root.
    - If base_dir is specified without allowed_roots, containment is strictly enforced against base_dir.
    - Otherwise, default allowed roots are:
        1. Repository/project root directory.
        2. Current working directory (if distinct).
        3. Operating system temporary directory (for test fixtures / ephemeral captures).
    - Prevents symlink escapes by verifying the resolved target path rather than the lexical link.
    - Returns the canonical resolved Path object to be used for directory creation and file opening.
    """
    if not path or (isinstance(path, str) and not path.strip()):
        raise ValueError("Output path cannot be empty")

    raw_path = Path(path)

    if allowed_roots is not None:
        permitted_roots = [Path(r).resolve() for r in allowed_roots]
    elif base_dir is not None:
        permitted_roots = [Path(base_dir).resolve()]
    else:
        permitted_roots = get_default_allowed_roots()

    if raw_path.is_absolute():
        resolved = raw_path.resolve()
    else:
        anchor = Path(base_dir).resolve() if base_dir else Path.cwd().resolve()
        resolved = (anchor / raw_path).resolve()

    if not any(resolved.is_relative_to(root) for root in permitted_roots):
        roots_str = ", ".join(str(r) for r in permitted_roots)
        raise ValueError(
            f"Path traversal detected: {path!r} resolves to {resolved!r}, "
            f"which is outside permitted boundaries: [{roots_str}]"
        )

    return resolved


def validate_finite_float(val: Any, field_name: str = "value") -> float:
    """Validate that a telemetry value is a valid finite float (rejecting NaN and Infinity)."""
    try:
        f_val = float(val)
    except (ValueError, TypeError) as exc:
        raise ValueError(f"{field_name} must be numeric, got {val!r}") from exc

    if math.isnan(f_val):
        raise ValueError(f"{field_name} cannot be NaN: {val!r}")
    if math.isinf(f_val):
        raise ValueError(f"{field_name} cannot be infinite: {val!r}")

    return f_val


def validate_positive_float(
    val: Any,
    field_name: str = "value",
    allow_zero: bool = False,
) -> float:
    """Validate that a configuration value is a finite, real, positive float (or non-negative if allow_zero=True)."""
    if isinstance(val, bool):
        raise TypeError(f"{field_name} cannot be boolean, got {val!r}")
    f_val = validate_finite_float(val, field_name=field_name)
    if allow_zero:
        if f_val < 0.0:
            raise ValueError(f"{field_name} must be non-negative (>= 0), got {f_val}")
    else:
        if f_val <= 0.0:
            raise ValueError(f"{field_name} must be positive (> 0), got {f_val}")
    return f_val


def validate_positive_int(
    val: Any,
    field_name: str = "value",
    allow_zero: bool = False,
) -> int:
    """Validate that a configuration value is a finite, real, positive integer (or non-negative if allow_zero=True)."""
    f_val = validate_positive_float(val, field_name=field_name, allow_zero=allow_zero)
    if not f_val.is_integer():
        raise ValueError(f"{field_name} must be an integer, got {val!r}")
    return int(f_val)
