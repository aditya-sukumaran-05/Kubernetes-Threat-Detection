"""Security validation utilities for Kubernetes telemetry collectors and inference pipeline.

Provides strict input validation for Kubernetes resource identifiers, label selectors,
gadget versions, file paths, and numerical telemetry values to prevent command/flag
injection, directory traversal, and numerical model evasion.
"""

from __future__ import annotations

import math
import os
import re
from pathlib import Path
from typing import Any

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


def validate_safe_output_path(path: Path | str, base_dir: Path | str | None = None) -> Path:
    """Validate an output path, ensuring relative paths do not escape the base directory."""
    raw_path = Path(path)
    if raw_path.is_absolute():
        # Absolute paths are accepted (e.g. temporary directories during automated tests)
        return raw_path.resolve()

    base = Path(base_dir).resolve() if base_dir else Path.cwd().resolve()
    resolved = (base / raw_path).resolve()

    try:
        resolved.relative_to(base)
    except ValueError as exc:
        raise ValueError(f"Path traversal detected: {path!r} resolves outside {base}") from exc

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
