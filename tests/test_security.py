"""Tests for security validation, subprocess argument sanitization, and dashboard hardening."""

from __future__ import annotations

import math
import os
import tomllib
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

import pandas as pd
from experiments.run_experiment import activity_command, cpu_attack_command
from ml.inference import InferenceSchemaError, ThreatDetector
from telemetry.network_collector import build_network_gadget_command
from telemetry.runtime_collector import build_runtime_gadget_command
from telemetry.security import (
    validate_finite_float,
    validate_gadget_version,
    validate_k8s_name,
    validate_k8s_selector,
    validate_safe_output_path,
)
from telemetry.workload_collector import get_metrics, get_webapp_pod


# ---------------------------------------------------------------------------
# 1. Kubernetes Name Validation (Flag Injection & Shell Metacharacters)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "valid_name",
    [
        "webapp",
        "default",
        "kube-system",
        "my-pod-123",
        "deployment/webapp",
        "apps/v1/deployment",
        "my-svc.default",
    ],
)
def test_validate_k8s_name_valid(valid_name: str) -> None:
    assert validate_k8s_name(valid_name) == valid_name


@pytest.mark.parametrize(
    "invalid_name",
    [
        "--all-namespaces",
        "-n",
        "-A",
        "--kubeconfig=/tmp/evil",
        "webapp; rm -rf /",
        "webapp | cat",
        "webapp && echo pwned",
        "webapp$(whoami)",
        "webapp`whoami`",
        "webapp>file",
        "webapp<file",
        "webapp\nevil",
        "",
        "   ",
        "a" * 254,  # Exceeds max length
    ],
)
def test_validate_k8s_name_invalid_rejected(invalid_name: str) -> None:
    with pytest.raises(ValueError):
        validate_k8s_name(invalid_name)


def test_validate_k8s_name_type_error() -> None:
    with pytest.raises(TypeError):
        validate_k8s_name(123)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# 2. Kubernetes Selector Validation
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "valid_selector",
    [
        "app=webapp",
        "app=webapp,tier=frontend",
        "app!=malicious",
        "env in (production, staging)",
        "app",
    ],
)
def test_validate_k8s_selector_valid(valid_selector: str) -> None:
    assert validate_k8s_selector(valid_selector) == valid_selector


@pytest.mark.parametrize(
    "invalid_selector",
    [
        "--all",
        "-A",
        "-l",
        "--selector=app=webapp",
        "app=webapp; cat /etc/passwd",
        "app=webapp | evil",
        "app=webapp && sleep 10",
        "app=webapp$(reboot)",
        "app=webapp`id`",
        "app=webapp\nmalicious",
        "",
        "   ",
    ],
)
def test_validate_k8s_selector_invalid_rejected(invalid_selector: str) -> None:
    with pytest.raises(ValueError):
        validate_k8s_selector(invalid_selector)


def test_validate_k8s_selector_type_error() -> None:
    with pytest.raises(TypeError):
        validate_k8s_selector(None)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# 3. Inspektor Gadget Version Validation
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "valid_version",
    [
        "v0.55.1",
        "0.55.1",
        "v1.0.0",
        "v0.55.1-alpha",
        "v2.1",
    ],
)
def test_validate_gadget_version_valid(valid_version: str) -> None:
    assert validate_gadget_version(valid_version) == valid_version


@pytest.mark.parametrize(
    "invalid_version",
    [
        "--version",
        "-v",
        "v0.55.1; cat /etc/shadow",
        "v0.55.1 | sh",
        "v0.55.1$(whoami)",
        "v0.55.1\nmalicious",
        "",
        "v invalid",
    ],
)
def test_validate_gadget_version_invalid_rejected(invalid_version: str) -> None:
    with pytest.raises(ValueError):
        validate_gadget_version(invalid_version)


def test_validate_gadget_version_type_error() -> None:
    with pytest.raises(TypeError):
        validate_gadget_version(1.0)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# 4. Safe Output Path & Directory Traversal Prevention
# ---------------------------------------------------------------------------

def test_validate_safe_output_path_relative(tmp_path: Path) -> None:
    safe = validate_safe_output_path("data/metrics.csv", base_dir=tmp_path)
    assert safe == (tmp_path / "data" / "metrics.csv").resolve()


def test_validate_safe_output_path_traversal_rejected(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="Path traversal detected"):
        validate_safe_output_path("../../etc/passwd", base_dir=tmp_path)


def test_validate_safe_output_path_absolute(tmp_path: Path) -> None:
    target = tmp_path / "telemetry" / "events.jsonl"
    resolved = validate_safe_output_path(target)
    assert resolved == target.resolve()


# ---------------------------------------------------------------------------
# 5. Finite Float Validation (Preventing Model Crash / Evasion via NaN / Inf)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "valid_num,expected",
    [
        (0.0, 0.0),
        (123.45, 123.45),
        ("42.5", 42.5),
        (10, 10.0),
        ("-3.14", -3.14),
    ],
)
def test_validate_finite_float_valid(valid_num: object, expected: float) -> None:
    assert validate_finite_float(valid_num) == expected


@pytest.mark.parametrize(
    "invalid_num",
    [
        float("nan"),
        float("inf"),
        float("-inf"),
        "nan",
        "NaN",
        "inf",
        "-inf",
        "Infinity",
        "-Infinity",
        "not_a_number",
        None,
        {},
    ],
)
def test_validate_finite_float_invalid_rejected(invalid_num: object) -> None:
    with pytest.raises(ValueError):
        validate_finite_float(invalid_num)


# ---------------------------------------------------------------------------
# 6. Command Construction & Collector Injection Prevention
# ---------------------------------------------------------------------------

def test_build_network_gadget_command_sanitizes_arguments() -> None:
    with pytest.raises(ValueError, match="flag injection rejected"):
        build_network_gadget_command(namespace="--all-namespaces")

    with pytest.raises(ValueError, match="flag injection rejected"):
        build_network_gadget_command(selector="--all")

    with pytest.raises(ValueError, match="gadget_version cannot start with a hyphen"):
        build_network_gadget_command(gadget_version="--version")

    with pytest.raises(ValueError, match="prohibited shell metacharacters"):
        build_network_gadget_command(namespace="default; rm -rf /")


def test_build_runtime_gadget_command_sanitizes_arguments() -> None:
    with pytest.raises(ValueError, match="flag injection rejected"):
        build_runtime_gadget_command(namespace="-n")

    with pytest.raises(ValueError, match="flag injection rejected"):
        build_runtime_gadget_command(selector="-l")

    with pytest.raises(ValueError, match="Invalid gadget_version format"):
        build_runtime_gadget_command(gadget_version="v0.55.1; evil")


def test_workload_collector_functions_sanitize_arguments() -> None:
    with pytest.raises(ValueError, match="flag injection rejected"):
        get_webapp_pod(namespace="--kubeconfig=/tmp/bad")

    with pytest.raises(ValueError, match="flag injection rejected"):
        get_webapp_pod(selector="--all")

    with pytest.raises(ValueError, match="flag injection rejected"):
        get_metrics(pod_name="--bad-flag", namespace="default")


def test_run_experiment_commands_sanitize_arguments() -> None:
    cluster_bad_ns = {"namespace": "--all-namespaces", "target_workload": "webapp"}
    config = {
        "scenarios": {
            "network_normal": {"network_requests": 10, "request_delay_seconds": 1},
            "network_attack": {"network_duration_seconds": 30},
        }
    }
    with pytest.raises(ValueError, match="flag injection rejected"):
        activity_command("network_normal", config, cluster_bad_ns)

    with pytest.raises(ValueError, match="flag injection rejected"):
        cpu_attack_command(cluster_bad_ns)

    # Rejection of negative / invalid numeric bounds
    cluster_good = {"namespace": "default", "target_workload": "webapp"}
    bad_config = {
        "scenarios": {
            "network_normal": {"network_requests": -5, "request_delay_seconds": 1},
        }
    }
    with pytest.raises(ValueError, match="Invalid network request parameters"):
        activity_command("network_normal", bad_config, cluster_good)


# ---------------------------------------------------------------------------
# 7. ML ThreatDetector NaN / Inf Rejection
# ---------------------------------------------------------------------------

def test_inference_rejects_nan_and_inf_features() -> None:
    detector = ThreatDetector()
    df = pd.read_csv("results/ml_datasets/network_dataset.csv", nrows=1)
    base_window = df.to_dict("records")[0]

    nan_window = dict(base_window)
    nan_window["network_connection_count"] = float("nan")
    with pytest.raises(InferenceSchemaError, match="Malformed non-numeric value.*network_connection_count"):
        detector.predict(nan_window, modality="network", model_name="random_forest")

    inf_window = dict(base_window)
    inf_window["network_event_count"] = float("inf")
    with pytest.raises(InferenceSchemaError, match="Malformed non-numeric value.*network_event_count"):
        detector.predict(inf_window, modality="network", model_name="random_forest")


# ---------------------------------------------------------------------------
# 8. Dashboard Localhost-Only Hardening
# ---------------------------------------------------------------------------

def test_streamlit_config_hardened_for_localhost() -> None:
    config_file = Path(".streamlit/config.toml")
    assert config_file.is_file(), "Missing .streamlit/config.toml"

    with config_file.open("rb") as f:
        cfg = tomllib.load(f)

    assert cfg.get("server", {}).get("address") == "127.0.0.1", "Streamlit server must bind to 127.0.0.1"
    assert cfg.get("server", {}).get("port") == 8501, "Streamlit port must be 8501"
    assert cfg.get("server", {}).get("enableXsrfProtection") is True, "XSRF protection must be enabled"
    assert cfg.get("server", {}).get("enableCORS") is False, "CORS should be disabled"
    assert cfg.get("browser", {}).get("gatherUsageStats") is False, "Usage statistics collection must be disabled"
