"""Tests for security validation, subprocess argument sanitization, and dashboard hardening."""

from __future__ import annotations

import copy
import math
import os
import tomllib
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

import pandas as pd
from experiments.run_experiment import (
    activity_command,
    cpu_attack_command,
    run_scenario,
    validate_experiment_preflight,
)
from ml.inference import InferenceSchemaError, ThreatDetector
from telemetry.network_collector import build_network_gadget_command
from telemetry.runtime_collector import build_runtime_gadget_command
from telemetry.security import (
    get_default_allowed_roots,
    validate_finite_float,
    validate_gadget_version,
    validate_k8s_name,
    validate_k8s_selector,
    validate_positive_float,
    validate_positive_int,
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


def test_validate_safe_output_path_absolute_within_tempdir(tmp_path: Path) -> None:
    target = tmp_path / "telemetry" / "events.jsonl"
    resolved = validate_safe_output_path(target)
    assert resolved == target.resolve()


def test_validate_safe_output_path_absolute_within_project() -> None:
    project_root = Path(__file__).resolve().parents[1]
    target = project_root / "results" / "runs" / "test_run" / "workload.csv"
    resolved = validate_safe_output_path(target)
    assert resolved == target.resolve()


def test_validate_safe_output_path_outside_boundaries_rejected() -> None:
    foreign_path = Path("/etc/shadow") if os.name != "nt" else Path("C:/Windows/System32/drivers/etc/hosts")
    with pytest.raises(ValueError, match="Path traversal detected"):
        validate_safe_output_path(foreign_path)


def test_validate_safe_output_path_base_dir_enforces_strict_containment(tmp_path: Path) -> None:
    other_dir = tmp_path / "other"
    other_dir.mkdir()
    allowed_dir = tmp_path / "allowed"
    allowed_dir.mkdir()
    target_outside = other_dir / "data.csv"

    with pytest.raises(ValueError, match="Path traversal detected"):
        validate_safe_output_path(target_outside, base_dir=allowed_dir)


def test_validate_safe_output_path_explicit_allowed_roots(tmp_path: Path) -> None:
    root1 = tmp_path / "root1"
    root1.mkdir()
    root2 = tmp_path / "root2"
    root2.mkdir()
    root3 = tmp_path / "root3"
    root3.mkdir()

    target2 = root2 / "sub" / "output.csv"
    assert validate_safe_output_path(target2, allowed_roots=[root1, root2]) == target2.resolve()

    target3 = root3 / "output.csv"
    with pytest.raises(ValueError, match="Path traversal detected"):
        validate_safe_output_path(target3, allowed_roots=[root1, root2])


def test_validate_safe_output_path_empty_rejected() -> None:
    with pytest.raises(ValueError, match="Output path cannot be empty"):
        validate_safe_output_path("")

    with pytest.raises(ValueError, match="Output path cannot be empty"):
        validate_safe_output_path("   ")


def test_validate_safe_output_path_existing_legitimate_defaults() -> None:
    default_workload = validate_safe_output_path("telemetry/data/workload_metrics.csv")
    assert default_workload.name == "workload_metrics.csv"

    default_network = validate_safe_output_path("telemetry/data/network/network_events.jsonl")
    assert default_network.name == "network_events.jsonl"

    default_runtime = validate_safe_output_path("telemetry/data/runtime/runtime_events.jsonl")
    assert default_runtime.name == "runtime_events.jsonl"


def test_validate_safe_output_path_symlink_escape_rejected(tmp_path: Path) -> None:
    jail_dir = tmp_path / "jail"
    jail_dir.mkdir()
    secret_dir = tmp_path / "secret"
    secret_dir.mkdir()
    link = jail_dir / "escape_link"

    try:
        link.symlink_to(secret_dir, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("Symlink creation not permitted in this environment")

    target_via_link = link / "stolen.csv"
    with pytest.raises(ValueError, match="Path traversal detected"):
        validate_safe_output_path(target_via_link, base_dir=jail_dir)


# ---------------------------------------------------------------------------
# 5. Finite Float and Integer Validation (Rejecting NaN, Inf, and Out-of-Bounds)
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


@pytest.mark.parametrize(
    "val,expected",
    [
        (1.0, 1.0),
        ("2.5", 2.5),
        (10, 10.0),
        ("0.001", 0.001),
    ],
)
def test_validate_positive_float_valid(val: object, expected: float) -> None:
    assert validate_positive_float(val) == expected


def test_validate_positive_float_zero_allowed() -> None:
    assert validate_positive_float(0.0, allow_zero=True) == 0.0
    assert validate_positive_float("0", allow_zero=True) == 0.0

    with pytest.raises(ValueError, match="must be positive"):
        validate_positive_float(0.0, allow_zero=False)


@pytest.mark.parametrize(
    "invalid_val",
    [
        -1.0,
        "-0.5",
        float("nan"),
        "nan",
        float("inf"),
        "inf",
        float("-inf"),
        "-inf",
    ],
)
def test_validate_positive_float_rejected(invalid_val: object) -> None:
    with pytest.raises(ValueError):
        validate_positive_float(invalid_val)


def test_validate_positive_float_boolean_rejected() -> None:
    with pytest.raises(TypeError, match="cannot be boolean"):
        validate_positive_float(True)
    with pytest.raises(TypeError, match="cannot be boolean"):
        validate_positive_float(False)


@pytest.mark.parametrize(
    "val,expected",
    [
        (1, 1),
        ("10", 10),
        (10.0, 10),
        ("100.0", 100),
    ],
)
def test_validate_positive_int_valid(val: object, expected: int) -> None:
    assert validate_positive_int(val) == expected


def test_validate_positive_int_zero_allowed() -> None:
    assert validate_positive_int(0, allow_zero=True) == 0
    assert validate_positive_int("0", allow_zero=True) == 0

    with pytest.raises(ValueError, match="must be positive"):
        validate_positive_int(0, allow_zero=False)


@pytest.mark.parametrize(
    "invalid_int",
    [
        -1,
        "-5",
        1.5,
        "2.7",
        float("nan"),
        "nan",
        float("inf"),
        "inf",
        float("-inf"),
        "-inf",
    ],
)
def test_validate_positive_int_rejected(invalid_int: object) -> None:
    with pytest.raises(ValueError):
        validate_positive_int(invalid_int)


def test_validate_positive_int_boolean_rejected() -> None:
    with pytest.raises(TypeError, match="cannot be boolean"):
        validate_positive_int(True)


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


def test_workload_collector_rejects_non_finite_parameters() -> None:
    with pytest.raises(ValueError):
        get_webapp_pod(max_retries=float("nan"))  # type: ignore[arg-type]

    with pytest.raises(ValueError):
        get_webapp_pod(base_backoff=float("inf"))

    with pytest.raises(ValueError):
        get_metrics("webapp", max_retries=-1)

    with pytest.raises(ValueError):
        get_metrics("webapp", jitter=float("nan"))


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


def test_activity_command_rejects_non_finite_and_invalid_bounds() -> None:
    cluster = {"namespace": "default", "target_workload": "webapp"}

    for bad_req in [float("nan"), "nan", float("inf"), "inf", -10, 0, 1.5]:
        bad_config = {
            "scenarios": {
                "network_normal": {"network_requests": bad_req, "request_delay_seconds": 1},
            }
        }
        with pytest.raises(ValueError):
            activity_command("network_normal", bad_config, cluster)

    for bad_delay in [float("nan"), "nan", float("inf"), "inf", -1.0]:
        bad_config = {
            "scenarios": {
                "network_normal": {"network_requests": 10, "request_delay_seconds": bad_delay},
            }
        }
        with pytest.raises(ValueError):
            activity_command("network_normal", bad_config, cluster)

    for bad_dur in [float("nan"), "nan", float("inf"), "inf", -5, 0]:
        bad_config = {
            "scenarios": {
                "network_attack": {"network_duration_seconds": bad_dur},
            }
        }
        with pytest.raises(ValueError):
            activity_command("network_attack", bad_config, cluster)


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


# ---------------------------------------------------------------------------
# 9. Experiment Preflight Validation and Output Containment
# ---------------------------------------------------------------------------

@pytest.fixture
def base_experiment_config() -> dict:
    return {
        "cluster": {
            "expected_context": "minikube",
            "namespace": "default",
            "target_label": "app=webapp",
            "target_workload": "deployment/webapp",
        },
        "output_directory": "experiments/runs",
        "collectors": {
            "network_gadget_version": "v0.55.1",
            "workload_interval_seconds": 5,
        },
        "scenarios": {
            "network_normal": {
                "label": "normal",
                "warmup_seconds": 20,
                "activity_seconds": 60,
                "cooldown_seconds": 20,
                "network_activity": "low-rate HTTP requests",
                "workload_activity": "baseline",
                "network_requests": 30,
                "request_delay_seconds": 2,
            },
            "network_attack": {
                "label": "attack",
                "warmup_seconds": 20,
                "attack_seconds": 70,
                "cooldown_seconds": 20,
                "network_activity": "controlled high-rate HTTP connection burst",
                "workload_activity": "baseline",
                "network_requests": 120,
                "network_duration_seconds": 70,
            },
            "workload_attack": {
                "label": "attack",
                "warmup_seconds": 20,
                "attack_seconds": 70,
                "cooldown_seconds": 20,
                "network_activity": "low-rate HTTP requests",
                "workload_activity": "controlled in-container CPU loop",
                "network_requests": 30,
                "request_delay_seconds": 2,
            },
        },
    }


def test_experiment_preflight_fails_before_write_or_subprocess_on_invalid_intervals_and_durations(
    base_experiment_config: dict, tmp_path: Path
) -> None:
    bad_interval_values = [float("nan"), float("inf"), -5, 0, True, "not_numeric"]
    for bad_val in bad_interval_values:
        bad_cfg = copy.deepcopy(base_experiment_config)
        bad_cfg["collectors"]["workload_interval_seconds"] = bad_val
        with patch("subprocess.Popen") as mock_popen:
            with pytest.raises((ValueError, TypeError)):
                run_scenario(bad_cfg, "network_normal", project_root=tmp_path, execute=True)
            mock_popen.assert_not_called()
        assert not (tmp_path / "experiments").exists()

    bad_durations = [float("nan"), float("inf"), -1, True]
    for bad_val in bad_durations:
        bad_cfg = copy.deepcopy(base_experiment_config)
        bad_cfg["scenarios"]["network_normal"]["warmup_seconds"] = bad_val
        with patch("subprocess.Popen") as mock_popen:
            with pytest.raises((ValueError, TypeError)):
                run_scenario(bad_cfg, "network_normal", project_root=tmp_path, execute=True)
            mock_popen.assert_not_called()
        assert not (tmp_path / "experiments").exists()

    for bad_val in [float("nan"), float("inf"), -1, 0, True]:
        bad_cfg = copy.deepcopy(base_experiment_config)
        bad_cfg["scenarios"]["network_normal"]["activity_seconds"] = bad_val
        with patch("subprocess.Popen") as mock_popen:
            with pytest.raises((ValueError, TypeError)):
                run_scenario(bad_cfg, "network_normal", project_root=tmp_path, execute=True)
            mock_popen.assert_not_called()
        assert not (tmp_path / "experiments").exists()

    for bad_val in [float("nan"), float("inf"), -1, 0, True]:
        bad_cfg = copy.deepcopy(base_experiment_config)
        bad_cfg["scenarios"]["network_attack"]["attack_seconds"] = bad_val
        with patch("subprocess.Popen") as mock_popen:
            with pytest.raises((ValueError, TypeError)):
                run_scenario(bad_cfg, "network_attack", project_root=tmp_path, execute=True)
            mock_popen.assert_not_called()
        assert not (tmp_path / "experiments").exists()

    for bad_val in bad_durations:
        bad_cfg = copy.deepcopy(base_experiment_config)
        bad_cfg["scenarios"]["network_normal"]["cooldown_seconds"] = bad_val
        with patch("subprocess.Popen") as mock_popen:
            with pytest.raises((ValueError, TypeError)):
                run_scenario(bad_cfg, "network_normal", project_root=tmp_path, execute=True)
            mock_popen.assert_not_called()
        assert not (tmp_path / "experiments").exists()


def test_experiment_preflight_fails_before_write_or_subprocess_on_invalid_scenario_params(
    base_experiment_config: dict, tmp_path: Path
) -> None:
    for bad_req in [float("nan"), float("inf"), -1, 0, True]:
        bad_cfg = copy.deepcopy(base_experiment_config)
        bad_cfg["scenarios"]["network_normal"]["network_requests"] = bad_req
        with patch("subprocess.Popen") as mock_popen:
            with pytest.raises((ValueError, TypeError)):
                run_scenario(bad_cfg, "network_normal", project_root=tmp_path, execute=True)
            mock_popen.assert_not_called()
        assert not (tmp_path / "experiments").exists()

    for bad_delay in [float("nan"), float("inf"), -1, True]:
        bad_cfg = copy.deepcopy(base_experiment_config)
        bad_cfg["scenarios"]["network_normal"]["request_delay_seconds"] = bad_delay
        with patch("subprocess.Popen") as mock_popen:
            with pytest.raises((ValueError, TypeError)):
                run_scenario(bad_cfg, "network_normal", project_root=tmp_path, execute=True)
            mock_popen.assert_not_called()
        assert not (tmp_path / "experiments").exists()

    for bad_dur in [float("nan"), float("inf"), -1, 0, True]:
        bad_cfg = copy.deepcopy(base_experiment_config)
        bad_cfg["scenarios"]["network_attack"]["network_duration_seconds"] = bad_dur
        with patch("subprocess.Popen") as mock_popen:
            with pytest.raises((ValueError, TypeError)):
                run_scenario(bad_cfg, "network_attack", project_root=tmp_path, execute=True)
            mock_popen.assert_not_called()
        assert not (tmp_path / "experiments").exists()

    # Missing required network_duration_seconds in network_attack
    missing_cfg = copy.deepcopy(base_experiment_config)
    del missing_cfg["scenarios"]["network_attack"]["network_duration_seconds"]
    with patch("subprocess.Popen") as mock_popen:
        with pytest.raises(KeyError, match="network_duration_seconds"):
            run_scenario(missing_cfg, "network_attack", project_root=tmp_path, execute=True)
        mock_popen.assert_not_called()
    assert not (tmp_path / "experiments").exists()


def test_experiment_preflight_fails_before_write_or_subprocess_on_invalid_k8s_identifiers(
    base_experiment_config: dict, tmp_path: Path
) -> None:
    for bad_ns in ["--all-namespaces", "default; rm -rf /", "-n", ""]:
        bad_cfg = copy.deepcopy(base_experiment_config)
        bad_cfg["cluster"]["namespace"] = bad_ns
        with patch("subprocess.Popen") as mock_popen:
            with pytest.raises(ValueError):
                run_scenario(bad_cfg, "network_normal", project_root=tmp_path, execute=True)
            mock_popen.assert_not_called()
        assert not (tmp_path / "experiments").exists()

    for bad_workload in ["--all", "deployment/webapp | cat", ""]:
        bad_cfg = copy.deepcopy(base_experiment_config)
        bad_cfg["cluster"]["target_workload"] = bad_workload
        with patch("subprocess.Popen") as mock_popen:
            with pytest.raises(ValueError):
                run_scenario(bad_cfg, "network_normal", project_root=tmp_path, execute=True)
            mock_popen.assert_not_called()
        assert not (tmp_path / "experiments").exists()

    for bad_label in ["--evil", "app=webapp; evil", ""]:
        bad_cfg = copy.deepcopy(base_experiment_config)
        bad_cfg["cluster"]["target_label"] = bad_label
        with patch("subprocess.Popen") as mock_popen:
            with pytest.raises(ValueError):
                run_scenario(bad_cfg, "network_normal", project_root=tmp_path, execute=True)
            mock_popen.assert_not_called()
        assert not (tmp_path / "experiments").exists()

    # Missing cluster config key
    missing_cfg = copy.deepcopy(base_experiment_config)
    del missing_cfg["cluster"]["namespace"]
    with patch("subprocess.Popen") as mock_popen:
        with pytest.raises(KeyError):
            run_scenario(missing_cfg, "network_normal", project_root=tmp_path, execute=True)
        mock_popen.assert_not_called()
    assert not (tmp_path / "experiments").exists()


def test_experiment_preflight_fails_before_write_or_subprocess_on_escaping_output_dir(
    base_experiment_config: dict, tmp_path: Path
) -> None:
    project_root = tmp_path / "project"
    project_root.mkdir()

    # Preexisting external candidate directory with sentinel artifact
    outside_dir = (tmp_path / "candidate_outside_abs").resolve()
    outside_dir.mkdir()
    canary = outside_dir / "canary.txt"
    canary.write_text("sentinel_canary_payload", encoding="utf-8")
    canary_stat_before = canary.stat()

    # Candidate destinations for relative traversals
    candidate_parent = (project_root / "../outside_rel").resolve()
    candidate_grandparent = (project_root / "../../escaped_dir").resolve()
    assert not candidate_parent.exists()
    assert not candidate_grandparent.exists()

    # 1. Traversal via relative parent
    bad_cfg = copy.deepcopy(base_experiment_config)
    bad_cfg["output_directory"] = "../outside_rel"
    with patch("subprocess.Popen") as mock_popen:
        with pytest.raises(ValueError, match="Path traversal detected"):
            run_scenario(bad_cfg, "network_normal", project_root=project_root, execute=True)
        mock_popen.assert_not_called()
    assert not candidate_parent.exists(), "Traversal destination was created despite validation failure"

    # 2. Traversal via relative grandparent
    bad_cfg = copy.deepcopy(base_experiment_config)
    bad_cfg["output_directory"] = "../../escaped_dir"
    with patch("subprocess.Popen") as mock_popen:
        with pytest.raises(ValueError, match="Path traversal detected"):
            run_scenario(bad_cfg, "network_normal", project_root=project_root, execute=True)
        mock_popen.assert_not_called()
    assert not candidate_grandparent.exists(), "Grandparent traversal destination was created"

    # 3. Absolute path to external directory (outside project root)
    bad_cfg = copy.deepcopy(base_experiment_config)
    bad_cfg["output_directory"] = str(outside_dir)
    with patch("subprocess.Popen") as mock_popen:
        with pytest.raises(ValueError, match="Path traversal detected"):
            run_scenario(bad_cfg, "network_normal", project_root=project_root, execute=True)
        mock_popen.assert_not_called()
    assert list(outside_dir.iterdir()) == [canary], "Artifacts created in external candidate destination"
    assert canary.read_text(encoding="utf-8") == "sentinel_canary_payload"
    assert canary.stat().st_mtime_ns == canary_stat_before.st_mtime_ns

    # 4. Empty and whitespace output directories
    for empty_val in ["", "   "]:
        bad_cfg = copy.deepcopy(base_experiment_config)
        bad_cfg["output_directory"] = empty_val
        with patch("subprocess.Popen") as mock_popen:
            with pytest.raises(ValueError, match="output_directory cannot be empty"):
                run_scenario(bad_cfg, "network_normal", project_root=project_root, execute=True)
            mock_popen.assert_not_called()

    # Verify no artifacts created inside project root
    assert not (project_root / "experiments").exists()
    assert not (project_root / "runs").exists()
    assert list(project_root.iterdir()) == []


def test_experiment_preflight_fails_before_write_or_subprocess_on_symlink_output_escape(
    base_experiment_config: dict, tmp_path: Path
) -> None:
    project_root = tmp_path / "project"
    project_root.mkdir()

    external_dest = (tmp_path / "external_symlink_dest").resolve()
    external_dest.mkdir()
    canary = external_dest / "canary.txt"
    canary.write_text("protected_symlink_sentinel", encoding="utf-8")
    canary_stat_before = canary.stat()

    # Test Case A: Output directory is a symlink resolving outside project root
    symlink_output = project_root / "symlinked_runs"
    try:
        symlink_output.symlink_to(external_dest, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("Symlink creation not permitted in this environment")

    bad_cfg = copy.deepcopy(base_experiment_config)
    bad_cfg["output_directory"] = "symlinked_runs"

    with patch("subprocess.Popen") as mock_popen:
        with pytest.raises(ValueError, match="Path traversal detected"):
            run_scenario(bad_cfg, "network_normal", project_root=project_root, execute=True)
        mock_popen.assert_not_called()

    assert list(external_dest.iterdir()) == [canary], "Files were created in external symlink destination"
    assert canary.read_text(encoding="utf-8") == "protected_symlink_sentinel"
    assert canary.stat().st_mtime_ns == canary_stat_before.st_mtime_ns
    assert not (project_root / "experiments").exists()


def test_experiment_preflight_fails_before_write_or_subprocess_on_planted_run_dir_symlink(
    base_experiment_config: dict, tmp_path: Path
) -> None:
    project_root = tmp_path / "project"
    project_root.mkdir()

    normal_output_dir = project_root / "experiments" / "runs"
    normal_output_dir.mkdir(parents=True)
    fixed_run_id = "20261011T000000Z_network_normal_planted_link"
    run_dir_symlink = normal_output_dir / fixed_run_id

    external_run_dest = (tmp_path / "external_run_dest").resolve()
    external_run_dest.mkdir()
    run_canary = external_run_dest / "canary.txt"
    run_canary.write_text("protected_run_sentinel", encoding="utf-8")
    run_canary_stat_before = run_canary.stat()

    try:
        run_dir_symlink.symlink_to(external_run_dest, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("Symlink creation not permitted in this environment")

    cfg = copy.deepcopy(base_experiment_config)
    cfg["output_directory"] = "experiments/runs"

    with patch("experiments.run_experiment.experiment_id", return_value=fixed_run_id):
        with patch("subprocess.Popen") as mock_popen:
            with pytest.raises(ValueError, match="Path traversal detected"):
                run_scenario(cfg, "network_normal", project_root=project_root, execute=True)
            mock_popen.assert_not_called()

    assert list(external_run_dest.iterdir()) == [run_canary], "Files created in external run destination"
    assert run_canary.read_text(encoding="utf-8") == "protected_run_sentinel"
    assert run_canary.stat().st_mtime_ns == run_canary_stat_before.st_mtime_ns


def test_experiment_preflight_valid_plan_and_dry_run(
    base_experiment_config: dict, tmp_path: Path
) -> None:
    plan = validate_experiment_preflight(base_experiment_config, "network_normal", tmp_path, execute=False)
    assert plan.scenario == "network_normal"
    assert plan.workload_interval_seconds == 5
    assert plan.warmup_seconds == 20
    assert plan.attack_seconds == 0.0
    assert plan.cooldown_seconds == 20
    assert str(plan.canonical_run_dir).startswith(str((tmp_path / "experiments" / "runs").resolve()))

    attack_plan = validate_experiment_preflight(base_experiment_config, "network_attack", tmp_path, execute=False)
    assert attack_plan.scenario == "network_attack"
    assert attack_plan.attack_seconds == 70.0

    # Dry run execution writes metadata without spawning collectors
    with patch("subprocess.Popen") as mock_popen:
        run_dir, metadata = run_scenario(base_experiment_config, "network_normal", project_root=tmp_path, execute=False)
        mock_popen.assert_not_called()

    assert metadata.status == "planned"
    assert run_dir.is_dir()
    assert (run_dir / "metadata.json").is_file()
