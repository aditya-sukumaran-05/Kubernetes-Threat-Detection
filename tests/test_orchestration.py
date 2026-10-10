from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

from experiments.manifest import build_manifest
from experiments.metadata import load_run_capture_metadata
from experiments.orchestration import (
    RunMetadata,
    attack_window_report,
    complete_window_count,
    experiment_id,
    minikube_context_is_active,
    mark_interrupted,
    overlap_interval,
    validate_run_metadata,
    validate_capture_files,
    write_metadata,
)
from experiments import run_experiment
from experiments.run_experiment import activity_command, cpu_attack_command, load_config, run_scenario, stop_cpu_attack


def test_experiment_ids_are_unique_and_scenario_specific() -> None:
    now = datetime(2026, 9, 19, tzinfo=timezone.utc)
    assert experiment_id("fusion_attack", now).startswith("20260919T000000Z_fusion_attack_")
    assert experiment_id("fusion_attack", now) != experiment_id("fusion_attack", now)


def test_minikube_context_validation_is_exact() -> None:
    def accepted(*_args, **_kwargs):
        return SimpleNamespace(returncode=0, stdout="minikube\n")
    def rejected(*_args, **_kwargs):
        return SimpleNamespace(returncode=0, stdout="production\n")
    assert minikube_context_is_active(run=accepted)
    assert not minikube_context_is_active(run=rejected)


def test_overlap_requires_positive_shared_interval() -> None:
    assert overlap_interval("2026-01-01T00:00:00Z", "2026-01-01T00:00:10Z", "2026-01-01T00:00:05Z", "2026-01-01T00:00:15Z") == ("2026-01-01T00:00:05Z", "2026-01-01T00:00:10Z")
    assert overlap_interval("2026-01-01T00:00:00Z", "2026-01-01T00:00:05Z", "2026-01-01T00:00:05Z", "2026-01-01T00:00:10Z") == (None, None)


def test_workload_scenarios_launch_same_baseline_network_traffic() -> None:
    config = load_config(Path("configs/experiments.yaml"))
    cluster = config["cluster"]
    normal = activity_command("workload_normal", config, cluster)
    attack = activity_command("workload_attack", config, cluster)
    assert attack == normal
    assert "sleep 2" in attack[-1]


def test_cpu_attack_command_records_its_remote_pid() -> None:
    command = cpu_attack_command({"namespace": "default", "target_workload": "deployment/webapp"})
    assert command[:7] == ["kubectl", "exec", "-n", "default", "deployment/webapp", "--", "sh"]
    assert "kubernetes-threat-detection-cpu-attack.pid" in command[-1]
    assert "while :; do :; done" in command[-1]


def test_stop_cpu_attack_uses_pid_file_and_reports_cleanup_failure(monkeypatch) -> None:
    seen: list[list[str]] = []

    def success(command, **_kwargs):
        seen.append(command)
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(run_experiment.subprocess, "run", success)
    cluster = {"namespace": "default", "target_workload": "deployment/webapp"}
    assert stop_cpu_attack(cluster) is None
    assert seen[0][:7] == ["kubectl", "exec", "-n", "default", "deployment/webapp", "--", "sh"]
    assert "/proc/$pid/cmdline" in seen[0][-1]
    assert "kill \"$pid\"" in seen[0][-1]

    monkeypatch.setattr(
        run_experiment.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(returncode=1, stdout="", stderr="cleanup denied"),
    )
    assert stop_cpu_attack(cluster) == "failed to clean up controlled CPU workload: cleanup denied"


def test_complete_window_count_requires_full_epoch_aligned_windows() -> None:
    assert complete_window_count("2026-01-01T00:00:01Z", "2026-01-01T00:01:01Z") == 5
    assert complete_window_count("2026-01-01T00:00:00Z", "2026-01-01T00:01:00Z") == 6


def test_attack_window_report_contains_actual_overlap_coverage() -> None:
    report = attack_window_report({"network_attack_start_time_utc": "2026-01-01T00:00:01Z", "network_attack_end_time_utc": "2026-01-01T00:01:11Z", "workload_attack_start_time_utc": "2026-01-01T00:00:00Z", "workload_attack_end_time_utc": "2026-01-01T00:01:20Z", "overlap_start_time_utc": "2026-01-01T00:00:01Z", "overlap_end_time_utc": "2026-01-01T00:01:11Z"})
    assert report["network_attack"]["complete_10_second_windows"] == 6
    assert report["fusion_overlap"]["duration_seconds"] == 70.0


def test_fusion_metadata_rejects_zero_overlap() -> None:
    metadata = {"experiment_id": "x", "scenario": "fusion_attack", "label": "attack", "experiment_start_time_utc": "2026-01-01T00:00:00Z", "experiment_end_time_utc": "2026-01-01T00:01:00Z", "network_attack_start_time_utc": "2026-01-01T00:00:01Z", "network_attack_end_time_utc": "2026-01-01T00:00:05Z", "workload_attack_start_time_utc": "2026-01-01T00:00:05Z", "workload_attack_end_time_utc": "2026-01-01T00:00:10Z", "overlap_start_time_utc": None, "overlap_end_time_utc": None}
    assert "fusion attack requires non-zero network/workload overlap" in validate_run_metadata(metadata)


def test_interruption_preserves_metadata_state() -> None:
    metadata = RunMetadata("x", "workload_attack", "attack", "default", "deployment/webapp", {}, "baseline", "CPU")
    mark_interrupted(metadata)
    assert metadata.status == "interrupted"
    assert metadata.experiment_end_time_utc is not None


def test_capture_validation_requires_parseable_both_modalities(tmp_path: Path) -> None:
    metadata = {"experiment_id": "run", "scenario": "network_normal", "label": "normal", "experiment_start_time_utc": "2026-01-01T00:00:00Z", "experiment_end_time_utc": "2026-01-01T00:00:20Z", "telemetry": {"network": "network.jsonl", "workload": "workload.csv"}}
    (tmp_path / "network.jsonl").write_text('{"timestamp":"2026-01-01T00:00:01Z","type":"accept","src":{"addr":"a","port":80},"dst":{"addr":"b","port":1}}\n', encoding="utf-8")
    (tmp_path / "workload.csv").write_text("timestamp,pod,cpu_millicores,memory_mib,label\n2026-01-01T00:00:01Z,webapp,1,13,normal\n", encoding="utf-8")
    assert validate_capture_files(tmp_path, metadata) == []
    (tmp_path / "network.jsonl").write_text("not json\n", encoding="utf-8")
    assert any("invalid network capture" in error for error in validate_capture_files(tmp_path, metadata))


def test_dry_run_creates_planned_metadata_without_kubernetes(tmp_path: Path) -> None:
    config = {"cluster": {"expected_context": "minikube", "namespace": "default", "target_workload": "deployment/webapp"}, "output_directory": "runs", "collectors": {"workload_interval_seconds": 5}, "scenarios": {"network_normal": {"label": "normal", "warmup_seconds": 1, "activity_seconds": 1, "cooldown_seconds": 1, "network_activity": "low", "workload_activity": "baseline", "network_requests": 1, "request_delay_seconds": 1}}}
    run_dir, metadata = run_scenario(config, "network_normal", tmp_path, execute=False)
    assert metadata.status == "planned"
    assert (run_dir / "metadata.json").exists()
    assert not (run_dir / "network.jsonl").exists()


def test_manifest_includes_planned_run(tmp_path: Path) -> None:
    run_dir = tmp_path / "runs" / "example"
    metadata = RunMetadata("example", "network_normal", "normal", "default", "deployment/webapp", {}, "low", "baseline", status="planned")
    write_metadata(run_dir, metadata)
    manifest = build_manifest(tmp_path / "runs", tmp_path / "manifest.json")
    assert manifest["count"] == 1
    assert manifest["experiments"][0]["status"] == "planned"


def test_validated_run_is_discovered_with_experiment_session_id(tmp_path: Path) -> None:
    run_dir = tmp_path / "experiments" / "runs" / "fusion-1"
    run_dir.mkdir(parents=True)
    (run_dir / "network.jsonl").write_text('{"timestamp":"2026-01-01T00:00:01Z","type":"accept","src":{"addr":"10.0.0.1","port":80},"dst":{"addr":"10.0.0.2","port":40000}}\n', encoding="utf-8")
    (run_dir / "workload.csv").write_text("timestamp,pod,cpu_millicores,memory_mib,label\n2026-01-01T00:00:01Z,webapp,1,13,normal\n", encoding="utf-8")
    metadata = {"experiment_id": "fusion-1", "scenario": "fusion_attack", "status": "validated", "validation": {"valid": True}, "experiment_start_time_utc": "2026-09-20T10:00:00Z", "experiment_end_time_utc": "2026-09-20T10:01:00Z", "overlap_start_time_utc": "2026-09-20T10:00:10Z", "overlap_end_time_utc": "2026-09-20T10:00:20Z", "telemetry": {"network": "network.jsonl", "workload": "workload.csv"}}
    (run_dir / "metadata.json").write_text(__import__("json").dumps(metadata), encoding="utf-8")
    captures = load_run_capture_metadata(tmp_path / "experiments" / "runs")
    assert {capture.session_id for capture in captures} == {"fusion-1"}
    assert {capture.scenario for capture in captures} == {"fusion_attack"}

    # Runs before clean campaign cutoff are excluded
    pre_cutoff = {"experiment_id": "pre-1", "scenario": "network_normal", "status": "validated", "validation": {"valid": True}, "experiment_start_time_utc": "2026-01-01T00:00:00Z", "experiment_end_time_utc": "2026-01-01T00:01:00Z", "telemetry": {"network": "network.jsonl", "workload": "workload.csv"}}
    pre_dir = tmp_path / "experiments" / "runs" / "pre-1"
    pre_dir.mkdir(parents=True)
    (pre_dir / "network.jsonl").write_text('{"timestamp":"2026-01-01T00:00:01Z","type":"accept","src":{"addr":"10.0.0.1","port":80},"dst":{"addr":"10.0.0.2","port":40000}}\n', encoding="utf-8")
    (pre_dir / "workload.csv").write_text("timestamp,pod,cpu_millicores,memory_mib,label\n2026-01-01T00:00:01Z,webapp,1,13,normal\n", encoding="utf-8")
    (pre_dir / "metadata.json").write_text(__import__("json").dumps(pre_cutoff), encoding="utf-8")
    assert {capture.session_id for capture in load_run_capture_metadata(tmp_path / "experiments" / "runs")} == {"fusion-1"}

