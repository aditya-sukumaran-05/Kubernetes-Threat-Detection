from pathlib import Path

import yaml


def test_primary_attack_configuration_targets_six_full_windows() -> None:
    config = yaml.safe_load(Path("configs/experiments.yaml").read_text(encoding="utf-8"))
    for scenario in ("network_attack", "workload_attack", "fusion_attack"):
        assert config["scenarios"][scenario]["attack_seconds"] == 70
    assert config["scenarios"]["network_attack"]["network_duration_seconds"] == 70
    assert config["scenarios"]["fusion_attack"]["network_duration_seconds"] == 70
