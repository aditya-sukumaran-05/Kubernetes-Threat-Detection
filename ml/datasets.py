"""Construct ML-ready datasets from Phase 1 derived feature files."""

from __future__ import annotations

import csv
import hashlib
import json
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


NETWORK_PREFIX = "network_"
WORKLOAD_PREFIX = "workload_"
CONTEXT_COLUMNS = ("window_start", "window_end", "capture_id", "session_id", "experiment_id", "scenario", "label", "attack_type")
NETWORK_SCENARIOS = frozenset({"network_normal", "network_attack"})
WORKLOAD_SCENARIOS = frozenset({"workload_normal", "workload_attack"})
FUSION_SCENARIOS = frozenset({"fusion_normal", "fusion_attack"})


class DatasetError(ValueError):
    """Raised when a derived telemetry dataset is structurally invalid."""


@dataclass(frozen=True)
class DatasetSummary:
    name: str
    path: str
    rows: int
    labeled_rows: int
    class_counts: dict[str, int]
    session_counts: dict[str, int]
    features: tuple[str, ...]
    sha256: str
    limitation: str | None = None


def read_csv(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        raise DatasetError(f"derived dataset does not exist: {path}")
    with path.open(encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def _validate_unique_windows(rows: Iterable[dict[str, str]], source_name: str) -> None:
    seen: set[tuple[str, str]] = set()
    for row in rows:
        key = (row.get("capture_id", ""), row.get("window_start", ""))
        if not all(key):
            raise DatasetError(f"{source_name} requires capture_id and window_start")
        if key in seen:
            raise DatasetError(f"duplicate window in {source_name}: {key}")
        seen.add(key)


def _select_labeled(rows: list[dict[str, str]]) -> list[dict[str, str]]:
    return [row for row in rows if row.get("label") in {"normal", "attack"}]


def _feature_names(rows: list[dict[str, str]], prefix: str) -> tuple[str, ...]:
    fields = {name for row in rows for name in row if name.startswith(prefix)}
    return tuple(sorted(fields))


def _select_scenarios(rows: list[dict[str, str]], scenarios: frozenset[str]) -> list[dict[str, str]]:
    """Keep an ablation within its declared controlled scenario family.

    Compact legacy fixtures did not carry a scenario column.  They retain the
    prior behaviour solely for backwards-compatible processing of those
    explicitly scenario-less records; real runner captures always have one.
    """
    if not any(row.get("scenario") for row in rows):
        return rows
    return [row for row in rows if row.get("scenario") in scenarios]


def _write_dataset(path: Path, rows: list[dict[str, str]], features: tuple[str, ...]) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = [*CONTEXT_COLUMNS, *features]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _summary(name: str, path: Path, rows: list[dict[str, str]], all_rows: int, features: tuple[str, ...], limitation: str | None) -> DatasetSummary:
    return DatasetSummary(
        name=name,
        path=str(path),
        rows=all_rows,
        labeled_rows=len(rows),
        class_counts=dict(Counter(row["label"] for row in rows)),
        session_counts=dict(Counter(row["session_id"] for row in rows)),
        features=features,
        sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
        limitation=limitation,
    )


def build_datasets(processed_dir: Path, output_dir: Path) -> dict[str, DatasetSummary]:
    """Create network/workload datasets and only genuine same-session fusion.

    Unknown labels are excluded from supervised datasets, never inferred.  The
    fusion file is deliberately empty unless Phase 1 produced aligned windows.
    """
    all_sources = sorted(processed_dir.glob("*.csv"))
    if not all_sources:
        raise DatasetError(f"no processed feature files found in {processed_dir}")
    all_rows = [row for path in all_sources for row in read_csv(path)]
    network_all = [row for row in all_rows if row.get("telemetry_source") == "network"]
    workload_all = [row for row in all_rows if row.get("telemetry_source") == "workload"]
    # Supports the original Phase 1 outputs and compact unit-test fixtures.
    if not network_all:
        network_all = [row for path in all_sources if path.name.startswith("network_") for row in read_csv(path)]
    if not workload_all:
        workload_all = [row for path in all_sources if path.name.startswith("workload_") for row in read_csv(path)]
    network_all = _select_scenarios(network_all, NETWORK_SCENARIOS)
    workload_all = _select_scenarios(workload_all, WORKLOAD_SCENARIOS)
    _validate_unique_windows(network_all, "network dataset")
    _validate_unique_windows(workload_all, "workload dataset")
    network = _select_labeled(network_all)
    workload = _select_labeled(workload_all)
    network_features = _feature_names(network_all, NETWORK_PREFIX)
    workload_features = _feature_names(workload_all, WORKLOAD_PREFIX)
    network_path = output_dir / "network_dataset.csv"
    workload_path = output_dir / "workload_dataset.csv"
    _write_dataset(network_path, network, network_features)
    _write_dataset(workload_path, workload, workload_features)

    aligned_dir = processed_dir.parent / "aligned"
    aligned_paths = sorted(aligned_dir.glob("*.csv")) if aligned_dir.exists() else []
    fusion_all = _select_scenarios([row for path in aligned_paths for row in read_csv(path)], FUSION_SCENARIOS)
    fusion = [
        row for row in _select_labeled(fusion_all)
        if row.get("network_available") == "True" and row.get("workload_available") == "True"
    ]
    fusion_features = tuple(sorted(set(_feature_names(fusion_all, NETWORK_PREFIX)) | set(_feature_names(fusion_all, WORKLOAD_PREFIX))))
    fusion_path = output_dir / "fusion_dataset.csv"
    _write_dataset(fusion_path, fusion, fusion_features)

    summaries = {
        "network": _summary("network", network_path, network, len(network_all), network_features, None),
        "workload": _summary(
            "workload", workload_path, workload, len(workload_all), workload_features,
            None,
        ),
        "fusion": _summary(
            "fusion", fusion_path, fusion, len(fusion_all), fusion_features,
            None,
        ),
    }
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "dataset_summary.json").write_text(
        json.dumps({name: summary.__dict__ for name, summary in summaries.items()}, indent=2), encoding="utf-8"
    )
    return summaries
