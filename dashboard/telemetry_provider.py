"""Modular telemetry data providers for the threat detection dashboard."""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

import pandas as pd


class TelemetryProvider(ABC):
    """Abstract interface for supplying telemetry windows to the detection dashboard."""

    @abstractmethod
    def get_modalities(self) -> list[str]:
        """Return available telemetry modalities."""
        ...

    @abstractmethod
    def get_sessions(self, modality: str) -> list[str]:
        """Return session identifiers available for the given modality."""
        ...

    @abstractmethod
    def get_windows(self, modality: str, session_id: str | None = None) -> list[dict[str, Any]]:
        """Return sequence of telemetry observation windows."""
        ...


class CapturedDatasetProvider(TelemetryProvider):
    """Supplies recorded telemetry windows from offline experiment datasets."""

    def __init__(self, ml_datasets_dir: Path | str = "results/ml_datasets") -> None:
        self.datasets_dir = Path(ml_datasets_dir)
        self._cache: dict[str, pd.DataFrame] = {}

    def _get_dataframe(self, modality: str) -> pd.DataFrame:
        if modality not in self._cache:
            file_path = self.datasets_dir / f"{modality}_dataset.csv"
            if not file_path.exists():
                raise FileNotFoundError(f"Dataset for modality '{modality}' not found: {file_path}")
            df = pd.read_csv(file_path)
            self._cache[modality] = df
        return self._cache[modality]

    def get_modalities(self, include_all: bool = False) -> list[str]:
        if include_all:
            return [
                "fusion",
                "network",
                "workload",
                "runtime",
                "net_rt",
                "rt_wl",
                "full_fusion",
            ]
        return ["network", "workload", "fusion"]

    def get_all_modalities(self) -> list[str]:
        return [
            "fusion",
            "network",
            "workload",
            "runtime",
            "net_rt",
            "rt_wl",
            "full_fusion",
        ]

    def get_sessions(self, modality: str) -> list[str]:
        df = self._get_dataframe(modality)
        if "session_id" in df.columns:
            return sorted(df["session_id"].dropna().unique().tolist())
        return []

    def get_windows(self, modality: str, session_id: str | None = None) -> list[dict[str, Any]]:
        df = self._get_dataframe(modality)
        if session_id:
            df = df[df["session_id"] == session_id]

        windows: list[dict[str, Any]] = []
        for row in df.to_dict("records"):
            # Ensure affected_pods is present for user display
            if "affected_pods" not in row or pd.isna(row["affected_pods"]):
                row["affected_pods"] = "webapp (app=webapp)"
            windows.append(row)
        return windows


class LiveKubernetesProvider(TelemetryProvider):
    """Stub provider for future streaming Kubernetes telemetry (eBPF + Metrics Server)."""

    def get_modalities(self) -> list[str]:
        return ["network", "workload", "fusion"]

    def get_sessions(self, modality: str) -> list[str]:
        return ["live_cluster_stream"]

    def get_windows(self, modality: str, session_id: str | None = None) -> list[dict[str, Any]]:
        raise NotImplementedError("Live cluster streaming will be integrated in Phase 5.")
