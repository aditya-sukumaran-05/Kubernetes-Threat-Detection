"""End-to-end inference engine for Kubernetes threat detection."""

from __future__ import annotations

import argparse
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Sequence

import joblib
import numpy as np

from experiments.alignment import align_feature_windows
from ml.train import load_config
from telemetry.features.network import extract_network_features
from telemetry.features.runtime import extract_runtime_features, extract_runtime_window_features
from telemetry.features.workload import extract_workload_features
from telemetry.schemas import NetworkEvent, RuntimeEvent, WorkloadSample
from telemetry.security import validate_finite_float


class InferenceSchemaError(ValueError):
    """Raised when a telemetry window violates the expected feature schema."""


@dataclass(frozen=True)
class InferenceResult:
    """Structured output of threat detection inference for a telemetry window."""

    predicted_label: str  # "normal" or "attack"
    attack_probability: float | None
    confidence: float | None
    window_start: str | None
    window_end: str | None
    modality: str  # "network", "workload", "fusion", "runtime", "net_rt", "rt_wl", "full_fusion"
    model_name: str  # "random_forest", "xgboost", "svm"
    evidence: dict[str, Any]
    affected_pods: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class ThreatDetector:
    """Callable inference engine supporting all individual and multimodal telemetry combinations."""

    SUPPORTED_MODALITIES = (
        "network",
        "workload",
        "fusion",
        "runtime",
        "net_rt",
        "rt_wl",
        "full_fusion",
    )
    SUPPORTED_MODELS = ("random_forest", "xgboost", "svm")

    def __init__(
        self,
        project_root: Path | str | None = None,
        results_dir: Path | str | None = None,
        configs_dir: Path | str | None = None,
    ) -> None:
        self.project_root = Path(project_root) if project_root else Path(".")
        self.results_dir = Path(results_dir) if results_dir else (self.project_root / "results")
        self.configs_dir = Path(configs_dir) if configs_dir else (self.project_root / "configs")

        self._feature_cache: dict[str, list[str]] = {}
        self._model_cache: dict[tuple[str, str], Any] = {}

    def get_required_features(self, modality: str) -> list[str]:
        """Fetch the canonical required feature names for a modality from config."""
        if modality not in self.SUPPORTED_MODALITIES:
            raise InferenceSchemaError(
                f"Unsupported modality '{modality}'. Expected one of {self.SUPPORTED_MODALITIES}"
            )
        if modality not in self._feature_cache:
            config_path = self.configs_dir / f"{modality}.json"
            if not config_path.exists():
                raise FileNotFoundError(f"Configuration file not found: {config_path}")
            config = load_config(config_path)
            self._feature_cache[modality] = list(config["features"])
        return self._feature_cache[modality]

    def get_model(self, modality: str, model_name: str) -> Any:
        """Load and cache the trained Pipeline for (modality, model_name)."""
        if modality not in self.SUPPORTED_MODALITIES:
            raise InferenceSchemaError(
                f"Unsupported modality '{modality}'. Expected one of {self.SUPPORTED_MODALITIES}"
            )
        if model_name not in self.SUPPORTED_MODELS:
            raise InferenceSchemaError(
                f"Unsupported model '{model_name}'. Expected one of {self.SUPPORTED_MODELS}"
            )

        key = (modality, model_name)
        if key not in self._model_cache:
            model_path = self.results_dir / modality / "models" / f"{model_name}.joblib"
            if not model_path.exists():
                raise FileNotFoundError(f"Trained model checkpoint not found: {model_path}")
            self._model_cache[key] = joblib.load(model_path)
        return self._model_cache[key]

    def validate_window(
        self, window: dict[str, Any], modality: str
    ) -> tuple[np.ndarray, dict[str, float]]:
        """Validate that the telemetry window provides all required numeric features."""
        if not isinstance(window, dict):
            raise InferenceSchemaError("Telemetry window must be a dictionary.")

        required_features = self.get_required_features(modality)
        missing = [f for f in required_features if f not in window or window[f] is None]
        if missing:
            raise InferenceSchemaError(
                f"Missing required feature(s) for '{modality}' inference: {sorted(missing)}"
            )

        feature_values: dict[str, float] = {}
        row: list[float] = []
        for feature in required_features:
            val = window[feature]
            try:
                numeric_val = validate_finite_float(val, field_name=feature)
                feature_values[feature] = numeric_val
                row.append(numeric_val)
            except (ValueError, TypeError) as exc:
                raise InferenceSchemaError(
                    f"Malformed non-numeric value for feature '{feature}': {val!r}"
                ) from exc

        return np.asarray([row], dtype=float), feature_values

    def _extract_evidence(
        self, model: Any, feature_values: dict[str, float], required_features: list[str]
    ) -> dict[str, Any]:
        """Extract evidence including top contributing features when importance is exposed."""
        evidence: dict[str, Any] = {"feature_values": feature_values}
        classifier = getattr(model, "named_steps", {}).get("classifier", None)
        importances = getattr(classifier, "feature_importances_", None)

        if importances is not None and len(importances) == len(required_features):
            ranked = sorted(
                zip(required_features, importances),
                key=lambda item: abs(item[1]),
                reverse=True,
            )
            evidence["top_features"] = [
                {"feature": feat, "importance": float(imp), "value": feature_values[feat]}
                for feat, imp in ranked[:5]
            ]
        return evidence

    def predict(
        self,
        window: dict[str, Any],
        modality: str = "fusion",
        model_name: str = "random_forest",
    ) -> InferenceResult:
        """Perform threat detection inference on a single validated telemetry window."""
        matrix, feature_values = self.validate_window(window, modality)
        model = self.get_model(modality, model_name)

        predictions = model.predict(matrix)
        predicted_label = str(predictions[0])

        attack_probability: float | None = None
        confidence: float | None = None

        if hasattr(model, "predict_proba"):
            probabilities = model.predict_proba(matrix)[0]
            classes = list(getattr(model, "classes_", []))
            if "attack" in classes:
                attack_idx = classes.index("attack")
                attack_probability = float(probabilities[attack_idx])
            if predicted_label in classes:
                pred_idx = classes.index(predicted_label)
                confidence = float(probabilities[pred_idx])

        evidence = self._extract_evidence(model, feature_values, self.get_required_features(modality))

        window_start = str(window["window_start"]) if "window_start" in window and window["window_start"] else None
        window_end = str(window["window_end"]) if "window_end" in window and window["window_end"] else None
        affected_pods = str(window["affected_pods"]) if "affected_pods" in window and window["affected_pods"] else None

        return InferenceResult(
            predicted_label=predicted_label,
            attack_probability=attack_probability,
            confidence=confidence,
            window_start=window_start,
            window_end=window_end,
            modality=modality,
            model_name=model_name,
            evidence=evidence,
            affected_pods=affected_pods,
        )

    def predict_network_events(
        self, events: Sequence[NetworkEvent], model_name: str = "random_forest"
    ) -> list[InferenceResult]:
        """Aggregate raw eBPF network events into 10s windows and infer threat state."""
        windows = extract_network_features(list(events))
        return [self.predict(w, modality="network", model_name=model_name) for w in windows]

    def predict_workload_samples(
        self, samples: Sequence[WorkloadSample], model_name: str = "random_forest"
    ) -> list[InferenceResult]:
        """Aggregate raw workload samples into 10s windows and infer threat state."""
        windows = extract_workload_features(list(samples))
        return [self.predict(w, modality="workload", model_name=model_name) for w in windows]

    def predict_fusion_telemetry(
        self,
        network_events: Sequence[NetworkEvent],
        workload_samples: Sequence[WorkloadSample],
        session_id: str = "live_session",
        model_name: str = "random_forest",
    ) -> list[InferenceResult]:
        """Time-align raw network and workload telemetry and infer on fused windows."""
        net_windows = extract_network_features(list(network_events))
        workload_windows = extract_workload_features(list(workload_samples))
        for w in net_windows:
            w["session_id"] = session_id
            w["label"] = "unknown"
            w["attack_type"] = "unknown"
        for w in workload_windows:
            w["session_id"] = session_id
            w["label"] = "unknown"
            w["attack_type"] = "unknown"
        fusion_windows = align_feature_windows(net_windows, workload_windows)
        return [self.predict(w, modality="fusion", model_name=model_name) for w in fusion_windows]

    def predict_runtime_events(
        self, events: Sequence[RuntimeEvent], model_name: str = "random_forest"
    ) -> list[InferenceResult]:
        """Aggregate raw process execution events into 10s windows and infer threat state."""
        windows = extract_runtime_window_features(list(events))
        return [self.predict(w, modality="runtime", model_name=model_name) for w in windows]

    def predict_net_rt_telemetry(
        self,
        network_events: Sequence[NetworkEvent],
        runtime_events: Sequence[RuntimeEvent],
        session_id: str = "live_session",
        model_name: str = "random_forest",
    ) -> list[InferenceResult]:
        """Time-align raw network and runtime telemetry and infer on pairwise windows."""
        net_windows = extract_network_features(list(network_events))
        rt_windows = extract_runtime_window_features(list(runtime_events))
        for w in net_windows:
            w["session_id"] = session_id
            w["label"] = "unknown"
            w["attack_type"] = "unknown"
        for w in rt_windows:
            w["session_id"] = session_id
            w["label"] = "unknown"
            w["attack_type"] = "unknown"
        aligned_windows = align_feature_windows(net_windows, [], runtime_rows=rt_windows)
        rt_reqs = self.get_required_features("runtime")
        net_reqs = self.get_required_features("network")
        for w in aligned_windows:
            for f in rt_reqs:
                if f not in w or w[f] is None:
                    w[f] = 0.0
            for f in net_reqs:
                if f not in w or w[f] is None:
                    w[f] = 0.0
        return [self.predict(w, modality="net_rt", model_name=model_name) for w in aligned_windows]

    def predict_rt_wl_telemetry(
        self,
        workload_samples: Sequence[WorkloadSample],
        runtime_events: Sequence[RuntimeEvent],
        session_id: str = "live_session",
        model_name: str = "random_forest",
    ) -> list[InferenceResult]:
        """Time-align raw workload and runtime telemetry and infer on pairwise windows."""
        wl_windows = extract_workload_features(list(workload_samples))
        rt_windows = extract_runtime_window_features(list(runtime_events))
        for w in wl_windows:
            w["session_id"] = session_id
            w["label"] = "unknown"
            w["attack_type"] = "unknown"
        for w in rt_windows:
            w["session_id"] = session_id
            w["label"] = "unknown"
            w["attack_type"] = "unknown"
        aligned_windows = align_feature_windows([], wl_windows, runtime_rows=rt_windows)
        rt_reqs = self.get_required_features("runtime")
        wl_reqs = self.get_required_features("workload")
        for w in aligned_windows:
            for f in rt_reqs:
                if f not in w or w[f] is None:
                    w[f] = 0.0
            for f in wl_reqs:
                if f not in w or w[f] is None:
                    w[f] = 0.0
        return [self.predict(w, modality="rt_wl", model_name=model_name) for w in aligned_windows]

    def predict_full_fusion_telemetry(
        self,
        network_events: Sequence[NetworkEvent],
        workload_samples: Sequence[WorkloadSample],
        runtime_events: Sequence[RuntimeEvent],
        session_id: str = "live_session",
        model_name: str = "random_forest",
    ) -> list[InferenceResult]:
        """Time-align raw network, workload, and runtime telemetry and infer on full tri-modal windows."""
        net_windows = extract_network_features(list(network_events))
        wl_windows = extract_workload_features(list(workload_samples))
        rt_windows = extract_runtime_window_features(list(runtime_events))
        for w in net_windows:
            w["session_id"] = session_id
            w["label"] = "unknown"
            w["attack_type"] = "unknown"
        for w in wl_windows:
            w["session_id"] = session_id
            w["label"] = "unknown"
            w["attack_type"] = "unknown"
        for w in rt_windows:
            w["session_id"] = session_id
            w["label"] = "unknown"
            w["attack_type"] = "unknown"
        aligned_windows = align_feature_windows(net_windows, wl_windows, runtime_rows=rt_windows)
        all_reqs = self.get_required_features("full_fusion")
        for w in aligned_windows:
            for f in all_reqs:
                if f not in w or w[f] is None:
                    w[f] = 0.0
        return [self.predict(w, modality="full_fusion", model_name=model_name) for w in aligned_windows]


def predict_window(
    window: dict[str, Any],
    modality: str = "fusion",
    model_name: str = "random_forest",
    project_root: Path | str | None = None,
) -> dict[str, Any]:
    """Convenience functional API for single-window inference."""
    detector = ThreatDetector(project_root=project_root)
    return detector.predict(window, modality=modality, model_name=model_name).to_dict()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--modality", required=True, choices=ThreatDetector.SUPPORTED_MODALITIES)
    parser.add_argument("--model", default="random_forest", choices=ThreatDetector.SUPPORTED_MODELS)
    parser.add_argument("--input-json", type=str, default=None, help="Inline JSON object representing a window.")
    parser.add_argument("--input-file", type=Path, default=None, help="Path to JSON file with window dictionary.")
    parser.add_argument("--project-root", type=Path, default=Path("."))
    args = parser.parse_args()

    if args.input_json:
        window = json.loads(args.input_json)
    elif args.input_file:
        window = json.loads(args.input_file.read_text(encoding="utf-8"))
    else:
        raise ValueError("Must provide either --input-json or --input-file")

    result = predict_window(
        window=window,
        modality=args.modality,
        model_name=args.model,
        project_root=args.project_root.resolve(),
    )
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
