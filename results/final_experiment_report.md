# Final Experiment Report

## Dataset summary

- Valid experiments: 0
- Processed windows: 198
- Class distribution: `{'attack': 3, 'normal': 111, 'unknown': 84}`

## Evaluation

- network / logistic_regression: **not_evaluable** — need at least two independent sessions per class; available={'attack': ['network_burst_20260919'], 'normal': ['network_normal_20260919']}
- network / random_forest: **not_evaluable** — need at least two independent sessions per class; available={'attack': ['network_burst_20260919'], 'normal': ['network_normal_20260919']}
- workload / logistic_regression: **not_evaluable** — supervised evaluation requires both classes; missing ['attack']
- workload / random_forest: **not_evaluable** — supervised evaluation requires both classes; missing ['attack']
- fusion / logistic_regression: **not_evaluable** — dataset contains zero labeled samples
- fusion / random_forest: **not_evaluable** — dataset contains zero labeled samples

## Limitations

- Metrics and figures are emitted only for valid session-held-out evaluations.
- Feature importance is model-derived evidence, not causal attribution.
