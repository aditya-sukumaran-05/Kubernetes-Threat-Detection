"""Small, interpretable baseline model factories."""

from __future__ import annotations

import numpy as np
from sklearn.base import BaseEstimator, ClassifierMixin
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.svm import SVC
import xgboost as xgb


class XGBoostStringClassifier(BaseEstimator, ClassifierMixin):
    """XGBoost wrapper that supports string binary labels ('normal'/'attack')."""

    def __init__(
        self,
        random_state: int = 42,
        n_estimators: int = 100,
        max_depth: int = 6,
        learning_rate: float = 0.1,
        min_child_weight: float = 0,
    ):
        self.random_state = random_state
        self.n_estimators = n_estimators
        self.max_depth = max_depth
        self.learning_rate = learning_rate
        self.min_child_weight = min_child_weight
        self.classes_ = None
        self._clf = None

    def fit(self, X, y):
        self.classes_ = np.unique(y)
        y_int = (np.asarray(y) == "attack").astype(int)
        self._clf = xgb.XGBClassifier(
            random_state=self.random_state,
            n_estimators=self.n_estimators,
            max_depth=self.max_depth,
            learning_rate=self.learning_rate,
            min_child_weight=self.min_child_weight,
            eval_metric="logloss",
            n_jobs=1,
        )
        self._clf.fit(X, y_int)
        return self

    def predict(self, X):
        preds = self._clf.predict(X)
        return np.where(preds == 1, "attack", "normal")

    def predict_proba(self, X):
        probs = self._clf.predict_proba(X)
        if list(self.classes_) == ["attack", "normal"]:
            return np.column_stack([probs[:, 1], probs[:, 0]])
        return probs

    @property
    def feature_importances_(self):
        if hasattr(self, "_clf") and self._clf is not None:
            return self._clf.feature_importances_
        return None


def make_model(model_name: str, random_seed: int) -> Pipeline:
    if model_name == "logistic_regression":
        return Pipeline([
            ("imputer", SimpleImputer(strategy="median")),
            ("scaler", StandardScaler()),
            ("classifier", LogisticRegression(random_state=random_seed, max_iter=1000, class_weight="balanced")),
        ])
    if model_name == "random_forest":
        return Pipeline([
            ("imputer", SimpleImputer(strategy="median")),
            ("classifier", RandomForestClassifier(n_estimators=200, random_state=random_seed, class_weight="balanced", n_jobs=1)),
        ])
    if model_name == "xgboost":
        return Pipeline([
            ("imputer", SimpleImputer(strategy="median")),
            ("classifier", XGBoostStringClassifier(random_state=random_seed)),
        ])
    if model_name == "svm":
        return Pipeline([
            ("imputer", SimpleImputer(strategy="median")),
            ("scaler", StandardScaler()),
            ("classifier", SVC(kernel="rbf", probability=True, random_state=random_seed, class_weight="balanced")),
        ])
    raise ValueError(f"unsupported baseline model: {model_name}")
