"""
Trust scoring: converts device telemetry into a 0-100 trust score using
a real Isolation Forest anomaly detector (scikit-learn).

This is the "current trust" half of the trust engine. The forecasting
half (trust_engine/forecasting.py) operates on the *sequence* of scores
this module produces over time.
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler


class TrustScorer:
    """
    Wraps an IsolationForest trained on telemetry features. Anomaly scores
    from the model (higher = more anomalous) are inverted and rescaled to
    a 0-100 "trust score" (higher = more trustworthy), which is the
    convention used throughout the rest of the system.
    """

    def __init__(self, contamination: float = 0.12, random_state: int = 42):
        self.contamination = contamination
        self.random_state = random_state
        self.scaler = StandardScaler()
        self.model = IsolationForest(
            n_estimators=200,
            contamination=contamination,
            random_state=random_state,
        )
        self._fitted = False
        self._score_min = None
        self._score_max = None

    def fit(self, feature_df: pd.DataFrame):
        """Fit on a DataFrame of numeric telemetry features (benign-heavy)."""
        X = self.scaler.fit_transform(feature_df.values)
        self.model.fit(X)

        # Calibrate min/max of raw decision_function scores on the training
        # set so we can rescale consistently to a 0-100 trust range later.
        raw = self.model.decision_function(X)
        self._score_min, self._score_max = float(raw.min()), float(raw.max())
        self._fitted = True
        return self

    def score(self, feature_df: pd.DataFrame) -> np.ndarray:
        """
        Return a trust score in [0, 100] for each row of feature_df.
        100 = fully trusted / behaviourally normal.
        0   = maximally anomalous.
        """
        if not self._fitted:
            raise RuntimeError("TrustScorer.fit() must be called before score().")

        X = self.scaler.transform(feature_df.values)
        raw = self.model.decision_function(X)  # higher = more normal

        # Rescale raw decision_function output to 0-100 using the
        # calibration range captured at fit time. Clip to handle values
        # outside the original training range (genuinely novel behaviour).
        span = max(self._score_max - self._score_min, 1e-9)
        scaled = (raw - self._score_min) / span
        trust = np.clip(scaled * 100.0, 0, 100)
        return trust
