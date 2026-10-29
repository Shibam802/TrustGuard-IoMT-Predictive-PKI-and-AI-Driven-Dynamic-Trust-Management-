"""
Trust-trajectory forecasting: THE CORE NOVEL COMPONENT of TrustGuard-IoMT.

Existing PKI-IoT trust systems (see literature survey, papers 1, 2, 3, 6)
react only once a device's CURRENT trust score crosses a threshold -- by
which point the device may already be compromised.

This module instead looks at the TREND of a device's recent trust-score
history and forecasts whether the score is projected to breach the
critical threshold within a configurable prediction horizon. If so, the
policy controller can act pre-emptively (rotate the cert, escalate
monitoring) BEFORE the device is actually confirmed compromised.

Method (deliberately lightweight -- must run on modest/free-tier infra):
    1. Maintain a sliding window of the last `window_size` trust scores
       for each device.
    2. Fit a simple linear trend (least-squares slope) over that window.
    3. Extrapolate the trend forward by `horizon` steps.
    4. If the extrapolated score is below `breach_threshold`, flag a
       predicted breach and report how many steps out it's expected.

This is intentionally simple (no LSTM) so it's realistic to demo, explain,
and defend in a review -- while still being a genuinely predictive method,
not just a fixed-threshold reactive one. Swapping in a small LSTM/GRU
later (noted in "Next Steps") is a natural extension, not a redesign.
"""

from collections import deque
from dataclasses import dataclass
import numpy as np


@dataclass
class ForecastResult:
    device_id: str
    current_score: float
    trend_slope: float           # score change per time step (negative = degrading)
    forecasted_score: float      # extrapolated score `horizon` steps ahead
    breach_predicted: bool
    steps_to_breach: float | None  # None if no breach predicted within horizon


class TrustTrajectoryForecaster:
    def __init__(
        self,
        window_size: int = 8,
        horizon: int = 4,
        breach_threshold: float = 40.0,
    ):
        self.window_size = window_size
        self.horizon = horizon
        self.breach_threshold = breach_threshold
        self._history: dict[str, deque] = {}

    def update(self, device_id: str, score: float) -> ForecastResult:
        """Feed in the latest trust score for a device and get a forecast back."""
        if device_id not in self._history:
            self._history[device_id] = deque(maxlen=self.window_size)
        hist = self._history[device_id]
        hist.append(score)

        if len(hist) < 3:
            # Not enough points yet for a meaningful trend -- report flat.
            return ForecastResult(device_id, score, 0.0, score, False, None)

        y = np.array(hist, dtype=float)
        x = np.arange(len(y), dtype=float)

        # Least-squares linear fit: slope = trend per time step.
        slope, intercept = np.polyfit(x, y, 1)

        forecasted = float(slope * (len(y) - 1 + self.horizon) + intercept)
        forecasted = float(np.clip(forecasted, 0, 100))

        breach_predicted = forecasted < self.breach_threshold and slope < 0
        steps_to_breach = None
        if breach_predicted and slope < 0:
            # Solve for how many steps from "now" until the trend line
            # crosses the threshold.
            current_x = len(y) - 1
            steps = (self.breach_threshold - score) / slope
            steps_to_breach = round(float(max(steps, 0)), 1)

        return ForecastResult(
            device_id=device_id,
            current_score=score,
            trend_slope=round(float(slope), 3),
            forecasted_score=round(forecasted, 2),
            breach_predicted=bool(breach_predicted),
            steps_to_breach=steps_to_breach,
        )

    def reset(self, device_id: str):
        self._history.pop(device_id, None)
