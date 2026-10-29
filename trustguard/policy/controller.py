"""
Policy & Quarantine Controller.

Consumes both the CURRENT trust score and the FORECASTED trajectory for
each device and decides what action to take. Three tiers, matching the
architecture slide from Review 1:

    Tier 1 (Normal)                - no action
    Tier 2 (Predictive Escalation) - forecast predicts a breach soon ->
                                      rotate certificate early + tighten
                                      monitoring, device keeps operating
    Tier 3 (Confirmed Breach)      - CURRENT score itself is already below
                                      threshold -> revoke immediately,
                                      quarantine at network layer, alert

Every transition is written to the RevocationLedger for audit purposes.
"""

from dataclasses import dataclass
from enum import Enum

from ca.hybrid_ca import HybridCA
from ledger.ledger import RevocationLedger
from trust_engine.forecasting import ForecastResult


class Tier(str, Enum):
    NORMAL = "TIER_1_NORMAL"
    PREDICTIVE_ESCALATION = "TIER_2_PREDICTIVE_ESCALATION"
    CONFIRMED_BREACH = "TIER_3_CONFIRMED_BREACH"


@dataclass
class PolicyDecision:
    device_id: str
    tier: Tier
    action_taken: str
    new_cert_id: str | None


class PolicyController:
    def __init__(
        self,
        ca: HybridCA,
        ledger: RevocationLedger,
        current_breach_threshold: float = 35.0,
    ):
        self.ca = ca
        self.ledger = ledger
        self.current_breach_threshold = current_breach_threshold
        self.quarantined_devices: set[str] = set()

    def evaluate(self, forecast: ForecastResult, active_cert) -> PolicyDecision:
        device_id = forecast.device_id

        # --- Tier 3: current score already confirms breach ---
        if forecast.current_score < self.current_breach_threshold:
            self.ca.revoke_certificate(active_cert, reason="confirmed_breach")
            self.quarantined_devices.add(device_id)
            self.ledger.append(
                event_type="REVOKE",
                device_id=device_id,
                cert_id=active_cert.cert_id,
                detail=(
                    f"Confirmed breach: current_score={forecast.current_score:.1f} "
                    f"< threshold={self.current_breach_threshold}. Device quarantined."
                ),
            )
            return PolicyDecision(device_id, Tier.CONFIRMED_BREACH, "REVOKE_AND_QUARANTINE", None)

        # --- Tier 2: forecast predicts a breach soon (pre-emptive action) ---
        if forecast.breach_predicted:
            new_cert = self.ca.rotate_certificate(active_cert, reason="predictive_escalation")
            self.ledger.append(
                event_type="ROTATE",
                device_id=device_id,
                cert_id=new_cert.cert_id,
                detail=(
                    f"Predictive escalation: trend slope={forecast.trend_slope}, "
                    f"forecasted_score={forecast.forecasted_score:.1f} within "
                    f"{forecast.steps_to_breach} steps. Certificate rotated early."
                ),
            )
            return PolicyDecision(device_id, Tier.PREDICTIVE_ESCALATION, "PREEMPTIVE_ROTATE", new_cert.cert_id)

        # --- Tier 1: normal ---
        return PolicyDecision(device_id, Tier.NORMAL, "NONE", active_cert.cert_id)
