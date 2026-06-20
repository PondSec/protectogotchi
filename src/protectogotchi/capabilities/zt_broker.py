from __future__ import annotations

from typing import Any

from protectogotchi.capabilities.base import CapabilityModule, CapabilityResult


class ZTBroker(CapabilityModule):
    name = "zt-broker"
    domain = "zero-trust"
    status = "planned"
    risk = "privileged"

    def evaluate_access(self, subject: str, device_trusted: bool, risk_score: int) -> str:
        if risk_score >= 70:
            return "deny"
        if device_trusted and risk_score < 35:
            return "allow"
        return "step-up"

    def assess(self, context: dict[str, Any]) -> CapabilityResult:
        risk_score = int(context.get("risk_score", 0))
        return CapabilityResult(
            module=self.name,
            status=self.status,
            summary="Zero-trust decision broker model is ready for identity integration.",
            evidence={"sample_decision": self.evaluate_access("user", False, risk_score)},
            risk=self.risk,
        )
