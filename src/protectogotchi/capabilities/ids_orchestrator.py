from __future__ import annotations

from collections import Counter
from typing import Any

from protectogotchi.capabilities.base import CapabilityModule, CapabilityResult


class IDSOrchestrator(CapabilityModule):
    name = "ids-orchestrator"
    domain = "network-security"
    status = "requires-integration"

    def summarize_alerts(self, alerts: list[dict[str, Any]]) -> dict[str, Any]:
        severities = Counter(alert.get("severity", "unknown") for alert in alerts)
        signatures = Counter(alert.get("signature", "unknown") for alert in alerts)
        return {"alert_count": len(alerts), "severities": dict(severities), "top_signatures": signatures.most_common(5)}

    def assess(self, context: dict[str, Any]) -> CapabilityResult:
        alerts = context.get("ids_alerts", [])
        return CapabilityResult(
            module=self.name,
            status=self.status,
            summary=f"IDS correlation ready; {len(alerts)} alert(s) in context.",
            evidence=self.summarize_alerts(alerts),
        )
