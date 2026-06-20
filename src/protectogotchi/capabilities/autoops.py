from __future__ import annotations

from typing import Any

from protectogotchi.capabilities.base import CapabilityModule, CapabilityResult


class AutoOps(CapabilityModule):
    name = "autoops"
    domain = "automation"
    status = "planned"
    risk = "privileged"

    def route_event(self, event: dict[str, Any]) -> str:
        severity = str(event.get("severity", "info")).lower()
        if severity in {"critical", "high"}:
            return "ir-engine"
        if event.get("type") == "flow":
            return "flowcollector"
        return "logpipe"

    def assess(self, context: dict[str, Any]) -> CapabilityResult:
        events = context.get("events", [])
        routes = [self.route_event(event) for event in events]
        return CapabilityResult(
            module=self.name,
            status=self.status,
            summary=f"Automation routing prepared for {len(events)} event(s).",
            evidence={"routes": routes},
            risk=self.risk,
        )
