from __future__ import annotations

from typing import Any

from protectogotchi.capabilities.base import CapabilityModule, CapabilityResult


class LogPipe(CapabilityModule):
    name = "logpipe"
    domain = "siem"
    status = "requires-integration"

    def normalize(self, event: dict[str, Any]) -> dict[str, Any]:
        return {
            "timestamp": event.get("timestamp") or event.get("time") or "-",
            "source": event.get("source", "unknown"),
            "severity": str(event.get("severity", "info")).lower(),
            "message": event.get("message", ""),
        }

    def assess(self, context: dict[str, Any]) -> CapabilityResult:
        events = [self.normalize(event) for event in context.get("logs", [])]
        return CapabilityResult(
            module=self.name,
            status=self.status,
            summary=f"Log normalization ready; {len(events)} event(s) normalized.",
            evidence={"events": events[:5]},
        )
