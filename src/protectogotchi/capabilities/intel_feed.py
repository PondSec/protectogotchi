from __future__ import annotations

from typing import Any

from protectogotchi.capabilities.base import CapabilityModule, CapabilityResult


class IntelFeed(CapabilityModule):
    name = "intel-feed"
    domain = "threat-intelligence"
    status = "planned"

    def normalize_indicator(self, value: str, indicator_type: str) -> dict[str, str]:
        return {"type": indicator_type.lower(), "value": value.strip().lower()}

    def assess(self, context: dict[str, Any]) -> CapabilityResult:
        indicators = context.get("indicators", [])
        return CapabilityResult(
            module=self.name,
            status=self.status,
            summary=f"Threat-intel normalization prepared for {len(indicators)} indicator(s).",
            evidence={"indicator_count": len(indicators)},
        )
