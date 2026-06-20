from __future__ import annotations

from typing import Any

from protectogotchi.capabilities.base import CapabilityModule, CapabilityResult


class Holoview(CapabilityModule):
    name = "holoview"
    domain = "dashboard"

    PANELS = ("asset-graph", "threat-matrix", "neural-engine", "arsenal", "control-console")

    def manifest(self) -> dict[str, Any]:
        return {"panels": list(self.PANELS), "auth": "local-first", "refresh_ms": 1500}

    def assess(self, context: dict[str, Any]) -> CapabilityResult:
        return CapabilityResult(
            module=self.name,
            status="available",
            summary="Local dashboard manifest is available.",
            evidence=self.manifest(),
        )
