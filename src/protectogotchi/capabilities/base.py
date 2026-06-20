from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal


CapabilityStatus = Literal["available", "planned", "requires-integration", "disabled"]
CapabilityRisk = Literal["safe", "review", "privileged"]


@dataclass(frozen=True)
class CapabilityResult:
    module: str
    status: CapabilityStatus
    summary: str
    evidence: dict[str, Any] = field(default_factory=dict)
    recommendations: tuple[str, ...] = ()
    risk: CapabilityRisk = "safe"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class CapabilityModule:
    name = "capability"
    domain = "general"
    status: CapabilityStatus = "available"
    risk: CapabilityRisk = "safe"

    def describe(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "domain": self.domain,
            "status": self.status,
            "risk": self.risk,
        }

    def assess(self, context: dict[str, Any]) -> CapabilityResult:
        return CapabilityResult(
            module=self.name,
            status=self.status,
            summary="Capability loaded.",
            risk=self.risk,
        )
