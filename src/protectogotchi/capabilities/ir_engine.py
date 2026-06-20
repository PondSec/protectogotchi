from __future__ import annotations

from typing import Any

from protectogotchi.capabilities.base import CapabilityModule, CapabilityResult


class IREngine(CapabilityModule):
    name = "ir-engine"
    domain = "incident-response"
    status = "planned"
    risk = "privileged"

    PLAYBOOKS = {
        "contain-host": ("verify evidence", "notify owner", "apply approved containment", "collect post-action state"),
        "rotate-credentials": ("identify scope", "disable stale tokens", "rotate secrets", "verify access logs"),
    }

    def playbook(self, name: str) -> tuple[str, ...]:
        return self.PLAYBOOKS.get(name, ())

    def assess(self, context: dict[str, Any]) -> CapabilityResult:
        return CapabilityResult(
            module=self.name,
            status=self.status,
            summary="IR playbook state machine is prepared for reviewed containment actions.",
            evidence={"playbooks": sorted(self.PLAYBOOKS)},
            risk=self.risk,
        )
