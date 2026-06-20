from __future__ import annotations

from collections import Counter
from typing import Any

from protectogotchi.capabilities.base import CapabilityModule, CapabilityResult


class FlowCollector(CapabilityModule):
    name = "flowcollector"
    domain = "monitoring"
    status = "requires-integration"

    def summarize(self, flows: list[dict[str, Any]]) -> dict[str, Any]:
        protocols = Counter(flow.get("protocol", "unknown") for flow in flows)
        remotes = Counter(flow.get("remote_address", "unknown") for flow in flows)
        return {
            "flow_count": len(flows),
            "protocols": dict(protocols),
            "top_remotes": remotes.most_common(10),
        }

    def assess(self, context: dict[str, Any]) -> CapabilityResult:
        flows = context.get("flows", [])
        return CapabilityResult(
            module=self.name,
            status=self.status,
            summary=f"Flow metadata pipeline ready; {len(flows)} flow(s) in context.",
            evidence=self.summarize(flows),
        )
