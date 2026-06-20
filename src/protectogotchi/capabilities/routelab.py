from __future__ import annotations

from collections import defaultdict
from typing import Any

from protectogotchi.capabilities.base import CapabilityModule, CapabilityResult


class RouteLab(CapabilityModule):
    name = "routelab"
    domain = "network-administration"

    def detect_loops(self, routes: list[dict[str, str | None]]) -> list[tuple[str, str]]:
        graph: dict[str, set[str]] = defaultdict(set)
        for route in routes:
            source = route.get("interface") or "host"
            gateway = route.get("gateway")
            if gateway:
                graph[source].add(gateway)
        loops = []
        for source, targets in graph.items():
            for target in targets:
                if source in graph.get(target, set()):
                    loops.append((source, target))
        return loops

    def assess(self, context: dict[str, Any]) -> CapabilityResult:
        routes = context.get("routes", [])
        loops = self.detect_loops(routes)
        return CapabilityResult(
            module=self.name,
            status="available",
            summary=f"Route graph checked; {len(loops)} possible loop(s) found.",
            evidence={"route_count": len(routes), "loops": loops},
            recommendations=("Investigate route loops before enabling inline prevention.",) if loops else (),
        )
