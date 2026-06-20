from __future__ import annotations

from ipaddress import ip_network
from typing import Any

from protectogotchi.capabilities.base import CapabilityModule, CapabilityResult


class IPPlanner(CapabilityModule):
    name = "ip-planner"
    domain = "network-administration"

    def split(self, cidr: str, new_prefix: int) -> list[str]:
        network = ip_network(cidr, strict=False)
        return [str(subnet) for subnet in network.subnets(new_prefix=new_prefix)]

    def reserve(self, cidr: str, labels: dict[str, str]) -> dict[str, str]:
        network = ip_network(cidr, strict=False)
        hosts = [str(host) for host in network.hosts()]
        return {
            label: hosts[index]
            for index, label in enumerate(labels)
            if index < len(hosts)
        }

    def assess(self, context: dict[str, Any]) -> CapabilityResult:
        subnets = context.get("subnets", [])
        return CapabilityResult(
            module=self.name,
            status="available",
            summary=f"IP planning ready for {len(subnets)} known subnet(s).",
            evidence={"subnets": subnets},
            recommendations=("Document reservations before enabling enforcement policies.",),
        )
