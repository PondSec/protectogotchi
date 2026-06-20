from __future__ import annotations

from typing import Any

from protectogotchi.capabilities.base import CapabilityModule, CapabilityResult


class PcapBot(CapabilityModule):
    name = "pcapbot"
    domain = "diagnostics"
    status = "requires-integration"
    risk = "review"

    def capture_filter(self, hosts: list[str], ports: list[int]) -> str:
        host_expr = " or ".join(f"host {host}" for host in hosts)
        port_expr = " or ".join(f"port {port}" for port in ports)
        parts = [part for part in [host_expr, port_expr] if part]
        return " and ".join(f"({part})" for part in parts) or "ip"

    def assess(self, context: dict[str, Any]) -> CapabilityResult:
        return CapabilityResult(
            module=self.name,
            status=self.status,
            summary="Packet-capture analysis hooks are prepared for authorized captures.",
            evidence={"default_filter": self.capture_filter([], [])},
            recommendations=("Capture only on interfaces and networks you are authorized to monitor.",),
            risk=self.risk,
        )
