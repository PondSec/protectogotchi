from __future__ import annotations

from typing import Any

from protectogotchi.capabilities.base import CapabilityModule, CapabilityResult


class NetConfigEngine(CapabilityModule):
    name = "netconfig-engine"
    domain = "network-administration"
    status = "requires-integration"
    risk = "privileged"

    def render_vlan_config(self, vendor: str, vlan_id: int, name: str, ports: list[str]) -> str:
        if vendor.lower() in {"cisco", "ios", "nxos"}:
            port_lines = "\n".join(f"interface {port}\n switchport access vlan {vlan_id}" for port in ports)
            return f"vlan {vlan_id}\n name {name}\n{port_lines}".strip()
        if vendor.lower() in {"juniper", "junos"}:
            members = " ".join(ports)
            return f"set vlans {name} vlan-id {vlan_id}\nset interfaces {members} unit 0 family ethernet-switching vlan members {name}"
        return f"# unsupported vendor {vendor}; review manually"

    def assess(self, context: dict[str, Any]) -> CapabilityResult:
        return CapabilityResult(
            module=self.name,
            status=self.status,
            summary="Switch/router config rendering is available; push requires explicit controller credentials.",
            evidence={"supported_vendors": ["cisco-ios", "juniper-junos"]},
            recommendations=("Use rendered configs for review before applying them to real devices.",),
            risk=self.risk,
        )
