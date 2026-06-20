from __future__ import annotations

from typing import Any

from protectogotchi.capabilities.base import CapabilityModule, CapabilityResult


class AutoDNS(CapabilityModule):
    name = "autodns"
    domain = "network-administration"
    status = "planned"

    def records_from_devices(self, devices: list[dict[str, Any]], zone: str) -> list[str]:
        records = []
        for device in devices:
            host = device.get("hostname")
            ips = device.get("ips", [])
            if host and ips:
                records.append(f"{host}.{zone}. 300 IN A {ips[0]}")
        return records

    def assess(self, context: dict[str, Any]) -> CapabilityResult:
        devices = context.get("devices", [])
        return CapabilityResult(
            module=self.name,
            status=self.status,
            summary=f"DNS record generation prepared for {len(devices)} learned device(s).",
            evidence={"device_count": len(devices)},
            recommendations=("Enable only after DHCP source of truth is identified.",),
        )
