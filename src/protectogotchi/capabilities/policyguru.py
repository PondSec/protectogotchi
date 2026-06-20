from __future__ import annotations

from typing import Any

from protectogotchi.capabilities.base import CapabilityModule, CapabilityResult


class PolicyGuru(CapabilityModule):
    name = "policyguru"
    domain = "network-security"
    status = "requires-integration"
    risk = "privileged"

    def render_pf_block(self, table: str, ip: str) -> str:
        return f"table <{table}> persist\nblock drop quick from <{table}> to any\n# add: pfctl -t {table} -T add {ip}"

    def render_nft_block(self, set_name: str, ip: str) -> str:
        return (
            "table inet protectogotchi { "
            f"set {set_name} {{ type ipv4_addr; elements = {{ {ip} }}; }} "
            f"chain guard {{ type filter hook forward priority 0; ip saddr @{set_name} drop; }} }}"
        )

    def assess(self, context: dict[str, Any]) -> CapabilityResult:
        return CapabilityResult(
            module=self.name,
            status=self.status,
            summary="Policy rendering is ready; applying policies requires explicit active mode.",
            evidence={"targets": ["macos-pf", "linux-nftables"]},
            risk=self.risk,
        )
