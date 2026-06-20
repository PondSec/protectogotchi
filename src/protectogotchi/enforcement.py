from __future__ import annotations

from dataclasses import dataclass

from protectogotchi.config import ProtectogotchiConfig


@dataclass(frozen=True)
class EnforcementMode:
    name: str
    scope: str
    can_prevent: bool
    summary: str
    requirements: tuple[str, ...]
    current_status: str


MODES: tuple[EnforcementMode, ...] = (
    EnforcementMode(
        name="observer",
        scope="detect-and-alert",
        can_prevent=False,
        summary=(
            "Protectogotchi watches the local host view of the network. It can "
            "detect, learn, alert, and plan responses, but cannot stop every "
            "packet in the LAN."
        ),
        requirements=("macOS/Linux host", "local telemetry commands"),
        current_status="implemented",
    ),
    EnforcementMode(
        name="local-host-firewall",
        scope="protect-this-host",
        can_prevent=True,
        summary=(
            "Protectogotchi can block traffic to/from suspicious IPs on the host "
            "where it runs. This protects that host, not the whole network."
        ),
        requirements=("pf on macOS or nftables on Linux", "explicit active mode", "admin rights"),
        current_status="planned-safe-executor",
    ),
    EnforcementMode(
        name="dns-guard",
        scope="network-wide-dns-control",
        can_prevent=True,
        summary=(
            "Protectogotchi acts as the network DNS guard or controls a DNS sinkhole. "
            "This can block malicious domains for clients that use it through router DHCP."
        ),
        requirements=("router DHCP can advertise Protectogotchi DNS", "DNS sinkhole service"),
        current_status="planned",
    ),
    EnforcementMode(
        name="router-controller",
        scope="network-wide-control-plane",
        can_prevent=True,
        summary=(
            "Protectogotchi talks to the router/firewall/AP controller API and "
            "asks the real enforcement device to block or quarantine clients."
        ),
        requirements=("supported router/controller", "owner credentials/API token"),
        current_status="planned",
    ),
    EnforcementMode(
        name="inline-gateway",
        scope="network-wide-layer-3",
        can_prevent=True,
        summary=(
            "Raspberry Pi 5 runs as the default gateway. All routed traffic passes "
            "through Protectogotchi, so it can enforce policy directly."
        ),
        requirements=("Pi 5 image", "two network paths or AP mode", "nftables forwarding policy"),
        current_status="planned-pi-image",
    ),
    EnforcementMode(
        name="transparent-bridge",
        scope="network-wide-layer-2",
        can_prevent=True,
        summary=(
            "Protectogotchi sits physically inline as a bridge. It is not spoofing; "
            "it is an owner-installed bridge that can filter frames/flows."
        ),
        requirements=("two interfaces", "Linux bridge", "nftables/ebtables policy"),
        current_status="planned-pi-image",
    ),
    EnforcementMode(
        name="managed-ap-or-switch",
        scope="network-wide-access-control",
        can_prevent=True,
        summary=(
            "Protectogotchi uses managed AP/switch features to quarantine a client "
            "into a VLAN or block it at association/access-control level."
        ),
        requirements=("managed AP/switch/controller", "owner API access"),
        current_status="planned",
    ),
    EnforcementMode(
        name="endpoint-agent",
        scope="per-device",
        can_prevent=True,
        summary=(
            "A small agent on protected devices lets Protectogotchi enforce local "
            "firewall policy and report process/network correlation."
        ),
        requirements=("agent installed on each endpoint", "local owner consent"),
        current_status="planned",
    ),
    EnforcementMode(
        name="lab-simulation",
        scope="safe-testing",
        can_prevent=False,
        summary=(
            "Protectogotchi simulates attack/anomaly scenarios with synthetic "
            "snapshots so detections can be tested without touching live traffic."
        ),
        requirements=("local test run", "no packet injection"),
        current_status="implemented",
    ),
    EnforcementMode(
        name="arp-mitm",
        scope="rejected",
        can_prevent=False,
        summary=(
            "ARP spoofing to force traffic through Protectogotchi is intentionally "
            "not a supported protection mode. It is fragile, disruptive, and looks "
            "like the attack class Protectogotchi is meant to detect."
        ),
        requirements=("not used",),
        current_status="rejected",
    ),
)


def list_enforcement_modes() -> list[EnforcementMode]:
    return list(MODES)


def get_enforcement_mode(name: str) -> EnforcementMode | None:
    for mode in MODES:
        if mode.name == name:
            return mode
    return None


NETWORK_WIDE_MODES = {
    "dns-guard",
    "router-controller",
    "inline-gateway",
    "transparent-bridge",
    "managed-ap-or-switch",
}


def god_mode_readiness(config: ProtectogotchiConfig) -> dict[str, object]:
    mode = get_enforcement_mode(config.deployment_mode)
    network_wide = config.deployment_mode in NETWORK_WIDE_MODES
    host_wide = config.deployment_mode in {"local-host-firewall", "endpoint-agent"}
    active = config.active_response_enabled
    return {
        "deployment_mode": config.deployment_mode,
        "active_response_enabled": active,
        "can_prevent_network_wide": network_wide and active,
        "can_prevent_this_host": (host_wide or network_wide) and active,
        "mode_summary": mode.summary if mode else "Unknown deployment mode.",
        "warning": (
            "Client-only observer mode cannot reliably stop traffic between other devices. "
            "Network-wide autonomous prevention requires router/controller, inline gateway, "
            "transparent bridge, managed AP/switch, or endpoint enforcement."
        ),
        "recommended_next_step": recommended_next_step(config),
    }


def recommended_next_step(config: ProtectogotchiConfig) -> str:
    if config.deployment_mode == "observer":
        return (
            "For plug-and-play prevention, choose router-controller if your router/AP is supported, "
            "or dns-guard if you can set Protectogotchi as DHCP DNS. For full traffic control, use "
            "inline-gateway or transparent-bridge."
        )
    if config.deployment_mode == "dns-guard":
        return "Configure router DHCP to hand out Protectogotchi as DNS, then enable active mode."
    if config.deployment_mode == "local-host-firewall":
        return "Enable active mode to protect this host with the local firewall."
    if config.deployment_mode in NETWORK_WIDE_MODES:
        return "Enable active mode only after verifying the enforcement integration controls your own network."
    return "Install endpoint agents or choose a network-wide enforcement mode for broader protection."


def easy_protect_plan(config: ProtectogotchiConfig) -> list[dict[str, object]]:
    readiness = god_mode_readiness(config)
    return [
        {
            "mode": "observer",
            "effort": "zero setup",
            "prevents": False,
            "summary": "Detect, learn, alert, map, and plan responses from the current client position.",
        },
        {
            "mode": "dns-guard",
            "effort": "low",
            "prevents": True,
            "summary": "Set Protectogotchi as DHCP DNS to block malicious domains for clients using network DNS.",
        },
        {
            "mode": "router-controller",
            "effort": "low to medium",
            "prevents": True,
            "summary": "Use a supported router/AP/firewall API to block or quarantine devices.",
        },
        {
            "mode": "transparent-bridge",
            "effort": "medium",
            "prevents": True,
            "summary": "Place a Pi with two network interfaces inline; no ARP spoofing required.",
        },
        {
            "mode": "inline-gateway",
            "effort": "medium",
            "prevents": True,
            "summary": "Make Protectogotchi the default gateway/AP for full routed enforcement.",
        },
        {
            "current_readiness": readiness,
        },
    ]
