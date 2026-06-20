from __future__ import annotations

from dataclasses import dataclass


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
