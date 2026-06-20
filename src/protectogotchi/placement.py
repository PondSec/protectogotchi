from __future__ import annotations

from dataclasses import asdict, dataclass, field

from protectogotchi.config import ProtectogotchiConfig
from protectogotchi.network_map import NetworkMap


@dataclass(frozen=True)
class Capability:
    name: str
    status: str
    detail: str


@dataclass(frozen=True)
class PlacementReport:
    deployment_mode: str
    active_response_enabled: bool
    firewall_controller_automation: bool
    can_detect: tuple[Capability, ...]
    can_prevent: tuple[Capability, ...]
    cannot_prevent: tuple[Capability, ...]
    routed_subnets: tuple[str, ...] = field(default_factory=tuple)
    observed_remote_subnets: tuple[str, ...] = field(default_factory=tuple)
    same_subnet_devices: int = 0
    recommended_mode: str = "observer"
    summary: str = ""
    next_steps: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict:
        return asdict(self)


def build_placement_report(
    config: ProtectogotchiConfig,
    network_map: NetworkMap | None = None,
) -> PlacementReport:
    routed_subnets = tuple(
        route.destination for route in network_map.routes if route.role == "routed-network"
    ) if network_map else ()
    observed_remote_subnets = network_map.observed_remote_subnets if network_map else ()
    same_subnet_devices = (
        sum(
            1
            for device in network_map.devices
            if device.category not in {"local-host", "default-gateway"}
        )
        if network_map
        else 0
    )

    can_detect = (
        Capability(
            name="same-subnet visibility",
            status="available",
            detail="Neighbor tables, local routes, interface state, gateway identity, and observed devices.",
        ),
        Capability(
            name="routed-subnet visibility",
            status="partial" if routed_subnets or observed_remote_subnets else "limited",
            detail=(
                "Routes and active connections can reveal reachable VLANs/subnets, "
                "but silent networks cannot be proven from a client-only view."
            ),
        ),
        Capability(
            name="behavior learning",
            status="available",
            detail="Local baselines, feature spikes, new routes, new interfaces, and identity drift.",
        ),
    )

    can_prevent: list[Capability] = []
    cannot_prevent: list[Capability] = []

    if config.deployment_mode == "observer":
        cannot_prevent.extend(
            [
                Capability(
                    name="same-subnet peer traffic",
                    status="not-from-client",
                    detail="A normal client is not in the path between two other LAN peers.",
                ),
                Capability(
                    name="routed VLAN/subnet traffic",
                    status="not-from-client",
                    detail="A normal client can observe some signals but cannot block traffic crossing another router.",
                ),
            ]
        )
        recommended_mode = "observer"
        summary = "Client-only mode is useful for detection, learning, simulation, and alerting, but not network-wide prevention."
        next_steps = (
            "Use Attack Simulation to validate detections without touching live traffic.",
            "Keep Guard/God Mode honest: no ARP/MitM and no pretend network-wide blocking.",
            "For real prevention without controlling an existing firewall, Protectogotchi must become inline, an AP/gateway, or an endpoint agent.",
        )
    elif config.deployment_mode == "local-host-firewall":
        can_prevent.append(
            Capability(
                name="Protectogotchi host",
                status="available" if config.active_response_enabled else "needs-active-mode",
                detail="Can protect only the machine where Protectogotchi is running.",
            )
        )
        cannot_prevent.append(
            Capability(
                name="other device to other device",
                status="not-in-path",
                detail="Host-local controls do not stop traffic between separate devices.",
            )
        )
        recommended_mode = "local-host-firewall"
        summary = "This protects the Protectogotchi host, not the whole network."
        next_steps = ("Enable active response only after local firewall setup is verified.",)
    elif config.deployment_mode in {"inline-gateway", "transparent-bridge"}:
        can_prevent.append(
            Capability(
                name="traffic in path",
                status="available" if config.active_response_enabled else "needs-active-mode",
                detail="Inline placement can enforce traffic that actually passes through Protectogotchi.",
            )
        )
        recommended_mode = config.deployment_mode
        summary = "Inline placement is the clean non-MiTM path for real network-wide prevention."
        next_steps = ("Verify cabling/interface role before active mode.",)
    elif config.deployment_mode == "managed-ap-or-switch":
        can_prevent.append(
            Capability(
                name="access-layer quarantine",
                status="available" if config.active_response_enabled else "needs-active-mode",
                detail="A managed AP/switch can block association, ports, or VLAN access.",
            )
        )
        recommended_mode = "managed-ap-or-switch"
        summary = "Access-layer control is the clean way to stop same-subnet L2 traffic."
        next_steps = ("Connect only to owner-authorized AP/switch controls.",)
    elif config.deployment_mode == "endpoint-agent":
        can_prevent.append(
            Capability(
                name="agent-protected devices",
                status="available" if config.active_response_enabled else "needs-active-mode",
                detail="Each installed endpoint agent can enforce on its own device.",
            )
        )
        cannot_prevent.append(
            Capability(
                name="devices without agent",
                status="no-control",
                detail="Unmanaged devices still need network placement or access-layer control.",
            )
        )
        recommended_mode = "endpoint-agent"
        summary = "Endpoint agents avoid network takeover but only protect enrolled devices."
        next_steps = ("Install agents only on devices you own or administer.",)
    elif config.deployment_mode == "dns-guard":
        can_prevent.append(
            Capability(
                name="domain-level blocking",
                status="available" if config.active_response_enabled else "needs-active-mode",
                detail="Can block malicious domains for clients that voluntarily use Protectogotchi DNS.",
            )
        )
        cannot_prevent.append(
            Capability(
                name="raw IP and same-subnet traffic",
                status="not-covered",
                detail="DNS control does not stop direct IP traffic or LAN peer traffic.",
            )
        )
        recommended_mode = "dns-guard"
        summary = "DNS Guard is simple and low-risk, but it is not full traffic control."
        next_steps = ("Use it as a low-friction layer, not as the only enforcement layer.",)
    else:
        cannot_prevent.append(
            Capability(
                name="unknown placement",
                status="unknown",
                detail="This deployment mode is not evaluated by the no-firewall-control wizard.",
            )
        )
        recommended_mode = "observer"
        summary = "Unknown placement; defaulting to detect-and-alert assumptions."
        next_steps = ("Choose observer, inline-gateway, transparent-bridge, managed-ap-or-switch, or endpoint-agent.",)

    return PlacementReport(
        deployment_mode=config.deployment_mode,
        active_response_enabled=config.active_response_enabled,
        firewall_controller_automation=False,
        can_detect=can_detect,
        can_prevent=tuple(can_prevent),
        cannot_prevent=tuple(cannot_prevent),
        routed_subnets=routed_subnets,
        observed_remote_subnets=observed_remote_subnets,
        same_subnet_devices=same_subnet_devices,
        recommended_mode=recommended_mode,
        summary=summary,
        next_steps=next_steps,
    )
