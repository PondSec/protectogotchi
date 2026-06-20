from __future__ import annotations

from dataclasses import asdict, dataclass, field
from ipaddress import ip_address, ip_interface, ip_network
from typing import Any

from protectogotchi.models import InterfaceInfo, NetworkSnapshot, Route


@dataclass(frozen=True)
class InterfaceView:
    name: str
    status: str | None
    mac: str | None
    ipv4: tuple[str, ...]
    networks: tuple[str, ...]
    role: str


@dataclass(frozen=True)
class RouteView:
    destination: str
    gateway: str | None
    interface: str | None
    role: str


@dataclass(frozen=True)
class DeviceView:
    ip: str
    mac: str
    interface: str | None
    category: str
    ips_are_local: bool = False


@dataclass(frozen=True)
class NetworkMap:
    interfaces: tuple[InterfaceView, ...]
    routes: tuple[RouteView, ...]
    devices: tuple[DeviceView, ...]
    gateways: tuple[str, ...]
    subnets: tuple[str, ...]
    coverage: tuple[str, ...]
    summary: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class NetworkMapper:
    def build(self, snapshot: NetworkSnapshot) -> NetworkMap:
        local_ips = self._local_ips(snapshot.interfaces)
        default_interfaces = {
            route.interface
            for route in snapshot.routes
            if route.destination in {"default", "0.0.0.0/0"} and route.interface
        }

        interfaces = tuple(
            InterfaceView(
                name=interface.name,
                status=interface.status,
                mac=interface.mac,
                ipv4=tuple(interface.ipv4),
                networks=tuple(self._networks(interface)),
                role=self._interface_role(interface, default_interfaces),
            )
            for interface in snapshot.interfaces
        )

        routes = tuple(
            RouteView(
                destination=route.destination,
                gateway=route.gateway,
                interface=route.interface,
                role=self._route_role(route),
            )
            for route in snapshot.routes
        )

        devices = tuple(
            DeviceView(
                ip=device.ip,
                mac=device.normalized_mac(),
                interface=device.interface,
                category=self._device_category(device.ip, snapshot, local_ips),
                ips_are_local=device.ip in local_ips,
            )
            for device in snapshot.devices
        )

        subnets = sorted({network for interface in interfaces for network in interface.networks})
        gateways = sorted(
            {
                gateway
                for gateway in [
                    snapshot.default_gateway,
                    *(route.gateway for route in snapshot.routes),
                ]
                if gateway and self._looks_like_ip(gateway)
            }
        )
        coverage = self._coverage(snapshot, subnets, routes)

        summary = {
            "active_interfaces": sum(
                1
                for interface in interfaces
                if interface.role in {"default-uplink", "local-network", "tunnel"}
            ),
            "local_subnets": len(subnets),
            "routed_networks": sum(1 for route in routes if route.role == "routed-network"),
            "gateways": len(gateways),
            "devices": len(devices),
            "local_host_entries": sum(1 for device in devices if device.ips_are_local),
        }

        return NetworkMap(
            interfaces=interfaces,
            routes=routes,
            devices=devices,
            gateways=tuple(gateways),
            subnets=tuple(subnets),
            coverage=coverage,
            summary=summary,
        )

    def _interface_role(
        self,
        interface: InterfaceInfo,
        default_interfaces: set[str | None],
    ) -> str:
        if interface.name in default_interfaces:
            return "default-uplink"
        if interface.status and interface.status.lower() not in {"active", "up", "unknown"}:
            return "inactive"
        if self._networks(interface):
            return "local-network"
        if interface.name.startswith("utun"):
            return "tunnel"
        return "system"

    def _route_role(self, route: Route) -> str:
        if route.destination in {"default", "0.0.0.0/0"}:
            return "default"
        if route.destination in {"127", "169.254"}:
            return "system"
        if "/" not in route.destination and route.destination.count(".") == 2 and not route.gateway:
            return "connected-network"
        try:
            network = ip_network(route.destination, strict=False)
        except ValueError:
            return "unknown"
        if network.is_loopback or network.is_link_local or network.is_multicast:
            return "system"
        if network.prefixlen == network.max_prefixlen:
            return "host"
        if route.gateway:
            return "routed-network"
        return "connected-network"

    def _device_category(
        self,
        ip: str,
        snapshot: NetworkSnapshot,
        local_ips: set[str],
    ) -> str:
        if ip in local_ips:
            return "local-host"
        if ip == snapshot.default_gateway:
            return "default-gateway"
        if ip.endswith(".1") or ip.endswith(".254"):
            return "infrastructure-candidate"
        return "endpoint"

    def _coverage(
        self,
        snapshot: NetworkSnapshot,
        subnets: list[str],
        routes: tuple[RouteView, ...],
    ) -> tuple[str, ...]:
        coverage = [
            "Passive host-view: directly connected subnets are visible through local interfaces and neighbor tables.",
        ]
        if snapshot.default_gateway:
            coverage.append(f"Default gateway: {snapshot.default_gateway}.")
        routed = [route.destination for route in routes if route.role == "routed-network"]
        if routed:
            coverage.append("Routed networks known from the routing table: " + ", ".join(routed) + ".")
        if not subnets:
            coverage.append("No private local IPv4 subnet was detected from active interfaces.")
        return tuple(coverage)

    def _networks(self, interface: InterfaceInfo) -> list[str]:
        networks: list[str] = []
        for address in interface.ipv4:
            try:
                network = ip_interface(address).network
            except ValueError:
                continue
            if network.is_loopback or network.is_link_local or network.is_multicast:
                continue
            networks.append(str(network))
        return networks

    def _local_ips(self, interfaces: list[InterfaceInfo]) -> set[str]:
        result: set[str] = set()
        for interface in interfaces:
            for address in interface.ipv4:
                try:
                    result.add(str(ip_interface(address).ip))
                except ValueError:
                    continue
        return result

    def _looks_like_ip(self, value: str) -> bool:
        try:
            parsed = ip_address(value)
        except ValueError:
            return False
        return not (
            parsed.is_loopback
            or parsed.is_link_local
            or parsed.is_multicast
            or parsed.is_unspecified
        )
