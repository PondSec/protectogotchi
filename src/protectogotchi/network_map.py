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
    hostname: str | None
    category: str
    ips_are_local: bool = False


@dataclass(frozen=True)
class NetworkMap:
    interfaces: tuple[InterfaceView, ...]
    routes: tuple[RouteView, ...]
    devices: tuple[DeviceView, ...]
    gateways: tuple[str, ...]
    subnets: tuple[str, ...]
    observed_remote_subnets: tuple[str, ...]
    coverage: tuple[str, ...]
    graph: dict[str, Any]
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
                hostname=device.hostname,
                category=self._device_category(device.ip, snapshot, local_ips),
                ips_are_local=device.ip in local_ips,
            )
            for device in snapshot.devices
        )

        interface_subnets = {network for interface in interfaces for network in interface.networks}
        route_subnets = {
            network
            for network in (self._network_from_route(route) for route in snapshot.routes)
            if network
        }
        observed_remote_subnets = self._observed_remote_subnets(snapshot)
        subnets = sorted(interface_subnets | route_subnets | observed_remote_subnets)
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
        coverage = self._coverage(snapshot, subnets, routes, observed_remote_subnets)
        graph = self._graph(snapshot, interfaces, devices, subnets)

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
            "observed_remote_subnets": len(observed_remote_subnets),
        }

        return NetworkMap(
            interfaces=interfaces,
            routes=routes,
            devices=devices,
            gateways=tuple(gateways),
            subnets=tuple(subnets),
            observed_remote_subnets=tuple(sorted(observed_remote_subnets)),
            coverage=coverage,
            graph=graph,
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
        observed_remote_subnets: set[str],
    ) -> tuple[str, ...]:
        coverage = [
            "Passive host-view: directly connected subnets are visible through local interfaces and neighbor tables.",
        ]
        if snapshot.default_gateway:
            coverage.append(f"Default gateway: {snapshot.default_gateway}.")
        routed = [route.destination for route in routes if route.role == "routed-network"]
        if routed:
            coverage.append("Routed networks known from the routing table: " + ", ".join(routed) + ".")
        if observed_remote_subnets:
            coverage.append(
                "Private remote networks inferred from active connections: "
                + ", ".join(sorted(observed_remote_subnets))
                + "."
            )
        if not subnets:
            coverage.append("No private local IPv4 subnet was detected from active interfaces.")
        coverage.append(
            "Subnets that are not routed, observed in traffic, advertised by DNS/router APIs, or actively discovered cannot be proven from a client-only host view."
        )
        return tuple(coverage)

    def _graph(
        self,
        snapshot: NetworkSnapshot,
        interfaces: tuple[InterfaceView, ...],
        devices: tuple[DeviceView, ...],
        subnets: list[str],
    ) -> dict[str, Any]:
        nodes: list[dict[str, Any]] = [
            {"id": "host", "kind": "host", "label": snapshot.hostname},
        ]
        edges: list[dict[str, str]] = []

        for interface in interfaces:
            if not interface.networks and interface.role != "default-uplink":
                continue
            interface_id = f"if:{interface.name}"
            nodes.append(
                {
                    "id": interface_id,
                    "kind": "interface",
                    "label": interface.name,
                    "role": interface.role,
                    "mac": interface.mac,
                    "ipv4": list(interface.ipv4),
                }
            )
            edges.append({"source": "host", "target": interface_id, "relation": "interface"})
            for network in interface.networks:
                subnet_id = f"subnet:{network}"
                edges.append({"source": interface_id, "target": subnet_id, "relation": "attached"})

        for subnet in subnets:
            nodes.append({"id": f"subnet:{subnet}", "kind": "subnet", "label": subnet})

        for device in devices:
            node_id = f"device:{device.mac}"
            label = device.hostname or device.ip
            nodes.append(
                {
                    "id": node_id,
                    "kind": device.category,
                    "label": label,
                    "ip": device.ip,
                    "mac": device.mac,
                    "hostname": device.hostname,
                    "interface": device.interface,
                }
            )
            if device.interface:
                edges.append(
                    {
                        "source": f"if:{device.interface}",
                        "target": node_id,
                        "relation": "sees",
                    }
                )
            subnet = self._subnet_for_ip(device.ip, subnets)
            if subnet:
                edges.append(
                    {
                        "source": f"subnet:{subnet}",
                        "target": node_id,
                        "relation": "member",
                    }
                )

        return {"nodes": nodes, "edges": edges}

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

    def _network_from_route(self, route: Route) -> str | None:
        if route.destination in {"default", "0.0.0.0/0"}:
            return None
        destination = route.destination
        if "/" not in destination and destination.count(".") == 2:
            destination = f"{destination}.0/24"
        try:
            network = ip_network(destination, strict=False)
        except ValueError:
            return None
        if network.is_loopback or network.is_link_local or network.is_multicast:
            return None
        if network.prefixlen == network.max_prefixlen:
            return None
        return str(network)

    def _observed_remote_subnets(self, snapshot: NetworkSnapshot) -> set[str]:
        subnets: set[str] = set()
        for connection in snapshot.connections:
            if not connection.remote_address:
                continue
            try:
                remote = ip_address(connection.remote_address)
            except ValueError:
                continue
            if not remote.is_private or remote.is_loopback or remote.is_link_local:
                continue
            if remote.version == 4:
                subnets.add(str(ip_network(f"{remote}/24", strict=False)))
        return subnets

    def _subnet_for_ip(self, ip: str, subnets: list[str]) -> str | None:
        try:
            parsed = ip_address(ip)
        except ValueError:
            return None
        for subnet in subnets:
            if parsed in ip_network(subnet, strict=False):
                return subnet
        return None

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
