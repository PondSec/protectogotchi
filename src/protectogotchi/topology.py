from __future__ import annotations

from dataclasses import asdict, dataclass, field
from ipaddress import ip_address, ip_interface, ip_network
from typing import Any

from protectogotchi.models import Device, NetworkSnapshot


@dataclass
class TopologyNode:
    id: str
    kind: str
    label: str
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class TopologyEdge:
    source: str
    target: str
    relation: str


@dataclass
class NetworkTopology:
    nodes: list[TopologyNode]
    edges: list[TopologyEdge]
    summary: dict[str, int]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class TopologyBuilder:
    def build(self, snapshot: NetworkSnapshot) -> NetworkTopology:
        nodes: dict[str, TopologyNode] = {}
        edges: set[tuple[str, str, str]] = set()

        self._add(nodes, "host:local", "host", snapshot.hostname, {"platform": snapshot.platform})

        interface_networks: list[tuple[str, str]] = []
        for interface in snapshot.interfaces:
            interface_id = f"interface:{interface.name}"
            self._add(
                nodes,
                interface_id,
                "interface",
                interface.name,
                {
                    "ipv4": interface.ipv4,
                    "ipv6": interface.ipv6,
                    "mac": interface.mac,
                    "status": interface.status,
                },
            )
            edges.add(("host:local", interface_id, "owns-interface"))
            for address in interface.ipv4:
                network = self._network_from_interface(address)
                if not network:
                    continue
                subnet_id = f"subnet:{network}"
                self._add(nodes, subnet_id, "subnet", network, {"source": "interface"})
                edges.add((interface_id, subnet_id, "attached-to"))
                interface_networks.append((interface.name, network))

        for route in snapshot.routes:
            destination = self._normalize_destination(route.destination)
            if not destination:
                continue
            route_id = f"route:{destination}:{route.interface or '-'}"
            self._add(
                nodes,
                route_id,
                "route",
                destination,
                {
                    "gateway": route.gateway,
                    "interface": route.interface,
                    "flags": route.flags,
                },
            )
            if route.interface:
                edges.add((f"interface:{route.interface}", route_id, "has-route"))
            if route.gateway:
                gateway_id = f"gateway:{route.gateway}"
                self._add(nodes, gateway_id, "gateway", route.gateway, {"ip": route.gateway})
                edges.add((route_id, gateway_id, "routes-via"))

        for device in snapshot.devices:
            kind = "gateway" if self._is_gateway(device, snapshot) else "device"
            node_id = f"{kind}:{device.ip}" if kind == "gateway" else f"device:{device.mac}"
            self._add(
                nodes,
                node_id,
                kind,
                device.hostname or device.ip,
                {
                    "ip": device.ip,
                    "mac": device.normalized_mac(),
                    "interface": device.interface,
                    "category": self._category(device, snapshot),
                },
            )
            if device.interface:
                edges.add((node_id, f"interface:{device.interface}", "seen-on"))
            subnet = self._subnet_for_ip(device.ip, interface_networks)
            if subnet:
                edges.add((node_id, f"subnet:{subnet}", "member-of"))

        edge_models = [
            TopologyEdge(source=source, target=target, relation=relation)
            for source, target, relation in sorted(edges)
            if source in nodes and target in nodes
        ]
        return NetworkTopology(
            nodes=sorted(nodes.values(), key=lambda node: (node.kind, node.id)),
            edges=edge_models,
            summary=self._summary(nodes),
        )

    def _add(
        self,
        nodes: dict[str, TopologyNode],
        node_id: str,
        kind: str,
        label: str,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        if node_id in nodes:
            nodes[node_id].metadata.update(metadata or {})
            return
        nodes[node_id] = TopologyNode(
            id=node_id,
            kind=kind,
            label=label,
            metadata=metadata or {},
        )

    def _network_from_interface(self, address: str) -> str | None:
        try:
            network = ip_interface(address).network
        except ValueError:
            return None
        if network.is_loopback or network.is_link_local or network.is_multicast:
            return None
        return str(network)

    def _normalize_destination(self, destination: str) -> str | None:
        if destination == "default":
            return "0.0.0.0/0"
        try:
            if "/" in destination:
                network = ip_network(destination, strict=False)
                if network.prefixlen == network.max_prefixlen:
                    return None
                if network.is_loopback or network.is_link_local or network.is_multicast:
                    return None
                return str(network)
            parsed = ip_address(destination)
            if parsed.is_loopback or parsed.is_link_local or parsed.is_multicast:
                return None
            return None
        except ValueError:
            return None

    def _subnet_for_ip(self, ip: str, networks: list[tuple[str, str]]) -> str | None:
        try:
            parsed = ip_address(ip)
        except ValueError:
            return None
        for _, network in networks:
            if parsed in ip_network(network, strict=False):
                return network
        return None

    def _is_gateway(self, device: Device, snapshot: NetworkSnapshot) -> bool:
        return device.ip == snapshot.default_gateway or (
            snapshot.default_gateway_mac is not None
            and device.normalized_mac() == snapshot.default_gateway_mac.lower()
        )

    def _category(self, device: Device, snapshot: NetworkSnapshot) -> str:
        if self._is_gateway(device, snapshot):
            return "gateway"
        if device.ip.endswith(".1") or device.ip.endswith(".254"):
            return "network-infrastructure-candidate"
        return "endpoint"

    def _summary(self, nodes: dict[str, TopologyNode]) -> dict[str, int]:
        summary: dict[str, int] = {}
        for node in nodes.values():
            summary[node.kind] = summary.get(node.kind, 0) + 1
        return summary
