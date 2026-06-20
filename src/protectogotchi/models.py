from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from ipaddress import ip_address
from typing import Any, Literal


Severity = Literal["info", "low", "medium", "high", "critical"]

SEVERITY_SCORE: dict[str, int] = {
    "info": 0,
    "low": 15,
    "medium": 35,
    "high": 70,
    "critical": 95,
}


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


@dataclass
class WifiInfo:
    ssid: str | None = None
    bssid: str | None = None
    interface: str | None = None
    channel: str | None = None
    rssi: int | None = None
    noise: int | None = None


@dataclass
class Device:
    ip: str
    mac: str
    interface: str | None = None
    hostname: str | None = None
    source: str = "arp"

    def normalized_mac(self) -> str:
        return self.mac.lower()


@dataclass
class InterfaceInfo:
    name: str
    ipv4: list[str] = field(default_factory=list)
    ipv6: list[str] = field(default_factory=list)
    mac: str | None = None
    status: str | None = None


@dataclass
class Route:
    destination: str
    gateway: str | None = None
    interface: str | None = None
    flags: str | None = None
    family: str = "inet"


@dataclass
class Connection:
    protocol: str
    local_address: str
    local_port: int | None = None
    remote_address: str | None = None
    remote_port: int | None = None
    state: str | None = None

    def is_established(self) -> bool:
        return (self.state or "").upper() == "ESTABLISHED"

    def is_listening(self) -> bool:
        return (self.state or "").upper() in {"LISTEN", "LISTENING"}

    def has_external_remote(self) -> bool:
        if not self.remote_address:
            return False
        try:
            remote = ip_address(self.remote_address)
        except ValueError:
            return False
        return not (
            remote.is_private
            or remote.is_loopback
            or remote.is_link_local
            or remote.is_multicast
            or remote.is_unspecified
        )


@dataclass
class NetworkSnapshot:
    taken_at: str
    hostname: str
    platform: str
    wifi: WifiInfo = field(default_factory=WifiInfo)
    interfaces: list[InterfaceInfo] = field(default_factory=list)
    routes: list[Route] = field(default_factory=list)
    devices: list[Device] = field(default_factory=list)
    connections: list[Connection] = field(default_factory=list)
    default_gateway: str | None = None
    default_gateway_mac: str | None = None

    def features(self) -> dict[str, float]:
        unique_remotes = {
            connection.remote_address
            for connection in self.connections
            if connection.remote_address
        }
        listening_ports = {
            connection.local_port
            for connection in self.connections
            if connection.local_port is not None and connection.is_listening()
        }
        return {
            "device_count": float(len(self.devices)),
            "connection_count": float(len(self.connections)),
            "established_count": float(
                sum(1 for connection in self.connections if connection.is_established())
            ),
            "external_connection_count": float(
                sum(1 for connection in self.connections if connection.has_external_remote())
            ),
            "unique_remote_count": float(len(unique_remotes)),
            "listening_port_count": float(len(listening_ports)),
            "interface_count": float(len(self.interfaces)),
            "route_count": float(len(self.routes)),
        }

    def listening_ports(self) -> set[int]:
        return {
            connection.local_port
            for connection in self.connections
            if connection.local_port is not None and connection.is_listening()
        }

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "NetworkSnapshot":
        wifi = WifiInfo(**data.get("wifi", {}))
        interfaces = [InterfaceInfo(**item) for item in data.get("interfaces", [])]
        routes = [Route(**item) for item in data.get("routes", [])]
        devices = [Device(**item) for item in data.get("devices", [])]
        connections = [Connection(**item) for item in data.get("connections", [])]
        return cls(
            taken_at=data["taken_at"],
            hostname=data["hostname"],
            platform=data["platform"],
            wifi=wifi,
            interfaces=interfaces,
            routes=routes,
            devices=devices,
            connections=connections,
            default_gateway=data.get("default_gateway"),
            default_gateway_mac=data.get("default_gateway_mac"),
        )


@dataclass
class Finding:
    code: str
    title: str
    severity: Severity
    description: str
    evidence: dict[str, Any] = field(default_factory=dict)
    recommended_action: str = "observe"

    @property
    def score(self) -> int:
        return SEVERITY_SCORE[self.severity]


@dataclass
class ResponseAction:
    action_type: str
    target: str | None
    reason: str
    severity: Severity
    dry_run: bool = True
    command_preview: list[str] = field(default_factory=list)
    status: str = "planned"


@dataclass
class ScanResult:
    snapshot: NetworkSnapshot
    findings: list[Finding]
    actions: list[ResponseAction]
    risk_score: int
    face_state: str
    learned: bool
    level: int
    xp: int
    ai: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
