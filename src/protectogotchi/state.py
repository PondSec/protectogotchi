from __future__ import annotations

import json
import math
from dataclasses import asdict, dataclass, field
from ipaddress import ip_interface
from pathlib import Path
from typing import Any

from protectogotchi.models import Finding, NetworkSnapshot, utc_now
from protectogotchi.netutil import normalize_mac
from protectogotchi.neural import train_neural_baseline


@dataclass
class FeatureStats:
    count: int = 0
    mean: float = 0.0
    m2: float = 0.0

    def update(self, value: float) -> None:
        self.count += 1
        delta = value - self.mean
        self.mean += delta / self.count
        delta2 = value - self.mean
        self.m2 += delta * delta2

    @property
    def variance(self) -> float:
        if self.count < 2:
            return 0.0
        return self.m2 / (self.count - 1)

    @property
    def stddev(self) -> float:
        return math.sqrt(self.variance)

    def zscore(self, value: float) -> float:
        if self.count < 2 or self.stddev == 0:
            return 0.0
        return (value - self.mean) / self.stddev


@dataclass
class ProtectogotchiState:
    version: int = 1
    created_at: str = field(default_factory=utc_now)
    updated_at: str = field(default_factory=utc_now)
    observations: int = 0
    scans: int = 0
    xp: int = 0
    level: int = 1
    devices: dict[str, dict[str, Any]] = field(default_factory=dict)
    ip_mac: dict[str, str] = field(default_factory=dict)
    gateway_macs: dict[str, str] = field(default_factory=dict)
    feature_stats: dict[str, FeatureStats] = field(default_factory=dict)
    seen_listening_ports: list[int] = field(default_factory=list)
    trusted_devices: dict[str, dict[str, str]] = field(default_factory=dict)
    known_route_keys: list[str] = field(default_factory=list)
    known_subnets: list[str] = field(default_factory=list)
    known_interfaces: dict[str, dict[str, Any]] = field(default_factory=dict)
    finding_history: list[dict[str, Any]] = field(default_factory=list)
    neural_model: dict[str, Any] = field(default_factory=dict)
    policy_model: dict[str, Any] = field(default_factory=dict)

    def known_macs(self) -> set[str]:
        return set(self.devices)

    def is_learning(self, min_observations: int) -> bool:
        return self.observations < min_observations

    def record_scan(self, findings: list[Finding]) -> None:
        self.scans += 1
        self.xp += 1
        self.xp += sum(max(1, finding.score // 10) for finding in findings)
        self.level = max(1, int(math.sqrt(self.xp / 25)) + 1)
        for finding in findings:
            self.finding_history.append(
                {
                    "seen_at": utc_now(),
                    "code": finding.code,
                    "title": finding.title,
                    "severity": finding.severity,
                    "description": finding.description,
                    "evidence": finding.evidence,
                    "recommended_action": finding.recommended_action,
                }
            )
        self.finding_history = self.finding_history[-200:]
        self.updated_at = utc_now()

    def learn(self, snapshot: NetworkSnapshot) -> None:
        now = snapshot.taken_at
        self.observations += 1
        self.updated_at = utc_now()

        for device in snapshot.devices:
            mac = device.normalized_mac()
            record = self.devices.setdefault(
                mac,
                {
                    "mac": mac,
                    "ips": [],
                    "first_seen": now,
                    "last_seen": now,
                    "seen_count": 0,
                    "hostname": device.hostname,
                    "interface": device.interface,
                },
            )
            if device.ip not in record["ips"]:
                record["ips"].append(device.ip)
            record["last_seen"] = now
            record["seen_count"] = int(record.get("seen_count", 0)) + 1
            if device.hostname:
                record["hostname"] = device.hostname
            if device.interface:
                record["interface"] = device.interface
            self.ip_mac[device.ip] = mac

        if snapshot.default_gateway and snapshot.default_gateway_mac:
            self.gateway_macs[snapshot.default_gateway] = snapshot.default_gateway_mac.lower()

        route_keys = set(self.known_route_keys)
        route_keys.update(route_key(route) for route in snapshot.routes)
        self.known_route_keys = sorted(route_keys)

        subnets = set(self.known_subnets)
        subnets.update(snapshot_subnets(snapshot))
        self.known_subnets = sorted(subnets)

        for interface in snapshot.interfaces:
            self.known_interfaces[interface.name] = {
                "name": interface.name,
                "ipv4": interface.ipv4,
                "ipv6": interface.ipv6,
                "mac": interface.mac,
                "status": interface.status,
                "last_seen": now,
            }

        for name, value in snapshot.features().items():
            stats = self.feature_stats.setdefault(name, FeatureStats())
            stats.update(value)

        self.neural_model = train_neural_baseline(self.neural_model, snapshot.features())

        ports = set(self.seen_listening_ports)
        ports.update(snapshot.listening_ports())
        self.seen_listening_ports = sorted(ports)

    def trust_device(self, mac: str, label: str | None = None) -> str:
        normalized = normalize_mac(mac)
        self.trusted_devices[normalized] = {
            "mac": normalized,
            "label": label or normalized,
            "trusted_at": utc_now(),
        }
        self.updated_at = utc_now()
        return normalized

    def untrust_device(self, mac: str) -> bool:
        normalized = normalize_mac(mac)
        removed = self.trusted_devices.pop(normalized, None) is not None
        if removed:
            self.updated_at = utc_now()
        return removed

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["feature_stats"] = {
            name: asdict(stats) for name, stats in self.feature_stats.items()
        }
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ProtectogotchiState":
        clean = dict(data)
        clean["feature_stats"] = {
            name: FeatureStats(**stats)
            for name, stats in clean.get("feature_stats", {}).items()
        }
        return cls(**clean)


class StateStore:
    def __init__(self, state_dir: Path) -> None:
        self.state_dir = state_dir.expanduser()
        self.path = self.state_dir / "state.json"

    def load(self) -> ProtectogotchiState:
        if not self.path.exists():
            return ProtectogotchiState()
        data = json.loads(self.path.read_text(encoding="utf-8"))
        return ProtectogotchiState.from_dict(data)

    def save(self, state: ProtectogotchiState) -> None:
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.path.write_text(
            json.dumps(state.to_dict(), indent=2, sort_keys=True),
            encoding="utf-8",
        )


def route_key(route) -> str:
    return "|".join(
        [
            route.destination,
            route.gateway or "-",
            route.interface or "-",
            route.family,
        ]
    )


def snapshot_subnets(snapshot: NetworkSnapshot) -> set[str]:
    subnets: set[str] = set()
    for interface in snapshot.interfaces:
        for address in interface.ipv4:
            try:
                network = ip_interface(address).network
            except ValueError:
                continue
            if network.is_loopback or network.is_link_local or network.is_multicast:
                continue
            subnets.add(str(network))
    return subnets
