from __future__ import annotations

import platform
import socket
import subprocess

from protectogotchi.collectors.base import Collector
from protectogotchi.models import (
    Connection,
    Device,
    InterfaceInfo,
    NetworkSnapshot,
    Route,
    WifiInfo,
    utc_now,
)
from protectogotchi.netutil import is_relevant_neighbor


class LinuxCollector(Collector):
    def collect(self) -> NetworkSnapshot:
        gateway = self._default_gateway()
        devices = self._ip_neigh()
        gateway_mac = self._mac_for_ip(gateway, devices) if gateway else None
        return NetworkSnapshot(
            taken_at=utc_now(),
            hostname=socket.gethostname(),
            platform=platform.platform(),
            wifi=self._wifi_info(),
            interfaces=self._interfaces(),
            routes=self._routes(),
            devices=devices,
            connections=self._connections(),
            default_gateway=gateway,
            default_gateway_mac=gateway_mac,
        )

    def _run(self, command: list[str]) -> str:
        try:
            completed = subprocess.run(
                command,
                check=False,
                capture_output=True,
                text=True,
                timeout=5,
            )
        except (FileNotFoundError, subprocess.SubprocessError):
            return ""
        return completed.stdout + completed.stderr

    def _wifi_info(self) -> WifiInfo:
        output = self._run(["iwgetid", "-r"])
        ssid = output.strip() or None
        return WifiInfo(ssid=ssid)

    def _default_gateway(self) -> str | None:
        output = self._run(["ip", "route", "show", "default"])
        parts = output.split()
        if "via" in parts:
            index = parts.index("via")
            if index + 1 < len(parts):
                return parts[index + 1]
        return None

    def _ip_neigh(self) -> list[Device]:
        output = self._run(["ip", "neigh", "show"])
        devices: list[Device] = []
        for line in output.splitlines():
            parts = line.split()
            if "lladdr" not in parts or "dev" not in parts:
                continue
            ip = parts[0]
            mac = parts[parts.index("lladdr") + 1].lower()
            if not is_relevant_neighbor(ip, mac):
                continue
            iface = parts[parts.index("dev") + 1]
            devices.append(
                Device(
                    ip=ip,
                    mac=mac,
                    interface=iface,
                    hostname=self._hostname_for_ip(ip),
                    source="ip-neigh",
                )
            )
        return devices

    def _connections(self) -> list[Connection]:
        output = self._run(["ss", "-tun"])
        connections: list[Connection] = []
        for line in output.splitlines():
            parts = line.split()
            if not parts or parts[0] not in {"tcp", "udp"} or len(parts) < 5:
                continue
            state = parts[1] if parts[0] == "tcp" else None
            local = self._split_host_port(parts[-2])
            remote = self._split_host_port(parts[-1])
            connections.append(
                Connection(
                    protocol=parts[0],
                    local_address=local[0] or "",
                    local_port=local[1],
                    remote_address=remote[0],
                    remote_port=remote[1],
                    state=state,
                )
            )
        return connections

    def _interfaces(self) -> list[InterfaceInfo]:
        output = self._run(["ip", "-o", "addr", "show"])
        by_name: dict[str, InterfaceInfo] = {}
        for line in output.splitlines():
            parts = line.split()
            if len(parts) < 4:
                continue
            name = parts[1]
            interface = by_name.setdefault(name, InterfaceInfo(name=name))
            if parts[2] == "inet":
                interface.ipv4.append(parts[3])
            elif parts[2] == "inet6":
                interface.ipv6.append(parts[3])

        link_output = self._run(["ip", "-o", "link", "show"])
        for line in link_output.splitlines():
            parts = line.split()
            if len(parts) < 2:
                continue
            name = parts[1].rstrip(":")
            interface = by_name.setdefault(name, InterfaceInfo(name=name))
            if "link/ether" in parts:
                interface.mac = parts[parts.index("link/ether") + 1].lower()
            if "state" in parts:
                interface.status = parts[parts.index("state") + 1].lower()
        return list(by_name.values())

    def _routes(self) -> list[Route]:
        output = self._run(["ip", "route", "show"])
        routes: list[Route] = []
        for line in output.splitlines():
            parts = line.split()
            if not parts:
                continue
            destination = parts[0]
            gateway = None
            iface = None
            if "via" in parts:
                gateway = parts[parts.index("via") + 1]
            if "dev" in parts:
                iface = parts[parts.index("dev") + 1]
            routes.append(Route(destination=destination, gateway=gateway, interface=iface))
        return routes

    def _split_host_port(self, value: str) -> tuple[str | None, int | None]:
        if value in {"*", "*:*"}:
            return None, None
        if ":" not in value:
            return value, None
        host, port = value.rsplit(":", 1)
        return host.strip("[]"), self._int_or_none(port)

    def _mac_for_ip(self, ip: str, devices: list[Device]) -> str | None:
        for device in devices:
            if device.ip == ip:
                return device.normalized_mac()
        return None

    def _int_or_none(self, value: str) -> int | None:
        try:
            return int(value)
        except ValueError:
            return None

    def _hostname_for_ip(self, ip: str) -> str | None:
        output = self._run(["getent", "hosts", ip])
        parts = output.split()
        if len(parts) >= 2:
            return parts[1]
        return None
