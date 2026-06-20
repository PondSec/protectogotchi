from __future__ import annotations

import platform
import re
import socket
import subprocess
from pathlib import Path
from ipaddress import IPv4Network, ip_address

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


ARP_RE = re.compile(
    r"\((?P<ip>[^)]+)\)\s+at\s+(?P<mac>[0-9a-fA-F:]+)\s+on\s+(?P<iface>\S+)"
)


class MacOSCollector(Collector):
    def collect(self) -> NetworkSnapshot:
        wifi = self._wifi_info()
        gateway = self._default_gateway()
        devices = self._arp_devices()
        gateway_mac = self._mac_for_ip(gateway, devices) if gateway else None
        return NetworkSnapshot(
            taken_at=utc_now(),
            hostname=socket.gethostname(),
            platform=platform.platform(),
            wifi=wifi,
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
        ssid_output = self._run(["networksetup", "-getairportnetwork", "en0"])
        ssid = None
        if ":" in ssid_output and "not associated" not in ssid_output.lower():
            ssid = ssid_output.split(":", 1)[1].strip()

        info = WifiInfo(ssid=ssid, interface="en0")
        airport = Path(
            "/System/Library/PrivateFrameworks/Apple80211.framework/"
            "Versions/Current/Resources/airport"
        )
        if not airport.exists():
            return info

        output = self._run([str(airport), "-I"])
        for line in output.splitlines():
            if ":" not in line:
                continue
            key, value = [part.strip() for part in line.split(":", 1)]
            if key == "BSSID":
                info.bssid = value.lower()
            elif key == "channel":
                info.channel = value
            elif key == "agrCtlRSSI":
                info.rssi = self._int_or_none(value)
            elif key == "agrCtlNoise":
                info.noise = self._int_or_none(value)
        return info

    def _default_gateway(self) -> str | None:
        output = self._run(["route", "-n", "get", "default"])
        for line in output.splitlines():
            stripped = line.strip()
            if stripped.startswith("gateway:"):
                return stripped.split(":", 1)[1].strip()
        return None

    def _arp_devices(self) -> list[Device]:
        output = self._run(["arp", "-an"])
        devices: list[Device] = []
        for line in output.splitlines():
            match = ARP_RE.search(line)
            if not match:
                continue
            mac = match.group("mac").lower()
            if mac == "(incomplete)":
                continue
            if not is_relevant_neighbor(match.group("ip"), mac):
                continue
            devices.append(
                Device(
                    ip=match.group("ip"),
                    mac=mac,
                    interface=match.group("iface"),
                    source="arp",
                )
            )
        return devices

    def _connections(self) -> list[Connection]:
        connections: list[Connection] = []
        for proto in ("tcp", "udp"):
            output = self._run(["netstat", "-an", "-p", proto])
            connections.extend(self._parse_netstat(output, proto))
        return connections

    def _interfaces(self) -> list[InterfaceInfo]:
        output = self._run(["ifconfig"])
        interfaces: list[InterfaceInfo] = []
        current: InterfaceInfo | None = None
        for line in output.splitlines():
            if line and not line.startswith("\t") and ":" in line:
                name = line.split(":", 1)[0]
                current = InterfaceInfo(name=name)
                interfaces.append(current)
                continue
            if current is None:
                continue
            stripped = line.strip()
            if stripped.startswith("status:"):
                current.status = stripped.split(":", 1)[1].strip()
            elif stripped.startswith("ether "):
                current.mac = stripped.split()[1].lower()
            elif stripped.startswith("inet "):
                parts = stripped.split()
                ip = parts[1]
                prefix = None
                if "netmask" in parts:
                    mask = parts[parts.index("netmask") + 1]
                    prefix = self._prefix_from_macos_netmask(mask)
                current.ipv4.append(f"{ip}/{prefix}" if prefix is not None else ip)
            elif stripped.startswith("inet6 "):
                parts = stripped.split()
                current.ipv6.append(parts[1].split("%", 1)[0])
        return interfaces

    def _routes(self) -> list[Route]:
        output = self._run(["netstat", "-rn", "-f", "inet"])
        routes: list[Route] = []
        in_table = False
        for line in output.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            if stripped.startswith("Destination"):
                in_table = True
                continue
            if not in_table:
                continue
            parts = stripped.split()
            if len(parts) < 3:
                continue
            destination = parts[0]
            gateway = None if parts[1].startswith("link#") else parts[1]
            if gateway is not None and not self._is_ip(gateway):
                gateway = None
            flags = parts[2] if len(parts) > 2 else None
            iface = parts[3] if len(parts) > 3 else None
            routes.append(
                Route(
                    destination=destination,
                    gateway=gateway,
                    interface=iface,
                    flags=flags,
                    family="inet",
                )
            )
        return routes

    def _parse_netstat(self, output: str, proto: str) -> list[Connection]:
        connections: list[Connection] = []
        for line in output.splitlines():
            parts = line.split()
            if not parts or not parts[0].startswith(proto):
                continue
            if len(parts) < 4:
                continue

            local = self._split_host_port(parts[3])
            remote = self._split_host_port(parts[4]) if len(parts) > 4 else (None, None)
            state = parts[5] if proto == "tcp" and len(parts) > 5 else None
            connections.append(
                Connection(
                    protocol=proto,
                    local_address=local[0] or "",
                    local_port=local[1],
                    remote_address=remote[0],
                    remote_port=remote[1],
                    state=state,
                )
            )
        return connections

    def _split_host_port(self, value: str) -> tuple[str | None, int | None]:
        if value in {"*", "*.*"}:
            return None, None
        cleaned = value.strip()
        if cleaned.startswith("[") and "]:" in cleaned:
            host, port = cleaned.rsplit(":", 1)
            return host.strip("[]"), self._int_or_none(port)
        if "." not in cleaned:
            return cleaned, None
        host, port = cleaned.rsplit(".", 1)
        return host, self._int_or_none(port)

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

    def _prefix_from_macos_netmask(self, value: str) -> int | None:
        try:
            if value.startswith("0x"):
                mask_int = int(value, 16)
                return bin(mask_int).count("1")
            return IPv4Network(f"0.0.0.0/{value}").prefixlen
        except ValueError:
            return None

    def _is_ip(self, value: str) -> bool:
        try:
            ip_address(value)
        except ValueError:
            return False
        return True
