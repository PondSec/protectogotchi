from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import asdict, dataclass, field
from ipaddress import ip_address, ip_network
from pathlib import Path
from typing import Any, Callable
from xml.etree import ElementTree


Runner = Callable[[list[str], int], subprocess.CompletedProcess[str]]

ADMIN_PORTS = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    445: "smb",
    1433: "mssql",
    3306: "mysql",
    3389: "rdp",
    5432: "postgres",
    5900: "vnc",
}


@dataclass(frozen=True)
class ExternalToolSpec:
    name: str
    binary: str
    category: str
    purpose: str
    risk: str = "safe"
    notes: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ExternalToolStatus:
    spec: ExternalToolSpec
    available: bool
    path: str | None

    def to_dict(self) -> dict[str, Any]:
        return {
            **self.spec.to_dict(),
            "available": self.available,
            "path": self.path,
        }


@dataclass(frozen=True)
class ToolAction:
    tool: str
    purpose: str
    command: tuple[str, ...]
    risk: str
    requires_review: bool = True
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["command"] = list(self.command)
        return data


@dataclass(frozen=True)
class ToolRunResult:
    action: dict[str, Any]
    status: str
    stdout: str = ""
    stderr: str = ""
    parsed: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


EXTERNAL_TOOL_SPECS: tuple[ExternalToolSpec, ...] = (
    ExternalToolSpec(
        name="nmap",
        binary="nmap",
        category="network-discovery",
        purpose="Authorized host/port/service inventory for owned private networks.",
        risk="review",
        notes=("Uses conservative top-port connect scanning only in generated plans.",),
    ),
    ExternalToolSpec(
        name="tcpdump",
        binary="tcpdump",
        category="packet-capture",
        purpose="Read authorized packet captures or capture metadata with owner approval.",
        risk="review",
    ),
    ExternalToolSpec(
        name="tshark",
        binary="tshark",
        category="packet-analysis",
        purpose="Summarize authorized pcap files for protocol and endpoint evidence.",
        risk="review",
    ),
    ExternalToolSpec(
        name="zeek",
        binary="zeek",
        category="ids",
        purpose="Parse Zeek logs or run authorized local pcap analysis.",
        risk="review",
    ),
    ExternalToolSpec(
        name="suricata",
        binary="suricata",
        category="ids",
        purpose="Ingest Suricata alerts and correlate with local baseline context.",
        risk="review",
    ),
    ExternalToolSpec(
        name="snort",
        binary="snort",
        category="ids",
        purpose="Ingest Snort alerts and support defensive rule tuning.",
        risk="review",
    ),
    ExternalToolSpec(
        name="snmpwalk",
        binary="snmpwalk",
        category="inventory",
        purpose="Authorized SNMP inventory for switches, routers, and APs.",
        risk="review",
    ),
    ExternalToolSpec(
        name="mtr",
        binary="mtr",
        category="path-diagnostics",
        purpose="Path quality and routing diagnostics.",
    ),
    ExternalToolSpec(
        name="traceroute",
        binary="traceroute",
        category="path-diagnostics",
        purpose="Layer-3 path diagnostics.",
    ),
    ExternalToolSpec(
        name="ping",
        binary="ping",
        category="reachability",
        purpose="Basic reachability checks.",
    ),
    ExternalToolSpec(
        name="dig",
        binary="dig",
        category="dns",
        purpose="DNS resolver and record diagnostics.",
    ),
    ExternalToolSpec(
        name="pfctl",
        binary="pfctl",
        category="enforcement",
        purpose="macOS packet-filter enforcement through reviewed anchors.",
        risk="privileged",
    ),
    ExternalToolSpec(
        name="nft",
        binary="nft",
        category="enforcement",
        purpose="Linux nftables enforcement through reviewed tables/chains.",
        risk="privileged",
    ),
)


class ExternalToolRuntime:
    def __init__(
        self,
        *,
        which: Callable[[str], str | None] | None = None,
        runner: Runner | None = None,
    ) -> None:
        self.which = which or shutil.which
        self.runner = runner or self._run_subprocess

    def discover(self) -> list[ExternalToolStatus]:
        statuses = []
        for spec in EXTERNAL_TOOL_SPECS:
            path = self.which(spec.binary)
            statuses.append(ExternalToolStatus(spec=spec, available=path is not None, path=path))
        return statuses

    def report(self) -> dict[str, Any]:
        statuses = [status.to_dict() for status in self.discover()]
        available = [status for status in statuses if status["available"]]
        return {
            "available_count": len(available),
            "total_count": len(statuses),
            "tools": statuses,
            "recommendations": self._recommend_installations(statuses),
        }

    def plan_for_target(self, target: str) -> list[ToolAction]:
        if not is_private_or_local_target(target):
            raise ValueError("Refusing external tool plan for non-private/non-local target.")
        available = {status.spec.name for status in self.discover() if status.available}
        actions: list[ToolAction] = []
        if "ping" in available:
            actions.append(
                ToolAction(
                    tool="ping",
                    purpose="reachability",
                    command=("ping", "-c", "3", target),
                    risk="safe",
                    requires_review=False,
                    reason="Confirm the host responds before deeper diagnostics.",
                )
            )
        if "traceroute" in available:
            actions.append(
                ToolAction(
                    tool="traceroute",
                    purpose="path-diagnostics",
                    command=("traceroute", target),
                    risk="safe",
                    requires_review=False,
                    reason="Understand the routed path from this Protectogotchi placement.",
                )
            )
        if "nmap" in available:
            actions.append(
                ToolAction(
                    tool="nmap",
                    purpose="service-inventory",
                    command=("nmap", "-oX", "-", "-sT", "--top-ports", "64", "--version-light", target),
                    risk="review",
                    requires_review=True,
                    reason="Build authorized service inventory for defensive exposure analysis.",
                )
            )
        return actions

    def plan_for_pcap(self, pcap_path: Path) -> list[ToolAction]:
        available = {status.spec.name for status in self.discover() if status.available}
        actions: list[ToolAction] = []
        path = str(pcap_path)
        if "tshark" in available:
            actions.append(
                ToolAction(
                    tool="tshark",
                    purpose="pcap-protocol-summary",
                    command=("tshark", "-r", path, "-q", "-z", "io,phs"),
                    risk="review",
                    requires_review=True,
                    reason="Summarize authorized capture protocols without payload extraction.",
                )
            )
        if "tcpdump" in available:
            actions.append(
                ToolAction(
                    tool="tcpdump",
                    purpose="pcap-sample",
                    command=("tcpdump", "-nn", "-r", path, "-c", "200"),
                    risk="review",
                    requires_review=True,
                    reason="Read a bounded sample from an authorized capture.",
                )
            )
        return actions

    def run_plan(
        self,
        actions: list[ToolAction],
        *,
        allow_review: bool = False,
        timeout: int = 20,
    ) -> list[ToolRunResult]:
        results = []
        for action in actions:
            if action.requires_review and not allow_review:
                results.append(
                    ToolRunResult(
                        action=action.to_dict(),
                        status="requires-review",
                    )
                )
                continue
            completed = self.runner(list(action.command), timeout)
            parsed = self.parse_output(action.tool, completed.stdout)
            results.append(
                ToolRunResult(
                    action=action.to_dict(),
                    status="ok" if completed.returncode == 0 else "failed",
                    stdout=completed.stdout,
                    stderr=completed.stderr,
                    parsed=parsed,
                )
            )
        return results

    def parse_output(self, tool: str, output: str) -> dict[str, Any]:
        if tool == "nmap":
            return parse_nmap_xml(output)
        if tool in {"tcpdump", "tshark"}:
            return parse_packet_text(output)
        if tool == "ping":
            return parse_ping(output)
        return {"raw_lines": len(output.splitlines())}

    def decide(self, parsed_outputs: list[dict[str, Any]]) -> dict[str, Any]:
        open_admin = []
        protocols: dict[str, int] = {}
        for parsed in parsed_outputs:
            for host in parsed.get("hosts", []):
                for port in host.get("open_ports", []):
                    number = int(port.get("port", 0))
                    if number in ADMIN_PORTS:
                        open_admin.append({**port, "host": host.get("address"), "service_hint": ADMIN_PORTS[number]})
            for name, count in parsed.get("protocols", {}).items():
                protocols[name] = protocols.get(name, 0) + int(count)

        recommendations = []
        if open_admin:
            recommendations.append("Review exposed remote-admin services and restrict them to trusted management networks.")
        if protocols.get("ARP", 0) > 50:
            recommendations.append("High ARP volume in capture summary; inspect for identity churn or noisy discovery.")
        return {
            "open_admin_services": open_admin,
            "protocols": protocols,
            "recommendations": recommendations,
            "risk_score_hint": min(100, len(open_admin) * 25 + (20 if protocols.get("ARP", 0) > 50 else 0)),
        }

    def _run_subprocess(self, command: list[str], timeout: int) -> subprocess.CompletedProcess[str]:
        return subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=False)

    def _recommend_installations(self, statuses: list[dict[str, Any]]) -> list[str]:
        missing = {status["name"] for status in statuses if not status["available"]}
        recommendations = []
        if {"nmap", "tcpdump", "tshark"} & missing:
            recommendations.append("Install nmap/tcpdump/tshark for richer authorized diagnostics.")
        if {"zeek", "suricata"} & missing:
            recommendations.append("Add Zeek or Suricata when you want IDS log correlation.")
        return recommendations


def is_private_or_local_target(target: str) -> bool:
    try:
        if "/" in target:
            network = ip_network(target, strict=False)
            return network.is_private or network.is_loopback or network.is_link_local
        address = ip_address(target)
        return address.is_private or address.is_loopback or address.is_link_local
    except ValueError:
        return target in {"localhost", "::1"}


def parse_nmap_xml(output: str) -> dict[str, Any]:
    try:
        root = ElementTree.fromstring(output)
    except ElementTree.ParseError:
        return {"hosts": [], "parse_error": "invalid-nmap-xml"}
    hosts = []
    for host in root.findall("host"):
        address_node = host.find("address")
        address = address_node.attrib.get("addr") if address_node is not None else None
        ports = []
        for port in host.findall("./ports/port"):
            state = port.find("state")
            if state is None or state.attrib.get("state") != "open":
                continue
            service = port.find("service")
            port_id = int(port.attrib.get("portid", "0"))
            ports.append(
                {
                    "port": port_id,
                    "protocol": port.attrib.get("protocol", "tcp"),
                    "service": service.attrib.get("name") if service is not None else None,
                    "product": service.attrib.get("product") if service is not None else None,
                    "admin_service": port_id in ADMIN_PORTS,
                }
            )
        hosts.append({"address": address, "open_ports": ports})
    return {"hosts": hosts}


def parse_packet_text(output: str) -> dict[str, Any]:
    protocols = {}
    endpoints = {}
    for line in output.splitlines():
        upper = line.upper()
        for protocol in ("ARP", "TCP", "UDP", "ICMP", "DNS", "TLS", "HTTP"):
            if protocol in upper:
                protocols[protocol] = protocols.get(protocol, 0) + 1
        for endpoint in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", line):
            endpoints[endpoint] = endpoints.get(endpoint, 0) + 1
    return {"protocols": protocols, "endpoints": endpoints, "line_count": len(output.splitlines())}


def parse_ping(output: str) -> dict[str, Any]:
    loss_match = re.search(r"(\d+(?:\.\d+)?)% packet loss", output)
    return {
        "packet_loss_percent": float(loss_match.group(1)) if loss_match else None,
        "reachable": "bytes from" in output.lower() or "ttl=" in output.lower(),
    }
