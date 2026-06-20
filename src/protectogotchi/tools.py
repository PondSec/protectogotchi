from __future__ import annotations

from dataclasses import dataclass
from typing import Literal


ToolStatus = Literal["available", "planned"]
ToolRisk = Literal["safe", "review", "privileged"]


@dataclass(frozen=True)
class ToolDefinition:
    name: str
    category: str
    summary: str
    command: str
    status: ToolStatus = "available"
    risk: ToolRisk = "safe"
    platforms: tuple[str, ...] = ("macos", "linux")


TOOLS: tuple[ToolDefinition, ...] = (
    ToolDefinition(
        name="snapshot",
        category="observe",
        summary="Export raw local telemetry without learning or scoring.",
        command="protectogotchi snapshot",
    ),
    ToolDefinition(
        name="topology",
        category="observe",
        summary="Build a passive map of host, interfaces, subnets, routes, gateways, and devices.",
        command="protectogotchi topology",
    ),
    ToolDefinition(
        name="map",
        category="observe",
        summary="Show categorized interfaces, routes, subnets, gateways, and coverage limits.",
        command="protectogotchi map",
    ),
    ToolDefinition(
        name="web",
        category="interface",
        summary="Run local web status/API for network card, topology, tools, and knowledge.",
        command="protectogotchi web --host 127.0.0.1 --port 8765",
    ),
    ToolDefinition(
        name="rules",
        category="diagnose",
        summary="List local detection rules and their severity.",
        command="protectogotchi rules",
    ),
    ToolDefinition(
        name="knowledge",
        category="diagnose",
        summary="Browse local network-defense knowledge and playbooks.",
        command="protectogotchi knowledge",
    ),
    ToolDefinition(
        name="enforcement",
        category="respond",
        summary="Explain which deployment modes can actively prevent attacks.",
        command="protectogotchi enforcement",
    ),
    ToolDefinition(
        name="easy-protect",
        category="respond",
        summary="Show safe plug-and-play paths from detection to active protection.",
        command="protectogotchi easy-protect",
    ),
    ToolDefinition(
        name="setup-wizard",
        category="diagnose",
        summary="Check what this placement can safely detect or prevent without ARP/MitM.",
        command="protectogotchi setup-wizard",
    ),
    ToolDefinition(
        name="simulate",
        category="diagnose",
        summary="Run synthetic lab attack/anomaly scenarios without packet injection.",
        command="protectogotchi simulate arp-spoof",
    ),
    ToolDefinition(
        name="scan",
        category="observe",
        summary="Collect one local telemetry snapshot, score anomalies, and learn if safe.",
        command="protectogotchi scan",
    ),
    ToolDefinition(
        name="daemon",
        category="observe",
        summary="Run continuous local monitoring with interval-based scans.",
        command="protectogotchi daemon --interval 10",
    ),
    ToolDefinition(
        name="status",
        category="observe",
        summary="Show level, XP, scan count, and local baseline size.",
        command="protectogotchi status",
    ),
    ToolDefinition(
        name="doctor",
        category="diagnose",
        summary="Check whether platform telemetry and response commands are available.",
        command="protectogotchi doctor",
    ),
    ToolDefinition(
        name="tools",
        category="diagnose",
        summary="List Protectogotchi's defensive tool catalog.",
        command="protectogotchi tools",
    ),
    ToolDefinition(
        name="arsenal",
        category="diagnose",
        summary="Assess the modular defensive capability framework.",
        command="protectogotchi arsenal",
    ),
    ToolDefinition(
        name="toolbox",
        category="diagnose",
        summary="Discover installed external tools and plan safe defensive diagnostics.",
        command="protectogotchi toolbox",
    ),
    ToolDefinition(
        name="nmap-service-inventory",
        category="diagnose",
        summary="Use installed nmap for reviewed service inventory on private/local targets.",
        command="protectogotchi toolbox --target 192.168.1.1",
        risk="review",
    ),
    ToolDefinition(
        name="pcap-understanding",
        category="diagnose",
        summary="Use installed tshark/tcpdump to parse authorized pcap files into AI evidence.",
        command="protectogotchi toolbox --pcap capture.pcap",
        risk="review",
    ),
    ToolDefinition(
        name="ai-status",
        category="ml",
        summary="Show PyTorch autoencoder and DQN policy backend status.",
        command="protectogotchi ai",
    ),
    ToolDefinition(
        name="neural-anomaly-detector",
        category="ml",
        summary="PyTorch deep autoencoder for local network-metric anomaly detection.",
        command="protectogotchi scan --json",
    ),
    ToolDefinition(
        name="dqn-safety-policy",
        category="ml",
        summary="Safety-gated PyTorch DQN policy for defensive response prioritization.",
        command="protectogotchi ai",
    ),
    ToolDefinition(
        name="face",
        category="interface",
        summary="Render a status face for dashboards, logs, or displays.",
        command="protectogotchi face analyzing",
    ),
    ToolDefinition(
        name="scan-json",
        category="integrate",
        summary="Export a scan as JSON for dashboards and future automations.",
        command="protectogotchi scan --json",
    ),
    ToolDefinition(
        name="daemon-json",
        category="integrate",
        summary="Emit continuous JSON lines for log pipelines or local dashboards.",
        command="protectogotchi daemon --json",
    ),
    ToolDefinition(
        name="show-baseline",
        category="learn",
        summary="Inspect learned devices, gateway identity, and feature statistics.",
        command="protectogotchi baseline show",
    ),
    ToolDefinition(
        name="reset-baseline",
        category="learn",
        summary="Reset local learned state after explicit confirmation.",
        command="protectogotchi baseline reset --yes",
        risk="review",
    ),
    ToolDefinition(
        name="list-devices",
        category="learn",
        summary="List devices known from the local baseline.",
        command="protectogotchi devices",
    ),
    ToolDefinition(
        name="plan-block",
        category="respond",
        summary="Plan a defensive IP block without changing the firewall.",
        command="protectogotchi respond --ip 192.168.1.50 --reason suspicious",
        risk="review",
    ),
    ToolDefinition(
        name="notify-owner",
        category="respond",
        summary="Notify the local owner for medium or higher findings.",
        command="protectogotchi scan --execute-actions",
        risk="review",
        platforms=("macos",),
    ),
    ToolDefinition(
        name="macos-pf-block",
        category="respond",
        summary="Use a verified macOS pf anchor to block a suspicious host.",
        command="protectogotchi --active respond --ip 192.168.1.50 --execute",
        status="planned",
        risk="privileged",
        platforms=("macos",),
    ),
    ToolDefinition(
        name="linux-nft-block",
        category="respond",
        summary="Use nftables on Linux/Raspberry Pi to block a suspicious host.",
        command="protectogotchi --active respond --ip 192.168.1.50 --execute",
        status="planned",
        risk="privileged",
        platforms=("linux",),
    ),
    ToolDefinition(
        name="trust-device",
        category="learn",
        summary="Mark a device as trusted with an owner-supplied label.",
        command="protectogotchi trust-device --mac 00:11:22:33:44:55 --label laptop",
        risk="review",
    ),
    ToolDefinition(
        name="untrust-device",
        category="learn",
        summary="Remove trust from a device and increase scrutiny.",
        command="protectogotchi untrust-device --mac 00:11:22:33:44:55",
        risk="review",
    ),
    ToolDefinition(
        name="ip-planner",
        category="admin",
        summary="Subnet calculator and address-plan API for IPv4/IPv6 documentation.",
        command="protectogotchi ip-plan",
        status="planned",
    ),
    ToolDefinition(
        name="vlan-designer",
        category="admin",
        summary="Design VLANs, trunks, access ports, and segmentation intent from topology data.",
        command="protectogotchi vlan design",
        status="planned",
    ),
    ToolDefinition(
        name="route-auditor",
        category="admin",
        summary="Audit default routes, routed subnets, VPN paths, and route drift.",
        command="protectogotchi map --json",
    ),
    ToolDefinition(
        name="dhcp-dns-auditor",
        category="admin",
        summary="Track resolver and lease drift for rogue DHCP/DNS detection.",
        command="protectogotchi snapshot",
        status="planned",
    ),
    ToolDefinition(
        name="qos-profiler",
        category="admin",
        summary="Profile noisy applications and prepare traffic-shaping recommendations.",
        command="protectogotchi flows qos",
        status="planned",
    ),
    ToolDefinition(
        name="snmp-inventory",
        category="integrate",
        summary="Ingest authorized SNMP interface and device inventory.",
        command="protectogotchi ingest snmp",
        status="planned",
        risk="review",
    ),
    ToolDefinition(
        name="netflow-collector",
        category="observe",
        summary="Collect NetFlow/sFlow/IPFIX metadata for real behavior modeling.",
        command="protectogotchi flow-collector",
        status="planned",
        risk="review",
    ),
    ToolDefinition(
        name="pcap-analyzer",
        category="diagnose",
        summary="Analyze authorized packet captures for protocol and anomaly evidence.",
        command="protectogotchi pcap analyze capture.pcap",
        status="planned",
        risk="review",
    ),
    ToolDefinition(
        name="mtr-tracer",
        category="diagnose",
        summary="Run route health checks with traceroute/MTR-style diagnostics.",
        command="protectogotchi trace 8.8.8.8",
        status="planned",
    ),
    ToolDefinition(
        name="firewall-policy-guru",
        category="respond",
        summary="Convert defensive policy intent into reviewed pf/nft/router rules.",
        command="protectogotchi policy render",
        status="planned",
        risk="privileged",
    ),
    ToolDefinition(
        name="ids-log-ingest",
        category="integrate",
        summary="Ingest Zeek, Suricata, or Snort alerts and fuse them with the baseline.",
        command="protectogotchi ingest ids",
        status="planned",
    ),
    ToolDefinition(
        name="ids-rule-tuner",
        category="diagnose",
        summary="Recommend IDS rule tuning from false-positive and baseline context.",
        command="protectogotchi ids tune",
        status="planned",
    ),
    ToolDefinition(
        name="zero-trust-checker",
        category="diagnose",
        summary="Evaluate segmentation and identity-based access gaps.",
        command="protectogotchi zt audit",
        status="planned",
    ),
    ToolDefinition(
        name="pki-watch",
        category="diagnose",
        summary="Track certificate expiry, issuer drift, and local ACME posture.",
        command="protectogotchi pki watch",
        status="planned",
    ),
    ToolDefinition(
        name="threat-intel-hub",
        category="integrate",
        summary="Normalize STIX/TAXII feeds for local allow/deny/context enrichment.",
        command="protectogotchi intel sync",
        status="planned",
    ),
    ToolDefinition(
        name="vuln-scout",
        category="diagnose",
        summary="Schedule authorized vulnerability checks and import scanner reports.",
        command="protectogotchi vuln import report.json",
        status="planned",
        risk="review",
    ),
    ToolDefinition(
        name="pentest-report-import",
        category="diagnose",
        summary="Import authorized pentest findings and map them to assets and playbooks.",
        command="protectogotchi pentest import report.json",
        status="planned",
        risk="review",
    ),
    ToolDefinition(
        name="malware-sandbox-intake",
        category="diagnose",
        summary="Ingest sandbox verdicts and correlate them with network behavior.",
        command="protectogotchi sandbox import verdict.json",
        status="planned",
        risk="review",
    ),
    ToolDefinition(
        name="siem-logpipe",
        category="integrate",
        summary="Normalize syslog, endpoint, cloud, and IDS logs into local alerts.",
        command="protectogotchi logpipe",
        status="planned",
    ),
    ToolDefinition(
        name="ir-playbooks",
        category="respond",
        summary="Run reviewed incident-response playbooks for containment and recovery.",
        command="protectogotchi ir run contain-host",
        status="planned",
        risk="privileged",
    ),
    ToolDefinition(
        name="compliance-checker",
        category="diagnose",
        summary="Map network posture checks to CIS, NIST, ISO 27001, and GDPR controls.",
        command="protectogotchi compliance audit",
        status="planned",
    ),
    ToolDefinition(
        name="endpoint-agent",
        category="deploy",
        summary="Endpoint firewall/sensor agent for real prevention beyond client-only visibility.",
        command="protectogotchi agent install",
        status="planned",
        risk="privileged",
    ),
    ToolDefinition(
        name="controller-quarantine",
        category="respond",
        summary="Quarantine clients through authorized router/AP/switch controller APIs.",
        command="protectogotchi controller quarantine --mac 00:11:22:33:44:55",
        status="planned",
        risk="privileged",
    ),
    ToolDefinition(
        name="bridge-enforcer",
        category="deploy",
        summary="Transparent bridge deployment for real in-path capture and prevention.",
        command="protectogotchi bridge install",
        status="planned",
        risk="privileged",
        platforms=("linux",),
    ),
    ToolDefinition(
        name="dashboard",
        category="interface",
        summary="Local dashboard with face, findings, timeline, and known devices.",
        command="protectogotchi dashboard",
        status="planned",
    ),
    ToolDefinition(
        name="install-service",
        category="deploy",
        summary="Install Protectogotchi as a local service.",
        command="protectogotchi service install",
        status="planned",
        risk="privileged",
    ),
    ToolDefinition(
        name="pi-image",
        category="deploy",
        summary="Build a Raspberry Pi 5 image with Protectogotchi preinstalled.",
        command="protectogotchi image build --target pi5",
        status="planned",
        risk="privileged",
        platforms=("linux",),
    ),
)


def list_tools(include_planned: bool = True) -> list[ToolDefinition]:
    if include_planned:
        return list(TOOLS)
    return [tool for tool in TOOLS if tool.status == "available"]


def get_tool(name: str) -> ToolDefinition | None:
    for tool in TOOLS:
        if tool.name == name:
            return tool
    return None
