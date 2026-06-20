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
