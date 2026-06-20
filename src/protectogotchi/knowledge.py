from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class KnowledgeTopic:
    name: str
    domain: str
    summary: str
    signals: tuple[str, ...]
    defensive_tools: tuple[str, ...]
    response_playbook: tuple[str, ...]
    maturity: str = "mvp"


TOPICS: tuple[KnowledgeTopic, ...] = (
    KnowledgeTopic(
        name="arp-spoofing",
        domain="layer-2",
        summary="Detects suspicious IP-to-MAC identity changes, especially gateway changes.",
        signals=("gateway MAC drift", "IP/MAC rebinding", "ARP neighbor churn"),
        defensive_tools=("baseline identity graph", "gateway guard", "owner alert"),
        response_playbook=(
            "Stop autolearning for the suspicious snapshot.",
            "Alert the owner and display fighting state.",
            "Do not blindly block the gateway; require manual review.",
        ),
    ),
    KnowledgeTopic(
        name="rogue-device",
        domain="inventory",
        summary="Learns known local devices and highlights unknown devices after baseline warmup.",
        signals=("new MAC address", "new IP address", "interface mismatch"),
        defensive_tools=("device baseline", "trust labels", "newcomer scoring"),
        response_playbook=(
            "Classify as learning/info during warmup.",
            "Classify as low risk after warmup unless other signals escalate.",
            "Allow owner to trust or untrust the MAC.",
        ),
    ),
    KnowledgeTopic(
        name="service-exposure",
        domain="transport",
        summary="Tracks listening ports and highlights new local services.",
        signals=("new LISTEN port", "port count spike", "unexpected local bind"),
        defensive_tools=("netstat/ss collector", "listening-port baseline", "rule explanation"),
        response_playbook=(
            "Raise medium finding for new listeners.",
            "Ask owner to verify the service.",
            "Keep firewall enforcement dry-run unless explicitly enabled.",
        ),
    ),
    KnowledgeTopic(
        name="connection-anomaly",
        domain="behavior",
        summary="Uses local feature statistics to detect spikes in network behavior.",
        signals=("connection count z-score", "external remote count", "unique remote spike"),
        defensive_tools=("online baseline statistics", "explainable z-score evidence"),
        response_playbook=(
            "Score against the local network baseline.",
            "Avoid poisoning the baseline when risk is high.",
            "Escalate to alert or fighting face based on severity.",
        ),
    ),
    KnowledgeTopic(
        name="risky-remote-admin",
        domain="transport",
        summary="Flags connections to services often used for remote administration.",
        signals=("RDP", "VNC", "Telnet", "SMB", "database admin ports"),
        defensive_tools=("risky port knowledge", "connection metadata", "owner notification"),
        response_playbook=(
            "Explain that the signal can be legitimate.",
            "Ask owner to verify expected remote access.",
            "Plan a block only when combined with high-risk context.",
        ),
    ),
    KnowledgeTopic(
        name="wifi-security-posture",
        domain="wifi",
        summary="Tracks Wi-Fi context and prepares checks for WPA3, PMF, channel, and BSSID drift.",
        signals=("SSID", "BSSID", "RSSI/noise", "channel", "security mode"),
        defensive_tools=("airport/iw telemetry", "per-network profiles", "future monitor mode"),
        response_playbook=(
            "Keep per-SSID/per-BSSID profiles.",
            "Warn on BSSID drift once stable telemetry is available.",
            "Prefer owner guidance over disruptive automated actions.",
        ),
        maturity="planned",
    ),
    KnowledgeTopic(
        name="dns-and-dhcp-anomaly",
        domain="application",
        summary="Planned local checks for resolver drift, rogue DHCP, and suspicious DNS volume.",
        signals=("resolver change", "lease churn", "NXDOMAIN spike", "new DHCP server"),
        defensive_tools=("resolver inventory", "lease watcher", "DNS feature model"),
        response_playbook=(
            "Confirm whether resolver/DHCP changes are expected.",
            "Escalate rogue infrastructure signals.",
            "Offer owner-safe remediation steps.",
        ),
        maturity="planned",
    ),
    KnowledgeTopic(
        name="linux-ebpf-sensor",
        domain="advanced-sensor",
        summary="Planned Raspberry Pi/Linux sensor using eBPF-style event telemetry.",
        signals=("socket events", "flow metadata", "process/network correlation"),
        defensive_tools=("local kernel telemetry", "low-overhead flow model", "privacy-local storage"),
        response_playbook=(
            "Collect only local metadata needed for defense.",
            "Correlate process and flow behavior on the Protectogotchi host.",
            "Keep raw payload inspection out of the default path.",
        ),
        maturity="planned",
    ),
    KnowledgeTopic(
        name="ids-integration",
        domain="advanced-sensor",
        summary="Planned local integration path for IDS logs such as Zeek or Suricata.",
        signals=("IDS alert", "flow log", "protocol anomaly", "signature hit"),
        defensive_tools=("local log ingestion", "explainable correlation", "confidence fusion"),
        response_playbook=(
            "Treat IDS alerts as evidence, not automatic truth.",
            "Fuse with baseline and device identity context.",
            "Require explicit owner opt-in before blocking.",
        ),
        maturity="planned",
    ),
)


def list_topics(include_planned: bool = True) -> list[KnowledgeTopic]:
    if include_planned:
        return list(TOPICS)
    return [topic for topic in TOPICS if topic.maturity == "mvp"]


def get_topic(name: str) -> KnowledgeTopic | None:
    for topic in TOPICS:
        if topic.name == name:
            return topic
    return None
