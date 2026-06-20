import subprocess
from pathlib import Path

from protectogotchi.external_tools import (
    ExternalToolRuntime,
    is_private_or_local_target,
    parse_nmap_xml,
    parse_packet_text,
    parse_ping,
)


NMAP_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="192.168.1.10" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="closed"/>
        <service name="https"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


def fake_which(binary):
    available = {
        "ping": "/sbin/ping",
        "traceroute": "/usr/sbin/traceroute",
        "nmap": "/opt/homebrew/bin/nmap",
        "tcpdump": "/usr/sbin/tcpdump",
    }
    return available.get(binary)


def fake_runner(command, timeout):
    if command[0] == "nmap":
        return subprocess.CompletedProcess(command, 0, NMAP_XML, "")
    if command[0] == "ping":
        return subprocess.CompletedProcess(command, 0, "3 packets transmitted, 3 packets received, 0% packet loss", "")
    return subprocess.CompletedProcess(command, 0, "TCP 192.168.1.10.22 > 192.168.1.20.53000\nARP who-has 192.168.1.1", "")


def test_private_target_gate_allows_private_and_local_only():
    assert is_private_or_local_target("192.168.1.10")
    assert is_private_or_local_target("10.0.0.0/24")
    assert is_private_or_local_target("localhost")
    assert not is_private_or_local_target("8.8.8.8")


def test_runtime_discovers_and_plans_safe_private_target_actions():
    runtime = ExternalToolRuntime(which=fake_which, runner=fake_runner)

    actions = runtime.plan_for_target("192.168.1.10")

    assert [action.tool for action in actions] == ["ping", "traceroute", "nmap"]
    assert actions[0].requires_review is False
    assert actions[-1].requires_review is True


def test_runtime_refuses_public_target_plans():
    runtime = ExternalToolRuntime(which=fake_which, runner=fake_runner)

    try:
        runtime.plan_for_target("8.8.8.8")
    except ValueError as exc:
        assert "non-private" in str(exc)
    else:
        raise AssertionError("expected public target refusal")


def test_nmap_parser_extracts_open_admin_ports():
    parsed = parse_nmap_xml(NMAP_XML)

    assert parsed["hosts"][0]["address"] == "192.168.1.10"
    assert parsed["hosts"][0]["open_ports"][0]["port"] == 22
    assert parsed["hosts"][0]["open_ports"][0]["admin_service"] is True


def test_packet_and_ping_parsers_feed_decision_hints():
    packet_summary = parse_packet_text("TCP 192.168.1.10.22 > 192.168.1.20.53000\nARP who-has 192.168.1.1")
    ping_summary = parse_ping("3 packets transmitted, 3 received, 0% packet loss")

    assert packet_summary["protocols"]["TCP"] == 1
    assert packet_summary["protocols"]["ARP"] == 1
    assert ping_summary["packet_loss_percent"] == 0.0


def test_review_gate_blocks_nmap_until_confirmed_and_then_parses():
    runtime = ExternalToolRuntime(which=fake_which, runner=fake_runner)
    actions = runtime.plan_for_target("192.168.1.10")

    blocked = runtime.run_plan(actions, allow_review=False)
    executed = runtime.run_plan(actions, allow_review=True)
    decision = runtime.decide([result.parsed for result in executed])

    assert blocked[-1].status == "requires-review"
    assert executed[-1].parsed["hosts"][0]["open_ports"][0]["service"] == "ssh"
    assert decision["risk_score_hint"] >= 25
    assert decision["open_admin_services"][0]["service_hint"] == "ssh"


def test_pcap_plan_uses_available_capture_tools():
    runtime = ExternalToolRuntime(which=fake_which, runner=fake_runner)

    actions = runtime.plan_for_pcap(Path("capture.pcap"))

    assert [action.tool for action in actions] == ["tcpdump"]
