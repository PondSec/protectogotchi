from protectogotchi.models import (
    Connection,
    Device,
    InterfaceInfo,
    NetworkSnapshot,
    Route,
    ScanResult,
    utc_now,
)
from protectogotchi.state import StateStore
from protectogotchi.topology import TopologyBuilder
from protectogotchi.web import LiveWebState, _live_payload, dashboard_html


def test_dashboard_html_references_local_api_endpoints():
    html = dashboard_html()
    assert "/api/live" in html
    assert "/api/mode" in html
    assert "setInterval" in html
    assert "data-mode=\"guard\"" in html
    assert "data-mode=\"god\"" in html
    assert "ACTIVATE GOD MODE" in html
    assert "Kein heimliches ARP/MitM" in html
    assert "/api/simulate" in html
    assert "Protectogotchi" in html
    assert "Local defensive network AI" in html
    assert "console-grid" in html
    assert "Asset Graph" in html
    assert "Bedrohungsmatrix" in html
    assert "Realtime Feed" in html
    assert "Steuerung" in html
    assert "AI State" in html
    assert "mobile-nav" in html
    assert "Export JSON" in html
    assert "sortThreats" in html
    assert "setMobilePanel" in html
    assert "brand-mark" in html
    assert ">P</div>" in html
    assert "JSON.stringify((live" not in html
    assert "Netzwerkschutz, der sich wie ein kleines Haustier" not in html


def test_dashboard_html_uses_strict_enterprise_design_system():
    html = dashboard_html()
    for color in (
        "#0D1117",
        "#161B22",
        "#21262D",
        "#E6EDF3",
        "#8B949E",
        "#3FB950",
        "#F0883E",
        "#F85149",
        "#58A6FF",
    ):
        assert color in html

    assert "radial-gradient" not in html
    assert "linear-gradient" not in html
    assert "backdrop-filter" not in html
    assert "box-shadow" not in html
    assert "card" not in html.lower()
    assert "border-radius: 34px" not in html


def test_live_payload_contains_scan_state_and_topology(tmp_path):
    from protectogotchi.config import ProtectogotchiConfig

    config = ProtectogotchiConfig(state_dir=tmp_path, min_baseline_observations=1)
    snapshot = NetworkSnapshot(
        taken_at=utc_now(),
        hostname="test-host",
        platform="test",
        interfaces=[InterfaceInfo(name="en0", ipv4=["192.168.1.20/24"], status="active")],
        routes=[
            Route(destination="default", gateway="192.168.1.1", interface="en0"),
            Route(destination="10.20.0.0/16", gateway="192.168.1.254", interface="en0"),
        ],
        devices=[Device(ip="192.168.1.1", mac="aa:aa:aa:aa:aa:aa")],
        connections=[
            Connection(
                protocol="tcp",
                local_address="192.168.1.20",
                remote_address="10.20.4.8",
                remote_port=443,
                state="ESTABLISHED",
            )
        ],
        default_gateway="192.168.1.1",
        default_gateway_mac="aa:aa:aa:aa:aa:aa",
    )
    state = StateStore(tmp_path).load()
    state.learn(snapshot)
    StateStore(tmp_path).save(state)
    result = ScanResult(
        snapshot=snapshot,
        findings=[],
        actions=[],
        risk_score=0,
        face_state="happy",
        learned=True,
        level=1,
        xp=1,
    )
    payload = _live_payload(config, result, TopologyBuilder().build(snapshot), mode="watch")

    assert payload["state"]["baseline_ready"]
    assert payload["mode"] == "watch"
    assert payload["runtime"]["network_mode"] == "observer"
    assert payload["runtime"]["response_mode"] == "dry-run"
    assert "uptime_seconds" in payload["runtime"]
    assert payload["scan"]["face_state"] == "happy"
    assert payload["topology_summary"]["gateway"] == 2
    assert "network_map" in payload
    assert "192.168.1.0/24" in payload["network_map"]["subnets"]
    assert "10.20.0.0/16" in payload["network_map"]["subnets"]
    assert "10.20.4.0/24" in payload["network_map"]["observed_remote_subnets"]
    assert "finding_history" in payload
    assert "god_mode_readiness" in payload
    assert "easy_protect_plan" in payload
    assert "placement_report" in payload
    assert payload["placement_report"]["firewall_controller_automation"] is False
    assert "simulations" in payload
    assert "arp-spoof" in payload["simulations"]
    assert len(payload["devices"]) == 1
    assert payload["pet_headline"]
    assert payload["thought"]
    assert payload["activity_summary"]
    assert "quiet_scans" in payload
    assert "Ruhige Scans" in "\n".join(payload["calm_status"])


def test_live_web_state_mode_switch_without_thread(tmp_path):
    from protectogotchi.config import ProtectogotchiConfig

    live = LiveWebState(ProtectogotchiConfig(state_dir=tmp_path), collector_name=None, scan_interval=1)
    payload = live.set_mode("watch")
    assert payload["mode"] == "watch"

    try:
        live.set_mode("does-not-exist")
    except ValueError as exc:
        assert "Unknown web mode" in str(exc)
    else:
        raise AssertionError("expected ValueError")


def test_live_web_state_god_mode_requires_confirmation(tmp_path):
    from protectogotchi.config import ProtectogotchiConfig

    live = LiveWebState(ProtectogotchiConfig(state_dir=tmp_path), collector_name=None, scan_interval=1)
    try:
        live.set_mode("god")
    except ValueError as exc:
        assert "ACTIVATE GOD MODE" in str(exc)
    else:
        raise AssertionError("expected ValueError")

    payload = live.set_mode("god", confirmation="ACTIVATE GOD MODE")
    assert payload["mode"] == "god"
    assert "Enforcement-Punkt" in payload["mode_description"]
