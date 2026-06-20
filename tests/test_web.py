from protectogotchi.models import Device, NetworkSnapshot, ScanResult, utc_now
from protectogotchi.state import StateStore
from protectogotchi.topology import TopologyBuilder
from protectogotchi.web import LiveWebState, _live_payload, dashboard_html


def test_dashboard_html_references_local_api_endpoints():
    html = dashboard_html()
    assert "/api/live" in html
    assert "/api/mode" in html
    assert "setInterval" in html
    assert "data-tab=\"home\"" in html
    assert "data-tab=\"practice\"" in html
    assert "data-mode=\"guard\"" in html
    assert "data-mode=\"god\"" in html
    assert "ACTIVATE GOD MODE" in html
    assert "kein heimliches ARP/MitM" in html
    assert "/api/simulate" in html
    assert "Automatisierung" in html
    assert "tools" in html
    assert "Protectogotchi" in html
    assert "Statusnotiz" in html
    assert "thought" in html
    assert "Aktuelle Aktivität" in html
    assert "klarer Sprache statt in Rohdaten" in html
    assert "renderNetworkStory" in html
    assert "JSON.stringify((live" not in html
    assert "Netzwerkschutz, der sich wie ein kleines Haustier" not in html
    assert "radial-gradient" not in html
    assert "border-radius: 34px" not in html
    assert "box-shadow: none" in html


def test_live_payload_contains_scan_state_and_topology(tmp_path):
    from protectogotchi.config import ProtectogotchiConfig

    config = ProtectogotchiConfig(state_dir=tmp_path, min_baseline_observations=1)
    snapshot = NetworkSnapshot(
        taken_at=utc_now(),
        hostname="test-host",
        platform="test",
        devices=[Device(ip="192.168.1.1", mac="aa:aa:aa:aa:aa:aa")],
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
    assert payload["scan"]["face_state"] == "happy"
    assert payload["topology_summary"]["gateway"] == 1
    assert "network_map" in payload
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
