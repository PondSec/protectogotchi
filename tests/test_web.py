from protectogotchi.models import Device, NetworkSnapshot, ScanResult, utc_now
from protectogotchi.state import StateStore
from protectogotchi.topology import TopologyBuilder
from protectogotchi.web import _live_payload, dashboard_html


def test_dashboard_html_references_local_api_endpoints():
    html = dashboard_html()
    assert "/api/live" in html
    assert "setInterval" in html
    assert "tools" in html
    assert "Protectogotchi" in html
    assert "border-radius" not in html


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
    payload = _live_payload(config, result, TopologyBuilder().build(snapshot))

    assert payload["state"]["baseline_ready"]
    assert payload["scan"]["face_state"] == "happy"
    assert payload["topology_summary"]["gateway"] == 1
    assert len(payload["devices"]) == 1
