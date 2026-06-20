from protectogotchi.simulation import run_simulation


def test_arp_spoof_simulation_detects_gateway_mac_change():
    result = run_simulation("arp-spoof")
    assert result.isolated is True
    assert "no live traffic" in result.environment
    assert result.risk_score >= 95
    assert result.face_state == "fighting"
    assert result.timeline
    assert result.packets
    assert any(finding["code"] == "gateway_mac_changed" for finding in result.findings)
    assert any("synthetic snapshots" in lesson for lesson in result.lessons)


def test_vlan_lateral_movement_simulation_is_detect_only_from_client():
    result = run_simulation("vlan-lateral-movement")
    assert result.isolated is True
    assert any(packet.verdict == "detected-client-cannot-prevent" for packet in result.packets)
    assert any("without firewall/router/ap/switch control" in lesson.lower() for lesson in result.lessons)
    assert any(finding["code"] == "risky_remote_service" for finding in result.findings)


def test_unknown_simulation_raises_value_error():
    try:
        run_simulation("does-not-exist")
    except ValueError as exc:
        assert "Unknown simulation scenario" in str(exc)
    else:
        raise AssertionError("expected ValueError")
