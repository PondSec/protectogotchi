from protectogotchi.simulation import run_simulation


def test_arp_spoof_simulation_detects_gateway_mac_change():
    result = run_simulation("arp-spoof")
    assert result.risk_score >= 95
    assert result.face_state == "fighting"
    assert any(finding["code"] == "gateway_mac_changed" for finding in result.findings)


def test_unknown_simulation_raises_value_error():
    try:
        run_simulation("does-not-exist")
    except ValueError as exc:
        assert "Unknown simulation scenario" in str(exc)
    else:
        raise AssertionError("expected ValueError")
