from protectogotchi.models import Device, Finding, NetworkSnapshot, utc_now
from protectogotchi.state import StateStore


def test_state_persists_baseline_and_progress(tmp_path):
    store = StateStore(tmp_path)
    state = store.load()
    snapshot = NetworkSnapshot(
        taken_at=utc_now(),
        hostname="test-host",
        platform="test-platform",
        devices=[Device(ip="192.168.1.10", mac="00:11:22:33:44:55")],
        default_gateway="192.168.1.1",
        default_gateway_mac="aa:aa:aa:aa:aa:aa",
    )
    state.learn(snapshot)
    state.record_scan(
        [
            Finding(
                code="test",
                title="Test finding",
                severity="medium",
                description="test",
            )
        ]
    )
    store.save(state)

    loaded = store.load()
    assert loaded.observations == 1
    assert loaded.scans == 1
    assert loaded.xp > 1
    assert "00:11:22:33:44:55" in loaded.devices
    assert loaded.gateway_macs["192.168.1.1"] == "aa:aa:aa:aa:aa:aa"
