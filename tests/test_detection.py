from protectogotchi.config import ProtectogotchiConfig
from protectogotchi.detection import AnomalyDetector
from protectogotchi.models import Connection, Device, NetworkSnapshot, utc_now
from protectogotchi.response import ResponsePlanner
from protectogotchi.state import ProtectogotchiState


def make_snapshot(
    *,
    devices: list[Device] | None = None,
    connections: list[Connection] | None = None,
    gateway_mac: str = "aa:aa:aa:aa:aa:aa",
) -> NetworkSnapshot:
    gateway = Device(ip="192.168.1.1", mac=gateway_mac, interface="en0")
    return NetworkSnapshot(
        taken_at=utc_now(),
        hostname="test-host",
        platform="test-platform",
        devices=[gateway, *(devices or [])],
        connections=connections or [],
        default_gateway="192.168.1.1",
        default_gateway_mac=gateway_mac,
    )


def test_gateway_mac_change_is_critical_and_not_auto_blocked():
    config = ProtectogotchiConfig(min_baseline_observations=1)
    state = ProtectogotchiState()
    state.learn(make_snapshot())

    changed = make_snapshot(gateway_mac="bb:bb:bb:bb:bb:bb")
    analysis = AnomalyDetector(config).analyze(changed, state)

    assert analysis.risk_score >= 95
    assert any(finding.code == "gateway_mac_changed" for finding in analysis.findings)
    actions = ResponsePlanner(config).plan(analysis.findings, changed)
    assert actions[0].action_type == "alert_admin"
    assert actions[0].status == "manual-review"


def test_new_device_after_learning_phase_is_low_risk():
    config = ProtectogotchiConfig(min_baseline_observations=3)
    state = ProtectogotchiState()
    known = Device(ip="192.168.1.10", mac="00:11:22:33:44:55", interface="en0")
    for _ in range(3):
        state.learn(make_snapshot(devices=[known]))

    newcomer = Device(ip="192.168.1.99", mac="66:77:88:99:aa:bb", interface="en0")
    analysis = AnomalyDetector(config).analyze(make_snapshot(devices=[known, newcomer]), state)

    new_device_findings = [
        finding for finding in analysis.findings if finding.code == "new_device_seen"
    ]
    assert len(new_device_findings) == 1
    assert new_device_findings[0].severity == "low"
    assert analysis.face_state == "analyzing"


def test_trusted_new_device_is_info_after_learning_phase():
    config = ProtectogotchiConfig(min_baseline_observations=3)
    state = ProtectogotchiState()
    known = Device(ip="192.168.1.10", mac="00:11:22:33:44:55", interface="en0")
    for _ in range(3):
        state.learn(make_snapshot(devices=[known]))
    state.trust_device("66:77:88:99:aa:bb", "phone")

    trusted = Device(ip="192.168.1.99", mac="66:77:88:99:aa:bb", interface="en0")
    analysis = AnomalyDetector(config).analyze(make_snapshot(devices=[known, trusted]), state)

    trusted_findings = [
        finding for finding in analysis.findings if finding.code == "trusted_device_seen"
    ]
    assert len(trusted_findings) == 1
    assert trusted_findings[0].severity == "info"
    assert analysis.risk_score == 0
    assert analysis.face_state == "happy"


def test_feature_spike_is_detected_against_local_baseline():
    config = ProtectogotchiConfig(min_baseline_observations=4)
    state = ProtectogotchiState()
    for count in [1, 2, 1, 2]:
        state.learn(make_snapshot(connections=_connections(count)))

    analysis = AnomalyDetector(config).analyze(
        make_snapshot(connections=_connections(10)),
        state,
    )

    assert any(
        finding.code == "feature_spike_connection_count"
        for finding in analysis.findings
    )
    assert analysis.risk_score >= 35


def test_risky_remote_service_gets_medium_finding():
    config = ProtectogotchiConfig()
    state = ProtectogotchiState()
    connection = Connection(
        protocol="tcp",
        local_address="192.168.1.10",
        local_port=50000,
        remote_address="203.0.113.4",
        remote_port=3389,
        state="ESTABLISHED",
    )

    analysis = AnomalyDetector(config).analyze(
        make_snapshot(connections=[connection]),
        state,
    )

    assert any(finding.code == "risky_remote_service" for finding in analysis.findings)
    assert analysis.face_state == "alert"


def _connections(count: int) -> list[Connection]:
    return [
        Connection(
            protocol="tcp",
            local_address="192.168.1.10",
            local_port=50000 + index,
            remote_address=f"198.51.100.{index + 1}",
            remote_port=443,
            state="ESTABLISHED",
        )
        for index in range(count)
    ]
