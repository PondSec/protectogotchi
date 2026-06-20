from protectogotchi.config import ProtectogotchiConfig
from protectogotchi.models import Device, InterfaceInfo, NetworkSnapshot, Route, utc_now
from protectogotchi.network_map import NetworkMapper
from protectogotchi.placement import build_placement_report


def test_client_observer_report_is_detect_only_without_firewall_control():
    snapshot = NetworkSnapshot(
        taken_at=utc_now(),
        hostname="test-host",
        platform="test",
        interfaces=[InterfaceInfo(name="en0", ipv4=["192.168.10.10/24"], status="active")],
        routes=[
            Route(destination="default", gateway="192.168.10.1", interface="en0"),
            Route(destination="192.168.20.0/24", gateway="192.168.10.1", interface="en0"),
        ],
        devices=[
            Device(ip="192.168.10.1", mac="aa:aa:aa:aa:aa:aa", interface="en0"),
            Device(ip="192.168.10.77", mac="66:77:88:99:aa:bb", interface="en0"),
        ],
        default_gateway="192.168.10.1",
        default_gateway_mac="aa:aa:aa:aa:aa:aa",
    )
    report = build_placement_report(ProtectogotchiConfig(), NetworkMapper().build(snapshot))

    assert report.firewall_controller_automation is False
    assert report.can_prevent == ()
    assert "192.168.20.0/24" in report.routed_subnets
    assert report.same_subnet_devices == 1
    assert any(item.status == "not-from-client" for item in report.cannot_prevent)


def test_inline_mode_reports_real_prevention_requires_active_mode():
    report = build_placement_report(ProtectogotchiConfig(deployment_mode="transparent-bridge"))

    assert report.recommended_mode == "transparent-bridge"
    assert report.can_prevent[0].status == "needs-active-mode"
    assert "non-MiTM" in report.summary
