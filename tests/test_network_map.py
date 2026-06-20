from protectogotchi.models import Connection, Device, InterfaceInfo, NetworkSnapshot, Route, utc_now
from protectogotchi.network_map import NetworkMapper


def test_network_map_categorizes_interfaces_routes_and_devices():
    snapshot = NetworkSnapshot(
        taken_at=utc_now(),
        hostname="test-host",
        platform="test",
        interfaces=[
            InterfaceInfo(name="en0", ipv4=["192.168.10.10/24"], status="active"),
            InterfaceInfo(name="utun0", ipv4=["10.8.0.2/24"], status="active"),
            InterfaceInfo(name="en9", status="inactive"),
        ],
        routes=[
            Route(destination="default", gateway="192.168.10.1", interface="en0"),
            Route(destination="10.42.0.0/16", gateway="192.168.10.254", interface="en0"),
        ],
        connections=[
            Connection(
                protocol="tcp",
                local_address="192.168.10.10",
                local_port=50000,
                remote_address="172.16.5.20",
                remote_port=443,
                state="ESTABLISHED",
            )
        ],
        devices=[
            Device(ip="192.168.10.1", mac="aa:aa:aa:aa:aa:aa", interface="en0"),
            Device(ip="192.168.10.10", mac="00:11:22:33:44:55", interface="en0"),
            Device(ip="192.168.10.77", mac="66:77:88:99:aa:bb", interface="en0"),
        ],
        default_gateway="192.168.10.1",
        default_gateway_mac="aa:aa:aa:aa:aa:aa",
    )

    network_map = NetworkMapper().build(snapshot)
    roles = {interface.name: interface.role for interface in network_map.interfaces}
    categories = {device.ip: device.category for device in network_map.devices}

    assert roles["en0"] == "default-uplink"
    assert roles["utun0"] == "local-network"
    assert roles["en9"] == "inactive"
    assert categories["192.168.10.1"] == "default-gateway"
    assert categories["192.168.10.10"] == "local-host"
    assert network_map.summary["routed_networks"] == 1
    assert network_map.summary["observed_remote_subnets"] == 1
    assert "172.16.5.0/24" in network_map.observed_remote_subnets
    assert network_map.graph["nodes"]
    assert network_map.graph["edges"]
    assert "10.42.0.0/16" in " ".join(network_map.coverage)
