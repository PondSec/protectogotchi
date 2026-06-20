from protectogotchi.models import Device, InterfaceInfo, NetworkSnapshot, Route, utc_now
from protectogotchi.topology import TopologyBuilder


def test_topology_builds_gateways_subnets_routes_and_devices():
    snapshot = NetworkSnapshot(
        taken_at=utc_now(),
        hostname="protecto",
        platform="test",
        interfaces=[
            InterfaceInfo(
                name="en0",
                ipv4=["192.168.10.108/24"],
                mac="00:11:22:33:44:55",
                status="active",
            )
        ],
        routes=[
            Route(destination="default", gateway="192.168.10.5", interface="en0"),
            Route(destination="10.10.0.0/16", gateway="192.168.10.1", interface="en0"),
        ],
        devices=[
            Device(ip="192.168.10.5", mac="90:e3:ba:02:a3:6e", interface="en0"),
            Device(ip="192.168.10.25", mac="a2:7d:e4:36:fd:14", interface="en0"),
        ],
        default_gateway="192.168.10.5",
        default_gateway_mac="90:e3:ba:02:a3:6e",
    )

    topology = TopologyBuilder().build(snapshot)
    node_ids = {node.id for node in topology.nodes}
    assert "host:local" in node_ids
    assert "interface:en0" in node_ids
    assert "subnet:192.168.10.0/24" in node_ids
    assert "gateway:192.168.10.5" in node_ids
    assert "route:10.10.0.0/16:en0" in node_ids
    assert topology.summary["gateway"] >= 1
    assert any(edge.relation == "routes-via" for edge in topology.edges)


def test_snapshot_roundtrip_with_topology_fields():
    snapshot = NetworkSnapshot(
        taken_at=utc_now(),
        hostname="protecto",
        platform="test",
        interfaces=[InterfaceInfo(name="en0", ipv4=["192.168.10.108/24"])],
        routes=[Route(destination="default", gateway="192.168.10.5", interface="en0")],
    )

    loaded = NetworkSnapshot.from_dict(snapshot.to_dict())
    assert loaded.interfaces[0].name == "en0"
    assert loaded.routes[0].gateway == "192.168.10.5"
