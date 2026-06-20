from __future__ import annotations

from dataclasses import asdict, dataclass

from protectogotchi.config import ProtectogotchiConfig
from protectogotchi.detection import AnomalyDetector
from protectogotchi.models import Connection, Device, NetworkSnapshot, Route, utc_now
from protectogotchi.response import ResponsePlanner
from protectogotchi.state import ProtectogotchiState


@dataclass(frozen=True)
class SimulationEvent:
    phase: str
    detail: str
    protectogotchi_view: str


@dataclass(frozen=True)
class SimulatedPacket:
    source: str
    destination: str
    protocol: str
    summary: str
    verdict: str


@dataclass(frozen=True)
class SimulationResult:
    scenario: str
    isolated: bool
    environment: str
    risk_score: int
    face_state: str
    timeline: list[SimulationEvent]
    packets: list[SimulatedPacket]
    findings: list[dict]
    actions: list[dict]
    lessons: list[str]

    def to_dict(self) -> dict:
        return asdict(self)


SCENARIOS = ("arp-spoof", "new-device", "connection-spike", "vlan-lateral-movement")


def run_simulation(scenario: str, config: ProtectogotchiConfig | None = None) -> SimulationResult:
    config = config or ProtectogotchiConfig()
    state = ProtectogotchiState()
    baseline = _baseline_snapshot()
    for _ in range(config.min_baseline_observations):
        state.learn(baseline)

    if scenario == "arp-spoof":
        live = _baseline_snapshot(gateway_mac="de:ad:be:ef:00:01")
        timeline = [
            SimulationEvent(
                phase="baseline",
                detail="The lab host learned gateway 192.168.50.1 at aa:aa:aa:aa:aa:aa.",
                protectogotchi_view="gateway identity is stable",
            ),
            SimulationEvent(
                phase="attack",
                detail="A synthetic attacker claims the gateway IP with MAC de:ad:be:ef:00:01.",
                protectogotchi_view="gateway MAC differs from learned baseline",
            ),
            SimulationEvent(
                phase="response",
                detail="Protectogotchi raises a critical finding and refuses to learn the poisoned identity.",
                protectogotchi_view="alert and defensive response planning",
            ),
        ]
        packets = [
            SimulatedPacket(
                source="192.168.50.77",
                destination="192.168.50.10",
                protocol="ARP",
                summary="who-has/claim: gateway IP now maps to attacker MAC",
                verdict="detected",
            ),
            SimulatedPacket(
                source="192.168.50.10",
                destination="192.168.50.1",
                protocol="TCP",
                summary="victim traffic would be at risk if a real LAN accepted the forged ARP entry",
                verdict="blocked-in-lab-simulation",
            ),
        ]
        lessons = [
            "Gateway MAC drift is a high-confidence ARP-spoofing signal.",
            "Protectogotchi tests this with synthetic snapshots only; no live traffic is redirected.",
            "A client-only sensor can detect this, but real prevention needs access-layer control, an endpoint agent, or an inline position.",
        ]
    elif scenario == "new-device":
        live = _baseline_snapshot(
            extra_devices=[
                Device(ip="192.168.50.77", mac="66:77:88:99:aa:bb", interface="lab0")
            ]
        )
        timeline = [
            SimulationEvent(
                phase="baseline",
                detail="The lab network contains the gateway and one known laptop.",
                protectogotchi_view="inventory is stable",
            ),
            SimulationEvent(
                phase="change",
                detail="A new device appears on the synthetic neighbor table.",
                protectogotchi_view="new untrusted MAC after baseline warmup",
            ),
        ]
        packets = [
            SimulatedPacket(
                source="192.168.50.77",
                destination="192.168.50.255",
                protocol="ARP",
                summary="new host announces itself in the lab segment",
                verdict="inventory-alert",
            )
        ]
        lessons = [
            "New devices are not auto-trusted after the baseline is ready.",
            "Owner labels can convert known devices into trusted inventory.",
        ]
    elif scenario == "connection-spike":
        for count in [2, 3, 2, 3]:
            state.learn(_baseline_snapshot(connections=_connections(count)))
        live = _baseline_snapshot(connections=_connections(30))
        timeline = [
            SimulationEvent(
                phase="baseline",
                detail="The lab host normally keeps only a few outbound connections.",
                protectogotchi_view="connection count baseline is low",
            ),
            SimulationEvent(
                phase="anomaly",
                detail="The synthetic host suddenly opens many external connections.",
                protectogotchi_view="feature spike over local baseline",
            ),
        ]
        packets = [
            SimulatedPacket(
                source="192.168.50.10",
                destination="198.51.100.1-30",
                protocol="TCP/443",
                summary="many parallel outbound sessions in a short window",
                verdict="scored",
            )
        ]
        lessons = [
            "Behavioral spikes need a clean local baseline before they become meaningful.",
            "Protectogotchi scores the pattern and keeps the evidence explainable.",
        ]
    elif scenario == "vlan-lateral-movement":
        for count in [2, 3, 2, 3]:
            state.learn(_baseline_snapshot(connections=_connections(count)))
        live = _baseline_snapshot(
            connections=[
                *_connections(2),
                Connection(
                    protocol="tcp",
                    local_address="192.168.50.10",
                    local_port=50445,
                    remote_address="10.20.0.44",
                    remote_port=445,
                    state="ESTABLISHED",
                ),
                Connection(
                    protocol="tcp",
                    local_address="192.168.50.10",
                    local_port=53389,
                    remote_address="10.20.0.45",
                    remote_port=3389,
                    state="ESTABLISHED",
                ),
            ]
        )
        live.routes.append(
            # The route makes the scenario explicit: VLAN/subnet 20 is reachable
            # through a routed boundary that a plain client can observe but not control.
            Route(destination="10.20.0.0/24", gateway="192.168.50.1", interface="lab0")
        )
        timeline = [
            SimulationEvent(
                phase="baseline",
                detail="VLAN10 client can reach routed VLAN20 through the lab routing boundary.",
                protectogotchi_view="route to 10.20.0.0/24 is visible",
            ),
            SimulationEvent(
                phase="attack",
                detail="A synthetic host tries SMB/RDP sessions into VLAN20.",
                protectogotchi_view="risky remote admin services across a routed boundary",
            ),
            SimulationEvent(
                phase="response",
                detail="Protectogotchi can identify the risk from a client view but does not pretend to block routed traffic without a control point.",
                protectogotchi_view="detect-and-alert unless deployed inline or paired with an authorized enforcement point",
            ),
        ]
        packets = [
            SimulatedPacket(
                source="192.168.50.10",
                destination="10.20.0.44",
                protocol="TCP/445",
                summary="SMB attempt across routed VLAN boundary",
                verdict="detected-client-cannot-prevent",
            ),
            SimulatedPacket(
                source="192.168.50.10",
                destination="10.20.0.45",
                protocol="TCP/3389",
                summary="RDP attempt across routed VLAN boundary",
                verdict="detected-client-cannot-prevent",
            ),
        ]
        lessons = [
            "For VLAN10 to VLAN20 prevention, Protectogotchi must either be in the traffic path or have an authorized enforcement point.",
            "Without firewall/router/AP/switch control and without inline placement, a client can detect and alert but not reliably block other devices.",
            "Same-subnet L2 prevention needs access-layer control, endpoint agents, or an inline bridge; ARP/MitM is not implemented.",
        ]
    else:
        raise ValueError(f"Unknown simulation scenario: {scenario}")

    analysis = AnomalyDetector(config).analyze(live, state)
    actions = ResponsePlanner(config).plan(analysis.findings, live)
    return SimulationResult(
        scenario=scenario,
        isolated=True,
        environment="synthetic local lab; no packet injection; no live traffic redirection",
        risk_score=analysis.risk_score,
        face_state=analysis.face_state,
        timeline=timeline,
        packets=packets,
        findings=[asdict(finding) for finding in analysis.findings],
        actions=[asdict(action) for action in actions],
        lessons=lessons,
    )


def _baseline_snapshot(
    gateway_mac: str = "aa:aa:aa:aa:aa:aa",
    extra_devices: list[Device] | None = None,
    connections: list[Connection] | None = None,
) -> NetworkSnapshot:
    gateway = Device(ip="192.168.50.1", mac=gateway_mac, interface="lab0")
    laptop = Device(ip="192.168.50.10", mac="00:11:22:33:44:55", interface="lab0")
    return NetworkSnapshot(
        taken_at=utc_now(),
        hostname="protectogotchi-lab",
        platform="simulation",
        devices=[gateway, laptop, *(extra_devices or [])],
        connections=connections or _connections(2),
        default_gateway="192.168.50.1",
        default_gateway_mac=gateway_mac,
    )


def _connections(count: int) -> list[Connection]:
    return [
        Connection(
            protocol="tcp",
            local_address="192.168.50.10",
            local_port=50000 + index,
            remote_address=f"198.51.100.{index + 1}",
            remote_port=443,
            state="ESTABLISHED",
        )
        for index in range(count)
    ]
