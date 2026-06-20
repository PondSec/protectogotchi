from __future__ import annotations

from dataclasses import asdict, dataclass

from protectogotchi.config import ProtectogotchiConfig
from protectogotchi.detection import AnomalyDetector
from protectogotchi.models import Connection, Device, NetworkSnapshot, utc_now
from protectogotchi.response import ResponsePlanner
from protectogotchi.state import ProtectogotchiState


@dataclass(frozen=True)
class SimulationResult:
    scenario: str
    risk_score: int
    face_state: str
    findings: list[dict]
    actions: list[dict]

    def to_dict(self) -> dict:
        return asdict(self)


SCENARIOS = ("arp-spoof", "new-device", "connection-spike")


def run_simulation(scenario: str, config: ProtectogotchiConfig | None = None) -> SimulationResult:
    config = config or ProtectogotchiConfig()
    state = ProtectogotchiState()
    baseline = _baseline_snapshot()
    for _ in range(config.min_baseline_observations):
        state.learn(baseline)

    if scenario == "arp-spoof":
        live = _baseline_snapshot(gateway_mac="de:ad:be:ef:00:01")
    elif scenario == "new-device":
        live = _baseline_snapshot(
            extra_devices=[
                Device(ip="192.168.50.77", mac="66:77:88:99:aa:bb", interface="lab0")
            ]
        )
    elif scenario == "connection-spike":
        for count in [2, 3, 2, 3]:
            state.learn(_baseline_snapshot(connections=_connections(count)))
        live = _baseline_snapshot(connections=_connections(30))
    else:
        raise ValueError(f"Unknown simulation scenario: {scenario}")

    analysis = AnomalyDetector(config).analyze(live, state)
    actions = ResponsePlanner(config).plan(analysis.findings, live)
    return SimulationResult(
        scenario=scenario,
        risk_score=analysis.risk_score,
        face_state=analysis.face_state,
        findings=[asdict(finding) for finding in analysis.findings],
        actions=[asdict(action) for action in actions],
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
