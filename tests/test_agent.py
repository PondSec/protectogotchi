from protectogotchi.agent import ProtectogotchiAgent
from protectogotchi.config import ProtectogotchiConfig
from protectogotchi.models import Device, NetworkSnapshot, utc_now
from protectogotchi.state import StateStore


class SequenceCollector:
    def __init__(self, snapshots):
        self.snapshots = list(snapshots)
        self.index = 0

    def collect(self):
        snapshot = self.snapshots[min(self.index, len(self.snapshots) - 1)]
        self.index += 1
        return snapshot


def snapshot_for(devices):
    gateway = Device(ip="192.168.1.1", mac="aa:aa:aa:aa:aa:aa", interface="en0")
    return NetworkSnapshot(
        taken_at=utc_now(),
        hostname="test-host",
        platform="test",
        devices=[gateway, *devices],
        default_gateway="192.168.1.1",
        default_gateway_mac="aa:aa:aa:aa:aa:aa",
    )


def test_agent_does_not_autolearn_untrusted_new_device_after_warmup(tmp_path):
    known = Device(ip="192.168.1.10", mac="00:11:22:33:44:55", interface="en0")
    newcomer = Device(ip="192.168.1.99", mac="66:77:88:99:aa:bb", interface="en0")
    snapshots = [
        snapshot_for([known]),
        snapshot_for([known]),
        snapshot_for([known]),
        snapshot_for([known, newcomer]),
    ]
    config = ProtectogotchiConfig(state_dir=tmp_path, min_baseline_observations=3)
    agent = ProtectogotchiAgent(config)
    agent.collector = SequenceCollector(snapshots)

    for _ in range(3):
        result = agent.scan()
        assert result.learned

    result = agent.scan()
    assert not result.learned
    state = StateStore(tmp_path).load()
    assert "66:77:88:99:aa:bb" not in state.devices
    assert any(finding.code == "new_device_seen" for finding in result.findings)
