from __future__ import annotations

from protectogotchi.collectors import get_collector
from protectogotchi.config import ProtectogotchiConfig
from protectogotchi.detection import AnomalyDetector
from protectogotchi.models import ScanResult
from protectogotchi.response import ResponseExecutor, ResponsePlanner
from protectogotchi.state import StateStore


class ProtectogotchiAgent:
    def __init__(
        self,
        config: ProtectogotchiConfig,
        collector_name: str | None = None,
    ) -> None:
        self.config = config
        self.collector = get_collector(collector_name)
        self.store = StateStore(config.state_dir)
        self.detector = AnomalyDetector(config)
        self.planner = ResponsePlanner(config)
        self.executor = ResponseExecutor(config)

    def scan(self, learn: bool = True, execute_actions: bool = False) -> ScanResult:
        snapshot = self.collector.collect()
        state = self.store.load()
        analysis = self.detector.analyze(snapshot, state)
        actions = self.planner.plan(analysis.findings, snapshot)

        if execute_actions:
            actions = [self.executor.execute(action) for action in actions]

        learned = False
        if learn and analysis.risk_score <= self.config.autolearn_max_score:
            state.learn(snapshot)
            learned = True

        state.record_scan(analysis.findings)
        self.store.save(state)

        return ScanResult(
            snapshot=snapshot,
            findings=analysis.findings,
            actions=actions,
            risk_score=analysis.risk_score,
            face_state=analysis.face_state,
            learned=learned,
            level=state.level,
            xp=state.xp,
        )
