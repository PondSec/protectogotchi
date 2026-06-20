from __future__ import annotations

from protectogotchi.collectors import get_collector
from protectogotchi.config import ProtectogotchiConfig
from protectogotchi.detection import AnomalyDetector
from protectogotchi.models import Finding, ScanResult
from protectogotchi.policy import recommend_policy
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
        policy, policy_model = recommend_policy(
            state.policy_model,
            analysis.findings,
            risk_score=analysis.risk_score,
            neural_score=int(analysis.neural.get("score", 0)),
            config=self.config,
        )
        state.policy_model = policy_model

        if execute_actions:
            actions = [self.executor.execute(action) for action in actions]

        learned = False
        if self._should_learn(learn, state, analysis.findings, analysis.risk_score):
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
            ai={
                "neural": analysis.neural,
                "policy": policy.to_dict(),
            },
        )

    def _should_learn(
        self,
        learn: bool,
        state,
        findings: list[Finding],
        risk_score: int,
    ) -> bool:
        if not learn or risk_score > self.config.autolearn_max_score:
            return False
        if state.is_learning(self.config.min_baseline_observations):
            return all(finding.severity == "info" for finding in findings)
        return all(finding.severity == "info" for finding in findings)
