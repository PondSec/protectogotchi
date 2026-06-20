from __future__ import annotations

from typing import Any

from protectogotchi.capabilities import ProtectogotchiArsenalOrchestrator
from protectogotchi.config import ProtectogotchiConfig
from protectogotchi.external_tools import ExternalToolRuntime
from protectogotchi.state import StateStore


def build_arsenal_context(config: ProtectogotchiConfig) -> dict[str, Any]:
    state = StateStore(config.state_dir).load()
    return {
        "devices": list(state.devices.values()),
        "subnets": list(state.known_subnets),
        "neural_model": state.neural_model,
        "policy_model": state.policy_model,
        "external_tools": ExternalToolRuntime().report(),
        "risk_score": 0,
    }


def assess_arsenal(config: ProtectogotchiConfig) -> dict[str, Any]:
    orchestrator = ProtectogotchiArsenalOrchestrator()
    return orchestrator.assess(build_arsenal_context(config)).to_dict()
