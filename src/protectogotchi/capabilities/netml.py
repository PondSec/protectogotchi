from __future__ import annotations

from typing import Any

from protectogotchi.capabilities.base import CapabilityModule, CapabilityResult
from protectogotchi.neural import neural_model_summary
from protectogotchi.policy import policy_model_summary


class NetML(CapabilityModule):
    name = "netml"
    domain = "machine-learning"

    def assess(self, context: dict[str, Any]) -> CapabilityResult:
        neural = neural_model_summary(context.get("neural_model", {}))
        policy = policy_model_summary(context.get("policy_model", {}))
        return CapabilityResult(
            module=self.name,
            status="available",
            summary="PyTorch neural anomaly and DQN policy modules are wired.",
            evidence={"neural": neural, "policy": policy},
            recommendations=("Install the ml extra to activate PyTorch runtime: pip install '.[ml]'.",)
            if not neural["backend_available"] else (),
        )
