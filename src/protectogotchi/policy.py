from __future__ import annotations

import math
from dataclasses import asdict, dataclass
from typing import Any

from protectogotchi.config import ProtectogotchiConfig
from protectogotchi.models import Finding


try:  # PyTorch is optional but used whenever protectogotchi[ml] is installed.
    import torch
    from torch import nn
except Exception:  # pragma: no cover - depends on local optional dependency.
    torch = None
    nn = None


POLICY_VERSION = 2
POLICY_FEATURES = (
    "bias",
    "risk",
    "neural_score",
    "critical_findings",
    "high_findings",
    "medium_findings",
    "has_enforcement_point",
)
POLICY_ACTIONS = (
    "observe",
    "learn_baseline",
    "notify_owner",
    "plan_host_block",
    "escalate_human",
    "require_enforcement_point",
)
HIDDEN_SIZE = 16
NETWORK_WIDE_MODES = {
    "router-controller",
    "inline-gateway",
    "transparent-bridge",
    "managed-ap-or-switch",
    "endpoint-agent",
}


@dataclass(frozen=True)
class PolicyDecision:
    action: str
    confidence: float
    reason: str
    safety_gate: str
    q_values: dict[str, float]
    model: str = "pytorch-safety-gated-dqn"
    backend: str = "pytorch"
    backend_available: bool = True

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def recommend_policy(
    model_data: dict[str, Any] | None,
    findings: list[Finding],
    *,
    risk_score: int,
    neural_score: int,
    config: ProtectogotchiConfig,
) -> tuple[PolicyDecision, dict[str, Any]]:
    model_data = _ensure_policy_data(model_data)
    x = _policy_vector(findings, risk_score, neural_score, config)
    q_values = _q_values(model_data, x)
    action = max(q_values, key=q_values.get)
    safety_gate = "allow"
    reason = "DQN selected the highest-value defensive action."

    if risk_score == 0 and all(finding.severity == "info" for finding in findings):
        action = "learn_baseline"
        reason = "No risky finding is present, so clean observations can strengthen the baseline."
    elif risk_score >= 70 and config.deployment_mode == "observer":
        action = "require_enforcement_point"
        safety_gate = "blocked-client-only"
        reason = "High risk is visible, but this placement cannot stop other devices without a real enforcement point."
    elif any(finding.severity == "critical" for finding in findings):
        action = "escalate_human"
        reason = "Critical identity or topology drift requires confirmation before containment."
    elif risk_score >= 70:
        action = "plan_host_block"
        reason = "High-risk evidence can be translated into a defensive block through configured enforcement."
    elif risk_score >= 35:
        action = "notify_owner"
        reason = "Medium-risk behavior should be surfaced quickly without disruptive action."
    elif findings:
        action = "observe"
        reason = "Low-risk findings should be watched without poisoning the baseline."

    reward = _reward(action, findings, risk_score, config)
    model_data = _reinforce(model_data, x, action, reward)
    q_values = _q_values(model_data, x)
    decision = PolicyDecision(
        action=action,
        confidence=_confidence(q_values, action),
        reason=reason,
        safety_gate=safety_gate,
        q_values={name: round(value, 4) for name, value in q_values.items()},
        backend_available=torch is not None and nn is not None,
    )
    model_data["updates"] = int(model_data.get("updates", 0)) + 1
    model_data["last_action"] = action
    model_data["last_reward"] = reward
    return decision, model_data


def policy_model_summary(model_data: dict[str, Any] | None) -> dict[str, Any]:
    model = _ensure_policy_data(model_data)
    return {
        "model": "pytorch-safety-gated-dqn",
        "backend": "pytorch",
        "backend_available": torch is not None and nn is not None,
        "version": model["version"],
        "updates": int(model.get("updates", 0)),
        "features": list(POLICY_FEATURES),
        "actions": list(POLICY_ACTIONS),
        "hidden_units": HIDDEN_SIZE,
        "last_action": model.get("last_action"),
        "last_reward": model.get("last_reward", 0.0),
    }


def _policy_vector(
    findings: list[Finding],
    risk_score: int,
    neural_score: int,
    config: ProtectogotchiConfig,
) -> list[float]:
    return [
        1.0,
        min(1.0, risk_score / 100.0),
        min(1.0, neural_score / 100.0),
        min(1.0, sum(1 for finding in findings if finding.severity == "critical") / 3.0),
        min(1.0, sum(1 for finding in findings if finding.severity == "high") / 3.0),
        min(1.0, sum(1 for finding in findings if finding.severity == "medium") / 5.0),
        1.0 if config.deployment_mode in NETWORK_WIDE_MODES or config.active_response_enabled else 0.0,
    ]


def _ensure_policy_data(model_data: dict[str, Any] | None) -> dict[str, Any]:
    if model_data and model_data.get("version") == POLICY_VERSION:
        clean = dict(model_data)
        clean.setdefault("backend", "pytorch")
        clean.setdefault("backend_available", torch is not None and nn is not None)
        clean.setdefault("updates", 0)
        clean.setdefault("state_dict", {})
        clean.setdefault("last_action", None)
        clean.setdefault("last_reward", 0.0)
        return clean
    return {
        "version": POLICY_VERSION,
        "backend": "pytorch",
        "backend_available": torch is not None and nn is not None,
        "updates": 0,
        "state_dict": {},
        "last_action": None,
        "last_reward": 0.0,
    }


def _q_values(model_data: dict[str, Any], x: list[float]) -> dict[str, float]:
    if torch is None or nn is None:
        return _fallback_q_values(x)
    torch.manual_seed(11)
    network = _build_network()
    _load_state_dict(network, model_data.get("state_dict", {}))
    network.eval()
    with torch.no_grad():
        output = network(torch.tensor([x], dtype=torch.float32))[0].detach().tolist()
    return {action: float(output[index]) for index, action in enumerate(POLICY_ACTIONS)}


def _fallback_q_values(x: list[float]) -> dict[str, float]:
    risk = x[1]
    neural = x[2]
    enforcement = x[6]
    return {
        "observe": 0.4 - risk,
        "learn_baseline": 0.5 if risk == 0 else -0.2,
        "notify_owner": 0.2 + risk + neural,
        "plan_host_block": -0.3 + risk + enforcement,
        "escalate_human": 0.1 + risk,
        "require_enforcement_point": 0.2 + risk - enforcement,
    }


def _reinforce(
    model_data: dict[str, Any],
    x: list[float],
    action: str,
    reward: float,
    learning_rate: float = 0.01,
) -> dict[str, Any]:
    if torch is None or nn is None:
        model_data["backend_available"] = False
        return model_data

    torch.manual_seed(11)
    network = _build_network()
    _load_state_dict(network, model_data.get("state_dict", {}))
    optimizer = torch.optim.Adam(network.parameters(), lr=learning_rate)
    loss_fn = nn.MSELoss()
    input_tensor = torch.tensor([x], dtype=torch.float32)
    action_index = POLICY_ACTIONS.index(action)

    network.train()
    optimizer.zero_grad()
    q_values = network(input_tensor)
    target = q_values.detach().clone()
    target[0, action_index] = reward
    loss = loss_fn(q_values, target)
    loss.backward()
    optimizer.step()
    model_data["state_dict"] = _dump_state_dict(network)
    model_data["backend_available"] = True
    return model_data


def _reward(
    action: str,
    findings: list[Finding],
    risk_score: int,
    config: ProtectogotchiConfig,
) -> float:
    if risk_score == 0:
        return 0.9 if action == "learn_baseline" else 0.2
    if risk_score >= 70 and config.deployment_mode == "observer":
        return 0.95 if action == "require_enforcement_point" else -0.4
    if any(finding.severity == "critical" for finding in findings):
        return 0.9 if action == "escalate_human" else -0.2
    if risk_score >= 70:
        return 0.8 if action == "plan_host_block" else 0.1
    if risk_score >= 35:
        return 0.75 if action == "notify_owner" else 0.2
    return 0.55 if action == "observe" else 0.1


def _confidence(q_values: dict[str, float], action: str) -> float:
    ordered = sorted(q_values.values(), reverse=True)
    if len(ordered) < 2:
        return 0.5
    margin = max(0.0, q_values[action] - ordered[1])
    return round(max(0.35, min(0.98, 0.55 + margin)), 2)


def _build_network():
    if nn is None:  # pragma: no cover
        raise RuntimeError("PyTorch is required for the DQN backend.")
    return nn.Sequential(
        nn.Linear(len(POLICY_FEATURES), HIDDEN_SIZE),
        nn.ReLU(),
        nn.Linear(HIDDEN_SIZE, HIDDEN_SIZE),
        nn.ReLU(),
        nn.Linear(HIDDEN_SIZE, len(POLICY_ACTIONS)),
    )


def _dump_state_dict(network) -> dict[str, Any]:
    return {
        name: tensor.detach().cpu().tolist()
        for name, tensor in network.state_dict().items()
    }


def _load_state_dict(network, raw_state: dict[str, Any]) -> None:
    if not raw_state or torch is None:
        return
    current = network.state_dict()
    loaded = {}
    for name, value in raw_state.items():
        if name not in current:
            continue
        tensor = torch.tensor(value, dtype=current[name].dtype)
        if tuple(tensor.shape) == tuple(current[name].shape):
            loaded[name] = tensor
    current.update(loaded)
    network.load_state_dict(current)
