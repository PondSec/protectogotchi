from __future__ import annotations

import math
from dataclasses import asdict, dataclass
from typing import Any


try:  # PyTorch is an optional runtime backend: install with protectogotchi[ml].
    import torch
    from torch import nn
except Exception:  # pragma: no cover - depends on local optional dependency.
    torch = None
    nn = None


FEATURE_NAMES: tuple[str, ...] = (
    "device_count",
    "connection_count",
    "established_count",
    "external_connection_count",
    "unique_remote_count",
    "listening_port_count",
    "interface_count",
    "route_count",
)

MODEL_VERSION = 2
HIDDEN_SIZE = 16
LATENT_SIZE = 8


@dataclass(frozen=True)
class NeuralEvaluation:
    ready: bool
    score: int
    reconstruction_error: float
    observations: int
    top_features: tuple[dict[str, float], ...]
    model: str = "pytorch-deep-autoencoder"
    backend: str = "pytorch"
    backend_available: bool = True

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def train_neural_baseline(
    model_data: dict[str, Any] | None,
    features: dict[str, float],
    *,
    epochs: int = 24,
    learning_rate: float = 0.01,
) -> dict[str, Any]:
    model_data = _ensure_model_data(model_data)
    if torch is None or nn is None:
        model_data["backend_available"] = False
        model_data["observations"] = int(model_data.get("observations", 0)) + 1
        return model_data

    torch.manual_seed(7)
    network = _build_network()
    _load_state_dict(network, model_data.get("state_dict", {}))
    optimizer = torch.optim.Adam(network.parameters(), lr=learning_rate)
    loss_fn = nn.MSELoss()
    x = torch.tensor([feature_vector(features)], dtype=torch.float32)

    network.train()
    last_loss = 0.0
    for _ in range(max(1, epochs)):
        optimizer.zero_grad()
        reconstructed = network(x)
        loss = loss_fn(reconstructed, x)
        loss.backward()
        optimizer.step()
        last_loss = float(loss.detach().item())

    with torch.no_grad():
        reconstruction = network(x)[0].detach().tolist()

    model_data.update(
        {
            "backend": "pytorch",
            "backend_available": True,
            "observations": int(model_data.get("observations", 0)) + 1,
            "last_error": round(last_loss, 8),
            "last_reconstruction": [round(value, 6) for value in reconstruction],
            "state_dict": _dump_state_dict(network),
        }
    )
    return model_data


def evaluate_neural_model(
    model_data: dict[str, Any] | None,
    features: dict[str, float],
    *,
    min_observations: int = 3,
) -> NeuralEvaluation:
    model_data = _ensure_model_data(model_data)
    observations = int(model_data.get("observations", 0))
    if torch is None or nn is None or not model_data.get("state_dict"):
        return NeuralEvaluation(
            ready=False,
            score=0,
            reconstruction_error=0.0,
            observations=observations,
            top_features=(),
            backend_available=False,
        )

    network = _build_network()
    _load_state_dict(network, model_data.get("state_dict", {}))
    x = torch.tensor([feature_vector(features)], dtype=torch.float32)
    network.eval()
    with torch.no_grad():
        reconstruction = network(x)[0].detach().tolist()
    vector = x[0].tolist()
    error = sum((reconstruction[index] - vector[index]) ** 2 for index in range(len(vector))) / len(vector)
    deltas = [
        {
            "feature": name,
            "value": round(features.get(name, 0.0), 4),
            "normalized": round(vector[index], 6),
            "reconstructed": round(reconstruction[index], 6),
            "delta": round(abs(vector[index] - reconstruction[index]), 6),
        }
        for index, name in enumerate(FEATURE_NAMES)
    ]
    deltas.sort(key=lambda item: item["delta"], reverse=True)
    score = int(min(100, round(math.sqrt(max(error, 0.0)) * 340)))
    return NeuralEvaluation(
        ready=observations >= min_observations,
        score=score if observations >= min_observations else 0,
        reconstruction_error=round(error, 8),
        observations=observations,
        top_features=tuple(deltas[:3]),
    )


def neural_model_summary(model_data: dict[str, Any] | None) -> dict[str, Any]:
    model = _ensure_model_data(model_data)
    return {
        "model": "pytorch-deep-autoencoder",
        "backend": "pytorch",
        "backend_available": torch is not None and nn is not None,
        "version": model["version"],
        "observations": int(model.get("observations", 0)),
        "input_features": list(FEATURE_NAMES),
        "hidden_units": HIDDEN_SIZE,
        "latent_units": LATENT_SIZE,
        "last_error": model.get("last_error", 0.0),
    }


def feature_vector(features: dict[str, float]) -> list[float]:
    return [_scale(features.get(name, 0.0)) for name in FEATURE_NAMES]


def _scale(value: float) -> float:
    return min(1.0, math.log1p(max(0.0, float(value))) / 8.0)


def _ensure_model_data(model_data: dict[str, Any] | None) -> dict[str, Any]:
    if model_data and model_data.get("version") == MODEL_VERSION:
        clean = dict(model_data)
        clean.setdefault("backend", "pytorch")
        clean.setdefault("backend_available", torch is not None and nn is not None)
        clean.setdefault("observations", 0)
        clean.setdefault("state_dict", {})
        clean.setdefault("last_error", 0.0)
        return clean
    return {
        "version": MODEL_VERSION,
        "backend": "pytorch",
        "backend_available": torch is not None and nn is not None,
        "observations": 0,
        "state_dict": {},
        "last_error": 0.0,
        "last_reconstruction": [],
    }


def _build_network():
    if nn is None:  # pragma: no cover
        raise RuntimeError("PyTorch is required for the neural backend.")
    return nn.Sequential(
        nn.Linear(len(FEATURE_NAMES), HIDDEN_SIZE),
        nn.ReLU(),
        nn.Linear(HIDDEN_SIZE, LATENT_SIZE),
        nn.ReLU(),
        nn.Linear(LATENT_SIZE, HIDDEN_SIZE),
        nn.ReLU(),
        nn.Linear(HIDDEN_SIZE, len(FEATURE_NAMES)),
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
