from protectogotchi.config import ProtectogotchiConfig
from protectogotchi.models import Finding
from protectogotchi.neural import evaluate_neural_model, neural_model_summary, train_neural_baseline
from protectogotchi.policy import recommend_policy


def test_neural_backend_reports_pytorch_status_without_fake_claims():
    summary = neural_model_summary({})

    assert summary["backend"] == "pytorch"
    assert "backend_available" in summary
    assert summary["model"] == "pytorch-deep-autoencoder"


def test_neural_training_tracks_observations_even_without_optional_backend():
    model = {}
    features = {
        "device_count": 2,
        "connection_count": 4,
        "established_count": 2,
        "external_connection_count": 1,
        "unique_remote_count": 1,
        "listening_port_count": 1,
        "interface_count": 1,
        "route_count": 2,
    }

    model = train_neural_baseline(model, features, epochs=1)
    evaluation = evaluate_neural_model(model, features, min_observations=1)

    assert model["observations"] == 1
    assert evaluation.backend == "pytorch"


def test_dqn_policy_requires_enforcement_point_in_observer_mode():
    finding = Finding(
        code="neural_behavior_anomaly",
        title="Neural drift",
        severity="high",
        description="test",
    )

    decision, model = recommend_policy(
        {},
        [finding],
        risk_score=80,
        neural_score=80,
        config=ProtectogotchiConfig(deployment_mode="observer"),
    )

    assert decision.action == "require_enforcement_point"
    assert decision.safety_gate == "blocked-client-only"
    assert model["last_action"] == "require_enforcement_point"
