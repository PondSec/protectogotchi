from protectogotchi.config import ProtectogotchiConfig


def test_config_loads_deployment_mode_from_environment(monkeypatch):
    monkeypatch.setenv("PROTECTOGOTCHI_DEPLOYMENT_MODE", "inline-gateway")
    config = ProtectogotchiConfig.load()
    assert config.deployment_mode == "inline-gateway"
