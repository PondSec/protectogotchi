from protectogotchi.config import ProtectogotchiConfig


def test_config_loads_deployment_mode_from_environment(monkeypatch):
    monkeypatch.setenv("PROTECTOGOTCHI_DEPLOYMENT_MODE", "dns-guard")
    config = ProtectogotchiConfig.load()
    assert config.deployment_mode == "dns-guard"
