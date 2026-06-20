from protectogotchi.config import ProtectogotchiConfig
from protectogotchi.enforcement import (
    get_enforcement_mode,
    god_mode_readiness,
    list_enforcement_modes,
)


def test_enforcement_modes_include_rejected_arp_mitm():
    modes = {mode.name: mode for mode in list_enforcement_modes()}
    assert modes["observer"].can_prevent is False
    assert modes["lab-simulation"].current_status == "implemented"
    assert modes["inline-gateway"].can_prevent is True
    assert modes["arp-mitm"].current_status == "rejected"


def test_get_enforcement_mode_returns_mode():
    mode = get_enforcement_mode("router-controller")
    assert mode is not None
    assert "router" in mode.summary.lower()


def test_god_mode_readiness_requires_real_enforcement_for_network_wide():
    observer = god_mode_readiness(ProtectogotchiConfig())
    assert observer["can_prevent_network_wide"] is False

    gateway = god_mode_readiness(
        ProtectogotchiConfig(
            deployment_mode="inline-gateway",
            response_mode="active",
            allow_active_blocking=True,
        )
    )
    assert gateway["can_prevent_network_wide"] is True
