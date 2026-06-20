from protectogotchi.arsenal import assess_arsenal
from protectogotchi.capabilities import ProtectogotchiArsenalOrchestrator
from protectogotchi.capabilities.ip_planner import IPPlanner
from protectogotchi.capabilities.policyguru import PolicyGuru
from protectogotchi.capabilities.redteam_bot import RedTeamBot
from protectogotchi.config import ProtectogotchiConfig


def test_orchestrator_loads_many_defensive_modules(tmp_path):
    report = assess_arsenal(ProtectogotchiConfig(state_dir=tmp_path))

    modules = {module["name"] for module in report["modules"]}
    assert len(modules) >= 18
    assert "ip-planner" in modules
    assert "netml" in modules
    assert "redteam-bot" in modules
    assert report["summary"]["available"] >= 4


def test_ip_planner_splits_and_reserves_addresses():
    planner = IPPlanner()

    assert planner.split("192.168.10.0/24", 26) == [
        "192.168.10.0/26",
        "192.168.10.64/26",
        "192.168.10.128/26",
        "192.168.10.192/26",
    ]
    assert planner.reserve("192.168.10.0/30", {"gateway": "router"}) == {
        "gateway": "192.168.10.1"
    }


def test_policyguru_renders_reviewable_defensive_rules():
    guru = PolicyGuru()

    assert "block drop" in guru.render_pf_block("blocked_hosts", "192.168.10.50")
    assert "nft" not in guru.render_pf_block("blocked_hosts", "192.168.10.50")
    assert "ip saddr" in guru.render_nft_block("blocked_ipv4", "192.168.10.50")


def test_redteam_bot_does_not_orchestrate_exploitation():
    result = RedTeamBot().assess(
        {"assessment_findings": [{"asset": "web01", "severity": "high", "title": "SQLi"}]}
    )

    assert result.status == "disabled"
    assert "disabled" in result.summary.lower()
    assert result.evidence["imported_findings"][0]["source"] == "authorized-assessment-report"


def test_orchestrator_context_assessment_accepts_runtime_models():
    report = ProtectogotchiArsenalOrchestrator().assess(
        {"subnets": ["192.168.1.0/24"], "neural_model": {}, "policy_model": {}}
    )

    names = {result["module"] for result in report.to_dict()["results"]}
    assert "netml" in names
    assert "holoview" in names
