from __future__ import annotations

from typing import Any

from protectogotchi.capabilities.base import CapabilityModule, CapabilityResult


class RedTeamBot(CapabilityModule):
    name = "redteam-bot"
    domain = "authorized-assessment"
    status = "disabled"
    risk = "review"

    def import_findings(self, report: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return [
            {
                "asset": item.get("asset", "unknown"),
                "severity": item.get("severity", "unknown"),
                "title": item.get("title", "untitled"),
                "source": "authorized-assessment-report",
            }
            for item in report
        ]

    def assess(self, context: dict[str, Any]) -> CapabilityResult:
        imported = self.import_findings(context.get("assessment_findings", []))
        return CapabilityResult(
            module=self.name,
            status=self.status,
            summary="Exploit orchestration is disabled; authorized assessment report import is supported.",
            evidence={"imported_findings": imported},
            recommendations=("Use external authorized pentest reports as evidence; do not automate exploitation from Protectogotchi.",),
            risk=self.risk,
        )
