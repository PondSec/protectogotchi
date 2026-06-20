from __future__ import annotations

from collections import Counter
from typing import Any

from protectogotchi.capabilities.base import CapabilityModule, CapabilityResult


class VulnScout(CapabilityModule):
    name = "vuln-scout"
    domain = "vulnerability-management"
    status = "requires-integration"
    risk = "review"

    def summarize_report(self, findings: list[dict[str, Any]]) -> dict[str, Any]:
        severities = Counter(finding.get("severity", "unknown") for finding in findings)
        return {"finding_count": len(findings), "severities": dict(severities)}

    def assess(self, context: dict[str, Any]) -> CapabilityResult:
        findings = context.get("vulnerabilities", [])
        return CapabilityResult(
            module=self.name,
            status=self.status,
            summary=f"Authorized vulnerability report ingestion ready; {len(findings)} finding(s).",
            evidence=self.summarize_report(findings),
            recommendations=("Run scanners only on assets you own or are explicitly authorized to test.",),
            risk=self.risk,
        )
