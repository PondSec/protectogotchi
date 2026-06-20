from __future__ import annotations

from typing import Any

from protectogotchi.capabilities.base import CapabilityModule, CapabilityResult


class SandBoxX(CapabilityModule):
    name = "sandboxx"
    domain = "malware-analysis"
    status = "requires-integration"
    risk = "review"

    def normalize_verdict(self, verdict: dict[str, Any]) -> dict[str, Any]:
        return {
            "sample": verdict.get("sample", "unknown"),
            "malicious": bool(verdict.get("malicious", False)),
            "families": list(verdict.get("families", [])),
            "network_indicators": list(verdict.get("network_indicators", [])),
        }

    def assess(self, context: dict[str, Any]) -> CapabilityResult:
        verdicts = [self.normalize_verdict(item) for item in context.get("sandbox_verdicts", [])]
        return CapabilityResult(
            module=self.name,
            status=self.status,
            summary=f"Sandbox verdict ingestion ready; {len(verdicts)} verdict(s).",
            evidence={"verdicts": verdicts},
            risk=self.risk,
        )
