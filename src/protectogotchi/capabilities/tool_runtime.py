from __future__ import annotations

from typing import Any

from protectogotchi.capabilities.base import CapabilityModule, CapabilityResult
from protectogotchi.external_tools import ExternalToolRuntime


class ToolRuntimeCapability(CapabilityModule):
    name = "external-tool-runtime"
    domain = "tool-orchestration"
    risk = "review"

    def __init__(self, runtime: ExternalToolRuntime | None = None) -> None:
        self.runtime = runtime or ExternalToolRuntime()

    def assess(self, context: dict[str, Any]) -> CapabilityResult:
        report = self.runtime.report()
        return CapabilityResult(
            module=self.name,
            status="available",
            summary=(
                f"{report['available_count']} of {report['total_count']} supported external "
                "tools are available on PATH."
            ),
            evidence=report,
            recommendations=tuple(report["recommendations"]),
            risk=self.risk,
        )
