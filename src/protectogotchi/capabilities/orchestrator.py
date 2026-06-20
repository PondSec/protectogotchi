from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from protectogotchi.capabilities.autodns import AutoDNS
from protectogotchi.capabilities.autoops import AutoOps
from protectogotchi.capabilities.base import CapabilityModule, CapabilityResult
from protectogotchi.capabilities.compliance import CompliCheck
from protectogotchi.capabilities.flowcollector import FlowCollector
from protectogotchi.capabilities.holoview import Holoview
from protectogotchi.capabilities.ids_orchestrator import IDSOrchestrator
from protectogotchi.capabilities.intel_feed import IntelFeed
from protectogotchi.capabilities.ip_planner import IPPlanner
from protectogotchi.capabilities.ir_engine import IREngine
from protectogotchi.capabilities.logpipe import LogPipe
from protectogotchi.capabilities.netconfig import NetConfigEngine
from protectogotchi.capabilities.netml import NetML
from protectogotchi.capabilities.pcapbot import PcapBot
from protectogotchi.capabilities.policyguru import PolicyGuru
from protectogotchi.capabilities.redteam_bot import RedTeamBot
from protectogotchi.capabilities.routelab import RouteLab
from protectogotchi.capabilities.sandboxx import SandBoxX
from protectogotchi.capabilities.tool_runtime import ToolRuntimeCapability
from protectogotchi.capabilities.vuln_scout import VulnScout
from protectogotchi.capabilities.zt_broker import ZTBroker


@dataclass(frozen=True)
class ArsenalReport:
    modules: tuple[dict[str, Any], ...]
    results: tuple[dict[str, Any], ...]
    summary: dict[str, int]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class ProtectogotchiArsenalOrchestrator:
    """Coordinates defensive capability modules without executing attack tooling."""

    def __init__(self, modules: list[CapabilityModule] | None = None) -> None:
        self.modules = modules or [
            IPPlanner(),
            NetConfigEngine(),
            RouteLab(),
            AutoDNS(),
            FlowCollector(),
            PcapBot(),
            PolicyGuru(),
            IDSOrchestrator(),
            ZTBroker(),
            IntelFeed(),
            VulnScout(),
            RedTeamBot(),
            SandBoxX(),
            LogPipe(),
            IREngine(),
            CompliCheck(),
            AutoOps(),
            NetML(),
            ToolRuntimeCapability(),
            Holoview(),
        ]

    def describe(self) -> list[dict[str, Any]]:
        return [module.describe() for module in self.modules]

    def assess(self, context: dict[str, Any] | None = None) -> ArsenalReport:
        context = context or {}
        results: list[CapabilityResult] = [module.assess(context) for module in self.modules]
        summary: dict[str, int] = {}
        for result in results:
            summary[result.status] = summary.get(result.status, 0) + 1
        return ArsenalReport(
            modules=tuple(self.describe()),
            results=tuple(result.to_dict() for result in results),
            summary=summary,
        )
