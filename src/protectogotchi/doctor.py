from __future__ import annotations

import platform
import shutil
from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class DoctorCheck:
    name: str
    ok: bool
    detail: str

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


CORE_COMMANDS: dict[str, list[str]] = {
    "Darwin": ["arp", "netstat", "route", "networksetup"],
    "Linux": ["ip", "ss", "iwgetid"],
}

RESPONSE_COMMANDS: dict[str, list[str]] = {
    "Darwin": ["pfctl", "osascript"],
    "Linux": ["nft"],
}


def run_doctor() -> list[DoctorCheck]:
    system = platform.system()
    checks: list[DoctorCheck] = [
        DoctorCheck(
            name="platform",
            ok=system in CORE_COMMANDS,
            detail=system or "unknown",
        )
    ]

    for command in CORE_COMMANDS.get(system, []):
        checks.append(_command_check(f"telemetry:{command}", command))
    for command in RESPONSE_COMMANDS.get(system, []):
        checks.append(_command_check(f"response:{command}", command))

    return checks


def _command_check(name: str, command: str) -> DoctorCheck:
    path = shutil.which(command)
    return DoctorCheck(
        name=name,
        ok=path is not None,
        detail=path or "not found on PATH",
    )
