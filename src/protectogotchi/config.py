from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Literal


ResponseMode = Literal["dry-run", "active"]
DeploymentMode = Literal[
    "observer",
    "local-host-firewall",
    "router-controller",
    "inline-gateway",
    "transparent-bridge",
    "managed-ap-or-switch",
    "endpoint-agent",
]


@dataclass
class ProtectogotchiConfig:
    state_dir: Path = Path.home() / ".protectogotchi"
    sample_interval: float = 10.0
    min_baseline_observations: int = 3
    zscore_threshold: float = 3.5
    high_zscore_threshold: float = 6.0
    autolearn_max_score: int = 34
    response_mode: ResponseMode = "dry-run"
    deployment_mode: DeploymentMode = "observer"
    allow_active_blocking: bool = False
    notify_on_medium: bool = True

    @classmethod
    def load(cls, path: Path | None = None) -> "ProtectogotchiConfig":
        config = cls()
        if path and path.exists():
            raw = json.loads(path.read_text(encoding="utf-8"))
            config = cls.from_dict(raw)

        state_dir = os.environ.get("PROTECTOGOTCHI_STATE_DIR")
        if state_dir:
            config.state_dir = Path(state_dir).expanduser()

        response_mode = os.environ.get("PROTECTOGOTCHI_RESPONSE_MODE")
        if response_mode in {"dry-run", "active"}:
            config.response_mode = response_mode  # type: ignore[assignment]

        deployment_mode = os.environ.get("PROTECTOGOTCHI_DEPLOYMENT_MODE")
        valid_modes = {
            "observer",
            "local-host-firewall",
            "router-controller",
            "inline-gateway",
            "transparent-bridge",
            "managed-ap-or-switch",
            "endpoint-agent",
        }
        if deployment_mode in valid_modes:
            config.deployment_mode = deployment_mode  # type: ignore[assignment]

        return config

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ProtectogotchiConfig":
        clean = dict(data)
        if "state_dir" in clean:
            clean["state_dir"] = Path(clean["state_dir"]).expanduser()
        return cls(**clean)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["state_dir"] = str(self.state_dir)
        return data

    @property
    def active_response_enabled(self) -> bool:
        return self.response_mode == "active" and self.allow_active_blocking
