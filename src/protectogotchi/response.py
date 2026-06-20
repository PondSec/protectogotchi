from __future__ import annotations

import platform
import subprocess
from ipaddress import ip_address

from protectogotchi.config import ProtectogotchiConfig
from protectogotchi.models import Finding, NetworkSnapshot, ResponseAction


class ResponsePlanner:
    def __init__(self, config: ProtectogotchiConfig) -> None:
        self.config = config

    def plan(
        self,
        findings: list[Finding],
        snapshot: NetworkSnapshot,
    ) -> list[ResponseAction]:
        actions: list[ResponseAction] = []
        for finding in findings:
            if finding.severity in {"critical", "high"}:
                target = self._target_ip(finding)
                if target and target != snapshot.default_gateway:
                    actions.append(
                        ResponseAction(
                            action_type="block_ip",
                            target=target,
                            reason=finding.title,
                            severity=finding.severity,
                            dry_run=not self.config.active_response_enabled,
                            command_preview=self.block_command_preview(target),
                        )
                    )
                else:
                    actions.append(
                        ResponseAction(
                            action_type="alert_admin",
                            target=target,
                            reason=finding.title,
                            severity=finding.severity,
                            dry_run=True,
                            status="manual-review",
                        )
                    )
            elif finding.severity == "medium" and self.config.notify_on_medium:
                actions.append(
                    ResponseAction(
                        action_type="notify",
                        target=None,
                        reason=finding.title,
                        severity=finding.severity,
                        dry_run=not self.config.active_response_enabled,
                    )
                )
        return actions

    def _target_ip(self, finding: Finding) -> str | None:
        value = finding.evidence.get("ip") or finding.evidence.get("remote_address")
        if not value:
            return None
        try:
            ip_address(str(value))
        except ValueError:
            return None
        return str(value)

    def block_command_preview(self, ip: str) -> list[str]:
        system = platform.system()
        if system == "Darwin":
            return [
                "sudo pfctl -e",
                (
                    "sudo pfctl -a com.protectogotchi -f "
                    "<protectogotchi pf anchor rules>"
                ),
                f"sudo pfctl -a com.protectogotchi -t blocked_hosts -T add {ip}",
            ]
        if system == "Linux":
            return [
                "sudo nft add table inet protectogotchi",
                (
                    "sudo nft add chain inet protectogotchi guard "
                    "{ type filter hook forward priority 0; policy accept; }"
                ),
                (
                    "sudo nft add set inet protectogotchi blocked_ipv4 "
                    "{ type ipv4_addr; }"
                ),
                (
                    "sudo nft add rule inet protectogotchi guard "
                    "ip saddr @blocked_ipv4 drop"
                ),
                f"sudo nft add element inet protectogotchi blocked_ipv4 {{ {ip} }}",
            ]
        return [f"block {ip} using the platform firewall"]


class ResponseExecutor:
    def __init__(self, config: ProtectogotchiConfig) -> None:
        self.config = config

    def execute(self, action: ResponseAction) -> ResponseAction:
        if action.dry_run or not self.config.active_response_enabled:
            action.status = "dry-run"
            return action

        if action.action_type == "notify":
            return self._notify(action)
        if action.action_type == "block_ip":
            return self._block_ip(action)

        action.status = "unsupported"
        return action

    def _notify(self, action: ResponseAction) -> ResponseAction:
        if platform.system() != "Darwin":
            action.status = "unsupported"
            return action

        subprocess.run(
            [
                "osascript",
                "-e",
                (
                    'display notification "'
                    + action.reason.replace('"', "'")
                    + '" with title "Protectogotchi"'
                ),
            ],
            check=False,
            timeout=5,
        )
        action.status = "executed"
        return action

    def _block_ip(self, action: ResponseAction) -> ResponseAction:
        # The MVP intentionally does not mutate pf/nftables automatically until
        # installation setup can verify anchors/chains safely.
        action.status = "requires-firewall-setup"
        return action
