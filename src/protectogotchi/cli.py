from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

from protectogotchi import __version__
from protectogotchi.agent import ProtectogotchiAgent
from protectogotchi.config import ProtectogotchiConfig
from protectogotchi.face import FACES, render_face
from protectogotchi.response import ResponseExecutor, ResponsePlanner
from protectogotchi.state import StateStore


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="protectogotchi",
        description="Local-first defensive AI companion for Wi-Fi and home networks.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument(
        "--config",
        type=Path,
        help="Path to a JSON config file. Environment variables can override it.",
    )
    parser.add_argument(
        "--state-dir",
        type=Path,
        help="Override the local state directory for baseline and XP data.",
    )
    parser.add_argument(
        "--active",
        action="store_true",
        help="Enable active response for this run if the config also allows it.",
    )

    subparsers = parser.add_subparsers(dest="command")
    face_parser = subparsers.add_parser("face", help="Render a Protectogotchi face.")
    face_parser.add_argument("state", choices=sorted(FACES), help="Face state to render.")

    scan_parser = subparsers.add_parser("scan", help="Collect telemetry and run one analysis.")
    scan_parser.add_argument("--json", action="store_true", help="Print machine-readable JSON.")
    scan_parser.add_argument("--no-learn", action="store_true", help="Do not update baseline.")
    scan_parser.add_argument(
        "--execute-actions",
        action="store_true",
        help="Execute planned actions when active response is enabled.",
    )
    scan_parser.add_argument(
        "--collector",
        choices=["macos", "linux"],
        help="Force a collector instead of auto-detecting the platform.",
    )

    daemon_parser = subparsers.add_parser("daemon", help="Continuously scan and learn.")
    daemon_parser.add_argument("--json", action="store_true", help="Print JSON lines.")
    daemon_parser.add_argument("--no-learn", action="store_true", help="Do not update baseline.")
    daemon_parser.add_argument(
        "--interval",
        type=float,
        help="Seconds between scans. Defaults to config sample_interval.",
    )
    daemon_parser.add_argument(
        "--collector",
        choices=["macos", "linux"],
        help="Force a collector instead of auto-detecting the platform.",
    )

    subparsers.add_parser("status", help="Show local level, XP, and baseline status.")

    respond_parser = subparsers.add_parser("respond", help="Plan or execute a defensive response.")
    respond_parser.add_argument("--ip", required=True, help="IP address to block.")
    respond_parser.add_argument("--reason", default="manual response", help="Reason to record.")
    respond_parser.add_argument(
        "--execute",
        action="store_true",
        help="Execute when active response is enabled. Otherwise print dry-run.",
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    config = _config_from_args(args)

    if args.command == "face":
        print(render_face(args.state))
        return 0
    if args.command == "scan":
        agent = ProtectogotchiAgent(config, collector_name=args.collector)
        result = agent.scan(learn=not args.no_learn, execute_actions=args.execute_actions)
        if args.json:
            print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
        else:
            _print_scan(result)
        return 0
    if args.command == "daemon":
        agent = ProtectogotchiAgent(config, collector_name=args.collector)
        interval = args.interval if args.interval is not None else config.sample_interval
        try:
            while True:
                result = agent.scan(learn=not args.no_learn, execute_actions=False)
                if args.json:
                    print(json.dumps(result.to_dict(), sort_keys=True), flush=True)
                else:
                    _print_scan(result)
                time.sleep(interval)
        except KeyboardInterrupt:
            print("\nProtectogotchi daemon stopped.")
        return 0
    if args.command == "status":
        state = StateStore(config.state_dir).load()
        print(render_face("happy" if state.observations else "learning"))
        print(f"level={state.level} xp={state.xp} scans={state.scans}")
        print(f"baseline_observations={state.observations}")
        print(f"known_devices={len(state.devices)}")
        print(f"state_file={StateStore(config.state_dir).path}")
        return 0
    if args.command == "respond":
        action = ResponsePlanner(config)._block_command_preview(args.ip)
        from protectogotchi.models import ResponseAction

        response = ResponseAction(
            action_type="block_ip",
            target=args.ip,
            reason=args.reason,
            severity="high",
            dry_run=not config.active_response_enabled or not args.execute,
            command_preview=action,
        )
        if args.execute:
            response = ResponseExecutor(config).execute(response)
        print(json.dumps(response.__dict__, indent=2, sort_keys=True))
        return 0

    parser.print_help()
    return 0


def _config_from_args(args: argparse.Namespace) -> ProtectogotchiConfig:
    config = ProtectogotchiConfig.load(args.config)
    if args.state_dir:
        config.state_dir = args.state_dir
    if args.active:
        config.response_mode = "active"
        config.allow_active_blocking = True
    return config


def _print_scan(result) -> None:
    print(render_face(result.face_state))
    print(
        f"risk={result.risk_score} level={result.level} xp={result.xp} "
        f"learned={'yes' if result.learned else 'no'}"
    )
    print(
        "snapshot="
        f"devices:{len(result.snapshot.devices)} "
        f"connections:{len(result.snapshot.connections)} "
        f"gateway:{result.snapshot.default_gateway or 'unknown'} "
        f"ssid:{result.snapshot.wifi.ssid or 'unknown'}"
    )
    if not result.findings:
        print("findings=none")
    for finding in result.findings:
        print(
            f"[{finding.severity}] {finding.code}: {finding.title} "
            f"-> {finding.recommended_action}"
        )
        if finding.evidence:
            print(f"  evidence={json.dumps(finding.evidence, sort_keys=True)}")
    if result.actions:
        print("actions:")
        for action in result.actions:
            mode = "dry-run" if action.dry_run else "active"
            print(
                f"- {action.action_type} target={action.target or '-'} "
                f"mode={mode} status={action.status}"
            )
            for command in action.command_preview:
                print(f"  $ {command}")
