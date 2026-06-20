from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

from protectogotchi import __version__
from protectogotchi.agent import ProtectogotchiAgent
from protectogotchi.arsenal import assess_arsenal
from protectogotchi.collectors import get_collector
from protectogotchi.config import ProtectogotchiConfig
from protectogotchi.detection import list_detection_rules
from protectogotchi.doctor import run_doctor
from protectogotchi.enforcement import (
    easy_protect_plan,
    get_enforcement_mode,
    list_enforcement_modes,
)
from protectogotchi.external_tools import ExternalToolRuntime
from protectogotchi.face import FACES, render_face
from protectogotchi.knowledge import get_topic, list_topics
from protectogotchi.netutil import normalize_mac
from protectogotchi.network_map import NetworkMapper
from protectogotchi.neural import neural_model_summary
from protectogotchi.placement import build_placement_report
from protectogotchi.policy import policy_model_summary
from protectogotchi.response import ResponseExecutor, ResponsePlanner
from protectogotchi.simulation import SCENARIOS, run_simulation
from protectogotchi.state import StateStore
from protectogotchi.tools import list_tools
from protectogotchi.topology import TopologyBuilder
from protectogotchi.web import run_web


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
    subparsers.add_parser("ai", help="Show local neural network and DQN policy status.")

    respond_parser = subparsers.add_parser("respond", help="Plan or execute a defensive response.")
    respond_parser.add_argument("--ip", required=True, help="IP address to block.")
    respond_parser.add_argument("--reason", default="manual response", help="Reason to record.")
    respond_parser.add_argument(
        "--execute",
        action="store_true",
        help="Execute when active response is enabled. Otherwise print dry-run.",
    )

    tools_parser = subparsers.add_parser("tools", help="List defensive tools.")
    tools_parser.add_argument(
        "--available-only",
        action="store_true",
        help="Hide planned tools and show only commands available in this MVP.",
    )

    arsenal_parser = subparsers.add_parser(
        "arsenal",
        help="Assess the modular defensive capability framework.",
    )
    arsenal_parser.add_argument("--json", action="store_true", help="Print JSON.")

    toolbox_parser = subparsers.add_parser(
        "toolbox",
        help="Discover and use installed defensive network tools.",
    )
    toolbox_parser.add_argument("--json", action="store_true", help="Print JSON.")
    toolbox_parser.add_argument("--target", help="Private/local IP or CIDR to plan diagnostics for.")
    toolbox_parser.add_argument("--pcap", type=Path, help="Authorized pcap file to plan analysis for.")
    toolbox_parser.add_argument(
        "--execute",
        action="store_true",
        help="Execute generated commands. Review-risk actions also require --yes.",
    )
    toolbox_parser.add_argument("--yes", action="store_true", help="Confirm review-risk tool execution.")

    subparsers.add_parser("doctor", help="Check local platform tool availability.")

    baseline_parser = subparsers.add_parser("baseline", help="Inspect or reset baseline.")
    baseline_subparsers = baseline_parser.add_subparsers(dest="baseline_command")
    baseline_subparsers.add_parser("show", help="Show learned baseline details.")
    reset_parser = baseline_subparsers.add_parser("reset", help="Reset local state.")
    reset_parser.add_argument("--yes", action="store_true", help="Confirm state deletion.")

    devices_parser = subparsers.add_parser("devices", help="List known baseline devices.")
    devices_parser.add_argument("--json", action="store_true", help="Print JSON.")

    snapshot_parser = subparsers.add_parser("snapshot", help="Export raw telemetry JSON.")
    snapshot_parser.add_argument(
        "--collector",
        choices=["macos", "linux"],
        help="Force a collector instead of auto-detecting the platform.",
    )

    topology_parser = subparsers.add_parser("topology", help="Build a passive network topology.")
    topology_parser.add_argument("--json", action="store_true", help="Print full topology JSON.")
    topology_parser.add_argument(
        "--collector",
        choices=["macos", "linux"],
        help="Force a collector instead of auto-detecting the platform.",
    )

    map_parser = subparsers.add_parser("map", help="Show categorized network map.")
    map_parser.add_argument("--json", action="store_true", help="Print JSON.")
    map_parser.add_argument(
        "--collector",
        choices=["macos", "linux"],
        help="Force a collector instead of auto-detecting the platform.",
    )

    web_parser = subparsers.add_parser("web", help="Run the local web UI/API.")
    web_parser.add_argument("--host", default="127.0.0.1", help="Bind host.")
    web_parser.add_argument("--port", type=int, default=8765, help="Bind port.")
    web_parser.add_argument(
        "--scan-interval",
        type=float,
        help="Seconds between live background scans. Defaults to a realtime-safe value.",
    )
    web_parser.add_argument(
        "--collector",
        choices=["macos", "linux"],
        help="Force a collector instead of auto-detecting the platform.",
    )

    subparsers.add_parser("rules", help="List local detection rules.")

    knowledge_parser = subparsers.add_parser("knowledge", help="Browse local network knowledge.")
    knowledge_parser.add_argument("topic", nargs="?", help="Optional topic name.")
    knowledge_parser.add_argument(
        "--mvp-only",
        action="store_true",
        help="Hide planned knowledge modules.",
    )

    enforcement_parser = subparsers.add_parser(
        "enforcement",
        help="Explain active protection/enforcement modes.",
    )
    enforcement_parser.add_argument("mode", nargs="?", help="Optional enforcement mode.")

    easy_parser = subparsers.add_parser(
        "easy-protect",
        help="Show the easiest safe paths from detection to active protection.",
    )
    easy_parser.add_argument("--json", action="store_true", help="Print JSON.")

    setup_parser = subparsers.add_parser(
        "setup-wizard",
        help="Check what this placement can safely detect or prevent without ARP/MitM.",
    )
    setup_parser.add_argument("--json", action="store_true", help="Print JSON.")
    setup_parser.add_argument(
        "--collector",
        choices=["macos", "linux"],
        help="Force a collector instead of auto-detecting the platform.",
    )

    simulate_parser = subparsers.add_parser(
        "simulate",
        help="Run a safe synthetic lab scenario without touching network traffic.",
    )
    simulate_parser.add_argument("scenario", choices=SCENARIOS)
    simulate_parser.add_argument("--json", action="store_true", help="Print JSON.")

    trust_parser = subparsers.add_parser("trust-device", help="Trust a device MAC.")
    trust_parser.add_argument("--mac", required=True, help="MAC address to trust.")
    trust_parser.add_argument("--label", help="Human label for the device.")

    untrust_parser = subparsers.add_parser("untrust-device", help="Remove device trust.")
    untrust_parser.add_argument("--mac", required=True, help="MAC address to untrust.")

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
        learning_remaining = max(0, config.min_baseline_observations - state.observations)
        print(render_face("happy" if learning_remaining == 0 else "learning"))
        print(f"level={state.level} xp={state.xp} scans={state.scans}")
        print(f"baseline_observations={state.observations}")
        print(f"baseline_ready={'yes' if learning_remaining == 0 else 'no'}")
        print(f"learning_remaining={learning_remaining}")
        print(f"known_devices={len(state.devices)}")
        print(f"state_file={StateStore(config.state_dir).path}")
        return 0
    if args.command == "ai":
        state = StateStore(config.state_dir).load()
        print(json.dumps(
            {
                "neural": neural_model_summary(state.neural_model),
                "policy": policy_model_summary(state.policy_model),
            },
            indent=2,
            sort_keys=True,
        ))
        return 0
    if args.command == "respond":
        action = ResponsePlanner(config).block_command_preview(args.ip)
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
    if args.command == "tools":
        _print_tools(include_planned=not args.available_only)
        return 0
    if args.command == "arsenal":
        report = assess_arsenal(config)
        if args.json:
            print(json.dumps(report, indent=2, sort_keys=True))
        else:
            _print_arsenal(report)
        return 0
    if args.command == "toolbox":
        return _handle_toolbox(args)
    if args.command == "doctor":
        checks = run_doctor()
        for check in checks:
            status = "ok" if check.ok else "missing"
            print(f"{status:7} {check.name} {check.detail}")
        return 0 if all(check.ok for check in checks if not check.name.startswith("response:")) else 1
    if args.command == "baseline":
        return _handle_baseline(args, config)
    if args.command == "devices":
        state = StateStore(config.state_dir).load()
        devices = list(state.devices.values())
        if args.json:
            print(json.dumps(devices, indent=2, sort_keys=True))
        else:
            _print_devices(devices)
        return 0
    if args.command == "snapshot":
        snapshot = get_collector(args.collector).collect()
        print(json.dumps(snapshot.to_dict(), indent=2, sort_keys=True))
        return 0
    if args.command == "topology":
        snapshot = get_collector(args.collector).collect()
        topology = TopologyBuilder().build(snapshot)
        if args.json:
            print(json.dumps(topology.to_dict(), indent=2, sort_keys=True))
        else:
            _print_topology(topology)
        return 0
    if args.command == "map":
        snapshot = get_collector(args.collector).collect()
        network_map = NetworkMapper().build(snapshot)
        if args.json:
            print(json.dumps(network_map.to_dict(), indent=2, sort_keys=True))
        else:
            _print_network_map(network_map)
        return 0
    if args.command == "web":
        run_web(
            config,
            host=args.host,
            port=args.port,
            collector_name=args.collector,
            scan_interval=args.scan_interval,
        )
        return 0
    if args.command == "rules":
        for rule in list_detection_rules():
            print(f"- {rule.code} [{rule.severity}] {rule.summary}")
        return 0
    if args.command == "knowledge":
        return _handle_knowledge(args)
    if args.command == "enforcement":
        return _handle_enforcement(args)
    if args.command == "easy-protect":
        plan = easy_protect_plan(config)
        if args.json:
            print(json.dumps(plan, indent=2, sort_keys=True))
        else:
            _print_easy_protect(plan)
        return 0
    if args.command == "setup-wizard":
        snapshot = get_collector(args.collector).collect()
        report = build_placement_report(config, NetworkMapper().build(snapshot))
        if args.json:
            print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
        else:
            _print_placement_report(report)
        return 0
    if args.command == "simulate":
        result = run_simulation(args.scenario, config)
        if args.json:
            print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
        else:
            print(f"scenario={result.scenario}")
            print(f"isolated={'yes' if result.isolated else 'no'}")
            print(f"environment={result.environment}")
            print(f"risk={result.risk_score} face={result.face_state}")
            print("timeline:")
            for event in result.timeline:
                print(f"- {event.phase}: {event.detail}")
                print(f"  view={event.protectogotchi_view}")
            print("simulated_packets:")
            for packet in result.packets:
                print(
                    f"- {packet.protocol} {packet.source} -> {packet.destination} "
                    f"{packet.verdict}: {packet.summary}"
                )
            for finding in result.findings:
                print(f"[{finding['severity']}] {finding['code']}: {finding['title']}")
            for action in result.actions:
                print(f"action={action['action_type']} target={action['target']} status={action['status']}")
            print("lessons:")
            for lesson in result.lessons:
                print(f"- {lesson}")
        return 0
    if args.command == "trust-device":
        store = StateStore(config.state_dir)
        state = store.load()
        mac = state.trust_device(args.mac, args.label)
        store.save(state)
        print(f"trusted {mac} label={state.trusted_devices[mac]['label']}")
        return 0
    if args.command == "untrust-device":
        store = StateStore(config.state_dir)
        state = store.load()
        mac = normalize_mac(args.mac)
        removed = state.untrust_device(mac)
        store.save(state)
        print(f"untrusted {mac}" if removed else f"{mac} was not trusted")
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


def _print_tools(include_planned: bool) -> None:
    current_category = None
    for tool in sorted(list_tools(include_planned), key=lambda item: (item.category, item.name)):
        if tool.category != current_category:
            current_category = tool.category
            print(f"\n[{current_category}]")
        platforms = ",".join(tool.platforms)
        print(
            f"- {tool.name} ({tool.status}, {tool.risk}, {platforms})\n"
            f"  {tool.summary}\n"
            f"  $ {tool.command}"
        )


def _print_arsenal(report: dict) -> None:
    print("Protectogotchi modular arsenal")
    for status, count in sorted(report.get("summary", {}).items()):
        print(f"{status}={count}")
    for result in report.get("results", []):
        print(f"- {result['module']} [{result['status']}] {result['summary']}")


def _handle_toolbox(args: argparse.Namespace) -> int:
    runtime = ExternalToolRuntime()
    payload: dict
    try:
        if args.target:
            actions = runtime.plan_for_target(args.target)
            payload = {
                "target": args.target,
                "actions": [action.to_dict() for action in actions],
            }
            if args.execute:
                results = runtime.run_plan(actions, allow_review=args.yes)
                payload["results"] = [result.to_dict() for result in results]
                payload["decision"] = runtime.decide([result.parsed for result in results])
        elif args.pcap:
            actions = runtime.plan_for_pcap(args.pcap)
            payload = {
                "pcap": str(args.pcap),
                "actions": [action.to_dict() for action in actions],
            }
            if args.execute:
                results = runtime.run_plan(actions, allow_review=args.yes)
                payload["results"] = [result.to_dict() for result in results]
                payload["decision"] = runtime.decide([result.parsed for result in results])
        else:
            payload = runtime.report()
    except ValueError as exc:
        print(str(exc))
        return 2

    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        _print_toolbox(payload)
    return 0


def _print_toolbox(payload: dict) -> None:
    if "tools" in payload:
        print("External defensive tools")
        print(f"available={payload['available_count']} total={payload['total_count']}")
        for tool in payload["tools"]:
            status = "available" if tool["available"] else "missing"
            print(f"- {tool['name']} [{status}] {tool['purpose']}")
        for recommendation in payload.get("recommendations", []):
            print(f"recommendation={recommendation}")
        return
    for action in payload.get("actions", []):
        review = "review" if action["requires_review"] else "safe"
        print(f"- {action['tool']} ({review}) {' '.join(action['command'])}")
    for result in payload.get("results", []):
        print(f"result={result['action']['tool']} status={result['status']}")
    if "decision" in payload:
        print("decision=" + json.dumps(payload["decision"], sort_keys=True))


def _handle_baseline(args: argparse.Namespace, config: ProtectogotchiConfig) -> int:
    store = StateStore(config.state_dir)
    if args.baseline_command == "show":
        state = store.load()
        print(f"state_file={store.path}")
        print(f"observations={state.observations} scans={state.scans}")
        print(f"level={state.level} xp={state.xp}")
        print(f"known_devices={len(state.devices)}")
        print(f"trusted_devices={len(state.trusted_devices)}")
        print(f"known_routes={len(state.known_route_keys)}")
        print(f"known_subnets={len(state.known_subnets)}")
        print(f"known_interfaces={len(state.known_interfaces)}")
        print(f"neural_observations={neural_model_summary(state.neural_model)['observations']}")
        print(f"policy_updates={policy_model_summary(state.policy_model)['updates']}")
        print(f"gateway_macs={json.dumps(state.gateway_macs, sort_keys=True)}")
        print("feature_stats:")
        for name, stats in sorted(state.feature_stats.items()):
            print(
                f"- {name}: count={stats.count} "
                f"mean={stats.mean:.2f} stddev={stats.stddev:.2f}"
            )
        return 0

    if args.baseline_command == "reset":
        if not args.yes:
            print("Refusing to reset baseline without --yes.")
            return 2
        if store.path.exists():
            store.path.unlink()
            print(f"removed {store.path}")
        else:
            print(f"no state file at {store.path}")
        return 0

    print("Choose a baseline subcommand: show or reset.")
    return 2


def _print_devices(devices: list[dict]) -> None:
    if not devices:
        print("No devices learned yet.")
        return
    for device in sorted(devices, key=lambda item: item.get("mac", "")):
        ips = ",".join(device.get("ips", []))
        print(
            f"{device.get('mac')} ips={ips or '-'} "
            f"seen={device.get('seen_count', 0)} "
            f"last={device.get('last_seen', '-')}"
        )


def _handle_knowledge(args: argparse.Namespace) -> int:
    if args.topic:
        topic = get_topic(args.topic)
        if topic is None:
            print(f"Unknown topic: {args.topic}")
            return 2
        _print_topic(topic)
        return 0

    for topic in list_topics(include_planned=not args.mvp_only):
        print(f"- {topic.name} ({topic.domain}, {topic.maturity}) {topic.summary}")
    return 0


def _print_topic(topic) -> None:
    print(f"{topic.name} ({topic.domain}, {topic.maturity})")
    print(topic.summary)
    print("signals:")
    for signal in topic.signals:
        print(f"- {signal}")
    print("defensive_tools:")
    for tool in topic.defensive_tools:
        print(f"- {tool}")
    print("response_playbook:")
    for step in topic.response_playbook:
        print(f"- {step}")


def _handle_enforcement(args: argparse.Namespace) -> int:
    if args.mode:
        mode = get_enforcement_mode(args.mode)
        if mode is None:
            print(f"Unknown enforcement mode: {args.mode}")
            return 2
        _print_enforcement_mode(mode)
        return 0

    for mode in list_enforcement_modes():
        prevent = "prevents" if mode.can_prevent else "detects-only"
        print(f"- {mode.name} ({mode.scope}, {prevent}, {mode.current_status})")
        print(f"  {mode.summary}")
    return 0


def _print_enforcement_mode(mode) -> None:
    prevent = "yes" if mode.can_prevent else "no"
    print(f"{mode.name} ({mode.scope})")
    print(f"can_prevent={prevent}")
    print(f"status={mode.current_status}")
    print(mode.summary)
    print("requirements:")
    for requirement in mode.requirements:
        print(f"- {requirement}")


def _print_easy_protect(plan: list[dict]) -> None:
    print("Easy protection paths:")
    for item in plan:
        if "current_readiness" in item:
            readiness = item["current_readiness"]
            print("current:")
            for key, value in readiness.items():
                print(f"- {key}: {value}")
            continue
        prevents = "prevents" if item.get("prevents") else "detects"
        print(f"- {item['mode']} ({item['effort']}, {prevents})")
        print(f"  {item['summary']}")


def _print_placement_report(report) -> None:
    print("Protectogotchi setup wizard")
    print("mode=" + report.deployment_mode)
    print(f"active_response={'yes' if report.active_response_enabled else 'no'}")
    print("firewall_controller_automation=no")
    print(report.summary)
    if report.routed_subnets:
        print("routed_subnets=" + ", ".join(report.routed_subnets))
    if report.observed_remote_subnets:
        print("observed_remote_subnets=" + ", ".join(report.observed_remote_subnets))
    print(f"same_subnet_devices={report.same_subnet_devices}")
    print("can_detect:")
    for capability in report.can_detect:
        print(f"- {capability.name} [{capability.status}] {capability.detail}")
    print("can_prevent:")
    if not report.can_prevent:
        print("- none from this placement")
    for capability in report.can_prevent:
        print(f"- {capability.name} [{capability.status}] {capability.detail}")
    print("cannot_prevent:")
    for capability in report.cannot_prevent:
        print(f"- {capability.name} [{capability.status}] {capability.detail}")
    print("next_steps:")
    for step in report.next_steps:
        print(f"- {step}")


def _print_topology(topology) -> None:
    print("summary:")
    for kind, count in sorted(topology.summary.items()):
        print(f"- {kind}: {count}")
    print("nodes:")
    for node in topology.nodes:
        print(f"- {node.id} [{node.kind}] {node.label}")
    print("edges:")
    for edge in topology.edges:
        print(f"- {edge.source} --{edge.relation}--> {edge.target}")


def _print_network_map(network_map) -> None:
    print("summary:")
    for key, value in sorted(network_map.summary.items()):
        print(f"- {key}: {value}")
    print("coverage:")
    for item in network_map.coverage:
        print(f"- {item}")
    print("interfaces:")
    for interface in network_map.interfaces:
        print(f"- {interface.name} [{interface.role}] ipv4={','.join(interface.ipv4) or '-'}")
    print("routes:")
    important_routes = [
        route
        for route in network_map.routes
        if route.role in {"default", "routed-network", "connected-network"}
    ]
    for route in important_routes:
        print(
            f"- {route.destination} [{route.role}] "
            f"via={route.gateway or '-'} dev={route.interface or '-'}"
        )
    if not important_routes:
        print("- none")
