# Protectogotchi

Protectogotchi is a local-first defensive AI companion for Wi-Fi and home
networks. It is inspired by the playful "pet with a face" idea, but its job is
the opposite of an offensive Wi-Fi toy: observe, learn normal behavior, detect
anomalies, and respond defensively.

The project starts on macOS and is designed to grow toward a Raspberry Pi 5
image later.

## Current status

This repository is in active MVP development. The first usable target is a
local macOS agent that can:

- collect local network telemetry without cloud services,
- learn a baseline for the current network,
- score suspicious changes and anomalies,
- show a matching Protectogotchi face and status,
- keep XP/level progress locally,
- plan defensive responses in dry-run mode by default.

Active firewall enforcement is intentionally guarded behind explicit opt-in
configuration. Protectogotchi should protect the network, not surprise its
owner.

## Quick start

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install ".[dev]"
protectogotchi --help
protectogotchi scan
protectogotchi status
```

For live source-tree development you can also run commands with
`PYTHONPATH=src python -m protectogotchi ...`.

Useful commands:

```bash
# One local scan, update the baseline when the risk is low enough.
protectogotchi scan

# Machine-readable output for logs or a future dashboard.
protectogotchi scan --json

# Export raw telemetry without learning.
protectogotchi snapshot

# Build a passive topology from interfaces, routes, gateways, subnets, and devices.
protectogotchi topology
protectogotchi topology --json
protectogotchi map

# Run realtime local web status/API. Binds to localhost by default.
protectogotchi web --host 127.0.0.1 --port 8765 --scan-interval 3

# Continuous local daemon mode.
protectogotchi daemon --interval 10

# List the defensive arsenal, rules, and local network knowledge.
protectogotchi tools
protectogotchi rules
protectogotchi knowledge
protectogotchi knowledge arp-spoofing
protectogotchi enforcement
protectogotchi enforcement inline-gateway
protectogotchi simulate arp-spoof

# Trust or untrust devices explicitly.
protectogotchi trust-device --mac 00:11:22:33:44:55 --label laptop
protectogotchi untrust-device --mac 00:11:22:33:44:55

# Plan a defensive block without changing the system firewall.
protectogotchi respond --ip 192.168.1.50 --reason "manual test"
```

## Safety model

Protectogotchi defaults to observe-only behavior. It can propose defensive
actions such as blocking a suspicious IP, but system-level changes require
active mode and administrator permissions.

The MVP intentionally avoids cloud inference and avoids offensive Wi-Fi
behavior. Active enforcement is a controlled response layer, not an attack
toolkit.

## Authorized use

Protectogotchi is intended for networks you own or are explicitly authorized to
defend, including university lab networks where you have written permission.
The project does not implement covert ARP-spoofing or MitM takeover as a
protection mechanism. For network-wide prevention, use an owner-controlled
enforcement point: router/controller integration, managed AP/switch quarantine,
endpoint firewall agents, or a Raspberry Pi running as an explicit gateway/AP or
transparent bridge.

Use active enforcement only in your own network or in an explicitly authorized
lab. You are responsible for the effects of blocking, quarantine, routing, or
firewall actions. A client-only Protectogotchi can detect and protect its own
host, but it cannot reliably stop traffic between other devices unless it is
deployed as, or connected to, a real enforcement point.

God Mode is at your own risk and only for your own or explicitly authorized
networks. It lets Protectogotchi act autonomously through supported defensive
enforcement mechanisms after an explicit activation warning. As a client-only
observer, God Mode still cannot provide network-wide prevention; for that, run
Protectogotchi as a gateway/AP/transparent bridge or connect it to a
router/firewall/AP/switch controller or endpoint agent.

Important: Protectogotchi cannot reliably prevent all network traffic unless it
controls an enforcement point such as the router/firewall/AP, a managed switch,
an endpoint firewall, or an inline Pi gateway/bridge. It does not use covert
ARP-spoofing MitM as a protection strategy.

## Roadmap

- macOS MVP: local telemetry, baseline learning, anomaly scoring, XP/levels,
  status faces, dry-run responses.
- Hardened response layer: verified macOS pf setup and Raspberry Pi nftables
  setup with explicit owner opt-in.
- Local dashboard: face, mood, risk timeline, known devices, and response log.
- Raspberry Pi 5 image: service unit, first-run setup, Wi-Fi interface
  selection, and local-only configuration UI.
- Stronger local AI: richer feature extraction, per-network profiles,
  explainable scoring, and signed community rules.
