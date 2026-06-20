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

# Continuous local daemon mode.
protectogotchi daemon --interval 10

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
