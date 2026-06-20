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
python -m pip install -e ".[dev]"
protectogotchi --help
protectogotchi face idle
```

## Safety model

Protectogotchi defaults to observe-only behavior. It can propose defensive
actions such as blocking a suspicious IP, but system-level changes require
active mode and administrator permissions.
