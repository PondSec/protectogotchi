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

## Easiest start after cloning

If you just want the local web app, you do not need to create a virtual
environment or install the package first:

```bash
python3 start.py
```

Then open:

```text
http://127.0.0.1:8765
```

`start.py` adds the local `src` folder to Python automatically and starts the
web UI with safe localhost defaults. You can still pass normal CLI arguments,
for example `python3 start.py scan` or `python3 start.py web --port 9000`.

## Quick start without venv

```bash
python3 start.py
python3 start.py scan
python3 start.py status
```

Protectogotchi is intentionally runnable straight from the source tree. Use
`python3 start.py ...` for all local commands; it adds `src` automatically and
does not require package installation or virtualenv activation.

To start the local web UI directly from the source tree:

```bash
python3 start.py
```

Useful commands:

```bash
# One local scan, update the baseline when the risk is low enough.
python3 start.py scan

# Machine-readable output for logs or a future dashboard.
python3 start.py scan --json

# Export raw telemetry without learning.
python3 start.py snapshot

# Build a passive topology from interfaces, routes, gateways, subnets, and devices.
python3 start.py topology
python3 start.py topology --json
python3 start.py map

# Run realtime local web status/API. Binds to localhost by default.
python3 start.py web --host 127.0.0.1 --port 8765 --scan-interval 3

# Continuous local daemon mode.
python3 start.py daemon --interval 10

# List the defensive arsenal, rules, and local network knowledge.
python3 start.py tools
python3 start.py arsenal
python3 start.py toolbox
python3 start.py toolbox --target 192.168.1.1
python3 start.py toolbox --pcap capture.pcap
python3 start.py ai
python3 start.py rules
python3 start.py knowledge
python3 start.py knowledge arp-spoofing
python3 start.py enforcement
python3 start.py enforcement inline-gateway
python3 start.py easy-protect
python3 start.py setup-wizard
python3 start.py simulate arp-spoof
python3 start.py simulate vlan-lateral-movement

# Trust or untrust devices explicitly.
python3 start.py trust-device --mac 00:11:22:33:44:55 --label laptop
python3 start.py untrust-device --mac 00:11:22:33:44:55

# Plan a defensive block without changing the system firewall.
python3 start.py respond --ip 192.168.1.50 --reason "manual test"
```

## Local AI engine

Protectogotchi now has a real neural backend interface:

- `NetML`: PyTorch deep autoencoder for local network-metric anomaly detection.
- `DQN policy`: PyTorch safety-gated Deep-Q style policy for defensive action
  prioritization.
- `python3 start.py ai`: shows whether the PyTorch backend is installed, model
  observations, hidden/latent units, and policy update state.

Install the ML runtime when you want the neural network to execute locally:

```bash
python3.12 -m pip install --user --break-system-packages torch
python3.12 start.py ai
```

Homebrew Python blocks global package writes by default. `--user` keeps the
package in the user site-packages; `--break-system-packages` is the explicit
override required by Homebrew's externally-managed Python. Start Protectogotchi
with the same Python version you used to install Torch. Without Torch,
Protectogotchi still runs detection, baselines, topology mapping, UI, and the
capability orchestrator, but it reports the neural backend as unavailable
instead of pretending a framework model is active.

## Modular arsenal

The defensive arsenal is split into many Python modules under
`src/protectogotchi/capabilities/` and coordinated through
`ProtectogotchiArsenalOrchestrator`. Run:

```bash
protectogotchi arsenal
protectogotchi arsenal --json
```

Current modules cover IP planning, VLAN/config rendering, route analysis,
DNS/DHCP planning, flow metadata, authorized pcap analysis, firewall policy
rendering, IDS ingestion, zero-trust decisions, threat intel normalization,
vulnerability-report ingestion, authorized assessment-report ingestion, malware
sandbox verdict import, SIEM normalization, IR playbooks, compliance mapping,
automation routing, NetML, and the local dashboard manifest.

`protectogotchi toolbox` discovers existing defensive tools such as `nmap`,
`tcpdump`, `tshark`, `zeek`, `suricata`, `snort`, `snmpwalk`, `dig`,
`traceroute`, `mtr`, `pfctl`, and `nft`. Generated target plans are limited to
private or local addresses, and review-risk actions such as Nmap service
inventory or pcap parsing require an explicit `--execute --yes`.

## Safety model

Protectogotchi defaults to observe-only behavior. It can propose defensive
actions such as blocking a suspicious IP, but system-level changes require
active mode and administrator permissions.

The MVP intentionally avoids cloud inference and avoids offensive Wi-Fi
behavior. Active enforcement is a controlled response layer, not an attack
toolkit.

## Attack Simulation and Setup Wizard

Protectogotchi includes a safe local lab simulator:

```bash
protectogotchi simulate arp-spoof
protectogotchi simulate vlan-lateral-movement
```

These scenarios use synthetic snapshots only. They do not inject packets, do
not redirect live traffic, and do not touch other devices. The goal is to show
what an attack would look like from Protectogotchi's point of view, which
findings fire, and what the user should learn from the event.

The setup wizard is intentionally honest about placement:

```bash
protectogotchi setup-wizard
```

It does not automate firewall/router control, does not enable ARP spoofing, and
does not claim that a normal client can block traffic between other devices. If
Protectogotchi is only a client, it can detect, learn, alert, simulate, and
protect its own host when local controls are configured. For true network-wide
prevention without controlling an existing firewall/router, Protectogotchi must
be deployed as an inline gateway/bridge, access-layer component, or endpoint
agent.

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

For end users, the intended easy paths are:

- `dns-guard`: low-friction DNS blocking when the router can advertise
  Protectogotchi as DNS through DHCP.
- `router-controller`: use a supported router/AP/firewall API to block or
  quarantine clients.
- `transparent-bridge`: place a Pi inline as a real bridge for full traffic
  visibility without ARP spoofing.
- `inline-gateway`: make Protectogotchi the router/AP for full routed
  enforcement.

Important: Protectogotchi cannot reliably prevent all network traffic unless it
controls an enforcement point such as the router/firewall/AP, a managed switch,
an endpoint firewall, or an inline Pi gateway/bridge. It does not use covert
ARP-spoofing MitM as a protection strategy.

If you do not want Protectogotchi to control a firewall/router/API, keep it in
observer plus simulation mode or deploy it physically/explicitly in path later.
There is no client-only mechanism that can safely and reliably stop other
devices' traffic without such a control point.

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
