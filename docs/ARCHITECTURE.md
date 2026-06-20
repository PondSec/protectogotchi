# Protectogotchi Architecture

Protectogotchi is designed as a local defensive AI. It can always observe,
learn, score anomalies, and explain findings. It can only actively prevent
network-wide attacks when it controls a real enforcement point.

## Enforcement truth

If Protectogotchi is just another client on the Wi-Fi, it cannot reliably stop
traffic between other devices. In that mode it can:

- detect anomalies from local telemetry,
- warn the owner,
- protect the host it runs on,
- ask an external controller to enforce a block when integration exists.

It should not secretly ARP-spoof or force a MitM position. That behavior is
fragile and resembles the attack class it is supposed to detect.

Active enforcement is therefore an owner-responsibility feature. Use it only in
your own network or an explicitly authorized lab. Once an active mode is armed,
Protectogotchi may block, quarantine, or route traffic through supported
enforcement mechanisms according to its local policy.

## Supported direction

The safe path is explicit owner-controlled enforcement:

- Observer mode: detect, learn, alert, and plan responses.
- Local host firewall: block suspicious peers for the Protectogotchi host.
- Router/controller mode: call router, AP, firewall, or switch APIs.
- Inline gateway mode: Raspberry Pi 5 becomes the default gateway.
- Transparent bridge mode: Raspberry Pi 5 is physically inline as a bridge.
- Managed AP/switch mode: quarantine clients through VLAN or access control.
- Endpoint agent mode: protect individual devices with local firewall policy.

The current MVP implements observer mode, local telemetry, anomaly scoring,
topology mapping, dry-run response planning, and a local web UI/API. Network-wide
prevention is planned for the Pi/router/controller phases.

## God Mode

God Mode is an explicitly armed autonomous defensive mode. After activation,
Protectogotchi may decide and execute supported defensive response actions
without per-action prompts. It still uses owner-controlled enforcement points
only. It does not perform covert ARP spoofing or MitM takeover.

God Mode is intentionally honest about placement:

- Observer/client-only: detection, alerting, baseline learning, response
  planning, and host-local protection only.
- Local host firewall or endpoint agent: autonomous protection for that host.
- Router/controller, managed AP/switch, inline gateway, or transparent bridge:
  possible network-wide autonomous prevention.

Use God Mode only in your own network or an explicitly authorized lab, at your
own responsibility.
