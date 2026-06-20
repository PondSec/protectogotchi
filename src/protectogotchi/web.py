from __future__ import annotations

import json
import threading
import time
from dataclasses import asdict
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from protectogotchi.agent import ProtectogotchiAgent
from protectogotchi.config import ProtectogotchiConfig
from protectogotchi.knowledge import list_topics
from protectogotchi.models import ScanResult, utc_now
from protectogotchi.state import StateStore
from protectogotchi.tools import list_tools
from protectogotchi.topology import NetworkTopology, TopologyBuilder


def dashboard_html() -> str:
    return """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Protectogotchi</title>
  <style>
    :root {
      color-scheme: light;
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      --bg: #eef3f7;
      --ink: #17202a;
      --muted: #607086;
      --line: #c9d4e2;
      --strong: #0f766e;
      --warn: #b45309;
      --danger: #b91c1c;
    }
    * { box-sizing: border-box; }
    body { margin: 0; background: var(--bg); color: var(--ink); }
    header { padding: 18px 24px; border-bottom: 1px solid var(--line); display: flex; align-items: center; justify-content: space-between; gap: 18px; }
    h1 { font-size: 22px; margin: 0; letter-spacing: 0; }
    h2 { font-size: 13px; margin: 0 0 10px; text-transform: uppercase; color: var(--muted); letter-spacing: .08em; }
    main { display: grid; grid-template-columns: minmax(270px, 360px) 1fr; min-height: calc(100vh - 72px); }
    .side { border-right: 1px solid var(--line); padding: 20px 24px; }
    .work { padding: 0 24px 24px; }
    .band { border-top: 1px solid var(--line); padding: 18px 0; }
    .band:first-child { border-top: 0; }
    .face { font: 700 44px/1 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; margin-bottom: 12px; }
    .state { font-size: 28px; font-weight: 700; margin-bottom: 6px; }
    .muted { color: var(--muted); }
    .live { display: inline-flex; align-items: center; gap: 7px; font-size: 13px; color: var(--muted); }
    .dot { width: 8px; height: 8px; background: var(--strong); display: inline-block; }
    .metrics { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 10px 18px; margin-top: 18px; }
    .metric span { display: block; color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: .06em; }
    .metric strong { display: block; font-size: 24px; margin-top: 2px; }
    .risk-low { color: var(--strong); }
    .risk-mid { color: var(--warn); }
    .risk-high { color: var(--danger); }
    table { width: 100%; border-collapse: collapse; font-size: 13px; }
    th, td { text-align: left; padding: 9px 6px; border-bottom: 1px solid var(--line); vertical-align: top; }
    th { color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: .06em; }
    code, pre { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 12px; }
    pre { white-space: pre-wrap; overflow-wrap: anywhere; margin: 0; line-height: 1.45; }
    .split { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 26px; }
    .finding { padding: 10px 0; border-bottom: 1px solid var(--line); }
    .finding strong { display: block; }
    .severity-critical, .severity-high { color: var(--danger); }
    .severity-medium { color: var(--warn); }
    @media (max-width: 860px) {
      main { grid-template-columns: 1fr; }
      .side { border-right: 0; border-bottom: 1px solid var(--line); }
      .split { grid-template-columns: 1fr; }
    }
  </style>
</head>
<body>
  <header>
    <div>
      <h1>Protectogotchi</h1>
      <div class="muted">Local defensive network AI · realtime local view</div>
    </div>
    <div class="live"><span class="dot"></span><span id="liveText">starting</span></div>
  </header>
  <main>
    <aside class="side">
      <div class="face" id="face">( o_o)</div>
      <div class="state" id="state">Learning</div>
      <div class="muted" id="mood">waiting for first scan</div>
      <div class="metrics">
        <div class="metric"><span>Risk</span><strong id="risk">-</strong></div>
        <div class="metric"><span>Level</span><strong id="level">-</strong></div>
        <div class="metric"><span>Baseline</span><strong id="baseline">-</strong></div>
        <div class="metric"><span>Devices</span><strong id="devicesCount">-</strong></div>
      </div>
    </aside>
    <div class="work">
      <div class="band">
        <h2>Network</h2>
        <div class="split">
          <pre id="network">loading...</pre>
          <pre id="topology">loading...</pre>
        </div>
      </div>
      <div class="band">
        <h2>Findings</h2>
        <div id="findings">loading...</div>
      </div>
      <div class="band">
        <h2>Known Devices</h2>
        <table>
          <thead><tr><th>MAC</th><th>IPs</th><th>Seen</th><th>Last seen</th></tr></thead>
          <tbody id="devices"></tbody>
        </table>
      </div>
      <div class="band">
        <h2>Arsenal</h2>
        <div class="split">
          <pre id="tools">loading...</pre>
          <pre id="knowledge">loading...</pre>
        </div>
      </div>
    </div>
  </main>
  <script>
    const faces = {
      idle: "( -_-)",
      learning: "( o_o)",
      analyzing: "( @_@)",
      alert: "( O_O)!",
      fighting: "( >_<)",
      happy: "( ^_^)"
    };
    async function getJson(path) {
      const response = await fetch(path);
      if (!response.ok) throw new Error(path + " -> " + response.status);
      return response.json();
    }
    async function refresh() {
      const live = await getJson("/api/live");
      const scan = live.scan || {};
      const state = live.state || {};
      const snapshot = scan.snapshot || {};
      const faceState = scan.face_state || (state.baseline_ready ? "happy" : "learning");

      document.getElementById("face").textContent = faces[faceState] || faces.idle;
      document.getElementById("state").textContent = faceState.replace("-", " ");
      document.getElementById("mood").textContent = live.error || (scan.learned ? "learning safely" : "watching without baseline change");
      document.getElementById("risk").textContent = scan.risk_score ?? "-";
      document.getElementById("risk").className = (scan.risk_score || 0) >= 70 ? "risk-high" : ((scan.risk_score || 0) >= 35 ? "risk-mid" : "risk-low");
      document.getElementById("level").textContent = state.level ?? "-";
      document.getElementById("baseline").textContent = state.baseline_ready ? "ready" : ((state.learning_remaining || 0) + " left");
      document.getElementById("devicesCount").textContent = state.known_devices ?? "-";
      document.getElementById("liveText").textContent = "updated " + (live.updated_at || "now");

      document.getElementById("network").textContent = [
        "ssid: " + ((snapshot.wifi || {}).ssid || "unknown"),
        "gateway: " + (snapshot.default_gateway || "unknown"),
        "interfaces: " + ((snapshot.interfaces || []).length),
        "routes: " + ((snapshot.routes || []).length),
        "connections: " + ((snapshot.connections || []).length)
      ].join("\\n");
      document.getElementById("topology").textContent = JSON.stringify(live.topology_summary || {}, null, 2);

      renderFindings(scan.findings || []);
      renderDevices(live.devices || []);
      document.getElementById("tools").textContent = (live.tools || []).map(t => t.name + " [" + t.status + "]").join("\\n");
      document.getElementById("knowledge").textContent = (live.knowledge || []).map(t => t.name + " (" + t.domain + ")").join("\\n");
    }
    function renderFindings(findings) {
      const target = document.getElementById("findings");
      if (!findings.length) {
        target.innerHTML = "<span class='muted'>No findings in the latest scan.</span>";
        return;
      }
      target.innerHTML = findings.map(f => `
        <div class="finding">
          <strong class="severity-${f.severity}">[${f.severity}] ${f.title}</strong>
          <span>${f.description}</span><br>
          <code>${JSON.stringify(f.evidence || {})}</code>
        </div>
      `).join("");
    }
    function renderDevices(devices) {
      const target = document.getElementById("devices");
      target.innerHTML = devices.map(d => `
        <tr>
          <td><code>${d.mac}</code></td>
          <td>${(d.ips || []).join(", ")}</td>
          <td>${d.seen_count || 0}</td>
          <td>${d.last_seen || "-"}</td>
        </tr>
      `).join("");
    }
    refresh().catch(error => {
      document.getElementById("liveText").textContent = String(error);
    });
    setInterval(() => refresh().catch(error => {
      document.getElementById("liveText").textContent = String(error);
    }), 2000);
  </script>
</body>
</html>
"""


class LiveWebState:
    def __init__(
        self,
        config: ProtectogotchiConfig,
        collector_name: str | None,
        scan_interval: float,
    ) -> None:
        self.config = config
        self.collector_name = collector_name
        self.scan_interval = max(1.0, scan_interval)
        self.agent = ProtectogotchiAgent(config, collector_name=collector_name)
        self.lock = threading.Lock()
        self.stop_event = threading.Event()
        self.thread = threading.Thread(target=self._loop, name="protectogotchi-web-scan", daemon=True)
        self.payload: dict | None = None

    def start(self) -> None:
        self.thread.start()

    def stop(self) -> None:
        self.stop_event.set()
        self.thread.join(timeout=3)

    def current(self) -> dict:
        with self.lock:
            if self.payload is None:
                return {
                    "updated_at": utc_now(),
                    "error": "waiting for first scan",
                    "state": _state_summary(self.config),
                    "scan": None,
                    "topology_summary": {},
                    "devices": [],
                    "tools": [asdict(tool) for tool in list_tools()],
                    "knowledge": [asdict(topic) for topic in list_topics()],
                }
            return self.payload

    def refresh_once(self, learn: bool = True) -> dict:
        try:
            result = self.agent.scan(learn=learn)
            topology = TopologyBuilder().build(result.snapshot)
            payload = _live_payload(self.config, result, topology)
        except Exception as exc:  # pragma: no cover - defensive runtime guard
            payload = {
                "updated_at": utc_now(),
                "error": str(exc),
                "state": _state_summary(self.config),
                "scan": None,
                "topology_summary": {},
                "devices": [],
                "tools": [asdict(tool) for tool in list_tools()],
                "knowledge": [asdict(topic) for topic in list_topics()],
            }
        with self.lock:
            self.payload = payload
        return payload

    def _loop(self) -> None:
        while not self.stop_event.is_set():
            self.refresh_once(learn=True)
            self.stop_event.wait(self.scan_interval)


def _live_payload(
    config: ProtectogotchiConfig,
    result: ScanResult,
    topology: NetworkTopology,
) -> dict:
    state = StateStore(config.state_dir).load()
    return {
        "updated_at": utc_now(),
        "state": _state_summary(config),
        "scan": result.to_dict(),
        "topology_summary": topology.summary,
        "topology": topology.to_dict(),
        "devices": sorted(state.devices.values(), key=lambda item: item.get("mac", "")),
        "tools": [asdict(tool) for tool in list_tools()],
        "knowledge": [asdict(topic) for topic in list_topics()],
    }


def _state_summary(config: ProtectogotchiConfig) -> dict:
    state = StateStore(config.state_dir).load()
    learning_remaining = max(0, config.min_baseline_observations - state.observations)
    return {
        "level": state.level,
        "xp": state.xp,
        "scans": state.scans,
        "observations": state.observations,
        "baseline_ready": learning_remaining == 0,
        "learning_remaining": learning_remaining,
        "known_devices": len(state.devices),
        "trusted_devices": len(state.trusted_devices),
        "updated_at": state.updated_at,
    }


def run_web(
    config: ProtectogotchiConfig,
    host: str = "127.0.0.1",
    port: int = 8765,
    collector_name: str | None = None,
    scan_interval: float | None = None,
) -> None:
    live_state = LiveWebState(
        config,
        collector_name=collector_name,
        scan_interval=scan_interval or min(config.sample_interval, 3.0),
    )
    live_state.start()
    handler = _handler(config, collector_name, live_state)
    server = ThreadingHTTPServer((host, port), handler)
    print(f"Protectogotchi web listening on http://{host}:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nProtectogotchi web stopped.")
    finally:
        live_state.stop()
        server.server_close()


def _handler(
    config: ProtectogotchiConfig,
    collector_name: str | None,
    live_state: LiveWebState,
) -> type[BaseHTTPRequestHandler]:
    class ProtectogotchiHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            parsed = urlparse(self.path)
            query = parse_qs(parsed.query)
            if parsed.path == "/":
                self._send_text(dashboard_html(), content_type="text/html; charset=utf-8")
                return
            if parsed.path == "/api/status":
                self._send_json(StateStore(config.state_dir).load().to_dict())
                return
            if parsed.path == "/api/live":
                self._send_json(live_state.current())
                return
            if parsed.path == "/api/scan":
                learn = query.get("learn", ["1"])[0] != "0"
                self._send_json(live_state.refresh_once(learn=learn))
                return
            if parsed.path == "/api/topology":
                live = live_state.current()
                self._send_json(live.get("topology", {}))
                return
            if parsed.path == "/api/tools":
                self._send_json([asdict(tool) for tool in list_tools()])
                return
            if parsed.path == "/api/knowledge":
                self._send_json([asdict(topic) for topic in list_topics()])
                return
            self._send_json({"error": "not found"}, status=HTTPStatus.NOT_FOUND)

        def log_message(self, format: str, *args) -> None:
            return

        def _send_json(self, payload, status: HTTPStatus = HTTPStatus.OK) -> None:
            body = json.dumps(payload, indent=2, sort_keys=True).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _send_text(
            self,
            body: str,
            content_type: str,
            status: HTTPStatus = HTTPStatus.OK,
        ) -> None:
            raw = body.encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

    return ProtectogotchiHandler
