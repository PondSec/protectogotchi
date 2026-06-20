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
from protectogotchi.enforcement import easy_protect_plan, god_mode_readiness
from protectogotchi.knowledge import list_topics
from protectogotchi.models import ScanResult, utc_now
from protectogotchi.network_map import NetworkMapper
from protectogotchi.state import StateStore
from protectogotchi.tools import list_tools
from protectogotchi.topology import NetworkTopology, TopologyBuilder


WEB_MODES: dict[str, dict[str, object]] = {
    "learn": {
        "label": "Learn",
        "description": "Safely update the baseline when the latest scan is clean enough.",
    },
    "watch": {
        "label": "Watch",
        "description": "Observe and score without changing the baseline.",
    },
    "guard": {
        "label": "Guard",
        "description": "Observe, learn safely, and execute response planning. Active blocks still require explicit config.",
    },
    "god": {
        "label": "God",
        "description": "Fully autonomous defensive mode after explicit activation. Protectogotchi decides and executes supported response actions without per-action prompts. Network-wide prevention requires a real enforcement point; covert ARP/MitM is not part of this mode.",
    },
    "pause": {
        "label": "Pause",
        "description": "Keep the web UI open without running background scans.",
    },
}


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
    .headerActions { display: flex; align-items: center; gap: 18px; flex-wrap: wrap; justify-content: flex-end; }
    .modeSwitch, .tabs { display: flex; gap: 6px; align-items: center; flex-wrap: wrap; }
    .modeSwitch button, .tabs button {
      appearance: none;
      border: 1px solid var(--line);
      background: transparent;
      color: var(--ink);
      padding: 8px 10px;
      font: inherit;
      cursor: pointer;
    }
    .modeSwitch button.active, .tabs button.active {
      border-color: var(--ink);
      background: rgba(255, 255, 255, .48);
    }
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
    svg { width: 100%; min-height: 360px; border-top: 1px solid var(--line); border-bottom: 1px solid var(--line); }
    .nodeLabel { font: 12px ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; fill: var(--ink); }
    .nodeMeta { font: 10px ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; fill: var(--muted); }
    .link { stroke: #9bacbd; stroke-width: 1.2; }
    .node { fill: #ffffff; stroke: var(--line); stroke-width: 1.3; }
    .node.gateway, .node.default-gateway { stroke: var(--strong); stroke-width: 2; }
    .node.host { fill: #dfeeea; }
    .node.subnet { fill: #e4ebf5; }
    .split { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 26px; }
    .tabs { position: sticky; top: 0; padding: 14px 0; background: var(--bg); border-bottom: 1px solid var(--line); z-index: 1; }
    .panel { display: none; }
    .panel.active { display: block; }
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
    <div class="headerActions">
      <div class="modeSwitch" aria-label="Mode">
        <button data-mode="learn" class="active" onclick="setMode('learn')">Learn</button>
        <button data-mode="watch" onclick="setMode('watch')">Watch</button>
        <button data-mode="guard" onclick="setMode('guard')">Guard</button>
        <button data-mode="god" onclick="setMode('god')">God Mode</button>
        <button data-mode="pause" onclick="setMode('pause')">Pause</button>
      </div>
      <div class="live"><span class="dot"></span><span id="liveText">starting</span></div>
    </div>
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
      <nav class="tabs" aria-label="Views">
        <button data-tab="overview" class="active" onclick="switchTab('overview')">Overview</button>
        <button data-tab="network" onclick="switchTab('network')">Network</button>
        <button data-tab="findings" onclick="switchTab('findings')">Findings</button>
        <button data-tab="devices" onclick="switchTab('devices')">Devices</button>
        <button data-tab="arsenal" onclick="switchTab('arsenal')">Arsenal</button>
      </nav>
      <div class="band panel active" data-panel="overview">
        <h2>Overview</h2>
        <svg id="networkGraph" role="img" aria-label="Logical network map"></svg>
        <div class="split">
          <pre id="network">loading...</pre>
          <pre id="topology">loading...</pre>
        </div>
      </div>
      <div class="band panel" data-panel="network">
        <h2>Network</h2>
        <div class="split">
          <pre id="networkDetail">loading...</pre>
          <pre id="coverage">loading...</pre>
        </div>
      </div>
      <div class="band panel" data-panel="findings">
        <h2>Findings</h2>
        <div id="findings">loading...</div>
        <h2 style="margin-top:22px">Recent History</h2>
        <div id="history">loading...</div>
      </div>
      <div class="band panel" data-panel="devices">
        <h2>Known Devices</h2>
        <table>
          <thead><tr><th>MAC</th><th>IPs</th><th>Seen</th><th>Last seen</th></tr></thead>
          <tbody id="devices"></tbody>
        </table>
      </div>
      <div class="band panel" data-panel="arsenal">
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
      document.getElementById("mood").textContent = live.error || live.mode_description || (scan.learned ? "learning safely" : "watching without baseline change");
      renderMode(live.mode || "learn", live.mode_description || "");
      document.getElementById("risk").textContent = scan.risk_score ?? "-";
      document.getElementById("risk").className = (scan.risk_score || 0) >= 70 ? "risk-high" : ((scan.risk_score || 0) >= 35 ? "risk-mid" : "risk-low");
      document.getElementById("level").textContent = state.level ?? "-";
      document.getElementById("baseline").textContent = state.baseline_ready ? "ready" : ((state.learning_remaining || 0) + " left");
      document.getElementById("devicesCount").textContent = state.known_devices ?? "-";
      document.getElementById("liveText").textContent = "updated " + (live.updated_at || "now");

      document.getElementById("network").textContent = [
        "ssid: " + ((snapshot.wifi || {}).ssid || "unknown"),
        "gateway: " + (snapshot.default_gateway || "unknown"),
        "mode: " + (live.mode || "learn"),
        "active interfaces: " + (((live.network_map || {}).summary || {}).active_interfaces ?? "-"),
        "local subnets: " + (((live.network_map || {}).subnets || []).join(", ") || "none"),
        "interfaces: " + ((snapshot.interfaces || []).length),
        "routes: " + ((snapshot.routes || []).length),
        "connections: " + ((snapshot.connections || []).length)
      ].join("\\n");
      document.getElementById("topology").textContent = JSON.stringify(live.topology_summary || {}, null, 2);
      document.getElementById("networkDetail").textContent = JSON.stringify((live.network_map || {}).summary || {}, null, 2);
      document.getElementById("coverage").textContent = ((live.network_map || {}).coverage || []).join("\\n");
      renderGraph((live.network_map || {}).graph || { nodes: [], edges: [] });

      renderFindings(scan.findings || []);
      renderHistory(live.finding_history || []);
      renderDevices(live.devices || []);
      document.getElementById("tools").textContent = (live.tools || []).map(t => t.name + " [" + t.status + "]").join("\\n");
      document.getElementById("knowledge").textContent = [
        "God Mode readiness:",
        JSON.stringify(live.god_mode_readiness || {}, null, 2),
        "",
        ...(live.knowledge || []).map(t => t.name + " (" + t.domain + ")")
      ].join("\\n");
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
    function renderHistory(history) {
      const target = document.getElementById("history");
      if (!history.length) {
        target.innerHTML = "<span class='muted'>No finding history yet.</span>";
        return;
      }
      target.innerHTML = history.slice(-12).reverse().map(f => `
        <div class="finding">
          <strong class="severity-${f.severity}">${f.seen_at} · [${f.severity}] ${f.title}</strong>
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
    function renderGraph(graph) {
      const svg = document.getElementById("networkGraph");
      const nodes = graph.nodes || [];
      const edges = graph.edges || [];
      const width = Math.max(760, svg.clientWidth || 760);
      const byId = new Map(nodes.map(n => [n.id, n]));
      const columns = {
        host: 70,
        interface: 230,
        subnet: 410,
        gateway: 610,
        "default-gateway": 610,
        endpoint: 610,
        "local-host": 610,
        "infrastructure-candidate": 610
      };
      const grouped = {};
      for (const node of nodes) {
        const kind = node.kind || "endpoint";
        grouped[kind] = grouped[kind] || [];
        grouped[kind].push(node);
      }
      const ySlots = {};
      const ordered = ["host", "interface", "subnet", "default-gateway", "gateway", "infrastructure-candidate", "endpoint", "local-host"];
      for (const kind of ordered) {
        const items = grouped[kind] || [];
        items.forEach((node, index) => {
          const x = columns[kind] || 610;
          const spread = Math.max(1, items.length);
          const y = 60 + index * Math.max(54, 270 / spread);
          ySlots[node.id] = { x, y };
        });
      }
      const height = Math.max(360, ...Object.values(ySlots).map(p => p.y + 45));
      svg.setAttribute("viewBox", `0 0 ${width} ${height}`);
      const edgeSvg = edges.map(edge => {
        const source = ySlots[edge.source];
        const target = ySlots[edge.target];
        if (!source || !target) return "";
        return `<line class="link" x1="${source.x + 60}" y1="${source.y}" x2="${target.x - 60}" y2="${target.y}"></line>`;
      }).join("");
      const nodeSvg = nodes.map(node => {
        const pos = ySlots[node.id];
        if (!pos) return "";
        const kind = node.kind || "endpoint";
        const label = escapeHtml(node.label || node.id);
        const meta = escapeHtml([node.ip, node.mac].filter(Boolean).join(" · "));
        return `
          <g>
            <rect class="node ${kind}" x="${pos.x - 58}" y="${pos.y - 20}" width="116" height="40"></rect>
            <text class="nodeLabel" x="${pos.x - 50}" y="${pos.y - 3}">${label}</text>
            <text class="nodeMeta" x="${pos.x - 50}" y="${pos.y + 12}">${meta}</text>
          </g>
        `;
      }).join("");
      svg.innerHTML = edgeSvg + nodeSvg;
    }
    function escapeHtml(value) {
      return String(value)
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;");
    }
    function switchTab(tab) {
      document.querySelectorAll("[data-tab]").forEach(button => button.classList.toggle("active", button.dataset.tab === tab));
      document.querySelectorAll("[data-panel]").forEach(panel => panel.classList.toggle("active", panel.dataset.panel === tab));
    }
    function renderMode(mode, description) {
      document.querySelectorAll("[data-mode]").forEach(button => button.classList.toggle("active", button.dataset.mode === mode));
    }
    async function setMode(mode) {
      let body = { mode };
      if (mode === "god") {
        const phrase = window.prompt('God Mode is autonomous and acts at your own responsibility. Network-wide prevention requires a real enforcement point such as router-controller, inline-gateway, transparent-bridge, managed AP/switch, or endpoint agent. It does not enable covert ARP/MitM. Type ACTIVATE GOD MODE to continue.');
        if (phrase !== "ACTIVATE GOD MODE") return;
        body.confirm = phrase;
      }
      await fetch("/api/mode", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body)
      });
      await refresh();
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
        self.mode = "learn"

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
                    "mode": self.mode,
                    "mode_description": WEB_MODES[self.mode]["description"],
                    "state": _state_summary(self.config),
                    "scan": None,
                    "topology_summary": {},
                    "network_map": {},
                    "devices": [],
                    "finding_history": [],
                    "god_mode_readiness": god_mode_readiness(self.config),
                    "easy_protect_plan": easy_protect_plan(self.config),
                    "tools": [asdict(tool) for tool in list_tools()],
                    "knowledge": [asdict(topic) for topic in list_topics()],
                }
            return self.payload

    def set_mode(self, mode: str, confirmation: str | None = None) -> dict:
        if mode not in WEB_MODES:
            raise ValueError(f"Unknown web mode: {mode}")
        if mode == "god" and confirmation != "ACTIVATE GOD MODE":
            raise ValueError("God Mode requires typed confirmation: ACTIVATE GOD MODE")
        with self.lock:
            self.mode = mode
            if self.payload is not None:
                self.payload["mode"] = mode
                self.payload["mode_description"] = WEB_MODES[mode]["description"]
                return self.payload
        return self.current()

    def refresh_once(self, learn: bool | None = None) -> dict:
        with self.lock:
            mode = self.mode
        if mode == "pause" and learn is None:
            return self.current()

        learn_flag = learn if learn is not None else mode in {"learn", "guard"}
        execute_actions = mode in {"guard", "god"}
        try:
            result = self.agent.scan(learn=learn_flag, execute_actions=execute_actions)
            topology = TopologyBuilder().build(result.snapshot)
            payload = _live_payload(self.config, result, topology, mode)
        except Exception as exc:  # pragma: no cover - defensive runtime guard
            payload = {
                "updated_at": utc_now(),
                "error": str(exc),
                "mode": mode,
                "mode_description": WEB_MODES[mode]["description"],
                "state": _state_summary(self.config),
                "scan": None,
                "topology_summary": {},
                "network_map": {},
                "devices": [],
                "finding_history": [],
                "god_mode_readiness": god_mode_readiness(self.config),
                "easy_protect_plan": easy_protect_plan(self.config),
                "tools": [asdict(tool) for tool in list_tools()],
                "knowledge": [asdict(topic) for topic in list_topics()],
            }
        with self.lock:
            self.payload = payload
        return payload

    def _loop(self) -> None:
        while not self.stop_event.is_set():
            self.refresh_once()
            self.stop_event.wait(self.scan_interval)


def _live_payload(
    config: ProtectogotchiConfig,
    result: ScanResult,
    topology: NetworkTopology,
    mode: str = "learn",
) -> dict:
    state = StateStore(config.state_dir).load()
    return {
        "updated_at": utc_now(),
        "mode": mode,
        "mode_description": WEB_MODES[mode]["description"],
        "state": _state_summary(config),
        "scan": result.to_dict(),
        "topology_summary": topology.summary,
        "topology": topology.to_dict(),
        "network_map": NetworkMapper().build(result.snapshot).to_dict(),
        "devices": sorted(state.devices.values(), key=lambda item: item.get("mac", "")),
        "finding_history": state.finding_history[-50:],
        "god_mode_readiness": god_mode_readiness(config),
        "easy_protect_plan": easy_protect_plan(config),
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

        def do_POST(self) -> None:
            parsed = urlparse(self.path)
            if parsed.path == "/api/mode":
                try:
                    length = int(self.headers.get("Content-Length", "0"))
                    raw = self.rfile.read(length) if length else b"{}"
                    payload = json.loads(raw.decode("utf-8"))
                    mode = str(payload.get("mode", ""))
                    confirmation = payload.get("confirm")
                    self._send_json(live_state.set_mode(mode, confirmation=confirmation))
                except ValueError as exc:
                    self._send_json({"error": str(exc)}, status=HTTPStatus.BAD_REQUEST)
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
