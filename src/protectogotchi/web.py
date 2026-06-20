from __future__ import annotations

import json
from dataclasses import asdict
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from protectogotchi.agent import ProtectogotchiAgent
from protectogotchi.collectors import get_collector
from protectogotchi.config import ProtectogotchiConfig
from protectogotchi.knowledge import list_topics
from protectogotchi.state import StateStore
from protectogotchi.tools import list_tools
from protectogotchi.topology import TopologyBuilder


def dashboard_html() -> str:
    return """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Protectogotchi</title>
  <style>
    :root { color-scheme: light; font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }
    body { margin: 0; background: #f6f8fb; color: #17202a; }
    header { padding: 18px 22px; background: #ffffff; border-bottom: 1px solid #d9e1ec; display: flex; justify-content: space-between; gap: 14px; align-items: center; }
    h1 { font-size: 22px; margin: 0; }
    main { padding: 18px; display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 14px; }
    section { background: #ffffff; border: 1px solid #d9e1ec; border-radius: 8px; padding: 14px; min-height: 120px; }
    h2 { font-size: 15px; margin: 0 0 10px; }
    pre { white-space: pre-wrap; overflow-wrap: anywhere; font-size: 12px; line-height: 1.35; }
    button { border: 1px solid #9db0c7; background: #ffffff; border-radius: 6px; padding: 8px 10px; cursor: pointer; }
    .face { font-size: 28px; font-weight: 700; }
    .muted { color: #607086; }
  </style>
</head>
<body>
  <header>
    <div>
      <h1>Protectogotchi</h1>
      <div class="muted">Local defensive network AI</div>
    </div>
    <button onclick="refresh()">Refresh</button>
  </header>
  <main>
    <section>
      <h2>Status</h2>
      <div id="face" class="face">( o_o)</div>
      <pre id="status">loading...</pre>
    </section>
    <section>
      <h2>Topology</h2>
      <pre id="topology">loading...</pre>
    </section>
    <section>
      <h2>Tools</h2>
      <pre id="tools">loading...</pre>
    </section>
    <section>
      <h2>Knowledge</h2>
      <pre id="knowledge">loading...</pre>
    </section>
  </main>
  <script>
    async function getJson(path) {
      const response = await fetch(path);
      if (!response.ok) throw new Error(path + " -> " + response.status);
      return response.json();
    }
    async function refresh() {
      const status = await getJson("/api/status");
      document.getElementById("status").textContent = JSON.stringify(status, null, 2);
      document.getElementById("face").textContent = status.observations ? "( ^_^)" : "( o_o)";
      const topology = await getJson("/api/topology");
      document.getElementById("topology").textContent = JSON.stringify(topology.summary, null, 2);
      const tools = await getJson("/api/tools");
      document.getElementById("tools").textContent = tools.map(t => t.name + " [" + t.status + "]").join("\\n");
      const knowledge = await getJson("/api/knowledge");
      document.getElementById("knowledge").textContent = knowledge.map(t => t.name + " (" + t.domain + ")").join("\\n");
    }
    refresh().catch(error => {
      document.getElementById("status").textContent = String(error);
    });
  </script>
</body>
</html>
"""


def run_web(
    config: ProtectogotchiConfig,
    host: str = "127.0.0.1",
    port: int = 8765,
    collector_name: str | None = None,
) -> None:
    handler = _handler(config, collector_name)
    server = ThreadingHTTPServer((host, port), handler)
    print(f"Protectogotchi web listening on http://{host}:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nProtectogotchi web stopped.")
    finally:
        server.server_close()


def _handler(
    config: ProtectogotchiConfig,
    collector_name: str | None,
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
            if parsed.path == "/api/scan":
                learn = query.get("learn", ["1"])[0] != "0"
                result = ProtectogotchiAgent(config, collector_name=collector_name).scan(learn=learn)
                self._send_json(result.to_dict())
                return
            if parsed.path == "/api/topology":
                snapshot = get_collector(collector_name).collect()
                topology = TopologyBuilder().build(snapshot)
                self._send_json(topology.to_dict())
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
