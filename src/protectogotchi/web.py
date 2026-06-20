from __future__ import annotations

import json
import os
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
from protectogotchi.neural import neural_model_summary
from protectogotchi.placement import build_placement_report
from protectogotchi.policy import policy_model_summary
from protectogotchi.simulation import SCENARIOS, run_simulation
from protectogotchi.state import StateStore
from protectogotchi.tools import list_tools
from protectogotchi.topology import NetworkTopology, TopologyBuilder


WEB_MODES: dict[str, dict[str, object]] = {
    "learn": {
        "label": "Lernen",
        "description": "Lernt unauffällige Beobachtungen als normales Verhalten.",
    },
    "watch": {
        "label": "Beobachten",
        "description": "Beobachtet und bewertet, ohne die Baseline zu verändern.",
    },
    "guard": {
        "label": "Schützen",
        "description": "Beobachtet, lernt vorsichtig und bereitet Schutzreaktionen vor.",
    },
    "god": {
        "label": "Autopilot",
        "description": "Autonomer Schutzmodus nach ausdrücklicher Aktivierung. Netzwerkweiter Schutz braucht einen echten Enforcement-Punkt; heimliches ARP/MitM ist nicht Teil dieses Modus.",
    },
    "pause": {
        "label": "Pause",
        "description": "Lässt die Oberfläche offen, pausiert aber Hintergrundscans.",
    },
}


def dashboard_html() -> str:
    return """<!doctype html>
<html lang="de">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Protectogotchi</title>
  <style>
    :root {
      color-scheme: dark;
      font-family: Inter, -apple-system, BlinkMacSystemFont, "SF Pro Display", "Segoe UI", sans-serif;
      --bg: #0D1117;
      --panel: #161B22;
      --line: #21262D;
      --text: #E6EDF3;
      --muted: #8B949E;
      --safe: #3FB950;
      --attention: #F0883E;
      --critical: #F85149;
      --info: #58A6FF;
    }
    * { box-sizing: border-box; }
    html { background: var(--bg); }
    body {
      margin: 0;
      min-height: 100vh;
      color: var(--text);
      background: var(--bg);
      font-size: 14px;
      line-height: 1.5;
    }
    button, input { font: inherit; }
    button {
      appearance: none;
      border: 0;
      cursor: pointer;
    }
    button:focus-visible, [tabindex]:focus-visible {
      outline: 2px solid var(--info);
      outline-offset: 2px;
    }
    .app-shell { min-height: 100vh; display: grid; grid-template-rows: auto 1fr; }
    .topbar {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 24px;
      padding: 16px 24px;
      border-bottom: 1px solid var(--line);
      background: var(--bg);
    }
    .brand { display: flex; align-items: center; gap: 12px; min-width: 240px; }
    .brand-mark {
      width: 32px;
      height: 32px;
      border: 1px solid var(--line);
      border-radius: 6px;
      display: grid;
      place-items: center;
      color: var(--info);
      font-family: "JetBrains Mono", "Fira Code", ui-monospace, SFMono-Regular, Menlo, monospace;
      font-size: 16px;
      font-weight: 700;
    }
    .brand h1 { margin: 0; font-size: 20px; line-height: 1.2; font-weight: 700; }
    .brand-subtitle { color: var(--muted); font-size: 12px; line-height: 1.4; }
    .system-strip { display: flex; justify-content: flex-end; gap: 16px; flex-wrap: wrap; }
    .system-item { min-width: 88px; }
    .system-label {
      display: block;
      color: var(--muted);
      font-size: 12px;
      line-height: 1.4;
      text-transform: uppercase;
    }
    .system-value {
      display: block;
      margin-top: 4px;
      font-family: "JetBrains Mono", "Fira Code", ui-monospace, SFMono-Regular, Menlo, monospace;
      font-size: 14px;
      line-height: 1.4;
      color: var(--text);
    }
    /* Design decision: fixed enterprise columns keep operational density predictable. */
    .console-grid {
      display: grid;
      grid-template-columns: minmax(280px, 30%) minmax(416px, 45%) minmax(280px, 25%);
      gap: 16px;
      padding: 16px 24px 24px;
      min-height: 0;
    }
    .column { min-width: 0; display: grid; gap: 16px; align-content: start; }
    .panel {
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 6px;
      min-width: 0;
    }
    .panel-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 16px;
      padding: 12px 16px;
      border-bottom: 1px solid var(--line);
    }
    .panel-title { margin: 0; font-size: 16px; line-height: 1.4; font-weight: 700; }
    .panel-subtitle { margin: 4px 0 0; color: var(--muted); font-size: 12px; line-height: 1.4; }
    .panel-body { padding: 16px; }
    .status-pill {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      min-height: 24px;
      padding: 2px 8px;
      border: 1px solid var(--line);
      border-radius: 4px;
      color: var(--muted);
      font-size: 12px;
      line-height: 1.4;
      white-space: nowrap;
    }
    .status-pill::before {
      content: "";
      width: 8px;
      height: 8px;
      border-radius: 4px;
      background: var(--info);
    }
    .status-safe { color: var(--safe); border-color: var(--safe); }
    .status-safe::before { background: var(--safe); }
    .status-attention { color: var(--attention); border-color: var(--attention); }
    .status-attention::before { background: var(--attention); }
    .status-critical { color: var(--critical); border-color: var(--critical); }
    .status-critical::before { background: var(--critical); }
    .status-info { color: var(--info); border-color: var(--info); }
    .status-info::before { background: var(--info); }
    .metric-grid {
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      border-top: 1px solid var(--line);
      border-left: 1px solid var(--line);
    }
    .metric {
      padding: 12px;
      border-right: 1px solid var(--line);
      border-bottom: 1px solid var(--line);
    }
    .metric-label { color: var(--muted); font-size: 12px; line-height: 1.4; text-transform: uppercase; }
    .metric-value { margin-top: 4px; font-size: 24px; line-height: 1.2; font-weight: 700; }
    .asset-canvas {
      position: relative;
      min-height: 360px;
      border: 1px solid var(--line);
      border-radius: 6px;
      overflow: hidden;
      background: var(--bg);
    }
    svg { width: 100%; min-height: 360px; display: block; }
    .link { stroke: var(--line); stroke-width: 1.5; }
    .node { fill: var(--panel); stroke: var(--line); stroke-width: 1.5; rx: 6; ry: 6; }
    .node.host { stroke: var(--info); }
    .node.gateway, .node.default-gateway { stroke: var(--safe); }
    .node.endpoint, .node.local-host, .node.infrastructure-candidate { stroke: var(--muted); }
    .nodeLabel { fill: var(--text); font-size: 12px; font-weight: 700; }
    .nodeMeta {
      fill: var(--muted);
      font-family: "JetBrains Mono", "Fira Code", ui-monospace, SFMono-Regular, Menlo, monospace;
      font-size: 12px;
    }
    .graph-tooltip {
      position: absolute;
      display: none;
      max-width: 240px;
      padding: 8px;
      border: 1px solid var(--line);
      border-radius: 4px;
      background: var(--panel);
      color: var(--text);
      font-size: 12px;
      pointer-events: none;
      z-index: 4;
    }
    .table-wrap { overflow: auto; border: 1px solid var(--line); border-radius: 6px; }
    table { width: 100%; border-collapse: collapse; min-width: 640px; }
    th, td {
      padding: 8px 12px;
      border-bottom: 1px solid var(--line);
      text-align: left;
      vertical-align: top;
      font-size: 14px;
    }
    th {
      color: var(--muted);
      font-size: 12px;
      line-height: 1.4;
      text-transform: uppercase;
      background: var(--panel);
    }
    th button {
      color: inherit;
      background: transparent;
      padding: 0;
      text-transform: inherit;
    }
    tr:last-child td { border-bottom: 0; }
    code, .mono {
      font-family: "JetBrains Mono", "Fira Code", ui-monospace, SFMono-Regular, Menlo, monospace;
      font-size: 12px;
      color: var(--text);
    }
    .feed { display: grid; border-top: 1px solid var(--line); }
    .feed-row {
      display: grid;
      grid-template-columns: 112px 1fr auto;
      gap: 12px;
      padding: 12px 0;
      border-bottom: 1px solid var(--line);
    }
    .feed-row:last-child { border-bottom: 0; }
    .feed-time { color: var(--muted); font-size: 12px; font-family: "JetBrains Mono", "Fira Code", ui-monospace, SFMono-Regular, Menlo, monospace; }
    .feed-title { font-size: 14px; font-weight: 700; }
    .feed-detail { margin-top: 4px; color: var(--muted); font-size: 14px; }
    .button-row { display: flex; gap: 8px; flex-wrap: wrap; }
    .btn {
      min-height: 32px;
      padding: 6px 10px;
      border-radius: 4px;
      font-size: 14px;
      color: var(--text);
      background: transparent;
      border: 1px solid var(--line);
    }
    .btn:hover { border-color: var(--info); color: var(--info); }
    .btn-primary { color: var(--bg); background: var(--safe); border-color: var(--safe); font-weight: 700; }
    .btn-primary:hover { color: var(--bg); border-color: var(--safe); }
    .btn-critical { color: var(--bg); background: var(--critical); border-color: var(--critical); font-weight: 700; }
    .btn-text { border-color: transparent; color: var(--muted); }
    .btn[disabled] { color: var(--muted); border-color: var(--line); cursor: not-allowed; }
    .mode-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 8px; }
    .mode-grid .btn.active { border-color: var(--info); color: var(--info); }
    .ai-state {
      display: grid;
      grid-template-columns: 120px 1fr;
      gap: 16px;
      align-items: center;
    }
    .ai-face {
      width: 120px;
      height: 120px;
      border: 1px solid var(--line);
      border-radius: 6px;
      display: grid;
      place-items: center;
      color: var(--text);
      font-family: "JetBrains Mono", "Fira Code", ui-monospace, SFMono-Regular, Menlo, monospace;
      font-size: 32px;
      line-height: 1;
    }
    .ai-headline { margin: 0; font-size: 20px; line-height: 1.2; }
    .ai-copy { margin: 8px 0 0; color: var(--muted); font-size: 14px; }
    .detail-list { display: grid; border-top: 1px solid var(--line); }
    .detail-line {
      display: grid;
      grid-template-columns: minmax(112px, 34%) 1fr;
      gap: 12px;
      padding: 8px 0;
      border-bottom: 1px solid var(--line);
      font-size: 12px;
    }
    .detail-line span:first-child { color: var(--muted); text-transform: uppercase; }
    .arsenal-list { display: grid; border-top: 1px solid var(--line); }
    .arsenal-line {
      display: grid;
      grid-template-columns: 96px 1fr auto;
      gap: 8px;
      align-items: start;
      padding: 8px 0;
      border-bottom: 1px solid var(--line);
      font-size: 12px;
    }
    .log-list { display: grid; border-top: 1px solid var(--line); }
    .log-line { padding: 8px 0; border-bottom: 1px solid var(--line); color: var(--muted); font-size: 12px; }
    .empty-state { color: var(--muted); font-size: 14px; padding: 16px 0; }
    .skeleton {
      min-height: 16px;
      border: 1px solid var(--line);
      border-radius: 4px;
      color: var(--muted);
      padding: 8px;
    }
    .mobile-nav { display: none; }
    @media (max-width: 980px) {
      .topbar { align-items: flex-start; flex-direction: column; padding: 16px; }
      .system-strip { justify-content: flex-start; }
      .console-grid { grid-template-columns: 1fr; padding: 16px 16px 80px; }
      .column { display: none; }
      .column.active-mobile { display: grid; }
      .mobile-nav {
        position: fixed;
        left: 0;
        right: 0;
        bottom: 0;
        display: grid;
        grid-template-columns: repeat(3, 1fr);
        gap: 1px;
        border-top: 1px solid var(--line);
        background: var(--line);
        z-index: 10;
      }
      .mobile-nav button {
        min-height: 56px;
        color: var(--muted);
        background: var(--bg);
        font-size: 12px;
      }
      .mobile-nav button.active { color: var(--info); }
      table { min-width: 560px; }
      .feed-row { grid-template-columns: 1fr; }
    }
  </style>
</head>
<body>
  <div class="app-shell">
    <header class="topbar">
      <div class="brand" aria-label="Protectogotchi">
        <div class="brand-mark" aria-hidden="true">P</div>
        <div>
          <h1>Protectogotchi</h1>
          <div class="brand-subtitle">Local defensive network AI</div>
        </div>
      </div>
      <div class="system-strip" aria-label="Systemstatus">
        <div class="system-item"><span class="system-label">Uptime</span><span class="system-value" id="uptime">--</span></div>
        <div class="system-item"><span class="system-label">Modus</span><span class="system-value" id="headerMode">learn</span></div>
        <div class="system-item"><span class="system-label">Last</span><span class="system-value" id="headerLoad">0%</span></div>
        <div class="system-item"><span class="system-label">Netzwerkmodus</span><span class="system-value" id="networkMode">observer</span></div>
      </div>
    </header>

    <main class="console-grid" id="consoleGrid">
      <section class="column active-mobile" data-mobile-panel="assets" aria-label="Asset Graph">
        <section class="panel">
          <div class="panel-header">
            <div>
              <h2 class="panel-title">Asset Graph</h2>
              <p class="panel-subtitle">Sichtbare Knoten, Gateways und Subnetze</p>
            </div>
            <span class="status-pill status-info" id="assetCoverage">loading</span>
          </div>
          <div class="panel-body">
            <div class="asset-canvas" id="graphCanvas">
              <svg id="networkGraph" role="img" aria-label="Asset Graph"></svg>
              <div class="graph-tooltip" id="graphTooltip" role="status"></div>
            </div>
          </div>
        </section>

        <section class="panel">
          <div class="panel-header">
            <div>
              <h2 class="panel-title">Assets</h2>
              <p class="panel-subtitle">Inventar aus lokaler Sicht</p>
            </div>
          </div>
          <div class="panel-body">
            <div class="metric-grid">
              <div class="metric"><div class="metric-label">Geräte</div><div class="metric-value" id="metricDevices">--</div></div>
              <div class="metric"><div class="metric-label">Subnets</div><div class="metric-value" id="metricSubnets">--</div></div>
              <div class="metric"><div class="metric-label">Gateway</div><div class="metric-value" id="metricGateways">--</div></div>
              <div class="metric"><div class="metric-label">Routen</div><div class="metric-value" id="metricRoutes">--</div></div>
            </div>
          </div>
        </section>
      </section>

      <section class="column active-mobile" data-mobile-panel="matrix" aria-label="Realtime Feed und Bedrohungsmatrix">
        <section class="panel">
          <div class="panel-header">
            <div>
              <h2 class="panel-title">Bedrohungsmatrix</h2>
              <p class="panel-subtitle">Priorisierte Befunde mit Begründung und Empfehlung</p>
            </div>
            <span class="status-pill" id="matrixStatus">loading</span>
          </div>
          <div class="panel-body">
            <div class="table-wrap">
              <table aria-label="Bedrohungsmatrix">
                <thead>
                  <tr>
                    <th><button type="button" onclick="sortThreats('severity')">Status</button></th>
                    <th><button type="button" onclick="sortThreats('title')">Befund</button></th>
                    <th>Empfehlung</th>
                    <th><button type="button" onclick="sortThreats('time')">Zeit</button></th>
                  </tr>
                </thead>
                <tbody id="threatRows"><tr><td colspan="4"><div class="skeleton">Warte auf ersten Scan</div></td></tr></tbody>
              </table>
            </div>
          </div>
        </section>

        <section class="panel">
          <div class="panel-header">
            <div>
              <h2 class="panel-title">Realtime Feed</h2>
              <p class="panel-subtitle">Letzte Beobachtungen und Statuswechsel</p>
            </div>
            <span class="status-pill status-info" id="feedCount">0 events</span>
          </div>
          <div class="panel-body">
            <div class="feed" id="feedRows"><div class="empty-state">Noch keine Ereignisse im aktuellen Lauf.</div></div>
          </div>
        </section>

        <section class="panel">
          <div class="panel-header">
            <div>
              <h2 class="panel-title">Geräte</h2>
              <p class="panel-subtitle">Bekannte Geräte aus der Baseline</p>
            </div>
          </div>
          <div class="panel-body">
            <div class="table-wrap">
              <table aria-label="Geräteliste">
                <thead><tr><th>Name</th><th>IP</th><th>MAC</th><th>Zuletzt</th></tr></thead>
                <tbody id="deviceRows"><tr><td colspan="4"><div class="skeleton">Inventar wird geladen</div></td></tr></tbody>
              </table>
            </div>
          </div>
        </section>
      </section>

      <section class="column active-mobile" data-mobile-panel="control" aria-label="Steuerungskonsole">
        <section class="panel">
          <div class="panel-header">
            <div>
              <h2 class="panel-title">Steuerung</h2>
              <p class="panel-subtitle">Beobachtung und Aktion klar getrennt</p>
            </div>
          </div>
          <div class="panel-body">
            <div class="mode-grid" aria-label="Modus wechseln">
              <button class="btn" data-mode="learn" onclick="setMode('learn')">Lernen</button>
              <button class="btn" data-mode="watch" onclick="setMode('watch')">Beobachten</button>
              <button class="btn" data-mode="guard" onclick="setMode('guard')">Schützen</button>
              <button class="btn btn-critical" data-mode="god" onclick="setMode('god')">Autopilot</button>
              <button class="btn" data-mode="pause" onclick="setMode('pause')">Pause</button>
              <button class="btn" onclick="refresh(true)">Scan jetzt</button>
            </div>
          </div>
        </section>

        <section class="panel">
          <div class="panel-header">
            <div>
              <h2 class="panel-title">AI State</h2>
              <p class="panel-subtitle">Live-Zustand des lokalen Agenten</p>
            </div>
            <span class="status-pill" id="aiStatusPill">loading</span>
          </div>
          <div class="panel-body">
            <div class="ai-state">
              <div class="ai-face" id="aiFace" aria-label="Companion face">( o_o)</div>
              <div>
                <h3 class="ai-headline" id="aiHeadline">Initialisierung</h3>
                <p class="ai-copy" id="aiCopy">Der lokale Agent wartet auf den ersten Scan.</p>
              </div>
            </div>
          </div>
        </section>

        <section class="panel">
          <div class="panel-header">
            <div>
              <h2 class="panel-title">Neural Engine</h2>
              <p class="panel-subtitle">PyTorch Autoencoder und DQN-Policy</p>
            </div>
            <span class="status-pill" id="nnStatusPill">loading</span>
          </div>
          <div class="panel-body">
            <div class="detail-list" id="neuralDetails">
              <div class="detail-line"><span>Backend</span><strong>warte</strong></div>
            </div>
          </div>
        </section>

        <section class="panel">
          <div class="panel-header">
            <div>
              <h2 class="panel-title">Arsenal</h2>
              <p class="panel-subtitle">Defensive Fähigkeiten und Integrationen</p>
            </div>
            <span class="status-pill status-info" id="arsenalCount">0 tools</span>
          </div>
          <div class="panel-body">
            <div class="arsenal-list" id="arsenalRows">
              <div class="empty-state">Arsenal wird geladen.</div>
            </div>
          </div>
        </section>

        <section class="panel">
          <div class="panel-header">
            <div>
              <h2 class="panel-title">Export</h2>
              <p class="panel-subtitle">Live-Daten lokal sichern</p>
            </div>
          </div>
          <div class="panel-body">
            <div class="button-row">
              <button class="btn btn-primary" onclick="exportSnapshot()">Export JSON</button>
            </div>
          </div>
        </section>

        <section class="panel">
          <div class="panel-header">
            <div>
              <h2 class="panel-title">Logs</h2>
              <p class="panel-subtitle">Kompakte Betriebsnotizen</p>
            </div>
          </div>
          <div class="panel-body">
            <div class="log-list" id="controlLogs"><div class="log-line">Warte auf Live-Daten.</div></div>
          </div>
        </section>
      </section>
    </main>

    <nav class="mobile-nav" aria-label="Mobile Navigation">
      <button type="button" data-mobile-tab="assets" class="active" onclick="setMobilePanel('assets')">Assets</button>
      <button type="button" data-mobile-tab="matrix" onclick="setMobilePanel('matrix')">Matrix</button>
      <button type="button" data-mobile-tab="control" onclick="setMobilePanel('control')">Control</button>
    </nav>
  </div>
  <script>
    const faceVariants = {
      idle:["( -_-)", "( ._.)", "( -.-)"],
      bored:["( -_-) z", "( -.-) z", "( ._.)"],
      learning:["( o_o)", "( ._.)?", "( o_o)"],
      analyzing:["( @_@)", "( o_O)", "( @_-)"],
      alert:["( O_O)!", "(! o_o)", "( O_O)"],
      fighting:["( >_<)", "( >_>)!", "( <_<)!"],
      happy:["( ^_^)", "( ^.^)", "( ^_-)"],
      curious:["( ?_?)", "( o_o)?", "( ._.)?"],
    };
    const severityRank = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
    let currentLive = null;
    let threatSort = { key: "time", direction: "desc" };
    let activeMobilePanel = "assets";
    let touchStartX = 0;
    let currentFaceState = "idle";
    let faceTick = 0;

    async function getJson(path) {
      const response = await fetch(path);
      if (!response.ok) throw new Error(path + " -> " + response.status);
      return response.json();
    }

    async function refresh(manual = false) {
      const live = manual ? await getJson("/api/scan?learn=1") : await getJson("/api/live");
      currentLive = live;
      renderHeader(live);
      renderControls(live);
      renderAiState(live);
      renderAssets(live);
      renderThreatMatrix(live);
      renderFeed(live);
      renderDevices(live.devices || []);
      renderNeuralEngine(live);
      renderArsenal(live.tools || []);
      renderLogs(live);
    }

    function renderHeader(live) {
      const runtime = live.runtime || {};
      const scan = live.scan || {};
      const systemLoad = Number.isFinite(runtime.load_percent) ? runtime.load_percent : (scan.risk_score || 0);
      document.getElementById("uptime").textContent = formatDuration(runtime.uptime_seconds || 0);
      document.getElementById("headerMode").textContent = live.mode || "learn";
      document.getElementById("headerLoad").textContent = String(systemLoad) + "%";
      document.getElementById("networkMode").textContent = runtime.network_mode || "observer";
    }

    function renderControls(live) {
      document.querySelectorAll("[data-mode]").forEach(button => {
        button.classList.toggle("active", button.dataset.mode === live.mode);
        button.setAttribute("aria-pressed", String(button.dataset.mode === live.mode));
      });
    }

    function renderAiState(live) {
      const scan = live.scan || {};
      const faceState = live.pet_state || scan.face_state || "idle";
      const risk = scan.risk_score || 0;
      currentFaceState = faceState;
      animateFace();
      document.getElementById("aiHeadline").textContent = live.pet_headline || "Initialisierung";
      document.getElementById("aiCopy").textContent = live.thought || "Warte auf Live-Daten.";
      setPill(document.getElementById("aiStatusPill"), riskStatus(risk), riskLabel(risk));
    }

    function animateFace() {
      const variants = faceVariants[currentFaceState] || faceVariants.idle;
      document.getElementById("aiFace").textContent = variants[faceTick % variants.length];
      faceTick += 1;
    }

    function renderAssets(live) {
      const networkMap = live.network_map || {};
      const summary = networkMap.summary || {};
      document.getElementById("metricDevices").textContent = summary.devices ?? 0;
      document.getElementById("metricSubnets").textContent = summary.local_subnets ?? 0;
      document.getElementById("metricGateways").textContent = summary.gateways ?? 0;
      document.getElementById("metricRoutes").textContent = summary.routed_networks ?? 0;
      setPill(document.getElementById("assetCoverage"), "info", (summary.active_interfaces || 0) + " active ifaces");
      renderGraph(networkMap.graph || { nodes: [], edges: [] });
    }

    function renderThreatMatrix(live) {
      const findings = ((live.scan || {}).findings || []).map((finding, index) => ({
        ...finding,
        time: live.updated_at || "",
        index
      }));
      setPill(document.getElementById("matrixStatus"), findings.length ? riskStatus((live.scan || {}).risk_score || 0) : "safe", findings.length ? findings.length + " findings" : "clear");
      const sorted = findings.sort(compareThreats);
      const target = document.getElementById("threatRows");
      if (!sorted.length) {
        target.innerHTML = "<tr><td colspan='4'><div class='empty-state'>Keine aktiven Befunde im letzten Scan.</div></td></tr>";
        return;
      }
      target.innerHTML = sorted.map(finding => `
        <tr>
          <td>${pillHtml(finding.severity, severityLabel(finding.severity))}</td>
          <td><strong>${escapeHtml(finding.title)}</strong><div class="mono">${escapeHtml(finding.code)}</div></td>
          <td>${escapeHtml(finding.recommended_action || "Beobachten")}</td>
          <td class="mono">${escapeHtml(shortTime(finding.time))}</td>
        </tr>
      `).join("");
    }

    function renderFeed(live) {
      const findings = ((live.scan || {}).findings || []).slice(0, 6);
      const rows = [];
      rows.push({
        time: live.updated_at,
        title: "Scan abgeschlossen",
        detail: live.activity_summary || "Live-Daten aktualisiert.",
        severity: riskStatus((live.scan || {}).risk_score || 0)
      });
      for (const finding of findings) {
        rows.push({
          time: live.updated_at,
          title: finding.title,
          detail: finding.description,
          severity: finding.severity
        });
      }
      document.getElementById("feedCount").textContent = rows.length + " events";
      document.getElementById("feedRows").innerHTML = rows.map(row => `
        <div class="feed-row">
          <div class="feed-time">${escapeHtml(shortTime(row.time))}</div>
          <div><div class="feed-title">${escapeHtml(row.title)}</div><div class="feed-detail">${escapeHtml(row.detail)}</div></div>
          <div>${pillHtml(row.severity, severityLabel(row.severity))}</div>
        </div>
      `).join("");
    }

    function renderDevices(devices) {
      const target = document.getElementById("deviceRows");
      if (!devices.length) {
        target.innerHTML = "<tr><td colspan='4'><div class='empty-state'>Noch keine Geräte in der Baseline.</div></td></tr>";
        return;
      }
      target.innerHTML = devices.map(device => `
        <tr>
          <td>${escapeHtml(device.hostname || "Unbenannt")}</td>
          <td class="mono">${escapeHtml((device.ips || []).join(", ") || "-")}</td>
          <td class="mono">${escapeHtml(device.mac || "-")}</td>
          <td class="mono">${escapeHtml(shortTime(device.last_seen || "-"))}</td>
        </tr>
      `).join("");
    }

    function renderNeuralEngine(live) {
      const scan = live.scan || {};
      const ai = scan.ai || live.ai_engine || {};
      const neural = ai.neural || (live.ai_engine || {}).neural || {};
      const policy = ai.policy || (live.ai_engine || {}).policy || {};
      const backendReady = neural.backend_available !== false && (live.ai_engine || {}).neural_summary?.backend_available !== false;
      setPill(document.getElementById("nnStatusPill"), backendReady ? "info" : "attention", backendReady ? "PyTorch" : "Backend fehlt");
      const lines = [
        ["Backend", backendReady ? "pytorch aktiv" : "pytorch nicht installiert"],
        ["NN Score", String(neural.score ?? 0)],
        ["NN Samples", String(neural.observations ?? (live.ai_engine || {}).neural_summary?.observations ?? 0)],
        ["Policy", policy.action || (live.ai_engine || {}).policy_summary?.last_action || "warte"],
        ["Safety", policy.safety_gate || "allow"],
      ];
      document.getElementById("neuralDetails").innerHTML = lines.map(([label, value]) => `
        <div class="detail-line"><span>${escapeHtml(label)}</span><strong class="mono">${escapeHtml(value)}</strong></div>
      `).join("");
    }

    function renderArsenal(tools) {
      const target = document.getElementById("arsenalRows");
      document.getElementById("arsenalCount").textContent = tools.length + " tools";
      if (!tools.length) {
        target.innerHTML = "<div class='empty-state'>Keine Arsenal-Daten verfügbar.</div>";
        return;
      }
      const priority = ["ml", "observe", "diagnose", "respond", "integrate", "deploy"];
      const rows = tools
        .slice()
        .sort((a, b) => (priority.indexOf(a.category) - priority.indexOf(b.category)) || a.name.localeCompare(b.name))
        .slice(0, 12);
      target.innerHTML = rows.map(tool => `
        <div class="arsenal-line">
          <span class="mono">${escapeHtml(tool.category)}</span>
          <span>${escapeHtml(tool.name)}<br><span class="mono">${escapeHtml(tool.summary)}</span></span>
          ${pillHtml(tool.status === "available" ? "safe" : "info", tool.status)}
        </div>
      `).join("");
    }

    function renderLogs(live) {
      const state = live.state || {};
      const readiness = live.god_mode_readiness || {};
      const lines = [
        "mode=" + (live.mode || "learn"),
        "baseline=" + (state.baseline_ready ? "ready" : "learning"),
        "network_prevention=" + (readiness.can_prevent_network_wide ? "available" : "not-available"),
        "quiet_scans=" + (live.quiet_scans || 0),
      ];
      document.getElementById("controlLogs").innerHTML = lines.map(line => `<div class="log-line mono">${escapeHtml(line)}</div>`).join("");
    }

    function renderGraph(graph) {
      const svg = document.getElementById("networkGraph");
      const nodes = graph.nodes || [];
      const edges = graph.edges || [];
      const width = Math.max(360, svg.clientWidth || 360);
      const columns = { host: 72, interface: 184, subnet: 296, gateway: 408, "default-gateway": 408, endpoint: 408, "local-host": 408, "infrastructure-candidate": 408 };
      const grouped = {};
      for (const node of nodes) {
        const kind = node.kind || "endpoint";
        (grouped[kind] = grouped[kind] || []).push(node);
      }
      const positions = {};
      ["host", "interface", "subnet", "default-gateway", "gateway", "infrastructure-candidate", "endpoint", "local-host"].forEach(kind => {
        (grouped[kind] || []).forEach((node, index) => {
          positions[node.id] = { x: columns[kind] || 408, y: 48 + index * 64 };
        });
      });
      const height = Math.max(360, ...Object.values(positions).map(point => point.y + 56));
      svg.setAttribute("viewBox", `0 0 ${Math.max(width, 480)} ${height}`);
      const edgeSvg = edges.map(edge => {
        const source = positions[edge.source];
        const target = positions[edge.target];
        if (!source || !target) return "";
        return `<line class="link" x1="${source.x + 48}" y1="${source.y}" x2="${target.x - 48}" y2="${target.y}"></line>`;
      }).join("");
      const nodeSvg = nodes.map(node => {
        const point = positions[node.id];
        if (!point) return "";
        const meta = [node.ip, node.mac].filter(Boolean).join(" ");
        const label = node.label || node.id;
        const tooltip = [label, node.kind, meta].filter(Boolean).join(" | ");
        return `
          <g tabindex="0" data-tooltip="${escapeHtml(tooltip)}" onmousemove="showGraphTooltip(event)" onmouseleave="hideGraphTooltip()" onfocus="showGraphTooltip(event)" onblur="hideGraphTooltip()">
            <title>${escapeHtml(tooltip)}</title>
            <rect class="node ${escapeHtml(node.kind || "endpoint")}" x="${point.x - 48}" y="${point.y - 24}" width="96" height="48"></rect>
            <text class="nodeLabel" x="${point.x - 40}" y="${point.y - 4}">${escapeHtml(truncate(label, 14))}</text>
            <text class="nodeMeta" x="${point.x - 40}" y="${point.y + 12}">${escapeHtml(truncate(meta, 16))}</text>
          </g>
        `;
      }).join("");
      svg.innerHTML = edgeSvg + nodeSvg;
    }

    function showGraphTooltip(event) {
      const tooltip = document.getElementById("graphTooltip");
      const target = event.currentTarget;
      const bounds = document.getElementById("graphCanvas").getBoundingClientRect();
      const pointerX = Number.isFinite(event.offsetX) ? event.offsetX : Math.max(16, bounds.width - 256);
      const pointerY = Number.isFinite(event.offsetY) ? event.offsetY : 16;
      tooltip.textContent = target.dataset.tooltip || "";
      tooltip.style.display = "block";
      tooltip.style.left = Math.min(pointerX + 16, Math.max(16, bounds.width - 256)) + "px";
      tooltip.style.top = Math.max(pointerY + 16, 8) + "px";
    }

    function hideGraphTooltip() {
      document.getElementById("graphTooltip").style.display = "none";
    }

    function sortThreats(key) {
      if (threatSort.key === key) {
        threatSort.direction = threatSort.direction === "asc" ? "desc" : "asc";
      } else {
        threatSort = { key, direction: key === "title" ? "asc" : "desc" };
      }
      if (currentLive) renderThreatMatrix(currentLive);
    }

    function compareThreats(a, b) {
      const direction = threatSort.direction === "asc" ? 1 : -1;
      if (threatSort.key === "severity") return ((severityRank[a.severity] || 0) - (severityRank[b.severity] || 0)) * direction;
      if (threatSort.key === "title") return a.title.localeCompare(b.title) * direction;
      return (String(a.time).localeCompare(String(b.time)) || (a.index - b.index)) * direction;
    }

    async function setMode(mode) {
      const body = { mode };
      if (mode === "god") {
        const phrase = window.prompt("Autopilot fuehrt vorbereitete Schutzaktionen autonom aus. Netzwerkweiter Schutz braucht einen echten Enforcement-Punkt. Kein heimliches ARP/MitM. Tippe ACTIVATE GOD MODE.");
        if (phrase !== "ACTIVATE GOD MODE") return;
        body.confirm = phrase;
      }
      await fetch("/api/mode", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
      await refresh();
    }

    async function runLabScenario(scenario) {
      const result = await getJson("/api/simulate?scenario=" + encodeURIComponent(scenario));
      const lines = [
        "scenario=" + result.scenario,
        "isolated=" + String(result.isolated),
        "risk=" + String(result.risk_score),
        ...(result.lessons || []).slice(0, 3),
      ];
      document.getElementById("simulationLog").innerHTML = lines.map(line => `<div class="log-line">${escapeHtml(line)}</div>`).join("");
    }

    function exportSnapshot() {
      if (!currentLive) return;
      const blob = new Blob([JSON.stringify(currentLive, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = "protectogotchi-snapshot.json";
      link.click();
      URL.revokeObjectURL(url);
    }

    function setMobilePanel(panel) {
      activeMobilePanel = panel;
      document.querySelectorAll("[data-mobile-panel]").forEach(column => column.classList.toggle("active-mobile", column.dataset.mobilePanel === panel));
      document.querySelectorAll("[data-mobile-tab]").forEach(button => button.classList.toggle("active", button.dataset.mobileTab === panel));
    }

    document.getElementById("consoleGrid").addEventListener("touchstart", event => { touchStartX = event.changedTouches[0].clientX; }, { passive: true });
    document.getElementById("consoleGrid").addEventListener("touchend", event => {
      const delta = event.changedTouches[0].clientX - touchStartX;
      if (Math.abs(delta) < 48) return;
      const panels = ["assets", "matrix", "control"];
      const current = panels.indexOf(activeMobilePanel);
      const next = delta < 0 ? Math.min(current + 1, panels.length - 1) : Math.max(current - 1, 0);
      setMobilePanel(panels[next]);
    }, { passive: true });

    function setPill(element, status, label) {
      element.className = "status-pill status-" + status;
      element.textContent = label;
    }
    function pillHtml(status, label) { return `<span class="status-pill status-${statusClass(status)}">${escapeHtml(label)}</span>`; }
    function statusClass(status) {
      if (status === "critical" || status === "high") return "critical";
      if (status === "medium" || status === "low" || status === "attention") return "attention";
      if (status === "safe") return "safe";
      return "info";
    }
    function riskStatus(score) { return score >= 70 ? "critical" : (score >= 35 ? "attention" : "safe"); }
    function riskLabel(score) { return score >= 70 ? "kritisch" : (score >= 35 ? "aufmerksam" : "sicher"); }
    function severityLabel(severity) {
      return ({ critical: "kritisch", high: "hoch", medium: "mittel", low: "niedrig", info: "info", safe: "sicher", attention: "aufmerksam" })[severity] || severity;
    }
    function formatDuration(seconds) {
      const value = Math.max(0, Math.floor(seconds));
      const hours = Math.floor(value / 3600);
      const minutes = Math.floor((value % 3600) / 60);
      const secs = value % 60;
      if (hours) return `${hours}h ${minutes}m`;
      if (minutes) return `${minutes}m ${secs}s`;
      return `${secs}s`;
    }
    function shortTime(value) {
      if (!value || value === "-") return "-";
      const date = new Date(value);
      if (Number.isNaN(date.getTime())) return String(value).slice(0, 19);
      return date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
    }
    function truncate(value, length) {
      const text = String(value || "");
      return text.length > length ? text.slice(0, length - 1) + "…" : text;
    }
    function escapeHtml(value) {
      return String(value)
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#39;");
    }

    setMobilePanel("assets");
    refresh().catch(error => { document.getElementById("feedRows").innerHTML = `<div class="empty-state">${escapeHtml(String(error))}</div>`; });
    setInterval(animateFace, 900);
    setInterval(() => refresh().catch(() => {}), 1500);
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
        self.quiet_scans = 0
        self.started_monotonic = time.monotonic()

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
                    "runtime": _runtime_summary(self.config, self.mode, self.started_monotonic),
                    "state": _state_summary(self.config),
                    "scan": None,
                    "topology_summary": {},
                    "network_map": {},
                    "devices": [],
                    "finding_history": [],
                    "ai_engine": _ai_engine_summary(self.config),
                    "god_mode_readiness": god_mode_readiness(self.config),
                    "easy_protect_plan": easy_protect_plan(self.config),
                    "placement_report": build_placement_report(self.config).to_dict(),
                    "simulations": list(SCENARIOS),
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
                self.payload["runtime"] = _runtime_summary(
                    self.config,
                    mode,
                    self.started_monotonic,
                )
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
            if analysis_is_quiet(result):
                self.quiet_scans += 1
            else:
                self.quiet_scans = 0
            payload = _live_payload(
                self.config,
                result,
                topology,
                mode,
                quiet_scans=self.quiet_scans,
                runtime=_runtime_summary(self.config, mode, self.started_monotonic),
            )
        except Exception as exc:  # pragma: no cover - defensive runtime guard
            payload = {
                "updated_at": utc_now(),
                "error": str(exc),
                "mode": mode,
                "mode_description": WEB_MODES[mode]["description"],
                "runtime": _runtime_summary(self.config, mode, self.started_monotonic),
                "state": _state_summary(self.config),
                "scan": None,
                "topology_summary": {},
                "network_map": {},
                "devices": [],
                "finding_history": [],
                "ai_engine": _ai_engine_summary(self.config),
                "god_mode_readiness": god_mode_readiness(self.config),
                "easy_protect_plan": easy_protect_plan(self.config),
                "placement_report": build_placement_report(self.config).to_dict(),
                "simulations": list(SCENARIOS),
                "tools": [asdict(tool) for tool in list_tools()],
                "knowledge": [asdict(topic) for topic in list_topics()],
            }
        with self.lock:
            self.payload = payload
        return payload

    def _loop(self) -> None:
        while not self.stop_event.is_set():
            self.refresh_once()
            wait_for = self._next_wait()
            self.stop_event.wait(wait_for)

    def _next_wait(self) -> float:
        with self.lock:
            mode = self.mode
            quiet_scans = self.quiet_scans
        if mode == "pause":
            return self.scan_interval
        if quiet_scans >= 2:
            return 1.0
        return max(1.0, min(self.scan_interval, 2.0))


def _live_payload(
    config: ProtectogotchiConfig,
    result: ScanResult,
    topology: NetworkTopology,
    mode: str = "learn",
    quiet_scans: int = 0,
    runtime: dict | None = None,
) -> dict:
    state = StateStore(config.state_dir).load()
    network_map = NetworkMapper().build(result.snapshot)
    pet_state, headline, subtitle, thought, activity, calm_status = _pet_narration(result, mode, quiet_scans)
    return {
        "updated_at": utc_now(),
        "pet_state": pet_state,
        "pet_headline": headline,
        "pet_subtitle": subtitle,
        "thought": thought,
        "activity_summary": activity,
        "calm_status": calm_status,
        "quiet_scans": quiet_scans,
        "mode": mode,
        "mode_description": WEB_MODES[mode]["description"],
        "runtime": runtime or _runtime_summary(config, mode, time.monotonic()),
        "state": _state_summary(config),
        "scan": result.to_dict(),
        "topology_summary": topology.summary,
        "topology": topology.to_dict(),
        "network_map": network_map.to_dict(),
        "devices": sorted(state.devices.values(), key=lambda item: item.get("mac", "")),
        "finding_history": state.finding_history[-50:],
        "ai_engine": _ai_engine_summary(config, state),
        "god_mode_readiness": god_mode_readiness(config),
        "easy_protect_plan": easy_protect_plan(config),
        "placement_report": build_placement_report(config, network_map).to_dict(),
        "simulations": list(SCENARIOS),
        "tools": [asdict(tool) for tool in list_tools()],
        "knowledge": [asdict(topic) for topic in list_topics()],
    }



def analysis_is_quiet(result: ScanResult) -> bool:
    return result.risk_score < 10 and all(finding.severity == "info" for finding in result.findings)


def _ai_engine_summary(
    config: ProtectogotchiConfig,
    state=None,
) -> dict[str, object]:
    state = state or StateStore(config.state_dir).load()
    return {
        "neural_summary": neural_model_summary(state.neural_model),
        "policy_summary": policy_model_summary(state.policy_model),
    }


def _pet_narration(
    result: ScanResult,
    mode: str,
    quiet_scans: int,
) -> tuple[str, str, str, str, str, list[str]]:
    snapshot = result.snapshot
    finding_count = len([finding for finding in result.findings if finding.severity != "info"])
    connection_count = len(snapshot.connections)
    device_count = len(snapshot.devices)
    gateway = snapshot.default_gateway or "die Internet-Tür"

    if result.risk_score >= 70:
        pet_state = "alert"
        headline = "Aufgeregt"
        subtitle = "Eine starke Abweichung braucht Aufmerksamkeit."
        thought = "Ich sehe ein Muster, das nicht zur gelernten Normalität passt. Bitte prüfe die Hinweise mit Priorität."
    elif result.risk_score >= 35 or finding_count:
        pet_state = "curious"
        headline = "Aufmerksam"
        subtitle = "Es gibt Veränderungen, die beobachtet werden sollten."
        thought = "Die Lage ist nicht kritisch, aber ein paar Signale verdienen einen zweiten Blick."
    elif quiet_scans >= 2:
        pet_state = "bored"
        headline = "Gelangweilt"
        subtitle = "Längere Ruhe erkannt; ich erhöhe kurz die Kontrollfrequenz."
        thought = "Die letzten Scans waren unauffällig. Ich bleibe aktiv, wechsle aber in einen ruhigen Kontrollrhythmus."
    elif result.learned:
        pet_state = "learning"
        headline = "Lernend"
        subtitle = "Unauffällige Beobachtungen stärken die Baseline."
        thought = "Diese Beobachtung wirkt normal. Ich nutze sie, um die künftige Einschätzung genauer zu machen."
    else:
        pet_state = result.face_state if result.face_state in {"happy", "analyzing"} else "happy"
        headline = "Ruhig"
        subtitle = "Keine akute Auffälligkeit."
        thought = "Die aktuelle Lage wirkt stabil. Ich melde mich, sobald etwas Aufmerksamkeit braucht."

    if mode == "god":
        subtitle = "Autopilot ist aktiv: vorbereitete Schutzaktionen dürfen autonom laufen."
    elif mode == "guard":
        subtitle = "Schutzmodus: beobachten, vorsichtig lernen und Antworten vorbereiten."
    elif mode == "watch":
        subtitle = "Beobachten: keine Änderungen, nur klare Einordnung."
    elif mode == "pause":
        pet_state = "idle"
        headline = "Pausiert"
        subtitle = "Die Oberfläche bleibt offen, aber ich scanne nicht weiter."

    activity = (
        f"Aktuell sichtbar: {device_count} Gerät(e), {connection_count} Verbindung(en), Gateway {gateway}."
    )
    if finding_count:
        activity += f" Markierte Hinweise: {finding_count}."
    else:
        activity += " Keine akute Auffälligkeit."

    calm_status = [
        f"Modus: {mode}",
        f"Risiko-Zahl intern: {result.risk_score}/100",
        f"Geräte in diesem Blick: {device_count}",
        f"Verbindungen in diesem Blick: {connection_count}",
        f"Ruhige Scans hintereinander: {quiet_scans}",
    ]
    return pet_state, headline, subtitle, thought, activity, calm_status


def _runtime_summary(
    config: ProtectogotchiConfig,
    mode: str,
    started_monotonic: float,
) -> dict[str, object]:
    try:
        load_percent = min(100, round((os.getloadavg()[0] / max(1, os.cpu_count() or 1)) * 100))
    except (AttributeError, OSError):
        load_percent = 0
    return {
        "uptime_seconds": max(0, int(time.monotonic() - started_monotonic)),
        "mode": mode,
        "network_mode": config.deployment_mode,
        "response_mode": config.response_mode,
        "load_percent": load_percent,
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
    handler = _handler(config, collector_name, live_state)
    server = ThreadingHTTPServer((host, port), handler)
    live_state.start()
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
            if parsed.path == "/api/setup-wizard":
                live = live_state.current()
                self._send_json(live.get("placement_report", build_placement_report(config).to_dict()))
                return
            if parsed.path == "/api/simulations":
                self._send_json(list(SCENARIOS))
                return
            if parsed.path == "/api/simulate":
                scenario = query.get("scenario", ["arp-spoof"])[0]
                try:
                    self._send_json(run_simulation(scenario, config).to_dict())
                except ValueError as exc:
                    self._send_json({"error": str(exc)}, status=HTTPStatus.BAD_REQUEST)
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
