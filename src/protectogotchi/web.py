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
from protectogotchi.placement import build_placement_report
from protectogotchi.simulation import SCENARIOS, run_simulation
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
<html lang="de">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Protectogotchi</title>
  <style>
    :root {
      color-scheme: light;
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      --bg: #f7f8fa;
      --surface: #ffffff;
      --ink: #111827;
      --muted: #5f6b7a;
      --faint: #8a95a3;
      --line: #dfe4ea;
      --line-strong: #c8d0da;
      --accent: #2563eb;
      --good: #087f5b;
      --warn: #b7791f;
      --bad: #b4233b;
      --row: #f2f5f8;
      --focus: 0 0 0 3px rgba(37, 99, 235, .18);
    }
    * { box-sizing: border-box; }
    body { margin: 0; min-height: 100vh; color: var(--ink); background: var(--bg); }
    button { appearance: none; font: inherit; cursor: pointer; }
    .shell { width: min(1440px, 100%); margin: 0 auto; padding: 28px clamp(18px, 4vw, 48px) 48px; }
    .top { display: grid; grid-template-columns: 1fr auto; gap: 28px; align-items: end; padding-bottom: 28px; border-bottom: 1px solid var(--line-strong); }
    .product { display: flex; align-items: center; gap: 10px; color: var(--muted); font-size: 14px; margin-bottom: 14px; }
    .statusDot { width: 9px; height: 9px; border-radius: 50%; background: var(--good); }
    h1 { margin: 0; max-width: 980px; font-size: clamp(38px, 6vw, 76px); line-height: .96; letter-spacing: -.07em; font-weight: 850; }
    .lead { margin: 18px 0 0; max-width: 790px; color: var(--muted); font-size: clamp(16px, 2vw, 20px); line-height: 1.55; }
    .modeBar { display: flex; flex-wrap: wrap; gap: 6px; justify-content: flex-end; }
    .modeBar button, .tabs button, .plainButton { border: 1px solid var(--line); background: transparent; color: var(--muted); padding: 9px 12px; border-radius: 10px; }
    .modeBar button:hover, .tabs button:hover, .plainButton:hover { border-color: var(--line-strong); color: var(--ink); background: #fff; }
    .modeBar button:focus-visible, .tabs button:focus-visible, .plainButton:focus-visible { outline: none; box-shadow: var(--focus); }
    .modeBar button.active, .tabs button.active { color: var(--ink); background: var(--surface); border-color: var(--ink); }
    .layout { display: grid; grid-template-columns: minmax(270px, 350px) minmax(0, 1fr); gap: 34px; margin-top: 28px; align-items: start; }
    .side { position: sticky; top: 18px; border-top: 2px solid var(--ink); }
    .statusBlock { padding: 18px 0; border-bottom: 1px solid var(--line); }
    .statusTitle { margin: 0 0 6px; font-size: 24px; letter-spacing: -.035em; }
    .statusText { margin: 0; color: var(--muted); line-height: 1.5; }
    .thinking { padding: 18px 0; border-bottom: 1px solid var(--line); }
    .label { display: block; margin-bottom: 8px; color: var(--faint); font-size: 12px; font-weight: 760; letter-spacing: .12em; text-transform: uppercase; }
    .thought { margin: 0; line-height: 1.55; }
    .metrics { display: grid; gap: 0; border-bottom: 1px solid var(--line); }
    .metric { display: grid; grid-template-columns: 1fr auto; gap: 16px; padding: 13px 0; border-top: 1px solid var(--line); }
    .metric span { color: var(--muted); }
    .metric strong { font-size: 18px; letter-spacing: -.03em; }
    .risk-low { color: var(--good); } .risk-mid { color: var(--warn); } .risk-high { color: var(--bad); }
    .tabs { position: sticky; top: 0; z-index: 5; display: flex; gap: 6px; flex-wrap: wrap; padding: 0 0 18px; margin-bottom: 4px; background: linear-gradient(var(--bg) 82%, rgba(247,248,250,0)); }
    .panel { display: none; } .panel.active { display: block; }
    .section { padding: 28px 0; border-top: 1px solid var(--line-strong); }
    .section:first-child { border-top: 0; padding-top: 0; }
    .sectionHeader { display: grid; grid-template-columns: minmax(0, 1fr) minmax(220px, 34%); gap: 28px; align-items: start; margin-bottom: 18px; }
    h2 { margin: 0; font-size: clamp(24px, 3vw, 40px); line-height: 1.05; letter-spacing: -.055em; }
    .sectionLead { margin: 0; color: var(--muted); line-height: 1.55; }
    .summaryLine { display: flex; flex-wrap: wrap; gap: 0; border-top: 1px solid var(--line); border-bottom: 1px solid var(--line); }
    .summaryItem { flex: 1 1 170px; padding: 14px 16px 14px 0; border-right: 1px solid var(--line); }
    .summaryItem:last-child { border-right: 0; }
    .summaryItem small { display: block; color: var(--faint); font-size: 12px; letter-spacing: .08em; text-transform: uppercase; margin-bottom: 5px; }
    .summaryItem strong { display: block; font-size: 18px; letter-spacing: -.025em; }
    .mapFrame { border-top: 1px solid var(--line); border-bottom: 1px solid var(--line); padding: 16px 0; }
    svg { width: 100%; min-height: 390px; background: transparent; }
    .nodeLabel { font: 13px ui-sans-serif, system-ui; fill: var(--ink); font-weight: 760; }
    .nodeMeta { font: 10px ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; fill: var(--muted); }
    .link { stroke: #aeb8c5; stroke-width: 1.5; stroke-linecap: round; }
    .node { fill: #fff; stroke: #aeb8c5; stroke-width: 1.2; rx: 8; ry: 8; }
    .node.gateway, .node.default-gateway { stroke: var(--accent); stroke-width: 2; }
    .node.host { fill: #eef4ff; } .node.subnet { fill: #f6f8fb; } .node.interface { fill: #eefaf5; }
    .list { border-top: 1px solid var(--line); }
    .row { display: grid; grid-template-columns: minmax(170px, 28%) minmax(0, 1fr); gap: 22px; padding: 16px 0; border-bottom: 1px solid var(--line); line-height: 1.5; }
    .rowTitle { font-weight: 760; }
    .rowBody { color: var(--muted); }
    .rowBody strong { color: var(--ink); }
    .quietbar { height: 8px; background: #e7ebf0; margin-top: 12px; overflow: hidden; }
    .quietbar > span { display:block; height: 100%; background: var(--accent); }
    .split { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 34px; }
    table { width: 100%; border-collapse: collapse; border-top: 1px solid var(--line); }
    th, td { text-align: left; padding: 14px 10px 14px 0; border-bottom: 1px solid var(--line); vertical-align: top; }
    th { color: var(--faint); font-size: 12px; letter-spacing: .08em; text-transform: uppercase; }
    code { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 12px; color: #4b5563; }
    .severity-critical, .severity-high { color: var(--bad); } .severity-medium { color: var(--warn); }
    @media (max-width: 980px) { .top, .layout, .sectionHeader, .split { grid-template-columns: 1fr; } .modeBar { justify-content: flex-start; } .side, .tabs { position: static; } }
    @media (max-width: 640px) { .shell { padding-inline: 16px; } .row { grid-template-columns: 1fr; gap: 4px; } .summaryItem { border-right: 0; border-bottom: 1px solid var(--line); } }
  </style>
</head>
<body>
  <div class="shell">
    <header class="top">
      <div>
        <div class="product"><span class="statusDot"></span><span id="liveText">Live-Status wird geladen</span></div>
        <h1>Netzwerkstatus klar, ruhig und verständlich.</h1>
        <p class="lead">Diese Oberfläche erklärt, was im lokalen Netzwerk passiert, ohne Rohdatenwände und ohne Fachsprache. Details bleiben verfügbar, werden aber in lesbare Aussagen übersetzt.</p>
      </div>
      <div class="modeBar" aria-label="Modus"><button data-mode="learn" class="active" onclick="setMode('learn')">Lernen</button><button data-mode="watch" onclick="setMode('watch')">Nur beobachten</button><button data-mode="guard" onclick="setMode('guard')">Schützen</button><button data-mode="god" onclick="setMode('god')">Autopilot</button><button data-mode="pause" onclick="setMode('pause')">Pause</button></div>
    </header>
    <main class="layout">
      <aside class="side" aria-label="Status">
        <div class="statusBlock"><span class="label">Aktueller Zustand</span><h2 class="statusTitle" id="state">Wird geladen</h2><p class="statusText" id="mood">Die erste Prüfung läuft.</p></div>
        <div class="thinking"><span class="label">Einordnung</span><p class="thought" id="thought">Ich prüfe gerade, ob etwas vom normalen Muster abweicht.</p></div>
        <div class="metrics"><div class="metric"><span>Risiko</span><strong id="risk">-</strong></div><div class="metric"><span>Lernstand</span><strong id="level">-</strong></div><div class="metric"><span>Basis gelernt</span><strong id="baseline">-</strong></div><div class="metric"><span>Geräte</span><strong id="devicesCount">-</strong></div></div>
      </aside>
      <div class="content">
        <nav class="tabs" aria-label="Ansichten"><button data-tab="home" class="active" onclick="switchTab('home')">Übersicht</button><button data-tab="now" onclick="switchTab('now')">Live</button><button data-tab="worries" onclick="switchTab('worries')">Hinweise</button><button data-tab="neighbors" onclick="switchTab('neighbors')">Geräte</button><button data-tab="practice" onclick="switchTab('practice')">Simulation</button><button data-tab="help" onclick="switchTab('help')">System</button></nav>
        <section class="panel active" data-panel="home"><section class="section"><div class="sectionHeader"><h2>Überblick</h2><p class="sectionLead">Die wichtigsten Fakten in einem Satz pro Thema: Verbindung nach draußen, bekannte Geräte, aktueller Modus und sichtbare Aktivität.</p></div><div class="summaryLine" id="plainSummary"></div></section><section class="section"><div class="sectionHeader"><h2>Netzwerkkarte</h2><p class="sectionLead">Eine reduzierte Karte zeigt nur die Struktur, die für Orientierung wichtig ist.</p></div><div class="mapFrame"><svg id="networkGraph" role="img" aria-label="Einfache Netzwerkkarte"></svg></div></section><section class="section"><div class="sectionHeader"><h2>Wachsamkeit</h2><p class="sectionLead">Wenn über mehrere Prüfungen nichts Auffälliges passiert, prüft Protectogotchi häufiger im Hintergrund. Das wird hier transparent angezeigt.</p></div><div id="watchfulness" class="list"></div></section></section>
        <section class="panel" data-panel="now"><section class="section"><div class="sectionHeader"><h2>Live-Aktivität</h2><p class="sectionLead">Aktuelle Bewegungen werden als verständliche Ereignisse beschrieben. Keine rohen JSON-Daten, keine Protokollwand.</p></div><div id="activity" class="list">lädt...</div></section><div class="split"><section class="section"><div class="sectionHeader"><h2>Zusammenfassung</h2><p class="sectionLead">Was gerade wichtig ist.</p></div><div id="networkDetail" class="list">lädt...</div></section><section class="section"><div class="sectionHeader"><h2>Sichtbarkeit</h2><p class="sectionLead">Was die aktuelle Platzierung gut oder weniger gut erkennen kann.</p></div><div id="coverage" class="list">lädt...</div></section></div></section>
        <section class="panel" data-panel="worries"><section class="section"><div class="sectionHeader"><h2>Hinweise und Empfehlungen</h2><p class="sectionLead">Auffälligkeiten werden nach Dringlichkeit erklärt und mit einer konkreten nächsten Handlung versehen.</p></div><div id="findings" class="list">lädt...</div></section><section class="section"><div class="sectionHeader"><h2>Verlauf</h2><p class="sectionLead">Die letzten gemerkten Hinweise, damit Veränderungen nachvollziehbar bleiben.</p></div><div id="history" class="list">lädt...</div></section></section>
        <section class="panel" data-panel="neighbors"><section class="section"><div class="sectionHeader"><h2>Bekannte Geräte</h2><p class="sectionLead">Geräte werden nach Name, Adresse, Häufigkeit und letzter Sichtung sortiert dargestellt.</p></div><table><thead><tr><th>Name</th><th>Adresse</th><th>Gesehen</th><th>Zuletzt</th></tr></thead><tbody id="devices"></tbody></table></section></section>
        <section class="panel" data-panel="practice"><section class="section"><div class="sectionHeader"><h2>Simulation</h2><p class="sectionLead">Gefahrensituationen können gefahrlos mit synthetischen Daten ausprobiert werden.</p></div><div id="simulationButtons" class="summaryLine"></div><div id="simulation" class="list"><div class="row"><div class="rowTitle">Bereit</div><div class="rowBody">Wähle ein Szenario aus.</div></div></div></section><section class="section"><div class="sectionHeader"><h2>Platzierung</h2><p class="sectionLead">Zeigt ehrlich, was diese Installation erkennen oder verhindern kann.</p></div><div id="placement" class="list">lädt...</div></section></section>
        <section class="panel" data-panel="help"><div class="split"><section class="section"><div class="sectionHeader"><h2>Werkzeuge</h2><p class="sectionLead">Welche lokalen Funktionen verfügbar sind.</p></div><div id="tools" class="list">lädt...</div></section><section class="section"><div class="sectionHeader"><h2>Wissen</h2><p class="sectionLead">Welche Themen Protectogotchi erklären kann.</p></div><div id="knowledge" class="list">lädt...</div></section></div></section>
      </div>
    </main>
  </div>
  <script>
    const modeNames = { learn:"Lernen", watch:"Nur beobachten", guard:"Schützen", god:"Autopilot", pause:"Pause" };
    async function getJson(path){ const r=await fetch(path); if(!r.ok) throw new Error(path+" -> "+r.status); return r.json(); }
    function severityWord(s){ return ({info:"Information",low:"Niedrig",medium:"Mittel",high:"Hoch",critical:"Kritisch"})[s] || s; }
    function riskWord(score){ if(score>=70) return "hoch"; if(score>=35) return "mittel"; return "niedrig"; }
    async function refresh(){
      const live=await getJson('/api/live'); const scan=live.scan||{}; const state=live.state||{}; const snapshot=scan.snapshot||{};
      document.getElementById('state').textContent=live.pet_headline || modeNames[live.mode] || 'Aktiv'; document.getElementById('mood').textContent=live.pet_subtitle || live.mode_description || '';
      document.getElementById('thought').textContent=live.thought || 'Keine akute Abweichung erkannt.'; renderMode(live.mode||'learn');
      document.getElementById('risk').textContent=riskWord(scan.risk_score||0); document.getElementById('risk').className=(scan.risk_score||0)>=70?'risk-high':((scan.risk_score||0)>=35?'risk-mid':'risk-low'); document.getElementById('level').textContent=state.level??'-'; document.getElementById('baseline').textContent=state.baseline_ready?'ja':((state.learning_remaining||0)+' Prüfungen'); document.getElementById('devicesCount').textContent=state.known_devices??'-'; document.getElementById('liveText').textContent='Aktualisiert: '+(live.updated_at||'gerade');
      renderPlainSummary(live, snapshot); renderWatchfulness(live); renderActivity(live, snapshot); renderGraph((live.network_map||{}).graph||{nodes:[],edges:[]}); renderFindings(scan.findings||[]); renderHistory(live.finding_history||[]); renderDevices(live.devices||[]); renderPlacement(live.placement_report||{}); renderSimulationButtons(live.simulations||[]); renderNetworkStory(live, snapshot); renderCoverage(live); renderTools(live.tools||[]); renderKnowledge(live.knowledge||[]);
    }
    function row(title, body, extra=''){ return `<div class="row"><div class="rowTitle">${escapeHtml(title)}</div><div class="rowBody">${body}${extra}</div></div>`; }
    function renderPlainSummary(live,s){ const items=[['WLAN', (s.wifi||{}).ssid || 'nicht erkannt'], ['Gateway', s.default_gateway || 'unbekannt'], ['Modus', modeNames[live.mode] || live.mode], ['Aktivität', (s.connections||[]).length+' Verbindungen'], ['Geräte', (s.devices||[]).length+' sichtbar']]; document.getElementById('plainSummary').innerHTML=items.map(i=>`<div class="summaryItem"><small>${escapeHtml(i[0])}</small><strong>${escapeHtml(i[1])}</strong></div>`).join(''); }
    function renderWatchfulness(live){ const quiet=live.quiet_scans||0; const pct=Math.min(100, quiet*25); const text=quiet>=2?'Seit mehreren Prüfungen unauffällig. Die Hintergrundprüfung läuft jetzt häufiger.':'Normale Hintergrundprüfung aktiv.'; document.getElementById('watchfulness').innerHTML=row('Prüfrhythmus', escapeHtml(text)+`<div class="quietbar"><span style="width:${pct}%"></span></div><div>Ruhige Prüfungen in Folge: ${quiet}</div>`); }
    function renderActivity(live,s){ const findings=(live.scan||{}).findings||[]; const lines=[]; lines.push(row(findings.length?'Auffälligkeit erkannt':'Keine Auffälligkeit', escapeHtml(live.activity_summary||'Aktuell keine ungewöhnliche Netzwerkaktivität.'))); (s.connections||[]).slice(0,8).forEach(c=>lines.push(row(c.protocol||'Verbindung', `Von ${escapeHtml(c.local_address||'lokal')} zu ${escapeHtml(c.remote_address||'extern/lokal')}. Status: ${escapeHtml(c.state||'unbekannt')}.`))); document.getElementById('activity').innerHTML=lines.join(''); }
    function renderNetworkStory(live,s){ const summary=(live.network_map||{}).summary||{}; const rows=[['Gateway', escapeHtml(s.default_gateway || 'Noch nicht erkannt')], ['Karte', escapeHtml(Object.entries(summary).map(([k,v])=>`${v}× ${k}`).join(', ') || 'Noch keine verwertbare Karte')], ['Aktivität', (s.connections||[]).length ? `${s.connections.length} aktuell sichtbare Verbindung(en)` : 'Keine aktuell sichtbare Verbindung']]; document.getElementById('networkDetail').innerHTML=rows.map(r=>row(r[0], r[1])).join(''); }
    function renderCoverage(live){ const coverage=((live.network_map||{}).coverage||[]); document.getElementById('coverage').innerHTML=(coverage.length?coverage:['Noch keine Aussage zur Abdeckung verfügbar.']).map(line=>row('Abdeckung', escapeHtml(line))).join(''); }
    function renderFindings(findings){ const t=document.getElementById('findings'); if(!findings.length){t.innerHTML=row('Keine Hinweise', 'Aktuell gibt es nichts, das Aufmerksamkeit braucht.'); return;} t.innerHTML=findings.map(f=>row(`${severityWord(f.severity)}: ${f.title}`, `${escapeHtml(f.description)}<br><strong>Empfehlung:</strong> ${escapeHtml(f.recommended_action||'beobachten')}`)).join(''); }
    function renderHistory(history){ const t=document.getElementById('history'); if(!history.length){t.innerHTML=row('Noch kein Verlauf', 'Bisher wurden keine Hinweise gespeichert.'); return;} t.innerHTML=history.slice(-10).reverse().map(f=>row(f.title, `${escapeHtml(f.seen_at)} · ${severityWord(f.severity)}`)).join(''); }
    function renderDevices(devices){ document.getElementById('devices').innerHTML=devices.map(d=>`<tr><td>${escapeHtml(d.hostname||'Unbenanntes Gerät')}<br><code>${escapeHtml(d.mac)}</code></td><td>${escapeHtml((d.ips||[]).join(', ')||'-')}</td><td>${d.seen_count||0}×</td><td>${escapeHtml(d.last_seen||'-')}</td></tr>`).join('') || '<tr><td colspan="4" class="muted">Noch keine Geräte gelernt.</td></tr>'; }
    function renderPlacement(r){ const items=[['Kurzfassung', r.summary||'noch unbekannt'], ['Schutz aktiv', r.active_response_enabled?'ja':'nein'], ['Automatisierung', r.firewall_controller_automation?'ja':'nein']]; const steps=(r.next_steps||[]).map(s=>row('Nächster Schritt', escapeHtml(s))).join(''); document.getElementById('placement').innerHTML=items.map(i=>row(i[0], escapeHtml(i[1]))).join('')+steps; }
    function renderSimulationButtons(s){ document.getElementById('simulationButtons').innerHTML=s.map(n=>`<div class="summaryItem"><button class="plainButton" onclick="runLabScenario('${escapeHtml(n)}')">${escapeHtml(n)}</button></div>`).join(''); }
    async function runLabScenario(scenario){ const r=await getJson('/api/simulate?scenario='+encodeURIComponent(scenario)); document.getElementById('simulation').innerHTML=row(r.scenario, `Bewertung: ${riskWord(r.risk_score||0)}.`)+((r.lessons||[]).map(l=>row('Lerneffekt', escapeHtml(l))).join('')); }
    function renderTools(tools){ document.getElementById('tools').innerHTML=tools.map(t=>row(t.name, `${escapeHtml(t.status)}`)).join('') || row('Keine Werkzeuge', 'Keine lokalen Werkzeuge gemeldet.'); }
    function renderKnowledge(topics){ document.getElementById('knowledge').innerHTML=topics.map(t=>row(t.name, `Bereich: ${escapeHtml(t.domain)}`)).join('') || row('Kein Wissen', 'Noch keine Themen geladen.'); }
    function renderGraph(graph){ const svg=document.getElementById('networkGraph'), nodes=graph.nodes||[], edges=graph.edges||[], width=Math.max(760,svg.clientWidth||760), columns={host:90,interface:250,subnet:430,gateway:630,'default-gateway':630,endpoint:630,'local-host':630,'infrastructure-candidate':630}, grouped={}; nodes.forEach(n=>{const k=n.kind||'endpoint'; (grouped[k]=grouped[k]||[]).push(n);}); const pos={}; ['host','interface','subnet','default-gateway','gateway','infrastructure-candidate','endpoint','local-host'].forEach(k=>(grouped[k]||[]).forEach((n,i)=>pos[n.id]={x:columns[k]||630,y:65+i*70})); const height=Math.max(390,...Object.values(pos).map(p=>p.y+55)); svg.setAttribute('viewBox',`0 0 ${width} ${height}`); svg.innerHTML=edges.map(e=>pos[e.source]&&pos[e.target]?`<line class="link" x1="${pos[e.source].x+62}" y1="${pos[e.source].y}" x2="${pos[e.target].x-62}" y2="${pos[e.target].y}"></line>`:'').join('')+nodes.map(n=>{const p=pos[n.id]; if(!p)return''; return `<g><rect class="node ${n.kind||'endpoint'}" x="${p.x-62}" y="${p.y-24}" width="124" height="48"></rect><text class="nodeLabel" x="${p.x-52}" y="${p.y-4}">${escapeHtml(n.label||n.id)}</text><text class="nodeMeta" x="${p.x-52}" y="${p.y+13}">${escapeHtml([n.ip,n.mac].filter(Boolean).join(' · '))}</text></g>`}).join(''); }
    function escapeHtml(v){ return String(v).replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;').replaceAll('"','&quot;').replaceAll("'",'&#39;'); }
    function switchTab(tab){ document.querySelectorAll('[data-tab]').forEach(b=>b.classList.toggle('active',b.dataset.tab===tab)); document.querySelectorAll('[data-panel]').forEach(p=>p.classList.toggle('active',p.dataset.panel===tab)); }
    function renderMode(mode){ document.querySelectorAll('[data-mode]').forEach(b=>b.classList.toggle('active',b.dataset.mode===mode)); }
    async function setMode(mode){ let body={mode}; if(mode==='god'){ const phrase=window.prompt('Autopilot handelt selbstständiger. Schutz im ganzen Netzwerk braucht Router, Firewall oder ähnliches. Es wird kein heimliches ARP/MitM aktiviert. Tippe ACTIVATE GOD MODE.'); if(phrase!=='ACTIVATE GOD MODE') return; body.confirm=phrase; } await fetch('/api/mode',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)}); await refresh(); }
    refresh().catch(e=>document.getElementById('liveText').textContent=String(e)); setInterval(()=>refresh().catch(e=>document.getElementById('liveText').textContent=String(e)),1500);
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
            payload = _live_payload(self.config, result, topology, mode, quiet_scans=self.quiet_scans)
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
        "state": _state_summary(config),
        "scan": result.to_dict(),
        "topology_summary": topology.summary,
        "topology": topology.to_dict(),
        "network_map": network_map.to_dict(),
        "devices": sorted(state.devices.values(), key=lambda item: item.get("mac", "")),
        "finding_history": state.finding_history[-50:],
        "god_mode_readiness": god_mode_readiness(config),
        "easy_protect_plan": easy_protect_plan(config),
        "placement_report": build_placement_report(config, network_map).to_dict(),
        "simulations": list(SCENARIOS),
        "tools": [asdict(tool) for tool in list_tools()],
        "knowledge": [asdict(topic) for topic in list_topics()],
    }



def analysis_is_quiet(result: ScanResult) -> bool:
    return result.risk_score < 10 and all(finding.severity == "info" for finding in result.findings)


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
        headline = "Oh! Das wirkt wichtig"
        subtitle = "Ich bleibe dicht dran und sammle Hinweise."
        thought = "Da ist etwas, das nicht zu deinem normalen Zuhause passt. Ich erkläre es unten ohne Technik-Kauderwelsch."
    elif result.risk_score >= 35 or finding_count:
        pet_state = "curious"
        headline = "Ich bin neugierig"
        subtitle = "Ein paar Dinge verdienen einen zweiten Blick."
        thought = "Nichts zum Panischwerden, aber ich möchte diese Veränderung lieber beobachten."
    elif quiet_scans >= 2:
        pet_state = "bored"
        headline = "Mir ist fast langweilig"
        subtitle = "Alles ist ruhig. Damit mir nicht langweilig wird, schaue ich selbstständig öfter kurz nach."
        thought = "Keine neuen Geräusche im Netzwerk. Mir wird ein bisschen langweilig, also mache ich extra Kontrollblicke und halte die Ohren flauschig offen."
    elif result.learned:
        pet_state = "learning"
        headline = "Ich lerne dein Zuhause"
        subtitle = "Saubere Beobachtungen merke ich mir als normal."
        thought = "Dieses Muster sieht freundlich aus. Ich lege es in mein kleines Gedächtnis."
    else:
        pet_state = result.face_state if result.face_state in {"happy", "analyzing"} else "happy"
        headline = "Alles wirkt ruhig"
        subtitle = "Ich passe leise im Hintergrund auf."
        thought = "Ich sehe keine akute Sorge. Wenn sich etwas komisch anfühlt, sage ich es hier in einfachen Worten."

    if mode == "god":
        subtitle = "Autopilot ist an: ich darf vorbereitete Schutzaktionen selbst ausführen."
    elif mode == "guard":
        subtitle = "Wächtermodus: ich beobachte, lerne vorsichtig und plane Schutz."
    elif mode == "watch":
        subtitle = "Nur schauen: ich verändere nichts und erzähle nur, was ich sehe."
    elif mode == "pause":
        pet_state = "idle"
        headline = "Ich mache Pause"
        subtitle = "Die Oberfläche bleibt offen, aber ich scanne nicht weiter."

    activity = (
        f"Ich sehe {device_count} Gerät(e), {connection_count} Verbindung(en) und nutze {gateway} als Ausgang nach draußen."
    )
    if finding_count:
        activity += f" Dabei habe ich {finding_count} Sorge(n) markiert."
    else:
        activity += " Gerade klingt das unauffällig."

    calm_status = [
        f"Modus: {mode}",
        f"Risiko-Zahl intern: {result.risk_score}/100",
        f"Geräte in diesem Blick: {device_count}",
        f"Verbindungen in diesem Blick: {connection_count}",
        f"Ruhige Blicke hintereinander: {quiet_scans}",
    ]
    return pet_state, headline, subtitle, thought, activity, calm_status

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
