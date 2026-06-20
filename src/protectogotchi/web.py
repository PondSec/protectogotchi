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
        "description": "Lernt unauffällige Beobachtungen als normales Verhalten.",
    },
    "watch": {
        "label": "Watch",
        "description": "Beobachtet und bewertet, ohne die Baseline zu verändern.",
    },
    "guard": {
        "label": "Guard",
        "description": "Beobachtet, lernt vorsichtig und bereitet Schutzreaktionen vor.",
    },
    "god": {
        "label": "God",
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
      color-scheme: light;
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      --bg: #f6f8fb;
      --ink: #17202a;
      --soft-ink: #64748b;
      --faint-ink: #8a98aa;
      --line: #d8e0ea;
      --panel: #ffffff;
      --panel-soft: #f9fbfd;
      --good: #0f766e;
      --wait: #b7791f;
      --bad: #b42318;
      --focus: #1f3a5f;
      --blue-soft: #e8f1ff;
      --green-soft: #e7f7ef;
      --amber-soft: #fff4db;
      --red-soft: #ffebe8;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      min-height: 100vh;
      color: var(--ink);
      background: var(--bg);
    }
    button { appearance: none; border: 0; font: inherit; cursor: pointer; }
    .app { width: min(1440px, 100%); margin: 0 auto; padding: 0 clamp(18px, 4vw, 46px) 42px; }
    .topbar { display: flex; align-items: flex-start; justify-content: space-between; gap: 28px; padding: 26px 0 22px; border-bottom: 1px solid var(--line); margin-bottom: 0; }
    .brandMark { display: inline-flex; align-items: center; gap: 10px; color: var(--soft-ink); font-size: 14px; }
    .brandDot { width: 10px; height: 10px; border-radius: 99px; background: var(--good); box-shadow: 0 0 0 7px rgba(18,128,107,.12); }
    h1 { margin: 12px 0 8px; font-size: clamp(34px, 5vw, 64px); line-height: 1.03; letter-spacing: 0; max-width: 940px; font-weight: 780; }
    .subtitle { margin: 0; max-width: 790px; color: var(--soft-ink); font-size: clamp(16px, 1.8vw, 20px); line-height: 1.55; }
    .modeDock { display: flex; flex-wrap: wrap; gap: 8px; justify-content: flex-end; max-width: 520px; }
    .modeDock button, .tabs button, .pillButton { border-radius: 8px; padding: 10px 13px; color: var(--ink); background: transparent; border: 1px solid var(--line); }
    .modeDock button:hover, .tabs button:hover, .pillButton:hover { background: var(--panel-soft); }
    .modeDock button.active, .tabs button.active { color: #fff; background: var(--focus); border-color: var(--focus); }
    .dashboard { display: grid; grid-template-columns: minmax(280px, 360px) minmax(0, 1fr); gap: 30px; align-items: start; }
    .companion { position: sticky; top: 0; display: grid; gap: 0; padding-top: 22px; border-right: 1px solid var(--line); min-height: calc(100vh - 98px); padding-right: 28px; }
    .mascotPanel, .section, .tabs { background: transparent; border: 0; border-radius: 0; box-shadow: none; backdrop-filter: none; }
    .mascotPanel { padding: 0 0 22px; overflow: hidden; border-bottom: 1px solid var(--line); margin-bottom: 20px; }
    .mascotHero { display: grid; grid-template-columns: 118px 1fr; gap: 18px; align-items: center; }
    .petBlob { width: 118px; aspect-ratio: 1; border-radius: 14px; display: grid; place-items: center; background: var(--panel); border: 1px solid var(--line); }
    .face { font: 850 34px/1 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
    .state { margin: 0 0 6px; font-size: 25px; font-weight: 760; letter-spacing: 0; }
    .muted { color: var(--soft-ink); }
    .thoughtCloud { margin-top: 22px; padding: 16px 0 0; border-top: 1px solid var(--line); line-height: 1.55; }
    .thoughtCloud::after { content: none; }
    .eyebrow { display: block; margin-bottom: 6px; color: var(--faint-ink); font-size: 12px; font-weight: 760; letter-spacing: .08em; text-transform: uppercase; }
    .senseGrid { display: grid; grid-template-columns: repeat(2, minmax(0,1fr)); gap: 0; border-top: 1px solid var(--line); border-bottom: 1px solid var(--line); }
    .sense { padding: 15px 0; border-top: 1px solid var(--line); }
    .sense:nth-child(-n+2) { border-top: 0; }
    .sense span { display:block; font-size: 12px; color: var(--soft-ink); }
    .sense strong { display:block; margin-top: 3px; font-size: 24px; letter-spacing: 0; }
    .risk-low { color: var(--good); } .risk-mid { color: var(--wait); } .risk-high { color: var(--bad); }
    .work { padding-top: 22px; }
    .tabs { position: sticky; top: 0; z-index: 5; display: flex; gap: 8px; flex-wrap: wrap; padding: 0 0 18px; margin-bottom: 0; background: var(--bg); border-bottom: 1px solid var(--line); }
    .panel { display: none; } .panel.active { display: grid; gap: 0; }
    .section { padding: 28px 0; overflow: hidden; border-bottom: 1px solid var(--line); }
    .sectionTitle { margin: 0 0 8px; font-size: clamp(24px, 2.6vw, 36px); letter-spacing: 0; font-weight: 760; }
    .sectionLead { margin: 0 0 22px; color: var(--soft-ink); line-height: 1.55; max-width: 850px; }
    .two { display: grid; grid-template-columns: repeat(2, minmax(0,1fr)); gap: 28px; }
    .lineList { display: grid; gap: 0; }
    .story { padding: 15px 0; border-top: 1px solid var(--line); line-height: 1.5; }
    .story:first-child { border-top: 0; padding-top: 0; }
    .story strong { display:block; margin-bottom: 4px; }
    .softStrip { display:flex; flex-wrap:wrap; gap:10px; margin: 14px 0 0; }
    .tag { display:inline-flex; align-items:center; gap:8px; border-radius:8px; padding:8px 10px; background: var(--panel); border:1px solid var(--line); color:var(--soft-ink); }
    .quietbar { height: 10px; border-radius: 5px; overflow:hidden; background:#e6ebf2; margin-top: 12px; }
    .quietbar > span { display:block; height:100%; background:linear-gradient(90deg,var(--good),#7aa7d9); }
    .mapWrap { padding: 0; background: transparent; border-top:1px solid var(--line); border-bottom:1px solid var(--line); }
    svg { width: 100%; min-height: 390px; background: var(--panel-soft); }
    .nodeLabel { font: 13px ui-sans-serif, system-ui; fill: var(--ink); font-weight: 800; }
    .nodeMeta { font: 10px ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; fill: var(--soft-ink); }
    .link { stroke: #aab8c8; stroke-width: 1.5; stroke-linecap: round; }
    .node { fill: #ffffff; stroke: #cbd5e1; stroke-width: 1.3; rx: 8; ry: 8; }
    .node.gateway, .node.default-gateway { stroke: var(--good); stroke-width: 2.5; }
    .node.host { fill: var(--blue-soft); } .node.subnet { fill: var(--panel); } .node.interface { fill: var(--green-soft); }
    .miniTable { width: 100%; border-collapse: collapse; }
    .miniTable th, .miniTable td { text-align:left; padding: 13px 8px; border-top:1px solid var(--line); vertical-align:top; }
    .miniTable th { color: var(--soft-ink); font-size:12px; letter-spacing:.08em; text-transform:uppercase; }
    code { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 12px; color: #42526a; }
    .tinyDetail { margin-top: 10px; color: var(--soft-ink); font-size: 13px; }
    .severity-critical, .severity-high { color: var(--bad); } .severity-medium { color: var(--wait); }
    @media (max-width: 980px) { .topbar, .dashboard, .two { grid-template-columns: 1fr; display: grid; } .modeDock { justify-content: flex-start; } .companion, .tabs { position: static; } .companion { border-right: 0; min-height: auto; padding-right: 0; } }
    @media (max-width: 560px) { .mascotHero { grid-template-columns: 1fr; } .petBlob { width: 112px; } .senseGrid { grid-template-columns: 1fr; } }
  </style>
</head>
<body>
  <div class="app">
    <header class="topbar">
      <div>
        <div class="brandMark"><span class="brandDot"></span><span id="liveText">Protectogotchi startet</span></div>
        <h1>Dein Netzwerk, verständlich und lokal überwacht.</h1>
        <p class="subtitle">Protectogotchi lernt normales Verhalten, erkennt Abweichungen und erklärt die Lage in klarer Sprache statt in Rohdaten.</p>
      </div>
      <div class="modeDock" aria-label="Modus"><button data-mode="learn" class="active" onclick="setMode('learn')">Lernen</button><button data-mode="watch" onclick="setMode('watch')">Beobachten</button><button data-mode="guard" onclick="setMode('guard')">Schützen</button><button data-mode="god" onclick="setMode('god')">Autopilot</button><button data-mode="pause" onclick="setMode('pause')">Pause</button></div>
    </header>
    <main class="dashboard">
      <aside class="companion">
        <section class="mascotPanel">
          <div class="mascotHero"><div class="petBlob"><div class="face" id="face">( o_o)</div></div><div><p class="state" id="state">Status wird geladen.</p><div class="muted" id="mood">Die erste Einschätzung kommt gleich.</div></div></div>
          <div class="thoughtCloud" aria-label="Statusnotiz"><span class="eyebrow">Statusnotiz</span><span id="thought">Ich prüfe die letzten Beobachtungen und fasse sie verständlich zusammen.</span></div>
        </section>
        <section class="mascotPanel senseGrid" aria-label="Kurzstatus"><div class="sense"><span>Einschätzung</span><strong id="risk">-</strong></div><div class="sense"><span>Level</span><strong id="level">-</strong></div><div class="sense"><span>Baseline</span><strong id="baseline">-</strong></div><div class="sense"><span>Geräte</span><strong id="devicesCount">-</strong></div></section>
      </aside>
      <div class="work">
        <nav class="tabs" aria-label="Ansichten"><button data-tab="home" class="active" onclick="switchTab('home')">Übersicht</button><button data-tab="now" onclick="switchTab('now')">Aktivität</button><button data-tab="worries" onclick="switchTab('worries')">Hinweise</button><button data-tab="neighbors" onclick="switchTab('neighbors')">Geräte</button><button data-tab="practice" onclick="switchTab('practice')">Simulation</button><button data-tab="help" onclick="switchTab('help')">Werkzeuge</button></nav>
        <section class="panel active" data-panel="home"><div class="section"><h2 class="sectionTitle">Netzwerkübersicht</h2><p class="sectionLead">Die Karte zeigt die wichtigsten Beziehungen: dieses Gerät, Schnittstellen, Subnetze, Gateway und bekannte Geräte.</p><div class="mapWrap"><svg id="networkGraph" role="img" aria-label="Einfache Netzwerkkarte"></svg></div><div class="softStrip" id="plainSummary"></div></div><div class="section"><h2 class="sectionTitle">Lebendiger Status</h2><p class="sectionLead">Der Companion-Zustand wechselt mit der Lage: ruhig, aufmerksam, aufgeregt, lernend oder gelangweilt bei längerer Stille.</p><div id="watchfulness"></div></div></section>
        <section class="panel" data-panel="now"><div class="section"><h2 class="sectionTitle">Aktuelle Aktivität</h2><p class="sectionLead">Eine verständliche Zusammenfassung der Bewegungen, ohne technische Rohdaten als Hauptansicht.</p><div id="activity" class="lineList">lädt...</div></div><div class="two"><div class="section"><h2 class="sectionTitle">Kurzbericht</h2><div id="networkDetail" class="lineList">lädt...</div></div><div class="section"><h2 class="sectionTitle">Sichtbarkeit</h2><div id="coverage" class="lineList">lädt...</div></div></div></section>
        <section class="panel" data-panel="worries"><div class="section"><h2 class="sectionTitle">Hinweise & Empfehlungen</h2><p class="sectionLead">Auffälligkeiten werden priorisiert und als konkrete Handlungsempfehlung formuliert.</p><div id="findings" class="lineList">lädt...</div></div><div class="section"><h2 class="sectionTitle">Verlauf</h2><div id="history" class="lineList">lädt...</div></div></section>
        <section class="panel" data-panel="neighbors"><div class="section"><h2 class="sectionTitle">Bekannte Geräte</h2><p class="sectionLead">Geräte werden mit Namen, Adresse und letzter Sichtung angezeigt.</p><table class="miniTable"><thead><tr><th>Name</th><th>Adresse</th><th>Gesehen</th><th>Zuletzt</th></tr></thead><tbody id="devices"></tbody></table></div></section>
        <section class="panel" data-panel="practice"><div class="section"><h2 class="sectionTitle">Angriffssimulation</h2><p class="sectionLead">Isolierte Szenarien zeigen, wie Protectogotchi Bedrohungen erkennen würde, ohne echten Verkehr umzuleiten.</p><div class="softStrip" id="simulationButtons"></div><div id="simulation" class="lineList"><div class="story">Wähle ein Szenario aus.</div></div></div><div class="section"><h2 class="sectionTitle">Schutzreichweite</h2><div id="placement" class="lineList">lädt...</div></div></section>
        <section class="panel" data-panel="help"><div class="two"><div class="section"><h2 class="sectionTitle">Werkzeuge</h2><div id="tools" class="lineList">lädt...</div></div><div class="section"><h2 class="sectionTitle">Wissensbasis</h2><div id="knowledge" class="lineList">lädt...</div></div></div></section>
      </div>
    </main>
  </div>
  <script>
    const faces = { idle:"( -_-)", bored:"( -_-) z", learning:"( o_o)", analyzing:"( @_@)", alert:"( O_O)!", fighting:"( >_<)", happy:"( ^_^)", curious:"( •_•)?" };
    const modeNames = { learn:"Lernen", watch:"Beobachten", guard:"Schützen", god:"Autopilot", pause:"Pause" };
    async function getJson(path){ const r=await fetch(path); if(!r.ok) throw new Error(path+" -> "+r.status); return r.json(); }
    function severityWord(s){ return ({info:"nur eine Notiz",low:"kleine Sorge",medium:"bitte anschauen",high:"wichtig",critical:"dringend"})[s] || s; }
    function riskWord(score){ if(score>=70) return "unruhig"; if(score>=35) return "aufmerksam"; return "ruhig"; }
    async function refresh(){
      const live=await getJson('/api/live'); const scan=live.scan||{}; const state=live.state||{}; const snapshot=scan.snapshot||{}; const faceState=live.pet_state || scan.face_state || (state.baseline_ready?'happy':'learning');
      document.getElementById('face').textContent=faces[faceState]||faces.idle; document.getElementById('state').textContent=live.pet_headline || modeNames[live.mode] || 'Ich passe auf'; document.getElementById('mood').textContent=live.pet_subtitle || live.mode_description || '';
      document.getElementById('thought').textContent=live.thought || 'Ich prüfe die Lage und melde verständlich, wenn etwas Aufmerksamkeit braucht.'; renderMode(live.mode||'learn');
      document.getElementById('risk').textContent=riskWord(scan.risk_score||0); document.getElementById('risk').className=(scan.risk_score||0)>=70?'risk-high':((scan.risk_score||0)>=35?'risk-mid':'risk-low'); document.getElementById('level').textContent=state.level??'-'; document.getElementById('baseline').textContent=state.baseline_ready?'bereit':((state.learning_remaining||0)+' Scans'); document.getElementById('devicesCount').textContent=state.known_devices??'-'; document.getElementById('liveText').textContent='aktualisiert: '+(live.updated_at||'gerade');
      renderPlainSummary(live, snapshot); renderWatchfulness(live); renderActivity(live, snapshot); renderGraph((live.network_map||{}).graph||{nodes:[],edges:[]}); renderFindings(scan.findings||[]); renderHistory(live.finding_history||[]); renderDevices(live.devices||[]); renderPlacement(live.placement_report||{}); renderSimulationButtons(live.simulations||[]); renderNetworkStory(live, snapshot); renderCoverage(live); renderTools(live.tools||[]); renderKnowledge(live.knowledge||[]);
    }
    function renderPlainSummary(live,s){ const items=[['WLAN', (s.wifi||{}).ssid || 'nicht erkannt'], ['Gateway', s.default_gateway || 'noch unbekannt'], ['Modus', modeNames[live.mode] || live.mode], ['Verbindungen', (s.connections||[]).length+' aktuell'], ['Geräte', (s.devices||[]).length+' gesehen']]; document.getElementById('plainSummary').innerHTML=items.map(i=>`<span class="tag"><strong>${i[0]}:</strong> ${escapeHtml(i[1])}</span>`).join(''); }
    function renderWatchfulness(live){ const quiet=live.quiet_scans||0; const pct=Math.min(100, quiet*25); const text=quiet>=2?'Längere Stille erkannt: Status gelangweilt, Prüfintervall erhöht.':'Normale Wachsamkeit: der Status bleibt ruhig und prüft regelmäßig.'; document.getElementById('watchfulness').innerHTML=`<div class="story"><strong>${escapeHtml(text)}</strong><span class="muted">Ruhige Scans hintereinander: ${quiet}. Der Companion bleibt dadurch sichtbar lebendig, ohne unnötig Alarm zu machen.</span><div class="quietbar"><span style="width:${pct}%"></span></div></div>`; }
    function renderActivity(live,s){ const findings=(live.scan||{}).findings||[]; const lines=[]; lines.push(`<div class="story"><strong>${findings.length?'Auffälligkeit erkannt':'Keine akute Auffälligkeit'}</strong><span class="muted">${escapeHtml(live.activity_summary||'Die aktuelle Aktivität wirkt normal.')}</span></div>`); (s.connections||[]).slice(0,8).forEach(c=>lines.push(`<div class="story"><strong>${escapeHtml(c.protocol||'Verbindung')} Verbindung</strong><span class="muted">Von ${escapeHtml(c.local_address||'diesem Gerät')} zu ${escapeHtml(c.remote_address||'intern oder extern')}. Status: ${escapeHtml(c.state||'unbekannt')}.</span></div>`)); document.getElementById('activity').innerHTML=lines.join(''); }
    function renderNetworkStory(live,s){ const summary=(live.network_map||{}).summary||{}; const rows=[['Gateway', s.default_gateway || 'noch nicht erkannt'], ['Erkannte Bereiche', Object.entries(summary).map(([k,v])=>`${v}× ${k}`).join(', ') || 'noch keine Karte'], ['Aktuelle Aktivität', (s.connections||[]).length ? `${s.connections.length} Verbindung(en) sichtbar` : 'gerade keine auffällige Aktivität']]; document.getElementById('networkDetail').innerHTML=rows.map(r=>`<div class="story"><strong>${r[0]}</strong><span class="muted">${escapeHtml(r[1])}</span></div>`).join(''); }
    function renderCoverage(live){ const coverage=((live.network_map||{}).coverage||[]); document.getElementById('coverage').innerHTML=(coverage.length?coverage:['Noch keine Abdeckung bekannt. Ich lerne erst, wo ich gut hinschauen kann.']).map(line=>`<div class="story"><span class="muted">${escapeHtml(line)}</span></div>`).join(''); }
    function renderFindings(findings){ const t=document.getElementById('findings'); if(!findings.length){t.innerHTML="<div class='story'><strong>Keine Hinweise.</strong><span class='muted'>Aktuell gibt es nichts, das Aufmerksamkeit braucht.</span></div>"; return;} t.innerHTML=findings.map(f=>`<div class="story"><strong class="severity-${f.severity}">${severityWord(f.severity)}: ${escapeHtml(f.title)}</strong><span>${escapeHtml(f.description)}</span><div class="tinyDetail">Empfehlung: ${escapeHtml(f.recommended_action||'erstmal beobachten')}</div></div>`).join(''); }
    function renderHistory(history){ const t=document.getElementById('history'); if(!history.length){t.innerHTML="<div class='story'><span class='muted'>Noch kein Verlauf vorhanden.</span></div>"; return;} t.innerHTML=history.slice(-10).reverse().map(f=>`<div class="story"><strong class="severity-${f.severity}">${escapeHtml(f.title)}</strong><span class="muted">${escapeHtml(f.seen_at)} · ${severityWord(f.severity)}</span></div>`).join(''); }
    function renderDevices(devices){ document.getElementById('devices').innerHTML=devices.map(d=>`<tr><td>${escapeHtml(d.hostname||'Unbenanntes Gerät')}<br><code>${escapeHtml(d.mac)}</code></td><td>${escapeHtml((d.ips||[]).join(', ')||'-')}</td><td>${d.seen_count||0}×</td><td>${escapeHtml(d.last_seen||'-')}</td></tr>`).join('') || '<tr><td colspan="4" class="muted">Noch keine Geräte gelernt.</td></tr>'; }
    function renderPlacement(r){ const items=[['Kurzfassung', r.summary||'noch unbekannt'], ['Schutz aktiv', r.active_response_enabled?'ja':'noch nicht'], ['Automatisierung', r.firewall_controller_automation?'ja':'nein']]; const steps=(r.next_steps||[]).map(s=>`<div class="story"><strong>Nächster Schritt</strong><span class="muted">${escapeHtml(s)}</span></div>`).join(''); document.getElementById('placement').innerHTML=items.map(i=>`<div class="story"><strong>${i[0]}</strong><span class="muted">${escapeHtml(i[1])}</span></div>`).join('')+steps; }
    function renderSimulationButtons(s){ document.getElementById('simulationButtons').innerHTML=s.map(n=>`<button class="pillButton" onclick="runLabScenario('${escapeHtml(n)}')">${escapeHtml(n)}</button>`).join(''); }
    async function runLabScenario(scenario){ const r=await getJson('/api/simulate?scenario='+encodeURIComponent(scenario)); document.getElementById('simulation').innerHTML=`<div class="story"><strong>${escapeHtml(r.scenario)}</strong><span class="muted">Einschätzung im Szenario: ${riskWord(r.risk_score||0)}.</span></div>`+((r.lessons||[]).map(l=>`<div class="story"><span class="muted">${escapeHtml(l)}</span></div>`).join('')); }
    function renderTools(tools){ document.getElementById('tools').innerHTML=tools.map(t=>`<div class="story"><strong>${escapeHtml(t.name)}</strong><span class="muted">${escapeHtml(t.status)}. ${escapeHtml(t.summary||'Werkzeug verfügbar.')}</span></div>`).join('') || '<div class="story"><span class="muted">Keine Werkzeuge gemeldet.</span></div>'; }
    function renderKnowledge(topics){ document.getElementById('knowledge').innerHTML=topics.map(t=>`<div class="story"><strong>${escapeHtml(t.name)}</strong><span class="muted">Bereich: ${escapeHtml(t.domain)}. ${escapeHtml(t.summary||'Erklärung verfügbar.')}</span></div>`).join('') || '<div class="story"><span class="muted">Noch kein Wissen geladen.</span></div>'; }
    function renderGraph(graph){ const svg=document.getElementById('networkGraph'), nodes=graph.nodes||[], edges=graph.edges||[], width=Math.max(760,svg.clientWidth||760), columns={host:90,interface:250,subnet:430,gateway:630,'default-gateway':630,endpoint:630,'local-host':630,'infrastructure-candidate':630}, grouped={}; nodes.forEach(n=>{const k=n.kind||'endpoint'; (grouped[k]=grouped[k]||[]).push(n);}); const pos={}; ['host','interface','subnet','default-gateway','gateway','infrastructure-candidate','endpoint','local-host'].forEach(k=>(grouped[k]||[]).forEach((n,i)=>pos[n.id]={x:columns[k]||630,y:65+i*70})); const height=Math.max(390,...Object.values(pos).map(p=>p.y+55)); svg.setAttribute('viewBox',`0 0 ${width} ${height}`); svg.innerHTML=edges.map(e=>pos[e.source]&&pos[e.target]?`<line class="link" x1="${pos[e.source].x+62}" y1="${pos[e.source].y}" x2="${pos[e.target].x-62}" y2="${pos[e.target].y}"></line>`:'').join('')+nodes.map(n=>{const p=pos[n.id]; if(!p)return''; return `<g><rect class="node ${n.kind||'endpoint'}" x="${p.x-62}" y="${p.y-24}" width="124" height="48"></rect><text class="nodeLabel" x="${p.x-52}" y="${p.y-4}">${escapeHtml(n.label||n.id)}</text><text class="nodeMeta" x="${p.x-52}" y="${p.y+13}">${escapeHtml([n.ip,n.mac].filter(Boolean).join(' · '))}</text></g>`}).join(''); }
    function escapeHtml(v){ return String(v).replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;').replaceAll('"','&quot;').replaceAll("'",'&#39;'); }
    function switchTab(tab){ document.querySelectorAll('[data-tab]').forEach(b=>b.classList.toggle('active',b.dataset.tab===tab)); document.querySelectorAll('[data-panel]').forEach(p=>p.classList.toggle('active',p.dataset.panel===tab)); }
    function renderMode(mode){ document.querySelectorAll('[data-mode]').forEach(b=>b.classList.toggle('active',b.dataset.mode===mode)); }
    async function setMode(mode){ let body={mode}; if(mode==='god'){ const phrase=window.prompt('Autopilot handelt selbstständiger. Netzwerkweiter Schutz braucht einen echten Enforcement-Punkt. Es wird kein heimliches ARP/MitM aktiviert. Tippe ACTIVATE GOD MODE.'); if(phrase!=='ACTIVATE GOD MODE') return; body.confirm=phrase; } await fetch('/api/mode',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)}); await refresh(); }
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
