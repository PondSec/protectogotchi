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
      --bg: #fffaf7;
      --paper: rgba(255,255,255,.76);
      --paper-solid: #fff;
      --ink: #2e2530;
      --soft-ink: #766878;
      --line: rgba(224, 194, 207, .72);
      --rose: #ffe0eb;
      --peach: #ffe9d6;
      --mint: #ddf8ea;
      --sky: #e6f2ff;
      --lavender: #efe8ff;
      --good: #12806b;
      --wait: #aa6a10;
      --bad: #be3455;
      --glow: 0 26px 80px rgba(120, 72, 99, .13);
      --small-shadow: 0 8px 26px rgba(120, 72, 99, .08);
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      min-height: 100vh;
      color: var(--ink);
      background:
        radial-gradient(circle at 8% 8%, rgba(255, 199, 224, .8) 0 11rem, transparent 22rem),
        radial-gradient(circle at 92% 2%, rgba(191, 244, 224, .75) 0 10rem, transparent 23rem),
        radial-gradient(circle at 72% 88%, rgba(218, 232, 255, .85) 0 13rem, transparent 24rem),
        linear-gradient(135deg, #fffaf7 0%, #fff1f7 47%, #f7fbff 100%);
    }
    body::before {
      content: "";
      position: fixed;
      inset: 0;
      pointer-events: none;
      opacity: .38;
      background-image: radial-gradient(circle, rgba(143,96,124,.16) 1px, transparent 1px);
      background-size: 28px 28px;
      mask-image: linear-gradient(to bottom, #000, transparent 72%);
    }
    button { appearance: none; border: 0; font: inherit; cursor: pointer; }
    .app { width: min(1460px, 100%); margin: 0 auto; padding: 28px clamp(16px, 4vw, 44px) 42px; }
    .topbar { display: flex; align-items: flex-start; justify-content: space-between; gap: 22px; margin-bottom: 24px; }
    .brandMark { display: inline-flex; align-items: center; gap: 10px; padding: 9px 13px; border: 1px solid var(--line); border-radius: 999px; background: rgba(255,255,255,.62); color: var(--soft-ink); box-shadow: var(--small-shadow); }
    .brandDot { width: 10px; height: 10px; border-radius: 99px; background: var(--good); box-shadow: 0 0 0 7px rgba(18,128,107,.12); }
    h1 { margin: 12px 0 8px; font-size: clamp(36px, 7vw, 82px); line-height: .92; letter-spacing: -.075em; max-width: 920px; }
    .subtitle { margin: 0; max-width: 760px; color: var(--soft-ink); font-size: clamp(17px, 2.2vw, 22px); line-height: 1.45; }
    .modeDock { display: flex; flex-wrap: wrap; gap: 8px; justify-content: flex-end; max-width: 520px; }
    .modeDock button, .tabs button, .pillButton { border-radius: 999px; padding: 10px 14px; color: var(--ink); background: rgba(255,255,255,.68); border: 1px solid var(--line); box-shadow: var(--small-shadow); }
    .modeDock button.active, .tabs button.active { color: #fff; background: #302735; border-color: #302735; }
    .dashboard { display: grid; grid-template-columns: minmax(300px, 410px) minmax(0, 1fr); gap: 22px; align-items: start; }
    .companion { position: sticky; top: 18px; display: grid; gap: 18px; }
    .mascotPanel, .section, .tabs { background: var(--paper); border: 1px solid var(--line); border-radius: 34px; box-shadow: var(--glow); backdrop-filter: blur(18px); }
    .mascotPanel { padding: 24px; overflow: hidden; }
    .mascotHero { display: grid; grid-template-columns: 132px 1fr; gap: 18px; align-items: center; }
    .petBlob { width: 132px; aspect-ratio: 1; border-radius: 45% 55% 52% 48%; display: grid; place-items: center; background: linear-gradient(145deg, #fff, #ffe4ef 48%, #e6fff3); border: 1px solid #ffd3e2; box-shadow: inset 0 -16px 25px rgba(215,99,139,.09), 0 18px 34px rgba(144,74,109,.12); }
    .face { font: 900 36px/1 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; transform: rotate(-2deg); }
    .state { margin: 0 0 6px; font-size: 30px; font-weight: 850; letter-spacing: -.055em; }
    .muted { color: var(--soft-ink); }
    .thoughtCloud { position: relative; margin-top: 22px; padding: 18px 18px 18px 20px; border-radius: 28px 28px 28px 10px; background: var(--paper-solid); border: 1px solid var(--line); line-height: 1.5; }
    .thoughtCloud::after { content: ""; position: absolute; left: 30px; bottom: -10px; width: 20px; height: 20px; background: var(--paper-solid); border-right: 1px solid var(--line); border-bottom: 1px solid var(--line); transform: rotate(45deg); }
    .eyebrow { display: block; margin-bottom: 5px; color: var(--soft-ink); font-size: 12px; font-weight: 800; letter-spacing: .12em; text-transform: uppercase; }
    .senseGrid { display: grid; grid-template-columns: repeat(2, minmax(0,1fr)); gap: 10px; }
    .sense { padding: 14px; border-radius: 24px; background: rgba(255,255,255,.58); border: 1px solid var(--line); }
    .sense span { display:block; font-size: 12px; color: var(--soft-ink); }
    .sense strong { display:block; margin-top: 3px; font-size: 25px; letter-spacing: -.05em; }
    .risk-low { color: var(--good); } .risk-mid { color: var(--wait); } .risk-high { color: var(--bad); }
    .tabs { position: sticky; top: 0; z-index: 5; display: flex; gap: 8px; flex-wrap: wrap; padding: 11px; margin-bottom: 18px; }
    .panel { display: none; } .panel.active { display: grid; gap: 18px; }
    .section { padding: clamp(20px, 3vw, 30px); overflow: hidden; }
    .sectionTitle { margin: 0 0 8px; font-size: clamp(24px, 3vw, 38px); letter-spacing: -.055em; }
    .sectionLead { margin: 0 0 22px; color: var(--soft-ink); line-height: 1.55; max-width: 850px; }
    .two { display: grid; grid-template-columns: repeat(2, minmax(0,1fr)); gap: 18px; }
    .lineList { display: grid; gap: 0; }
    .story { padding: 15px 0; border-top: 1px solid var(--line); line-height: 1.5; }
    .story:first-child { border-top: 0; padding-top: 0; }
    .story strong { display:block; margin-bottom: 4px; }
    .softStrip { display:flex; flex-wrap:wrap; gap:10px; margin: 14px 0 0; }
    .tag { display:inline-flex; align-items:center; gap:8px; border-radius:999px; padding:8px 12px; background:rgba(255,255,255,.65); border:1px solid var(--line); color:var(--soft-ink); }
    .quietbar { height: 13px; border-radius: 999px; overflow:hidden; background:#f7dbe5; margin-top: 12px; }
    .quietbar > span { display:block; height:100%; background:linear-gradient(90deg,#8ee6c6,#ffd6e5,#cfe0ff); }
    .mapWrap { border-radius: 32px; padding: 14px; background: rgba(255,255,255,.5); border:1px solid var(--line); }
    svg { width: 100%; min-height: 390px; border-radius: 24px; background: linear-gradient(180deg, #fff, #fff7fb); }
    .nodeLabel { font: 13px ui-sans-serif, system-ui; fill: var(--ink); font-weight: 800; }
    .nodeMeta { font: 10px ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; fill: var(--soft-ink); }
    .link { stroke: #e2b8c6; stroke-width: 2; stroke-linecap: round; }
    .node { fill: #ffffff; stroke: #efc8d5; stroke-width: 1.5; rx: 18; ry: 18; }
    .node.gateway, .node.default-gateway { stroke: var(--good); stroke-width: 2.5; }
    .node.host { fill: var(--rose); } .node.subnet { fill: var(--sky); } .node.interface { fill: var(--mint); }
    .miniTable { width: 100%; border-collapse: collapse; }
    .miniTable th, .miniTable td { text-align:left; padding: 13px 8px; border-top:1px solid var(--line); vertical-align:top; }
    .miniTable th { color: var(--soft-ink); font-size:12px; letter-spacing:.08em; text-transform:uppercase; }
    code { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 12px; color: #6d5968; }
    .tinyDetail { margin-top: 10px; color: var(--soft-ink); font-size: 13px; }
    .severity-critical, .severity-high { color: var(--bad); } .severity-medium { color: var(--wait); }
    @media (max-width: 980px) { .topbar, .dashboard, .two { grid-template-columns: 1fr; display: grid; } .modeDock { justify-content: flex-start; } .companion, .tabs { position: static; } }
    @media (max-width: 560px) { .mascotHero { grid-template-columns: 1fr; } .petBlob { width: 112px; } .senseGrid { grid-template-columns: 1fr; } }
  </style>
</head>
<body>
  <div class="app">
    <header class="topbar">
      <div>
        <div class="brandMark"><span class="brandDot"></span><span id="liveText">Protectogotchi wacht auf</span></div>
        <h1>Netzwerkschutz, der sich wie ein kleines Haustier anfühlt.</h1>
        <p class="subtitle">Keine Fachsprache, keine JSON-Wände: Protectogotchi erzählt dir ruhig und freundlich, ob zuhause alles normal wirkt.</p>
      </div>
      <div class="modeDock" aria-label="Modus"><button data-mode="learn" class="active" onclick="setMode('learn')">Lernen</button><button data-mode="watch" onclick="setMode('watch')">Nur erzählen</button><button data-mode="guard" onclick="setMode('guard')">Aufpassen</button><button data-mode="god" onclick="setMode('god')">Autopilot</button><button data-mode="pause" onclick="setMode('pause')">Pause</button></div>
    </header>
    <main class="dashboard">
      <aside class="companion">
        <section class="mascotPanel">
          <div class="mascotHero"><div class="petBlob"><div class="face" id="face">( o_o)</div></div><div><p class="state" id="state">Ich schnuppere kurz.</p><div class="muted" id="mood">Gleich erzähle ich dir, was ich sehe.</div></div></div>
          <div class="thoughtCloud" aria-label="Gedankenblase"><span class="eyebrow">Gedankenblase</span><span id="thought">Ich schaue nach, ob sich zuhause etwas ungewohnt anfühlt.</span></div>
        </section>
        <section class="mascotPanel senseGrid" aria-label="Kurzstatus"><div class="sense"><span>Bauchgefühl</span><strong id="risk">-</strong></div><div class="sense"><span>Erfahrung</span><strong id="level">-</strong></div><div class="sense"><span>Gelernt</span><strong id="baseline">-</strong></div><div class="sense"><span>Mitbewohner</span><strong id="devicesCount">-</strong></div></section>
      </aside>
      <div class="work">
        <nav class="tabs" aria-label="Ansichten"><button data-tab="home" class="active" onclick="switchTab('home')">Zuhause</button><button data-tab="now" onclick="switchTab('now')">Gerade los</button><button data-tab="worries" onclick="switchTab('worries')">Sorgen</button><button data-tab="neighbors" onclick="switchTab('neighbors')">Mitbewohner</button><button data-tab="practice" onclick="switchTab('practice')">Üben</button><button data-tab="help" onclick="switchTab('help')">Hilfe</button></nav>
        <section class="panel active" data-panel="home"><div class="section"><h2 class="sectionTitle">Dein Zuhause auf einen Blick</h2><p class="sectionLead">Ich übersetze Netzwerk-Signale in einfache Beobachtungen: Wer ist da, wohin geht es raus und ob sich etwas ungewohnt anfühlt.</p><div class="mapWrap"><svg id="networkGraph" role="img" aria-label="Einfache Netzwerkkarte"></svg></div><div class="softStrip" id="plainSummary"></div></div><div class="section"><h2 class="sectionTitle">Wie wach ich gerade bin</h2><p class="sectionLead">Wenn lange nichts passiert, wird mir ein bisschen langweilig — dann mache ich selbstständig häufigere Kontrollblicke.</p><div id="watchfulness"></div></div></section>
        <section class="panel" data-panel="now"><div class="section"><h2 class="sectionTitle">Was gerade im Netzwerk los ist</h2><p class="sectionLead">Hier steht nicht „TCP/UDP-Salat“, sondern eine kleine Alltagserzählung über die aktuellen Bewegungen.</p><div id="activity" class="lineList">lädt...</div></div><div class="two"><div class="section"><h2 class="sectionTitle">Meine kleine Zusammenfassung</h2><div id="networkDetail" class="lineList">lädt...</div></div><div class="section"><h2 class="sectionTitle">Was ich gut sehen kann</h2><div id="coverage" class="lineList">lädt...</div></div></div></section>
        <section class="panel" data-panel="worries"><div class="section"><h2 class="sectionTitle">Sorgen & liebe Vorschläge</h2><p class="sectionLead">Wenn mir etwas komisch vorkommt, formuliere ich es als klare Empfehlung statt als Alarmtext.</p><div id="findings" class="lineList">lädt...</div></div><div class="section"><h2 class="sectionTitle">Was ich mir gemerkt habe</h2><div id="history" class="lineList">lädt...</div></div></section>
        <section class="panel" data-panel="neighbors"><div class="section"><h2 class="sectionTitle">Bekannte Mitbewohner</h2><p class="sectionLead">Geräte werden wie Haushaltsmitglieder gezeigt: Name, Adresse und wann ich sie zuletzt gesehen habe.</p><table class="miniTable"><thead><tr><th>Name</th><th>Adresse</th><th>Gesehen</th><th>Zuletzt</th></tr></thead><tbody id="devices"></tbody></table></div></section>
        <section class="panel" data-panel="practice"><div class="section"><h2 class="sectionTitle">Gefahr gefahrlos üben</h2><p class="sectionLead">Du kannst kleine Situationen ausprobieren und ich erkläre, was ich daraus lernen würde.</p><div class="softStrip" id="simulationButtons"></div><div id="simulation" class="lineList"><div class="story">Such dir ein kleines Szenario aus.</div></div></div><div class="section"><h2 class="sectionTitle">Passt mein Platz?</h2><div id="placement" class="lineList">lädt...</div></div></section>
        <section class="panel" data-panel="help"><div class="two"><div class="section"><h2 class="sectionTitle">Was ich benutzen kann</h2><div id="tools" class="lineList">lädt...</div></div><div class="section"><h2 class="sectionTitle">Was ich erklären kann</h2><div id="knowledge" class="lineList">lädt...</div></div></div></section>
      </div>
    </main>
  </div>
  <script>
    const faces = { idle:"( -_-)", bored:"( -3-)", learning:"( o_o)", analyzing:"( @_@)", alert:"( O_O)!", fighting:"( >_<)", happy:"( ^_^)", curious:"( •_•)?" };
    const modeNames = { learn:"Lernen", watch:"Nur erzählen", guard:"Aufpassen", god:"Autopilot", pause:"Pause" };
    async function getJson(path){ const r=await fetch(path); if(!r.ok) throw new Error(path+" -> "+r.status); return r.json(); }
    function severityWord(s){ return ({info:"nur eine Notiz",low:"kleine Sorge",medium:"bitte anschauen",high:"wichtig",critical:"dringend"})[s] || s; }
    function riskWord(score){ if(score>=70) return "unruhig"; if(score>=35) return "aufmerksam"; return "ruhig"; }
    async function refresh(){
      const live=await getJson('/api/live'); const scan=live.scan||{}; const state=live.state||{}; const snapshot=scan.snapshot||{}; const faceState=live.pet_state || scan.face_state || (state.baseline_ready?'happy':'learning');
      document.getElementById('face').textContent=faces[faceState]||faces.idle; document.getElementById('state').textContent=live.pet_headline || modeNames[live.mode] || 'Ich passe auf'; document.getElementById('mood').textContent=live.pet_subtitle || live.mode_description || '';
      document.getElementById('thought').textContent=live.thought || 'Ich schaue mich um und sage Bescheid, wenn mir etwas komisch vorkommt.'; renderMode(live.mode||'learn');
      document.getElementById('risk').textContent=riskWord(scan.risk_score||0); document.getElementById('risk').className=(scan.risk_score||0)>=70?'risk-high':((scan.risk_score||0)>=35?'risk-mid':'risk-low'); document.getElementById('level').textContent=state.level??'-'; document.getElementById('baseline').textContent=state.baseline_ready?'ja':((state.learning_remaining||0)+' Blicke'); document.getElementById('devicesCount').textContent=state.known_devices??'-'; document.getElementById('liveText').textContent='zuletzt geschnuppert: '+(live.updated_at||'gerade');
      renderPlainSummary(live, snapshot); renderWatchfulness(live); renderActivity(live, snapshot); renderGraph((live.network_map||{}).graph||{nodes:[],edges:[]}); renderFindings(scan.findings||[]); renderHistory(live.finding_history||[]); renderDevices(live.devices||[]); renderPlacement(live.placement_report||{}); renderSimulationButtons(live.simulations||[]); renderNetworkStory(live, snapshot); renderCoverage(live); renderTools(live.tools||[]); renderKnowledge(live.knowledge||[]);
    }
    function renderPlainSummary(live,s){ const items=[['WLAN', (s.wifi||{}).ssid || 'nicht erkannt'], ['Internet-Tür', s.default_gateway || 'noch unbekannt'], ['Modus', modeNames[live.mode] || live.mode], ['Bewegungen', (s.connections||[]).length+' aktuell'], ['Geräte', (s.devices||[]).length+' gesehen']]; document.getElementById('plainSummary').innerHTML=items.map(i=>`<span class="tag"><strong>${i[0]}:</strong> ${escapeHtml(i[1])}</span>`).join(''); }
    function renderWatchfulness(live){ const quiet=live.quiet_scans||0; const pct=Math.min(100, quiet*25); const text=quiet>=2?'Mir ist etwas langweilig, also schaue ich extra oft nach.':'Ich mache normale Kontrollblicke und bleibe entspannt.'; document.getElementById('watchfulness').innerHTML=`<div class="story"><strong>${escapeHtml(text)}</strong><span class="muted">Ruhige Runden hintereinander: ${quiet}. Je ruhiger es ist, desto flauschiger und häufiger prüfe ich kurz.</span><div class="quietbar"><span style="width:${pct}%"></span></div></div>`; }
    function renderActivity(live,s){ const findings=(live.scan||{}).findings||[]; const lines=[]; lines.push(`<div class="story"><strong>${findings.length?'Ich habe etwas bemerkt':'Alles wirkt gerade ruhig'}</strong><span class="muted">${escapeHtml(live.activity_summary||'Keine ungewöhnlichen Geräusche im Netzwerk.')}</span></div>`); (s.connections||[]).slice(0,8).forEach(c=>lines.push(`<div class="story"><strong>${escapeHtml(c.protocol||'Verbindung')} bewegt sich</strong><span class="muted">Von ${escapeHtml(c.local_address||'diesem Gerät')} zu ${escapeHtml(c.remote_address||'zuhause oder Internet')}. Status: ${escapeHtml(c.state||'unbekannt')}.</span></div>`)); document.getElementById('activity').innerHTML=lines.join(''); }
    function renderNetworkStory(live,s){ const summary=(live.network_map||{}).summary||{}; const rows=[['Haustür ins Internet', s.default_gateway || 'noch nicht erkannt'], ['Bekannte Bereiche', Object.entries(summary).map(([k,v])=>`${v}× ${k}`).join(', ') || 'noch keine Karte'], ['Aktuelle Bewegungen', (s.connections||[]).length ? `${s.connections.length} Verbindung(en), die ich gerade sehe` : 'gerade keine auffällige Bewegung']]; document.getElementById('networkDetail').innerHTML=rows.map(r=>`<div class="story"><strong>${r[0]}</strong><span class="muted">${escapeHtml(r[1])}</span></div>`).join(''); }
    function renderCoverage(live){ const coverage=((live.network_map||{}).coverage||[]); document.getElementById('coverage').innerHTML=(coverage.length?coverage:['Noch keine Abdeckung bekannt. Ich lerne erst, wo ich gut hinschauen kann.']).map(line=>`<div class="story"><span class="muted">${escapeHtml(line)}</span></div>`).join(''); }
    function renderFindings(findings){ const t=document.getElementById('findings'); if(!findings.length){t.innerHTML="<div class='story'><strong>Keine Sorgen.</strong><span class='muted'>Ich sehe gerade nichts, das dich stressen sollte.</span></div>"; return;} t.innerHTML=findings.map(f=>`<div class="story"><strong class="severity-${f.severity}">${severityWord(f.severity)}: ${escapeHtml(f.title)}</strong><span>${escapeHtml(f.description)}</span><div class="tinyDetail">Mein Vorschlag: ${escapeHtml(f.recommended_action||'erstmal beobachten')}</div></div>`).join(''); }
    function renderHistory(history){ const t=document.getElementById('history'); if(!history.length){t.innerHTML="<div class='story'><span class='muted'>Noch keine Erinnerungen. Das ist eigentlich schön ruhig.</span></div>"; return;} t.innerHTML=history.slice(-10).reverse().map(f=>`<div class="story"><strong class="severity-${f.severity}">${escapeHtml(f.title)}</strong><span class="muted">${escapeHtml(f.seen_at)} · ${severityWord(f.severity)}</span></div>`).join(''); }
    function renderDevices(devices){ document.getElementById('devices').innerHTML=devices.map(d=>`<tr><td>${escapeHtml(d.hostname||'Unbenanntes Gerät')}<br><code>${escapeHtml(d.mac)}</code></td><td>${escapeHtml((d.ips||[]).join(', ')||'-')}</td><td>${d.seen_count||0}×</td><td>${escapeHtml(d.last_seen||'-')}</td></tr>`).join('') || '<tr><td colspan="4" class="muted">Noch keine Geräte gelernt.</td></tr>'; }
    function renderPlacement(r){ const items=[['Kurzfassung', r.summary||'noch unbekannt'], ['Schutz aktiv', r.active_response_enabled?'ja':'noch nicht'], ['Automatisierung', r.firewall_controller_automation?'ja':'nein']]; const steps=(r.next_steps||[]).map(s=>`<div class="story"><strong>Nächster Schritt</strong><span class="muted">${escapeHtml(s)}</span></div>`).join(''); document.getElementById('placement').innerHTML=items.map(i=>`<div class="story"><strong>${i[0]}</strong><span class="muted">${escapeHtml(i[1])}</span></div>`).join('')+steps; }
    function renderSimulationButtons(s){ document.getElementById('simulationButtons').innerHTML=s.map(n=>`<button class="pillButton" onclick="runLabScenario('${escapeHtml(n)}')">${escapeHtml(n)}</button>`).join(''); }
    async function runLabScenario(scenario){ const r=await getJson('/api/simulate?scenario='+encodeURIComponent(scenario)); document.getElementById('simulation').innerHTML=`<div class="story"><strong>${escapeHtml(r.scenario)}</strong><span class="muted">Mein Bauchgefühl wäre: ${riskWord(r.risk_score||0)}.</span></div>`+((r.lessons||[]).map(l=>`<div class="story"><span class="muted">${escapeHtml(l)}</span></div>`).join('')); }
    function renderTools(tools){ document.getElementById('tools').innerHTML=tools.map(t=>`<div class="story"><strong>${escapeHtml(t.name)}</strong><span class="muted">${escapeHtml(t.status)}. Das ist eines meiner kleinen Hilfsmittel.</span></div>`).join('') || '<div class="story"><span class="muted">Keine Hilfsmittel gemeldet.</span></div>'; }
    function renderKnowledge(topics){ document.getElementById('knowledge').innerHTML=topics.map(t=>`<div class="story"><strong>${escapeHtml(t.name)}</strong><span class="muted">Bereich: ${escapeHtml(t.domain)}. Frag mich danach, wenn du es einfacher erklärt haben möchtest.</span></div>`).join('') || '<div class="story"><span class="muted">Noch kein Wissen geladen.</span></div>'; }
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
