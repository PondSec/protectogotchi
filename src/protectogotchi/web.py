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
      --bg: #fff8f1;
      --surface: rgba(255, 255, 255, .72);
      --surface-strong: #ffffff;
      --ink: #352a33;
      --muted: #806f7a;
      --line: #f0d8df;
      --soft: #ffe7ef;
      --mint: #dff8ed;
      --blue: #e6f1ff;
      --strong: #17856f;
      --warn: #b7791f;
      --danger: #c2415d;
      --shadow: 0 18px 50px rgba(122, 80, 102, .10);
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      color: var(--ink);
      background:
        radial-gradient(circle at 12% 10%, #ffe4f1 0, transparent 28%),
        radial-gradient(circle at 88% 4%, #dff8ed 0, transparent 26%),
        linear-gradient(135deg, #fffaf4 0%, #fff1f6 48%, #f4fbff 100%);
      min-height: 100vh;
    }
    header { padding: 22px clamp(18px, 4vw, 42px); display: flex; align-items: center; justify-content: space-between; gap: 18px; }
    h1 { font-size: clamp(24px, 4vw, 38px); margin: 0; letter-spacing: -.04em; }
    h2 { font-size: 13px; margin: 0 0 12px; color: var(--muted); letter-spacing: .08em; text-transform: uppercase; }
    h3 { margin: 0 0 8px; font-size: 16px; }
    main { display: grid; grid-template-columns: minmax(300px, 390px) 1fr; gap: 22px; padding: 0 clamp(18px, 4vw, 42px) 34px; }
    .side, .sheet, .tabs { background: var(--surface); border: 1px solid rgba(240, 216, 223, .75); border-radius: 30px; box-shadow: var(--shadow); backdrop-filter: blur(16px); }
    .side { padding: 24px; align-self: start; position: sticky; top: 18px; }
    .work { min-width: 0; }
    .hero { display: flex; gap: 16px; align-items: center; }
    .pet { width: 116px; height: 116px; border-radius: 36px; background: linear-gradient(145deg, #fff, #ffe5ef); display: grid; place-items: center; box-shadow: inset 0 -10px 18px rgba(215, 99, 139, .08); border: 1px solid #ffd5e2; }
    .face { font: 800 35px/1 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
    .state { font-size: 25px; font-weight: 800; margin-bottom: 5px; letter-spacing: -.03em; }
    .muted { color: var(--muted); }
    .bubble { position: relative; margin: 20px 0; padding: 16px 17px; border-radius: 24px 24px 24px 8px; background: var(--surface-strong); border: 1px solid var(--line); line-height: 1.45; }
    .bubble::before { content: ""; position: absolute; left: 22px; bottom: -9px; width: 18px; height: 18px; background: var(--surface-strong); border-right: 1px solid var(--line); border-bottom: 1px solid var(--line); transform: rotate(45deg); }
    .live { display: inline-flex; align-items: center; gap: 8px; font-size: 13px; color: var(--muted); }
    .headerActions { display: flex; align-items: center; gap: 18px; flex-wrap: wrap; justify-content: flex-end; }
    .modeSwitch, .tabs { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }
    button { appearance: none; border: 0; border-radius: 999px; padding: 10px 14px; font: inherit; cursor: pointer; background: #fff; color: var(--ink); box-shadow: 0 4px 14px rgba(122,80,102,.08); }
    button.active { background: #352a33; color: #fff; }
    .dot { width: 10px; height: 10px; border-radius: 50%; background: var(--strong); display: inline-block; box-shadow: 0 0 0 6px rgba(23, 133, 111, .12); }
    .metrics { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 12px; margin-top: 18px; }
    .metric { background: rgba(255,255,255,.68); border: 1px solid var(--line); border-radius: 22px; padding: 14px; }
    .metric span { display: block; color: var(--muted); font-size: 12px; }
    .metric strong { display: block; font-size: 25px; margin-top: 2px; }
    .risk-low { color: var(--strong); } .risk-mid { color: var(--warn); } .risk-high { color: var(--danger); }
    .tabs { position: sticky; top: 0; padding: 12px; z-index: 2; margin-bottom: 18px; }
    .panel { display: none; } .panel.active { display: grid; gap: 18px; }
    .sheet { padding: 24px; overflow: hidden; }
    .grid2 { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 18px; }
    .storyList { display: grid; gap: 10px; }
    .story { padding: 13px 0; border-bottom: 1px solid var(--line); }
    .story:last-child { border-bottom: 0; }
    .pill { display:inline-flex; gap:7px; align-items:center; border-radius:999px; padding:7px 11px; background:rgba(255,255,255,.7); border:1px solid var(--line); color:var(--muted); font-size:13px; }
    .quietbar { height:10px; border-radius:999px; background:#f7dbe5; overflow:hidden; margin-top:10px; }
    .quietbar > span { display:block; height:100%; background:linear-gradient(90deg,#8ee6c6,#ffd6e5); }
    table { width: 100%; border-collapse: collapse; font-size: 14px; }
    th, td { text-align: left; padding: 12px 8px; border-bottom: 1px solid var(--line); vertical-align: top; }
    th { color: var(--muted); font-size: 12px; }
    code, pre { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 12px; }
    pre { white-space: pre-wrap; overflow-wrap: anywhere; margin: 0; line-height: 1.55; color: #594a54; }
    svg { width: 100%; min-height: 380px; border-radius: 24px; background: linear-gradient(180deg, #fff, #fff7fb); border: 1px solid var(--line); }
    .nodeLabel { font: 13px ui-sans-serif, system-ui; fill: var(--ink); font-weight: 700; }
    .nodeMeta { font: 10px ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; fill: var(--muted); }
    .link { stroke: #e2b8c6; stroke-width: 2; stroke-linecap: round; }
    .node { fill: #ffffff; stroke: #efc8d5; stroke-width: 1.5; rx: 18; ry: 18; }
    .node.gateway, .node.default-gateway { stroke: var(--strong); stroke-width: 2.5; }
    .node.host { fill: var(--soft); } .node.subnet { fill: var(--blue); } .node.interface { fill: var(--mint); }
    .severity-critical, .severity-high { color: var(--danger); } .severity-medium { color: var(--warn); }
    @media (max-width: 920px) { main { grid-template-columns: 1fr; } .side { position: static; } .grid2 { grid-template-columns: 1fr; } }
  </style>
</head>
<body>
  <header>
    <div><h1>Protectogotchi</h1><div class="muted">Dein kleines Netzwerk-Haustier erklärt Schutz in Menschensprache.</div></div>
    <div class="headerActions"><div class="modeSwitch" aria-label="Modus"><button data-mode="learn" class="active" onclick="setMode('learn')">Lernen</button><button data-mode="watch" onclick="setMode('watch')">Nur schauen</button><button data-mode="guard" onclick="setMode('guard')">Aufpassen</button><button data-mode="god" onclick="setMode('god')">Autopilot</button><button data-mode="pause" onclick="setMode('pause')">Pause</button></div><div class="live"><span class="dot"></span><span id="liveText">startet</span></div></div>
  </header>
  <main>
    <aside class="side"><div class="hero"><div class="pet"><div class="face" id="face">( o_o)</div></div><div><div class="state" id="state">Ich wache auf</div><div class="muted" id="mood">warte auf den ersten Blick ins Netzwerk</div></div></div><div class="bubble" aria-label="Gedankenblase"><strong>Gedankenblase</strong><br><span id="thought">Ich schaue gleich nach, ob zuhause alles ruhig ist.</span></div><div class="metrics"><div class="metric"><span>Bauchgefühl</span><strong id="risk">-</strong></div><div class="metric"><span>Erfahrung</span><strong id="level">-</strong></div><div class="metric"><span>Gelernt</span><strong id="baseline">-</strong></div><div class="metric"><span>Geräte</span><strong id="devicesCount">-</strong></div></div></aside>
    <div class="work"><nav class="tabs" aria-label="Ansichten"><button data-tab="overview" class="active" onclick="switchTab('overview')">Zuhause</button><button data-tab="activity" onclick="switchTab('activity')">Was passiert?</button><button data-tab="findings" onclick="switchTab('findings')">Sorgen</button><button data-tab="devices" onclick="switchTab('devices')">Mitbewohner</button><button data-tab="lab" onclick="switchTab('lab')">Spielwiese</button><button data-tab="arsenal" onclick="switchTab('arsenal')">Hilfe</button></nav>
      <section class="panel active" data-panel="overview"><div class="sheet"><h2>Die Wohnungskarte</h2><svg id="networkGraph" role="img" aria-label="Einfache Netzwerkkarte"></svg></div><div class="grid2"><div class="sheet"><h2>Kurz gesagt</h2><div id="plainSummary" class="storyList">lädt...</div></div><div class="sheet"><h2>Meine Wachsamkeit</h2><div id="watchfulness">lädt...</div><pre id="topology">lädt...</pre></div></div></section>
      <section class="panel" data-panel="activity"><div class="sheet"><h2>Gerade im Netzwerk los</h2><div id="activity">lädt...</div></div><div class="grid2"><div class="sheet"><h2>Details für Neugierige</h2><pre id="networkDetail">lädt...</pre></div><div class="sheet"><h2>Abdeckung</h2><pre id="coverage">lädt...</pre></div></div></section>
      <section class="panel" data-panel="findings"><div class="sheet"><h2>Sorgen & Empfehlungen</h2><div id="findings">lädt...</div></div><div class="sheet"><h2>Letzte Erinnerungen</h2><div id="history">lädt...</div></div></section>
      <section class="panel" data-panel="devices"><div class="sheet"><h2>Bekannte Mitbewohner</h2><table><thead><tr><th>Name</th><th>Adresse</th><th>Wie oft gesehen</th><th>Zuletzt</th></tr></thead><tbody id="devices"></tbody></table></div></section>
      <section class="panel" data-panel="lab"><div class="sheet"><h2>Passt mein Platz?</h2><pre id="placement">lädt...</pre></div><div class="sheet"><h2>Gefahr gefahrlos ausprobieren</h2><div class="modeSwitch" id="simulationButtons"></div><pre id="simulation">Such dir ein kleines Szenario aus.</pre></div></section>
      <section class="panel" data-panel="arsenal"><div class="grid2"><div class="sheet"><h2>Was ich benutzen kann</h2><pre id="tools">lädt...</pre></div><div class="sheet"><h2>Was ich weiß</h2><pre id="knowledge">lädt...</pre></div></div></section>
    </div>
  </main>
  <script>
    const faces = { idle:"( -_-)", bored:"( -3-)", learning:"( o_o)", analyzing:"( @_@)", alert:"( O_O)!", fighting:"( >_<)", happy:"( ^_^)", curious:"( •_•)?" };
    const modeNames = { learn:"Lernen", watch:"Nur schauen", guard:"Aufpassen", god:"Autopilot", pause:"Pause" };
    async function getJson(path){ const r=await fetch(path); if(!r.ok) throw new Error(path+" -> "+r.status); return r.json(); }
    function severityWord(s){ return ({info:"Info",low:"kleine Sorge",medium:"bitte anschauen",high:"wichtig",critical:"dringend"})[s] || s; }
    function riskWord(score){ if(score>=70) return "unruhig"; if(score>=35) return "aufmerksam"; return "ruhig"; }
    async function refresh(){
      const live=await getJson('/api/live'); const scan=live.scan||{}; const state=live.state||{}; const snapshot=scan.snapshot||{}; const faceState=live.pet_state || scan.face_state || (state.baseline_ready?'happy':'learning');
      document.getElementById('face').textContent=faces[faceState]||faces.idle; document.getElementById('state').textContent=live.pet_headline || modeNames[live.mode] || 'Ich passe auf'; document.getElementById('mood').textContent=live.pet_subtitle || live.mode_description || '';
      document.getElementById('thought').textContent=live.thought || 'Ich schaue mich um und sage Bescheid, wenn mir etwas komisch vorkommt.'; renderMode(live.mode||'learn');
      document.getElementById('risk').textContent=riskWord(scan.risk_score||0); document.getElementById('risk').className=(scan.risk_score||0)>=70?'risk-high':((scan.risk_score||0)>=35?'risk-mid':'risk-low'); document.getElementById('level').textContent=state.level??'-'; document.getElementById('baseline').textContent=state.baseline_ready?'ja':((state.learning_remaining||0)+' Blicke'); document.getElementById('devicesCount').textContent=state.known_devices??'-'; document.getElementById('liveText').textContent='zuletzt geschaut: '+(live.updated_at||'gerade');
      renderPlainSummary(live, snapshot); renderActivity(live, snapshot); renderGraph((live.network_map||{}).graph||{nodes:[],edges:[]}); renderFindings(scan.findings||[]); renderHistory(live.finding_history||[]); renderDevices(live.devices||[]); renderPlacement(live.placement_report||{}); renderSimulationButtons(live.simulations||[]);
      document.getElementById('topology').textContent=(live.calm_status||[]).join('\n'); renderWatchfulness(live); document.getElementById('networkDetail').textContent=JSON.stringify((live.network_map||{}).summary||{},null,2); document.getElementById('coverage').textContent=((live.network_map||{}).coverage||[]).join('\n') || 'Noch keine Abdeckung bekannt.'; document.getElementById('tools').textContent=(live.tools||[]).map(t=>'• '+t.name+' — '+t.status).join('\n'); document.getElementById('knowledge').textContent=(live.knowledge||[]).map(t=>'• '+t.name+' ('+t.domain+')').join('\n');
    }
    function renderWatchfulness(live){ const quiet=live.quiet_scans||0; const pct=Math.min(100, quiet*25); document.getElementById('watchfulness').innerHTML=`<span class="pill">öftere Kontrollblicke · ${quiet} ruhige Runden</span><div class="quietbar"><span style="width:${pct}%"></span></div>`; }
    function renderPlainSummary(live,s){ const items=[['WLAN', (s.wifi||{}).ssid || 'nicht erkannt'], ['Internet-Tür', s.default_gateway || 'noch unbekannt'], ['Modus', modeNames[live.mode] || live.mode], ['Aktive Verbindungen', (s.connections||[]).length], ['Gefundene Geräte', (s.devices||[]).length]]; document.getElementById('plainSummary').innerHTML=items.map(i=>`<div class="story"><strong>${i[0]}</strong><br><span class="muted">${escapeHtml(i[1])}</span></div>`).join(''); }
    function renderActivity(live,s){ const findings=(live.scan||{}).findings||[]; const lines=[]; lines.push(`<div class="story"><strong>${findings.length?'Ich habe etwas bemerkt':'Alles wirkt gerade ruhig'}</strong><br><span class="muted">${escapeHtml(live.activity_summary||'Keine ungewöhnlichen Geräusche im Netzwerk.')}</span></div>`); (s.connections||[]).slice(0,8).forEach(c=>lines.push(`<div class="story">${escapeHtml(c.protocol||'Verbindung')} von ${escapeHtml(c.local_address||'?')}:${c.local_port||''} zu ${escapeHtml(c.remote_address||'zuhause')}:${c.remote_port||''}<br><span class="muted">Status: ${escapeHtml(c.state||'unbekannt')}</span></div>`)); document.getElementById('activity').innerHTML=lines.join(''); }
    function renderFindings(findings){ const t=document.getElementById('findings'); if(!findings.length){t.innerHTML="<div class='story'><strong>Keine Sorgen.</strong><br><span class='muted'>Ich sehe gerade nichts, das dich stressen sollte.</span></div>"; return;} t.innerHTML=findings.map(f=>`<div class="story"><strong class="severity-${f.severity}">${severityWord(f.severity)}: ${escapeHtml(f.title)}</strong><br><span>${escapeHtml(f.description)}</span><br><span class="muted">Mein Vorschlag: ${escapeHtml(f.recommended_action||'beobachten')}</span></div>`).join(''); }
    function renderHistory(history){ const t=document.getElementById('history'); if(!history.length){t.innerHTML="<span class='muted'>Noch keine Erinnerungen.</span>"; return;} t.innerHTML=history.slice(-10).reverse().map(f=>`<div class="story"><strong class="severity-${f.severity}">${escapeHtml(f.title)}</strong><br><span class="muted">${escapeHtml(f.seen_at)} · ${severityWord(f.severity)}</span></div>`).join(''); }
    function renderDevices(devices){ document.getElementById('devices').innerHTML=devices.map(d=>`<tr><td>${escapeHtml(d.hostname||'Unbenanntes Gerät')}<br><code>${escapeHtml(d.mac)}</code></td><td>${escapeHtml((d.ips||[]).join(', ')||'-')}</td><td>${d.seen_count||0}</td><td>${escapeHtml(d.last_seen||'-')}</td></tr>`).join('') || '<tr><td colspan="4" class="muted">Noch keine Geräte gelernt.</td></tr>'; }
    function renderPlacement(r){ document.getElementById('placement').textContent=['Kurzfassung: '+(r.summary||'noch unbekannt'),'Schutz aktiv: '+(r.active_response_enabled?'ja':'noch nicht'),'Automatisierung: '+(r.firewall_controller_automation?'ja':'nein'),'Nächste liebevolle Schritte:',...((r.next_steps||[]).map(s=>'• '+s))].join('\n'); }
    function renderSimulationButtons(s){ document.getElementById('simulationButtons').innerHTML=s.map(n=>`<button onclick="runLabScenario('${escapeHtml(n)}')">${escapeHtml(n)}</button>`).join(''); }
    async function runLabScenario(scenario){ const r=await getJson('/api/simulate?scenario='+encodeURIComponent(scenario)); document.getElementById('simulation').textContent=['Szenario: '+r.scenario,'Risiko: '+riskWord(r.risk_score||0),'Was ich lerne:',...((r.lessons||[]).map(l=>'• '+l))].join('\n'); }
    function renderGraph(graph){ const svg=document.getElementById('networkGraph'), nodes=graph.nodes||[], edges=graph.edges||[], width=Math.max(760,svg.clientWidth||760), columns={host:90,interface:250,subnet:430,gateway:630,'default-gateway':630,endpoint:630,'local-host':630,'infrastructure-candidate':630}, grouped={}; nodes.forEach(n=>{const k=n.kind||'endpoint'; (grouped[k]=grouped[k]||[]).push(n);}); const pos={}; ['host','interface','subnet','default-gateway','gateway','infrastructure-candidate','endpoint','local-host'].forEach(k=>(grouped[k]||[]).forEach((n,i)=>pos[n.id]={x:columns[k]||630,y:65+i*70})); const height=Math.max(380,...Object.values(pos).map(p=>p.y+55)); svg.setAttribute('viewBox',`0 0 ${width} ${height}`); svg.innerHTML=edges.map(e=>pos[e.source]&&pos[e.target]?`<line class="link" x1="${pos[e.source].x+62}" y1="${pos[e.source].y}" x2="${pos[e.target].x-62}" y2="${pos[e.target].y}"></line>`:'').join('')+nodes.map(n=>{const p=pos[n.id]; if(!p)return''; return `<g><rect class="node ${n.kind||'endpoint'}" x="${p.x-62}" y="${p.y-24}" width="124" height="48"></rect><text class="nodeLabel" x="${p.x-52}" y="${p.y-4}">${escapeHtml(n.label||n.id)}</text><text class="nodeMeta" x="${p.x-52}" y="${p.y+13}">${escapeHtml([n.ip,n.mac].filter(Boolean).join(' · '))}</text></g>`}).join(''); }
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
