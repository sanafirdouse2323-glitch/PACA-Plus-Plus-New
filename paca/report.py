"""Generates the self-contained interactive demo page (docs/index.html)."""
from __future__ import annotations

import json
from typing import Any, Dict

PAGE = r"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>PACA++ - catalog-driven agent authorisation demo</title><style>
:root{--bg:#fff;--fg:#1c1b19;--mut:#6b675f;--card:#f6f4ef;--bd:#dcd8cf;--ok:#1b7a43;--bad:#b3261e;--warn:#9a6700;--acc:#2b5fb4}
@media(prefers-color-scheme:dark){:root{--bg:#16150f;--fg:#ece9e1;--mut:#a29d92;--card:#201f18;--bd:#38362c;--ok:#5fd08a;--bad:#ff8a80;--warn:#e3b341;--acc:#8ab4f8}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,Segoe UI,sans-serif}
header{padding:20px 24px;border-bottom:1px solid var(--bd)}h1{margin:0 0 4px;font-size:20px}.mut{color:var(--mut)}
main{display:grid;grid-template-columns:320px 1fr;gap:0;min-height:70vh}@media(max-width:820px){main{grid-template-columns:1fr}}
nav{border-right:1px solid var(--bd);padding:12px;max-height:80vh;overflow:auto}nav button{display:block;width:100%;text-align:left;background:none;color:var(--fg);border:0;border-radius:8px;padding:7px 9px;cursor:pointer;font:inherit}
nav button.on,nav button:hover{background:var(--card)}nav small{color:var(--mut);display:block}.dot{display:inline-block;width:9px;height:9px;border-radius:50%;margin-right:6px}
section{padding:18px 24px;min-width:0}.tabs{display:flex;flex-wrap:wrap;gap:6px;margin:10px 0}.tabs button{border:1px solid var(--bd);background:var(--card);color:var(--fg);border-radius:20px;padding:5px 12px;cursor:pointer;font:inherit}
.tabs button.on{background:var(--acc);color:#fff;border-color:var(--acc)}.banner{padding:10px 14px;border-radius:10px;font-weight:600;margin:8px 0}.banner.ok{background:color-mix(in srgb,var(--ok) 16%,transparent);color:var(--ok)}
.banner.bad{background:color-mix(in srgb,var(--bad) 16%,transparent);color:var(--bad)}.ev{border:1px solid var(--bd);border-radius:10px;padding:9px 12px;margin:7px 0;background:var(--card);overflow-wrap:anywhere}
.ev.act.exec{border-left:4px solid var(--ok)}.ev.act.evilx{border-left:4px solid var(--bad)}.ev.act.deny{border-left:4px solid var(--warn)}.tag{font:12px ui-monospace,monospace;padding:1px 6px;border-radius:5px;border:1px solid var(--bd);margin-left:4px}
.tag.U{color:var(--bad)}.chk{font:12.5px ui-monospace,monospace;color:var(--mut);margin-top:3px}code{font:13px ui-monospace,monospace}
table{border-collapse:collapse;width:100%;font-size:14px;margin:8px 0}th,td{border-bottom:1px solid var(--bd);padding:6px 8px;text-align:right}th:first-child,td:first-child{text-align:left}
.sc{padding:16px 24px;border-bottom:1px solid var(--bd)}.sc .wrap{overflow-x:auto}h2{font-size:16px;margin:16px 0 4px}.pill{font-size:12px;border:1px solid var(--bd);border-radius:10px;padding:1px 8px;color:var(--mut)}
</style></head><body><header><h1>PACA++ <span class="mut">- provenance-anchored continuous authorisation</span></h1>
<div class="mut">Every attack scenario is derived from the Public AI Attack Catalog 2023-2026. Simulated benchmark: the model is assumed fully hijacked by any injected text, so only stopping the <i>terminal effect</i> counts. Pick a scenario, then switch defences.</div></header>
<div class="sc"><div class="wrap" id="score"></div><div id="abl"></div></div>
<main><nav id="nav"></nav><section id="view"></section></main>
<div class="sc"><h2>Not addressed by PACA++ (explicit non-goals)</h2><div id="oos" class="mut"></div></div>
<script id="data" type="application/json">__DATA__</script><script>
const D=JSON.parse(document.getElementById('data').textContent);let cur=D.scenarios[0].id,def='paca';const $=id=>document.getElementById(id);
const esc=s=>String(s).replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));
function score(){let h='<h2>Scoreboard (lower attack success is better)</h2><table><tr><th>Defence</th><th>Attacks succeed<br>(vigilant human)</th><th>Attacks succeed<br>(rubber-stamp)</th><th>Mean attacker<br>effects</th><th>Benign tasks<br>completed</th><th>Prompts per<br>benign task</th></tr>';
for(const d of D.defences){const m=D.metrics[d.key];h+=`<tr><td>${d.label}</td><td>${m.asr_vig}%</td><td>${m.asr_rub}%</td><td>${m.blast}</td><td>${m.completion}%</td><td>${m.prompts}</td></tr>`}
$('score').innerHTML=h+`</table><div class="mut">${D.n_attacks} attack scenarios (incl. 2 residual cases PACA++ is not expected to stop) and ${D.n_benign} benign workflows. Baselines are explicit models of control classes, not the real products.</div>`;
let a='<h2>Ablation: which attacks succeed if one PACA++ check is removed</h2><table><tr><th>Check</th><th>What it does</th><th>Attacks that now succeed</th></tr>';
for(const [c,ids] of Object.entries(D.ablation))a+=`<tr><td>${c}</td><td style="text-align:left">${esc(D.checks[c].title)}</td><td>${ids.length?ids.join(', '):'<span class=mut>none (covered by another check)</span>'}</td></tr>`;$('abl').innerHTML=a+'</table>';
$('oos').innerHTML=D.out_of_scope.map(o=>`<div>- <b>${esc(o[0])}</b> <span class=pill>${o[1]}</span> ${esc(o[2])}</div>`).join('')}
function nav(){let h='',last='';for(const s of D.scenarios){const r=s.results.paca.vig,bad=s.kind=='attack'?r.harmed:!r.completed;
const g=s.kind=='benign'?'Benign workflows':'Section '+s.section;if(g!=last){h+=`<div class="mut" style="margin:10px 6px 2px;font-size:12px">${s.kind=='benign'?g:'Catalog '+g}</div>`;last=g}
h+=`<button data-id="${s.id}" class="${s.id==cur?'on':''}"><span class="dot" style="background:var(--${bad?'bad':'ok'})"></span><b>${s.id}</b> ${esc(s.title)}</button>`}
$('nav').innerHTML=h;$('nav').querySelectorAll('button').forEach(b=>b.onclick=()=>{cur=b.dataset.id;nav();view()})}
function ev(e,s){if(e.kind=='task')return`<div class="ev"><b>Task</b> ${esc(e.text)}<div class="chk">capability: ${esc(JSON.stringify(e.grants))} - role ${e.role}</div></div>`;
if(e.kind=='say')return`<div class="ev"><b>User says</b> "${esc(e.text)}"${e.blocked?' <b style="color:var(--warn)">- blocked by input filter</b>':''}</div>`;
if(e.kind=='data')return`<div class="ev"><b>Inbound ${e.source}</b> ${esc(e.name)}<span class="tag ${e.label[0]}">${e.label}</span><div class="chk">${esc(e.text)}${e.blocked?' - <b>filter blocked</b>':''}</div></div>`;
if(e.kind=='memread')return`<div class="ev"><b>Memory read</b> ${esc(e.key)} ${e.found?`<span class="tag ${e.label[0]}">${e.label}</span>`:'<span class=mut>(nothing stored)</span>'}</div>`;
if(e.kind=='time')return`<div class="ev mut">${esc(e.text)}</div>`;if(e.kind=='skip')return`<div class="ev mut">skipped: ${esc(e.text)}</div>`;
const x=e.executed?(e.evil?'evilx':'exec'):'deny';const v=e.executed?(e.evil?'EXECUTED (attacker effect)':'executed'):(e.verdict=='deny'?'DENIED':e.human=='rejected'?'ESCALATED - human rejected':'ESCALATED');
const a=Object.entries(e.args).map(([k,[v,l]])=>`${k}=<code>${esc(v)}</code><span class="tag ${l[0]}">${l}</span>`).join(' ');
const h=e.human=='approved'?' - human approved':'';return`<div class="ev act ${x}"><b>${e.action}</b> ${a}<div><b style="color:var(--${e.executed?(e.evil?'bad':'ok'):'warn'})">${v}${h}</b>${e.swapped?' (executed args differ from authorised args)':''}</div>${(e.checks||[]).map(c=>`<div class="chk">${c.id}: ${esc(c.msg)}</div>`).join('')}</div>`}
function view(){const s=D.scenarios.find(x=>x.id==cur),R=s.results[def];
let h=`<h2 style="margin-top:0">${s.id} - ${esc(s.title)}</h2><div class="mut">${esc(s.klass)} <span class="pill">${s.ref}</span>${s.residual?' <span class="pill">residual risk</span>':''}</div><p>${esc(s.summary)}</p><div class="tabs">`;
for(const d of D.defences)h+=`<button class="${d.key==def?'on':''}" data-d="${d.key}">${d.label}</button>`;h+='</div>';
const v=R.vig,r=R.rub;
if(s.kind=='attack')h+=v.harmed?`<div class="banner bad">Attacker goal achieved (${v.evil} attacker effect${v.evil>1?'s':''} executed)</div>`:`<div class="banner ok">Contained${r.harmed?' - but succeeds if the human rubber-stamps the prompt':''}${v.fired.length?' (stopped by '+v.fired.join(', ')+')':''}</div>`;
else h+=v.completed?`<div class="banner ok">Task completed - ${v.prompts} approval prompt${v.prompts==1?'':'s'}</div>`:`<div class="banner bad">Task blocked (false block)</div>`;
h+=R.trace.map(e=>ev(e,s)).join('');if(def=='paca')h+=`<div class="mut">Audit log hash chain verified: ${R.audit_ok}</div>`;
$('view').innerHTML=h;$('view').querySelectorAll('.tabs button').forEach(b=>b.onclick=()=>{def=b.dataset.d;view()})}
score();nav();view();</script></body></html>"""


def write_html(data: Dict[str, Any], path: str) -> None:
    blob = json.dumps(data, default=str).replace("</", "<\\/")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(PAGE.replace("__DATA__", blob))
