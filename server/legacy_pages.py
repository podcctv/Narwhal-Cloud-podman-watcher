"""Fallback inline HTML views when the compiled frontend bundle is absent."""
from __future__ import annotations

from pathlib import Path
from typing import Any, Callable

from fastapi import Request
from fastapi.responses import FileResponse, HTMLResponse


def security_alert_history_page(request: Request = None, static_dir: Path | None = None) -> Any:
    spa_index = (static_dir / "index.html") if static_dir is not None else None
    if spa_index is not None and request is not None and spa_index.is_file():
        return FileResponse(spa_index)
    return """
<!doctype html>
<html lang='zh-CN'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>
<title>告警历史 · Narwhal Monitor</title>
<style>
*{box-sizing:border-box}html,body{max-width:100%;overflow-x:hidden}:root{color-scheme:dark;--bg:#020617;--surface:#0f172a;--surface2:#172033;--surface3:#1e293b;--border:#334155;--text:#f8fafc;--muted:#94a3b8;--accent:#38bdf8;--success:#22c55e;--warning:#f59e0b;--danger:#ef4444;--focus:#7dd3fc}
body{margin:0;background:var(--bg);color:var(--text);font-family:system-ui,-apple-system,"Segoe UI",sans-serif;line-height:1.5}.skip-link{position:fixed;top:-70px;left:12px;z-index:1000;padding:10px 14px;border-radius:8px;background:var(--accent);color:#082f49;font-weight:750}.skip-link:focus{top:12px}.shell{width:min(1500px,100%);margin:auto;padding:20px}.header{display:flex;justify-content:space-between;align-items:flex-start;gap:18px;padding:18px 20px;border:1px solid var(--border);border-radius:14px;background:linear-gradient(135deg,#0f172a,#111d34)}h1{margin:0;font-size:22px}.subtitle{margin:5px 0 0;color:var(--muted);font-size:13px}.header-actions,.actions,.status-tabs{display:flex;align-items:center;gap:8px;flex-wrap:wrap}.btn,.nav-link{display:inline-flex;align-items:center;justify-content:center;min-height:44px;padding:8px 13px;border:1px solid var(--border);border-radius:8px;background:var(--surface3);color:var(--text);font:inherit;text-decoration:none;cursor:pointer;touch-action:manipulation;transition:filter 180ms ease,opacity 180ms ease}.btn:hover,.nav-link:hover{filter:brightness(1.13)}.btn:focus-visible,.nav-link:focus-visible,input:focus-visible,select:focus-visible,.status-chip:focus-visible{outline:3px solid var(--focus);outline-offset:2px}.btn:disabled{opacity:.55;cursor:wait}.btn-danger{border-color:#b91c1c;background:#7f1d1d}.btn-secondary{background:#334155}.panel{margin-top:16px;border:1px solid var(--border);border-radius:14px;background:var(--surface);overflow:hidden}.panel-head{padding:14px 16px;border-bottom:1px solid var(--border);background:var(--surface2)}.panel-head h2{margin:0;font-size:17px}.filters{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:12px;padding:16px}.field{min-width:0}.field label{display:block;margin-bottom:5px;color:#cbd5e1;font-size:12px;font-weight:650}.field input,.field select{width:100%;min-height:44px;padding:8px 10px;border:1px solid var(--border);border-radius:8px;background:#0b1220;color:var(--text);font:inherit}.filter-actions{display:flex;align-items:end;gap:8px}.status-tabs{padding:12px 16px;border-top:1px solid var(--border)}.status-chip{min-height:44px;padding:6px 10px;border:1px solid var(--border);border-radius:999px;background:#111827;color:#cbd5e1;cursor:pointer;touch-action:manipulation}.status-chip.active{border-color:#0ea5e9;background:#082f49;color:#bae6fd}.alert-list{display:grid;gap:12px;padding:16px}.alert-card{min-width:0;border:1px solid var(--border);border-left:4px solid var(--warning);border-radius:12px;background:#0b1220;padding:15px}.alert-card.critical{border-left-color:var(--danger)}.alert-card.info{border-left-color:var(--accent)}.alert-top{display:flex;justify-content:space-between;align-items:flex-start;gap:12px}.alert-title{min-width:0}.alert-title h3{margin:0;font-size:16px;overflow-wrap:anywhere}.meta{display:flex;gap:7px;flex-wrap:wrap;margin-top:7px}.pill{display:inline-flex;align-items:center;min-height:28px;padding:3px 9px;border:1px solid var(--border);border-radius:999px;background:#111827;color:#cbd5e1;font-size:12px;overflow-wrap:anywhere}.pill.active{border-color:#b91c1c;background:#450a0a;color:#fca5a5}.pill.suppressed{border-color:#166534;background:#052e16;color:#86efac}.pill.dismissed{border-color:#92400e;background:#451a03;color:#fcd34d}.pill.remediated{border-color:#0369a1;background:#082f49;color:#7dd3fc}.pill.resolved{color:#cbd5e1}.message{margin:13px 0;color:#e2e8f0;overflow-wrap:anywhere}.evidence{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:8px}.evidence-block{min-width:0;padding:10px;border:1px solid #26364e;border-radius:9px;background:#0f172a}.evidence-block span{display:block;color:var(--muted);font-size:11px}.evidence-block strong{display:block;margin-top:4px;font-size:13px;font-weight:600;overflow-wrap:anywhere}.result{margin-top:10px;padding:10px;border-radius:8px;background:#111827;color:#cbd5e1;font-size:12px;overflow-wrap:anywhere}.card-footer{display:flex;justify-content:space-between;align-items:flex-end;gap:12px;margin-top:12px}.timestamps{color:var(--muted);font-size:12px}.empty{padding:36px;text-align:center;color:var(--muted)}.load-more{display:flex;justify-content:center;padding:0 16px 18px}.toast{position:fixed;right:18px;bottom:18px;z-index:10;max-width:min(440px,calc(100% - 36px));padding:12px 14px;border:1px solid #166534;border-radius:10px;background:#052e16;color:#bbf7d0;box-shadow:0 12px 35px #0008}.toast.error{border-color:#991b1b;background:#450a0a;color:#fecaca}[hidden]{display:none!important}
@media(max-width:1000px){.filters{grid-template-columns:repeat(2,minmax(0,1fr))}.evidence{grid-template-columns:1fr}.filter-actions{align-items:center}.card-footer{align-items:flex-start;flex-direction:column}}
@media(max-width:640px){.shell{padding:8px}.header{padding:14px;flex-direction:column}.filters{grid-template-columns:1fr;padding:10px}.alert-list{padding:10px}.alert-top{flex-direction:column}.actions{width:100%}.actions .btn{flex:1 1 100%}.status-tabs{padding:10px}.status-chip{flex:1 1 calc(50% - 8px)}}
@media(prefers-reduced-motion:reduce){*,*::before,*::after{scroll-behavior:auto!important;transition:none!important;animation:none!important}}
</style></head><body><a class='skip-link' href='#history-main'>跳到主要内容</a><main id='history-main' class='shell'>
<header class='header'><div><h1>安全告警历史</h1><p class='subtitle'>保留活动、已忽略、已处理和已恢复事件；可重新禁止或恢复提醒。</p></div><div class='header-actions'><span id='server-version' class='pill'>Server</span><a class='nav-link' href='/'>返回总览</a><button class='btn' type='button' onclick='loadHistory(true)'>刷新</button></div></header>
<section class='panel' aria-labelledby='filter-title'><header class='panel-head'><h2 id='filter-title'>检索与筛选</h2></header><div class='filters'>
<div class='field'><label for='severity'>级别</label><select id='severity'><option value='all'>全部级别</option><option value='critical'>Critical</option><option value='warning'>Warning</option><option value='info'>Info</option></select></div>
<div class='field'><label for='alert-type'>告警类型</label><select id='alert-type'><option value='all'>全部类型</option></select></div>
<div class='field'><label for='host-id'>主机</label><select id='host-id'><option value=''>全部主机</option></select></div>
<div class='field'><label for='query'>关键词</label><input id='query' type='search' placeholder='容器、主机、说明'></div>
<div class='filter-actions'><button class='btn' type='button' onclick='applyFilters()'>应用筛选</button><button class='btn btn-secondary' type='button' onclick='resetFilters()'>重置</button></div>
</div><div id='status-tabs' class='status-tabs' aria-label='处理状态'></div></section>
<section class='panel' aria-labelledby='history-title'><header class='panel-head'><h2 id='history-title'>告警记录 <span id='result-count' class='pill'>0</span></h2></header><div id='alert-list' class='alert-list' aria-live='polite'><div class='empty'>正在加载告警历史…</div></div><div class='load-more'><button id='load-more' class='btn' type='button' hidden onclick='loadMore()'>加载更多</button></div></section>
</main><div id='toast' class='toast' role='status' aria-live='polite' hidden></div>
<script>
const state={status:'all',offset:0,limit:50,total:0,loading:false};
const labels={active:'活动',suppressed:'允许且不再提醒',dismissed:'本次取消提醒',resolved:'已恢复',remediated:'已处理'};
const decisions={deny:'禁止/处理',allow_silent:'允许且不再提醒',dismiss_once:'本次取消提醒',reopen:'恢复提醒'};
function esc(value){return String(value??'').replace(/[&<>'"]/g,ch=>({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[ch]));}
function showToast(message,error=false){const toast=document.getElementById('toast');toast.textContent=message;toast.className=`toast${error?' error':''}`;toast.hidden=false;setTimeout(()=>{toast.hidden=true},4500)}
function actionable(alert){const details=alert.details||{};const runmanReady=alert.runtime==='runman'&&/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(details.instance_id||'')&&((details.process_targets||[]).length>0||(details.file_targets||[]).length>0);const supported=alert.runtime==='incus'||alert.runtime==='podman'||runmanReady;if(!supported)return false;if(alert.type==='unauthorized_panel_pairing')return ((details.process_patterns||[]).length>0||(details.config_files||[]).length>0)&&(alert.runtime!=='runman'||runmanReady);if(alert.type==='socks_weak_auth')return alert.runtime!=='runman'&&['no_auth','weak_password'].includes(details.socks_auth_mode)&&(details.socks_processes||[]).length>0;if(alert.type==='malicious_process')return (details.malicious_processes||[]).some(x=>x.process==='xmrig')&&(alert.runtime!=='runman'||(details.process_targets||[]).some(x=>x.process==='xmrig'&&x.pattern==='xmrig'&&/^\\d+$/.test(x.start_ticks||'')));return false;}
function evidenceText(alert){const d=alert.details||{};if(alert.type==='unauthorized_panel_pairing')return [`域名：${(d.unapproved_domains||[]).join(', ')||'-'}`,`进程：${(d.process_patterns||[]).join(', ')||'-'}`,`配置：${(d.config_files||[]).join(', ')||'-'}`];if(alert.type==='socks_weak_auth')return [`认证：${d.socks_auth_mode||'unknown'}`,`进程：${(d.socks_processes||[]).join(', ')||'-'}`,`配置：${(d.socks_config_files||[]).join(', ')||'-'}`];if(alert.type==='malicious_process')return [`进程：${(d.malicious_processes||[]).map(x=>x.process).join(', ')||'-'}`,`PID：${(d.malicious_processes||[]).map(x=>x.pid||'-').join(', ')||'-'}`,'策略：仅精确匹配 XMRig'];return [`指标：${alert.value||0}`,`阈值：${alert.threshold||0}`,`类型：${alert.type}`];}
function resultText(alert){const automatic=alert.details?.automatic_remediation;const action=alert.latest_action;const decision=alert.latest_decision;const parts=[];if(automatic?.attempted)parts.push(`自动处置：${automatic.succeeded?'成功':'失败'} · ${automatic.message||'-'}`);if(action)parts.push(`节点操作：${action.status} · ${action.result_message||action.action_type}`);if(decision)parts.push(`人工决定：${decisions[decision.decision]||decision.decision} · ${decision.requested_by} · ${decision.created_at_utc8}`);return parts.join('<br>');}
function card(alert){const runtime=alert.project?`${alert.runtime}/${alert.project}`:(alert.runtime||'-');const evidence=evidenceText(alert);const canAct=actionable(alert);const historical=alert.status!=='active';const controls=[];if(canAct)controls.push(`<button class='btn btn-danger' type='button' data-action-id='${alert.id}' onclick="decide(${alert.id},'deny')">${historical?'重新禁止/处理':'禁止/处理'}</button>`);if(alert.status==='suppressed'||alert.status==='dismissed')controls.push(`<button class='btn btn-secondary' type='button' data-action-id='${alert.id}' onclick="decide(${alert.id},'reopen')">恢复提醒</button>`);const result=resultText(alert);return `<article class='alert-card ${esc(alert.severity)}'><div class='alert-top'><div class='alert-title'><h3>${esc(alert.title||alert.type)}</h3><div class='meta'><span class='pill ${esc(alert.status)}'>${esc(labels[alert.status]||alert.status)}</span><span class='pill'>${esc(alert.severity)}</span><span class='pill'>${esc(alert.host_id)}</span><span class='pill'>${esc(runtime)}</span><span class='pill'>${esc(alert.container_name||'-')}</span></div></div><span class='pill'>出现 ${Number(alert.occurrence_count||0)} 次</span></div><p class='message'>${esc(alert.message)}</p><div class='evidence'>${evidence.map((x,i)=>`<div class='evidence-block'><span>${['关键证据','关联对象','处置范围'][i]||'证据'}</span><strong>${esc(x)}</strong></div>`).join('')}</div>${result?`<div class='result'>${result}</div>`:''}<footer class='card-footer'><div class='timestamps'>首次 ${esc(alert.first_seen_utc8)} · 最近 ${esc(alert.last_seen_utc8)}</div><div class='actions'>${controls.join('')}</div></footer></article>`;}
function fillOptions(id,values,current,allLabel){const select=document.getElementById(id);select.innerHTML=`<option value='${id==='host-id'?'':'all'}'>${allLabel}</option>`+values.map(v=>`<option value='${esc(v)}'>${esc(v)}</option>`).join('');select.value=current||'';}
function renderTabs(counts){const tabs=document.getElementById('status-tabs');tabs.innerHTML=['all','active','suppressed','dismissed','remediated','resolved'].map(status=>`<button type='button' class='status-chip ${state.status===status?'active':''}' onclick="selectStatus('${status}')">${status==='all'?'全部':labels[status]} ${Number(counts?.[status]||0)}</button>`).join('');}
async function loadHistory(reset=false){if(state.loading)return;if(reset)state.offset=0;state.loading=true;const params=new URLSearchParams({status:state.status,severity:document.getElementById('severity').value,alert_type:document.getElementById('alert-type').value,host_id:document.getElementById('host-id').value,query:document.getElementById('query').value,limit:String(state.limit),offset:String(state.offset)});try{const response=await fetch(`/api/v1/security/history?${params}`);const data=await response.json();if(!response.ok)throw new Error(data.detail||`HTTP ${response.status}`);state.total=Number(data.total||0);document.getElementById('server-version').textContent='Server 已连接';document.getElementById('result-count').textContent=`${state.total} 条`;renderTabs(data.counts);if(reset){fillOptions('alert-type',data.alert_types||[],document.getElementById('alert-type').value,'全部类型');fillOptions('host-id',data.hosts||[],document.getElementById('host-id').value,'全部主机');document.getElementById('alert-list').innerHTML='';}const list=document.getElementById('alert-list');if(reset)list.innerHTML='';list.insertAdjacentHTML('beforeend',(data.items||[]).map(card).join(''));state.offset+=(data.items||[]).length;if(state.total===0)list.innerHTML='<div class="empty">没有符合条件的告警记录</div>';document.getElementById('load-more').hidden=state.offset>=state.total;}catch(error){showToast(`加载失败：${error.message||error}`,true)}finally{state.loading=false}}
function selectStatus(status){state.status=status;loadHistory(true)}function applyFilters(){loadHistory(true)}function resetFilters(){state.status='all';document.getElementById('severity').value='all';document.getElementById('alert-type').value='all';document.getElementById('host-id').value='';document.getElementById('query').value='';loadHistory(true)}function loadMore(){loadHistory(false)}
async function decide(id,decision){const warning=decision==='deny'?'确认重新执行定向处置？只会处理已识别的进程、服务和配置，不会停止容器。':'确认撤销忽略策略并恢复提醒？';if(!confirm(warning))return;document.querySelectorAll(`[data-action-id="${id}"]`).forEach(x=>x.disabled=true);try{const response=await fetch(`/api/v1/security/alerts/${id}/disposition`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({decision})});const data=await response.json();if(!response.ok)throw new Error(data.detail||`HTTP ${response.status}`);showToast(data.queued?'操作已排队，等待节点执行':'状态已更新');await loadHistory(true)}catch(error){showToast(`操作失败：${error.message||error}`,true);document.querySelectorAll(`[data-action-id="${id}"]`).forEach(x=>x.disabled=false)}}
document.getElementById('query').addEventListener('keydown',event=>{if(event.key==='Enter')loadHistory(true)});loadHistory(true);setInterval(()=>loadHistory(true),30000);
</script></body></html>
"""


def dashboard(request: Request = None, static_dir: Path | None = None) -> Any:
    spa_index = (static_dir / "index.html") if static_dir is not None else None
    if spa_index is not None and request is not None and spa_index.is_file():
        return FileResponse(spa_index)
    return """
<!doctype html>
<html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width, initial-scale=1'><title>Narwhal Container Monitor</title>
<style>
*{box-sizing:border-box}
html,body{max-width:100%;overflow-x:hidden}
body{font-family:system-ui,-apple-system,"Segoe UI",sans-serif;margin:1rem;background:#0f1a2e;color:#dbe7ff;line-height:1.5}
table{border-collapse:collapse;width:100%;max-width:100%;table-layout:fixed;background:#13213b;color:#dbe7ff}
th,td{border:1px solid #233b61;padding:8px;vertical-align:middle;text-align:center;overflow-wrap:anywhere;word-break:break-word}
th{background:#1a2c4e}
.bad{color:#ff6b78;font-weight:bold}
.ok{color:#72dfa7}
.severity-critical{color:#ff5f6d;font-weight:bold}
.severity-warning{color:#ffbf4b;font-weight:bold}
.btn{border:1px solid #4b6fa8;min-height:44px;padding:7px 11px;border-radius:8px;background:#1a2c4e;color:#dbe7ff;cursor:pointer;touch-action:manipulation}
.btn-danger{background:#7c2330;border-color:#d94b61;margin-right:6px}
.btn-allow{background:#185d4a;border-color:#36a77f;margin-right:6px}
.btn-dismiss{background:#34445e;border-color:#6e85a8}
.btn:disabled{opacity:.55;cursor:not-allowed}
.security-action-state{display:flex;align-items:center;justify-content:center;min-height:28px;margin-bottom:7px;font-weight:650}
.security-action-buttons{display:flex;align-items:center;justify-content:center;gap:6px;flex-wrap:wrap}
.security-action-buttons .btn{margin-right:0}
.action-status{font-size:12px;margin-top:7px;color:#a9bddc}
#modal{position:fixed;inset:0;background:rgba(0,0,0,.35);display:none;align-items:center;justify-content:center}
#card{background:#0d1730;border-radius:12px;padding:16px;width:min(1380px,96vw);max-height:94vh;overflow-y:auto}
.legend{display:flex;gap:14px;align-items:center;margin:8px 0 4px 0;font-size:14px}
.legend-item{display:flex;align-items:center;gap:6px}
.dot{width:10px;height:10px;border-radius:50%}
.detail-grid{display:grid;grid-template-columns:1fr 1fr;gap:12px}
.panel{background:#13213b;border:1px solid #233b61;border-radius:10px;padding:10px}
.panel h4{margin:0 0 6px 0}
svg{width:100%;height:220px;border-top:1px solid #28436c}
#traffic{height:280px}
.snapshot-grid{display:grid;grid-template-columns:repeat(3,minmax(220px,1fr));gap:10px;margin-top:12px}
.snapshot-list{margin:6px 0 0 18px;padding:0;text-align:left;max-height:180px;overflow:auto}
#security-alerts th:nth-child(6){width:28%}
#security-alerts th:nth-child(9){width:25%}
.host-list{display:grid;gap:12px;width:100%;min-width:0}
.host-group{min-width:0;overflow:hidden;border:1px solid #29466f;border-radius:14px;background:#111f38;box-shadow:0 8px 24px rgba(3,10,24,.18)}
.host-toggle{width:100%;min-height:76px;border:0;background:#172844;color:#dbe7ff;display:grid;grid-template-columns:24px minmax(0,1fr) minmax(240px,auto);align-items:center;gap:12px;padding:14px 16px;text-align:left;cursor:pointer;touch-action:manipulation}
.host-toggle:hover{background:#1b3153}
.host-toggle:focus-visible,.btn:focus-visible{outline:3px solid #8cc7ff;outline-offset:-3px}
.host-chevron{width:20px;height:20px;transition:transform 180ms ease;color:#8cc7ff}
.host-group.is-open .host-chevron{transform:rotate(90deg)}
.host-title{min-width:0}
.host-name{font-size:18px;font-weight:750;overflow-wrap:anywhere}
.host-subtitle{display:block;margin-top:3px;color:#9fb5d5;font-size:13px}
.host-summary{display:flex;justify-content:flex-end;align-items:center;gap:7px;flex-wrap:wrap;min-width:0}
.pill{display:inline-flex;align-items:center;min-height:28px;padding:3px 9px;border:1px solid #365680;border-radius:999px;background:#10213c;color:#c9dbf5;font-size:12px;white-space:normal}
.pill-ok{border-color:#2f8568;background:#123e35;color:#8ee6c2}
.pill-warn{border-color:#b78035;background:#49371b;color:#ffd58c}
.pill-bad{border-color:#a84655;background:#4f202a;color:#ffadb8}
.host-panel{padding:14px;border-top:1px solid #29466f}
.host-panel[hidden]{display:none}
.containers-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(520px,100%),1fr));gap:14px;min-width:0}
.container-card{min-width:0;border:1px solid #2a456d;border-radius:12px;background:#13213b;padding:14px;box-shadow:0 5px 16px rgba(4,11,26,.16)}
.container-card:hover{border-color:#4472aa;box-shadow:0 8px 24px rgba(4,11,26,.26)}
.container-head{display:flex;align-items:flex-start;justify-content:space-between;gap:12px;margin-bottom:12px}
.container-name{font-size:17px;font-weight:750;overflow-wrap:anywhere}
.container-meta{margin-top:2px;color:#9fb5d5;font-size:12px;overflow-wrap:anywhere}
.metric-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(110px,1fr));gap:8px;margin-bottom:10px}
.metric{min-width:0;border:1px solid #274365;border-radius:9px;background:#0f1c33;padding:8px}
.metric-label{display:block;color:#91a9cb;font-size:11px;line-height:1.25}
.metric-value{display:block;margin-top:4px;font-size:15px;font-weight:700;overflow-wrap:anywhere}
.container-info-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:9px}
.info-block{min-width:0;border:1px solid #274365;border-radius:9px;background:#101e36;padding:10px}
.info-block h4{margin:0 0 7px;font-size:13px;color:#9fc8ff}
.kv{display:grid;grid-template-columns:minmax(76px,auto) minmax(0,1fr);gap:5px 8px;margin:0;font-size:12px}
.kv dt{color:#8fa8ca}
.kv dd{min-width:0;margin:0;text-align:right;overflow-wrap:anywhere}
.container-actions{display:flex;justify-content:flex-end;align-items:center;gap:8px;margin-top:12px}
.empty-state{border:1px dashed #365680;border-radius:12px;padding:22px;text-align:center;color:#9fb5d5}
:root{color-scheme:dark;--bg:#020617;--surface:#0f172a;--surface-2:#172033;--surface-3:#1e293b;--border:#334155;--text:#f8fafc;--muted:#94a3b8;--accent:#38bdf8;--success:#22c55e;--warning:#f59e0b;--danger:#ef4444;--focus:#7dd3fc}
body{margin:0;background:var(--bg);color:var(--text)}
.skip-link{position:fixed;left:12px;top:-60px;z-index:1000;background:var(--accent);color:#082f49;padding:10px 14px;border-radius:8px;font-weight:700}.skip-link:focus{top:12px}
.app-shell{width:min(1600px,100%);margin:0 auto;padding:20px}
.app-header{display:flex;justify-content:space-between;align-items:flex-start;gap:20px;margin-bottom:18px;padding:18px 20px;border:1px solid var(--border);border-radius:14px;background:linear-gradient(135deg,#0f172a,#111d34)}
.brand{display:flex;align-items:center;gap:12px}.brand-mark{width:38px;height:38px;display:grid;place-items:center;border:1px solid #0ea5e9;border-radius:10px;background:#082f49;color:#7dd3fc;font:800 16px ui-monospace,monospace}.brand h1{font-size:22px;line-height:1.2;margin:0}.brand p{margin:5px 0 0;color:var(--muted);font-size:13px}
.header-actions{display:flex;align-items:center;justify-content:flex-end;gap:8px;flex-wrap:wrap}.nav-link{display:inline-flex;align-items:center;min-height:44px;padding:8px 13px;border:1px solid var(--border);border-radius:8px;color:var(--text);text-decoration:none;background:var(--surface-3)}
.nav-link:hover,.btn:hover{filter:brightness(1.12)}.nav-link:focus-visible,.btn:focus-visible,.host-toggle:focus-visible{outline:3px solid var(--focus);outline-offset:2px}
.refresh-time{color:var(--muted);font-size:12px;font-variant-numeric:tabular-nums}
.kpi-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;margin-bottom:18px}.kpi-card{padding:14px 16px;border:1px solid var(--border);border-radius:12px;background:var(--surface)}.kpi-label{color:var(--muted);font-size:12px}.kpi-value{display:block;margin-top:5px;font-size:24px;font-weight:750;font-variant-numeric:tabular-nums}.kpi-value.danger{color:#fca5a5}
.section-card{margin-bottom:18px;border:1px solid var(--border);border-radius:14px;background:var(--surface);overflow:hidden}.section-head{display:flex;align-items:flex-start;justify-content:space-between;gap:14px;padding:15px 16px;border-bottom:1px solid var(--border);background:var(--surface-2)}.section-head h2{margin:0;font-size:17px}.section-head p{margin:4px 0 0;color:var(--muted);font-size:12px}.section-body{padding:14px;min-width:0}
table{background:var(--surface);color:var(--text)}th,td{border-color:var(--border)}th{background:var(--surface-3);color:#cbd5e1;font-size:12px;letter-spacing:.02em}td{font-size:13px}.bad,.severity-critical{color:#fca5a5}.ok{color:#86efac}.severity-warning{color:#fcd34d}
.host-group,.container-card,.panel{background:var(--surface);border-color:var(--border);box-shadow:none}.host-toggle{background:var(--surface-2);color:var(--text)}.host-toggle:hover{background:#1e293b}.metric,.info-block{background:#0b1220;border-color:var(--border)}.host-subtitle,.metric-label,.kv dt,.action-status{color:var(--muted)}
.pill{border-color:var(--border);background:#111827;color:#cbd5e1}.pill-ok{border-color:#166534;background:#052e16;color:#86efac}.pill-warn{border-color:#92400e;background:#451a03;color:#fcd34d}.pill-bad{border-color:#991b1b;background:#450a0a;color:#fca5a5}.version-dot{width:7px;height:7px;border-radius:50%;background:currentColor;margin-right:6px;flex:none}
#modal{background:rgba(2,6,23,.82);backdrop-filter:blur(3px)}#card{background:var(--surface);border:1px solid var(--border)}
@media (max-width:1000px){
  .host-toggle{grid-template-columns:24px minmax(0,1fr)}
  .host-summary{grid-column:2;justify-content:flex-start}
  .container-info-grid{grid-template-columns:1fr}
  .snapshot-grid,.detail-grid{grid-template-columns:1fr}
}
@media (max-width:680px){
  .app-shell{padding:8px}.app-header{padding:14px;flex-direction:column}.header-actions{justify-content:flex-start}.kpi-grid{grid-template-columns:repeat(2,minmax(0,1fr))}.section-body{padding:8px}
  th,td{padding:6px;font-size:12px}
  .host-toggle{padding:12px 10px;gap:8px}
  .host-panel{padding:9px}
  .metric-grid{grid-template-columns:repeat(2,minmax(0,1fr))}
  .container-head{flex-direction:column}
  .host-summary{gap:5px}
  #security-alerts th:nth-child(4),#security-alerts td:nth-child(4),#security-alerts th:nth-child(7),#security-alerts td:nth-child(7),#security-alerts th:nth-child(8),#security-alerts td:nth-child(8){display:none}
}
@media (prefers-reduced-motion:reduce){*,*::before,*::after{scroll-behavior:auto!important;transition:none!important;animation:none!important}}
</style>
</head><body>
<a class='skip-link' href='#main-content'>跳到主要内容</a>
<main id='main-content' class='app-shell'>
<header class='app-header'><div class='brand'><span class='brand-mark' aria-hidden='true'>NW</span><div><h1>Narwhal Monitor</h1><p>容器安全与运行状态中心</p></div></div><div class='header-actions'><span id='server-version' class='pill'>Server 正在连接</span><span id='last-refresh' class='refresh-time'>尚未刷新</span><a class='nav-link' href='/alerts/history'>告警历史</a><a class='nav-link' href='/stats'>数据统计</a></div></header>
<section class='kpi-grid' aria-label='运行概览'><article class='kpi-card'><span class='kpi-label'>在线主机</span><strong id='kpi-hosts' class='kpi-value'>0</strong></article><article class='kpi-card'><span class='kpi-label'>监控容器</span><strong id='kpi-containers' class='kpi-value'>0</strong></article><article class='kpi-card'><span class='kpi-label'>活动告警</span><strong id='kpi-alerts' class='kpi-value danger'>0</strong></article><article class='kpi-card'><span class='kpi-label'>离线容器</span><strong id='kpi-offline' class='kpi-value'>0</strong></article></section>
<section class='section-card'><header class='section-head'><div><h2>安全告警 <span class='pill pill-bad'>活动 <span id='active-alert-count'>0</span></span></h2><p>机场组件禁止操作执行定向清理；无认证 SOCKS 操作只停止对应服务并持续拦截，均不会停止容器。</p></div></header><div class='section-body'><table id='security-alerts'><thead><tr><th>级别</th><th>主机</th><th>运行时/项目</th><th>容器</th><th>类型</th><th>说明</th><th>最近出现</th><th>次数</th><th>操作</th></tr></thead><tbody></tbody></table></div></section>
<section class='section-card'><header class='section-head'><div><h2>主机安全遥测</h2><p>低开销汇总网络与连接状态。</p></div></header><div class='section-body'><table id='security-status'><thead><tr><th>主机</th><th>RX Mbps</th><th>RX pps</th><th>SYN_RECV</th><th>HTTP RPS</th><th>最高单IP RPS</th><th>采样时间</th></tr></thead><tbody></tbody></table></div></section>
<section class='section-card'><header class='section-head'><div><h2>容器状态</h2><p>按主机折叠；版本、在线状态与运行时分布集中显示。</p></div></header><div class='section-body'><div id='host-containers' class='host-list' aria-live='polite'><div class='empty-state'>正在加载节点数据…</div></div></div></section>
</main>
<div id='modal'><div id='card'>
  <h3 id='detail-title'></h3>
  <div class='detail-grid'>
    <div class='panel'>
      <h4>负载详情</h4>
      <div class='legend'>
        <span class='legend-item'><span class='dot' style='background:#4a90e2'></span>CPU%</span>
        <span class='legend-item'><span class='dot' style='background:#16a085'></span>内存%</span>
        <span class='legend-item'><span class='dot' style='background:#9b59b6'></span>连接数</span>
        <span class='legend-item'><span class='dot' style='background:#f39c12'></span>总网速 Mbps</span>
      </div>
      <svg id='chart' viewBox='0 0 900 220' preserveAspectRatio='none'></svg>
    </div>
    <div class='panel'>
      <h4>带宽监控</h4>
      <div class='legend'>
        <span class='legend-item'><span class='dot' style='background:#2ecc71'></span>下行 RX Mbps</span>
        <span class='legend-item'><span class='dot' style='background:#4a90e2'></span>上行 TX Mbps</span>
      </div>
      <svg id='bandwidth' viewBox='0 0 900 220' preserveAspectRatio='none'></svg>
    </div>
  </div>
  <div class='snapshot-grid'>
    <div class='panel'><h4>当前速率与资源</h4><div id='detail-current'></div></div>
    <div class='panel'><h4>进程排查</h4><div id='detail-processes'></div></div>
    <div class='panel'><h4>安全与暴露面</h4><div id='detail-risks'></div></div>
  </div>
  <div class='panel' style='margin-top:12px'>
    <h4>流量统计（累计字节）</h4>
    <svg id='traffic' viewBox='0 0 1200 280' preserveAspectRatio='none'></svg>
  </div>
  <p><button class='btn' onclick='closeDetail()'>关闭</button></p>
</div></div>
<script>
function fmtBytes(n){
  const x = Number(n||0); if (x<=0) return '0 B';
  const units=['B','KB','MB','GB','TB']; let i=0; let v=x;
  while(v>=1024 && i<units.length-1){v/=1024;i++;}
  return `${v.toFixed(v>=100?0:1)}${units[i]}`;
}
function bpsToMbps(v){
  return (Number(v||0) * 8) / 1000 / 1000;
}
function formatSmallNumber(v, digits=2){
  const n = Number(v||0);
  if (!Number.isFinite(n)) return '0.00';
  const threshold = 1 / Math.pow(10, digits);
  if (n > 0 && n < threshold) return `<${threshold.toFixed(digits)}`;
  return n.toFixed(digits);
}
function formatCountryLine(protocol, stats){
  const arr = Array.isArray(stats) ? stats : [];
  if(!arr.length) return `${protocol} - -`;
  const top3 = arr.slice(0,3).map(x=>`${x.country||'UN'} (${Number(x.connections||0)})`).join('  ');
  return `${protocol} - ${top3}`;
}
function formatCountryStats(tcpStats, udpStats){
  return `${formatCountryLine('TCP', tcpStats)}<br/>${formatCountryLine('UDP', udpStats)}`;
}
function formatCapacity(total, avail){
  return Number(total||0)>0 ? `${fmtBytes(total)} / ${fmtBytes(avail)}` : '采集不可用';
}
function escapeHtml(value){
  return String(value??'').replace(/[&<>'"]/g, ch=>({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[ch]));
}
const alertsById=new Map();
const submittingAlertActions=new Set();
function remediationChanged(action){
  if(!action||!['remediate_panel_pairing','remediate_malicious_process'].includes(action.action_type)||action.status!=='succeeded'||!remediationReceipt(action))return false;
  const text=String(action.result_message||'');
  const values=[...text.matchAll(/\\b(?:killed_processes|removed_services|removed_configs|removed_binaries)=(\\d+)\\b/g)].map(x=>Number(x[1]||0));
  return values.some(x=>x>0);
}
function remediationReceipt(action){
  const text=String(action?.result_message||'');
  const has=key=>new RegExp('\\\\b'+key+'=\\\\d+\\\\b').test(text);
  const count=key=>Number((text.match(new RegExp('\\\\b'+key+'=(\\\\d+)\\\\b'))||[])[1]||0);
  const noProcessTargets=/\\bno_process_targets=1\\b/.test(text);
  const hasProcessScan=(has('matched_processes')||has('host_matched_processes'))&&!noProcessTargets;
  const hasConfigScan=noProcessTargets&&count('checked_configs')>0;
  if(!has('cleanup_errors')||!has('signal_errors')||(!hasProcessScan&&!hasConfigScan)||!/\\bremaining_processes=0\\b/.test(text))return false;
  const signalErrors=count('signal_errors'),hostMatched=count('host_matched_processes'),hostKilled=count('host_killed_processes'),hostErrors=count('host_kill_errors');
  const signalRecovered=signalErrors===0||(has('host_matched_processes')&&has('host_killed_processes')&&has('host_kill_errors')&&hostMatched>=signalErrors&&hostKilled>=signalErrors&&hostErrors===0);
  return count('cleanup_errors')===0&&hostErrors===0&&signalRecovered;
}
function remediationComplete(action){
  if(!action||!['remediate_panel_pairing','remediate_malicious_process'].includes(action.action_type)||action.status!=='succeeded')return false;
  const text=String(action.result_message||'');
  if(!remediationReceipt(action))return false;
  if(remediationChanged(action))return true;
  return /\\btarget_state=already_absent\\b/.test(text)||/\\b(?:matched_processes|host_matched_processes)=0\\b/.test(text)||/\\bchecked_configs=\\d+\\b/.test(text);
}
function actionStatusText(action){
  if(!action)return '';
  if(action.status==='queued')return '等待节点领取（正常情况下约 10 秒内）';
  if(action.status==='dispatched')return action.action_type==='enforce_socks_auth'?'节点已领取，正在停止无认证 SOCKS':(action.action_type==='release_socks_auth'?'节点已领取，正在解除 SOCKS 持续拦截':'节点已领取，正在执行清理');
  if(['remediate_panel_pairing','remediate_malicious_process'].includes(action.action_type)&&action.status==='succeeded'&&!remediationChanged(action)&&remediationComplete(action)){
    return '目标进程已复查为不在运行，本次无需重复清理；等待后续采样确认。';
  }
  if(['remediate_panel_pairing','remediate_malicious_process'].includes(action.action_type)&&action.status==='succeeded'&&!remediationComplete(action)){
    return `处置结果未验证：${action.result_message||'节点未确认目标进程已停止'}`;
  }
  const labels={succeeded:'已完成',failed:'失败'};
  const result=action.result_message?`：${action.result_message}`:'';
  return `${labels[action.status]||action.status}${result}`;
}
async function setAlertDisposition(alertId, decision){
  const alert=alertsById.get(Number(alertId)); if(!alert)return;
  if(submittingAlertActions.has(Number(alertId)))return;
  const details=alert.details||{};
  const latestAction=alert.latest_action||null;
  const socksPolicyActive=alert.type==='socks_weak_auth'&&latestAction?.action_type==='enforce_socks_auth'&&latestAction?.status==='succeeded'&&['no_auth','weak_password'].includes(details.socks_auth_mode);
  let promptText='';
  if(decision==='deny'){
    if(alert.type==='socks_weak_auth'){
      const processes=(details.socks_processes||[]).join(', ')||'无';
      promptText=`确认停止 ${alert.host_id} / ${alert.runtime} / ${alert.container_name} 内的无认证 SOCKS 服务并启用持续拦截？\n\n目标进程：${processes}\n不会停止容器，不会删除配置或服务文件。以后检测到该容器再次以无认证/空密码方式运行时会自动停止；检测到非空认证后会自动解除拦截，允许服务恢复。`;
    }else if(alert.type==='malicious_process'){
      const processes=(details.malicious_processes||[]).map(item=>`${item.process}${item.pid?` (PID ${item.pid})`:''}`).join(', ')||'无';
      promptText=`确认清理 ${alert.host_id} / ${alert.runtime} / ${alert.container_name} 内精确识别的 XMRig 挖矿程序？\n\n目标：${processes}\n将终止进程、停用对应服务并删除明确的 XMRig 配置和二进制文件；不会停止容器。`;
    }else{
      const processes=(details.process_patterns||[]).join(', ')||'无';
      const files=(details.config_files||[]).join(', ')||'无';
      promptText=`确认禁止并清理 ${alert.host_id} / ${alert.runtime} / ${alert.container_name} 内的机场对接组件？\n\n将终止进程特征：${processes}\n停用并删除对应服务，删除配置：${files}\n容器本身不会停止。成功后同一面板域名再次出现会自动清理且不再提醒。`;
    }
  }else if(decision==='allow_silent'){
    if(socksPolicyActive){
      promptText=`确认解除持续拦截并永久允许此 SOCKS 服务？\n\n节点会删除持续拦截策略，此告警以后不再提醒。即使服务仍然无认证并对公网/NAT 暴露，也不会再次自动停止。`;
    }else if(alert.type==='socks_weak_auth'){
      promptText=`确认允许此 SOCKS 告警且以后不再提醒？\n\n该告警指纹会被永久抑制，节点不会为这条告警启用持续拦截。`;
    }else{
      promptText=`确认允许此告警且以后不再提醒？\n\n该告警指纹会被永久抑制；机场面板域名还会同步加入节点放行名单。`;
    }
  }else{
    promptText=socksPolicyActive
      ?`确认仅隐藏本次告警并保留持续拦截？\n\n节点侧拦截策略不会解除；无认证 SOCKS 再次启动时仍会被自动停止。事件消失后如果再次出现，仍会重新告警。`
      :`确认仅取消本次提醒？\n\n当前连续出现期间不再显示；事件消失后如果再次出现，仍会重新告警。`;
  }
  if(!confirm(promptText))return;
  submittingAlertActions.add(Number(alertId));
  document.querySelectorAll(`[data-alert-action="${Number(alertId)}"]`).forEach(button=>{button.disabled=true;});
  const status=document.querySelector(`[data-alert-status="${Number(alertId)}"]`);
  if(status)status.textContent='正在提交操作…';
  try{
    const response=await fetch(`/api/v1/security/alerts/${Number(alertId)}/disposition`,{
      method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({decision})
    });
    const result=await response.json();
    if(!response.ok)throw new Error(result.detail||`HTTP ${response.status}`);
    await loadAlerts();
  }catch(error){window.alert(`操作提交失败：${error.message||error}`);}
  finally{submittingAlertActions.delete(Number(alertId));}
}
async function loadAlerts(){
  const response=await fetch('/api/v1/security/alerts?active_only=true&limit=100');
  const data=await response.json();
  document.getElementById('active-alert-count').innerText=Number(data.active_count||0);
  document.getElementById('kpi-alerts').innerText=Number(data.active_count||0);
  const body=document.querySelector('#security-alerts tbody'); body.innerHTML='';
  alertsById.clear();
  for(const alert of (data.items||[])){
    alertsById.set(Number(alert.id),alert);
    const tr=document.createElement('tr');
    const runtime=alert.project?`${alert.runtime}/${alert.project}`:(alert.runtime||'-');
    const supportedRuntime=alert.runtime==='podman'||alert.runtime==='incus'||alert.runtime==='runman';
    const runmanEvidenceReady=alert.runtime!=='runman'||(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(alert.details?.instance_id||'')&&((alert.details?.process_targets||[]).length>0||(alert.details?.file_targets||[]).length>0));
    const canPanelRemediate=supportedRuntime&&runmanEvidenceReady&&alert.type==='unauthorized_panel_pairing'&&((alert.details?.process_patterns||[]).length>0||(alert.details?.config_files||[]).length>0);
    const canSocksRemediate=supportedRuntime&&alert.runtime!=='runman'&&alert.type==='socks_weak_auth'&&['no_auth','weak_password'].includes(alert.details?.socks_auth_mode)&&(alert.details?.socks_processes||[]).length>0;
    const canMaliciousRemediate=supportedRuntime&&runmanEvidenceReady&&alert.type==='malicious_process'&&(alert.details?.malicious_processes||[]).some(item=>item.process==='xmrig')&&(alert.runtime!=='runman'||(alert.details?.process_targets||[]).some(item=>item.process==='xmrig'&&item.pattern==='xmrig'&&/^\\d+$/.test(item.start_ticks||'')));
    const pending=alert.latest_action&&(alert.latest_action.status==='queued'||alert.latest_action.status==='dispatched');
    const lastRemediation=['remediate_panel_pairing','remediate_malicious_process'].includes(alert.latest_action?.action_type)?alert.latest_action:null;
    const lastSocksEnforcement=alert.latest_action?.action_type==='enforce_socks_auth'?alert.latest_action:null;
    const changed=remediationChanged(lastRemediation);
    const completed=remediationComplete(lastRemediation);
    const recurred=completed&&Number(alert.last_seen||0)>Number(lastRemediation?.updated_at||0);
    const denyLabel=pending?'禁止处理中':((lastRemediation&&(lastRemediation.status==='failed'||!completed))?'重试禁止':(recurred?'再次禁止':'禁止'));
    const socksPolicyActive=lastSocksEnforcement?.status==='succeeded'&&['no_auth','weak_password'].includes(alert.details?.socks_auth_mode);
    const socksReleased=alert.details?.socks_auth_enforcement?.released===true;
    let denyControl='';
    if(canSocksRemediate){
      const socksLabel=pending?'正在启用持续拦截':(lastSocksEnforcement?.status==='failed'?'重试停止并持续拦截':'停止并持续拦截');
      denyControl=socksPolicyActive?`<span class='ok'>持续拦截已启用</span>`:`<button class='btn btn-danger' data-alert-action="${Number(alert.id)}" ${pending?'disabled':''} onclick="setAlertDisposition(${Number(alert.id)},'deny')">${socksLabel}</button>`;
    }else if(canPanelRemediate||canMaliciousRemediate){
      denyControl=completed&&!recurred?`<span class='ok'>${changed?'已处置，等待复检':'目标进程已不存在，等待复检'}</span>`:`<button class='btn btn-danger' data-alert-action="${Number(alert.id)}" ${pending?'disabled':''} onclick="setAlertDisposition(${Number(alert.id)},'deny')">${denyLabel}</button>`;
    }else if(socksReleased){denyControl=`<span class='ok'>已检测到非空认证，持续拦截已解除</span>`;}
    const allowLabel=socksPolicyActive?'解除拦截并允许（不再提醒）':'允许且不再提醒';
    const dismissLabel=socksPolicyActive?'仅隐藏本次告警（保留拦截）':'本次取消提醒';
    const actions=`<div class='security-action-state'>${denyControl}</div><div class='security-action-buttons'>`+
      `<button class='btn btn-allow' data-alert-action="${Number(alert.id)}" ${pending?'disabled':''} onclick="setAlertDisposition(${Number(alert.id)},'allow_silent')">${allowLabel}</button>`+
      `<button class='btn btn-dismiss' data-alert-action="${Number(alert.id)}" ${pending?'disabled':''} onclick="setAlertDisposition(${Number(alert.id)},'dismiss_once')">${dismissLabel}</button></div>`;
    tr.innerHTML=`<td class='severity-${escapeHtml(alert.severity)}'>${escapeHtml(alert.severity)}</td>`+
      `<td>${escapeHtml(alert.host_id)}</td><td>${escapeHtml(runtime)}</td>`+
      `<td>${escapeHtml(alert.container_name||'-')}</td><td>${escapeHtml(alert.type)}</td>`+
      `<td>${escapeHtml(alert.message)}</td><td>${escapeHtml(alert.last_seen_utc8)}</td>`+
      `<td>${Number(alert.occurrence_count||0)}</td><td>${actions}<div class='action-status' data-alert-status="${Number(alert.id)}">${escapeHtml(socksReleased?'非空认证已确认，节点已自动解除持续拦截':actionStatusText(alert.latest_action))}</div></td>`;
    body.appendChild(tr);
  }
  const statusResponse=await fetch('/api/v1/security/status');
  const statusData=await statusResponse.json();
  const statusBody=document.querySelector('#security-status tbody'); statusBody.innerHTML='';
  for(const item of (statusData.items||[])){
    const access=item.access_log||{};
    const tr=document.createElement('tr');
    tr.innerHTML=`<td>${escapeHtml(item.host_id)}</td>`+
      `<td>${formatSmallNumber(bpsToMbps(item.total_rx_bps),2)}</td>`+
      `<td>${formatSmallNumber(item.total_rx_pps,1)}</td><td>${Number(item.syn_recv_count||0)}</td>`+
      `<td>${formatSmallNumber(access.requests_per_second,1)}</td>`+
      `<td>${formatSmallNumber(access.top_ip_requests_per_second,1)} ${escapeHtml(access.top_ip||'')}</td>`+
      `<td>${escapeHtml(item.timestamp_utc8)}</td>`;
    statusBody.appendChild(tr);
  }
}
function groupByHost(items){
  const m=new Map();
  for(const x of items){
    if(!m.has(x.host_id))m.set(x.host_id,[]);
    m.get(x.host_id).push(x);
  }
  return [...m.entries()];
}
function containerDetailUrl(host,runtime,project,container){
  const q=new URLSearchParams({host,runtime,project:project||'',container});
  return `/container-detail?${q.toString()}`;
}
const expandedHosts=new Set();
function versionBadge(agentVersion,serverVersion){
  const client=String(agentVersion||'unknown'),server=String(serverVersion||'dev');
  if(client==='unknown'||client==='dev')return `<span class='pill pill-warn'><i class='version-dot'></i>Client 版本未知</span>`;
  if(server==='dev')return `<span class='pill pill-warn'><i class='version-dot'></i>Client v${escapeHtml(client)} · Server dev</span>`;
  if(client===server)return `<span class='pill pill-ok'><i class='version-dot'></i>v${escapeHtml(client)} · 最新</span>`;
  return `<span class='pill pill-bad'><i class='version-dot'></i>Client v${escapeHtml(client)} · 应为 v${escapeHtml(server)}</span>`;
}
function setHostExpanded(host, group, button, panel, expanded){
  if(expanded)expandedHosts.add(host);else expandedHosts.delete(host);
  group.classList.toggle('is-open',expanded);
  button.setAttribute('aria-expanded',String(expanded));
  panel.hidden=!expanded;
}
async function load(){
  const r=await fetch('/api/v1/latest'); const d=await r.json();
  const hostList=document.getElementById('host-containers'); hostList.innerHTML='';
  const groups=groupByHost(d.items||[]);
  const offlineTotal=(d.items||[]).filter(x=>x.alerts?.stale).length;
  document.getElementById('server-version').className=`pill ${d.server_version&&d.server_version!=='dev'?'pill-ok':'pill-warn'}`;
  document.getElementById('server-version').innerHTML=`<i class='version-dot'></i>Server ${d.server_version&&d.server_version!=='dev'?`v${escapeHtml(d.server_version)}`:'dev'}`;
  document.getElementById('last-refresh').innerText=`最近刷新 ${new Date().toLocaleTimeString('zh-CN',{hour12:false})}`;
  document.getElementById('kpi-hosts').innerText=groups.length;
  document.getElementById('kpi-containers').innerText=(d.items||[]).length;
  document.getElementById('kpi-offline').innerText=offlineTotal;
  if(!groups.length){
    hostList.innerHTML="<div class='empty-state'>暂未收到容器上报</div>";
    return;
  }
  groups.forEach(([host, rows],hostIndex)=>{
    rows.sort((a,b)=>a.container_name.localeCompare(b.container_name));
    const latest=rows.reduce((best,item)=>Number(item.timestamp||0)>Number(best.timestamp||0)?item:best,rows[0]);
    const offlineCount=rows.filter(x=>x.alerts?.stale).length;
    const runtimeCounts=new Map();
    rows.forEach(x=>{
      const runtimeBase=x.project&&x.runtime==='incus'?`${x.runtime}/${x.project}`:(x.runtime||'podman');
      runtimeCounts.set(runtimeBase,(runtimeCounts.get(runtimeBase)||0)+1);
    });
    const hostMount=latest.disk_data_mountpoint||latest.disk_data_requested_path||'/';
    const hostDiskText=`${hostMount}: ${formatCapacity(latest.disk_data_total_bytes,latest.disk_data_avail_bytes)}`;
    const panelId=`host-panel-${hostIndex}`;
    const toggleId=`host-toggle-${hostIndex}`;
    const group=document.createElement('section');
    group.className='host-group';
    const toggle=document.createElement('button');
    toggle.type='button';
    toggle.id=toggleId;
    toggle.className='host-toggle';
    toggle.setAttribute('aria-controls',panelId);
    toggle.innerHTML=`<svg class='host-chevron' viewBox='0 0 24 24' aria-hidden='true'><path d='m9 5 7 7-7 7' fill='none' stroke='currentColor' stroke-width='2.2' stroke-linecap='round' stroke-linejoin='round'/></svg>`+
      `<span class='host-title'><span class='host-name'>${escapeHtml(host)}</span><span class='host-subtitle'>${rows.length} 个容器 · 主盘 ${escapeHtml(hostDiskText)} · 最近上报 ${escapeHtml(latest.timestamp_iso_utc8||'-')}</span></span>`+
      `<span class='host-summary'>${[...runtimeCounts.entries()].map(([name,count])=>`<span class='pill'>${escapeHtml(name)} ${count}</span>`).join('')}`+
      `${versionBadge(latest.agent_version,d.server_version)}`+
      `<span class='pill ${offlineCount?'pill-bad':'pill-ok'}'>${offlineCount?`${offlineCount} 个离线`:'全部在线'}</span>`+
      `<span class='pill ${latest.container_network_ok_v4?'pill-ok':'pill-bad'}'>主机 IPv4 ${latest.container_network_ok_v4?'正常':'异常'}</span>`+
      `<span class='pill ${latest.container_network_ok_v6?'pill-ok':'pill-warn'}'>主机 IPv6 ${latest.container_network_ok_v6?'正常':'不可用'}</span></span>`;
    const panel=document.createElement('div');
    panel.id=panelId;
    panel.className='host-panel';
    panel.setAttribute('role','region');
    panel.setAttribute('aria-labelledby',toggleId);
    const grid=document.createElement('div');
    grid.className='containers-grid';
    rows.forEach(x=>{
      const cpuCls=x.alerts.cpu?'bad':'';
      const connSeverity=x.alerts?.conn_severity||'';
      const connCls=connSeverity==='critical'?'bad':(connSeverity==='warning'?'severity-warning':'');
      const connWarningThreshold=Number(x.alerts?.conn_warning_threshold||500),connCriticalThreshold=Number(x.alerts?.conn_critical_threshold||1000);
      const connHint=connSeverity==='critical'?`严重告警：连接数超过 ${connCriticalThreshold}`:(connSeverity==='warning'?`告警：连接数超过 ${connWarningThreshold}`:'连接数正常');
      const containerDiskText = formatCapacity(x.container_fs_root_total_bytes, x.container_fs_root_avail_bytes);
      const offlineText=x.alerts.stale?`离线 ${Number(x.offline_hours||0)} 小时`:'在线';
      const runtimeBase = x.project && x.runtime==='incus' ? `${x.runtime}/${x.project}` : (x.runtime||'podman');
      const runtimeText = x.monitor_mode==='notice' ? `${runtimeBase}（仅提醒）` : runtimeBase;
      const security=x.security||{};
      const inboundUniqueIps=Number(security.inbound_unique_ips||0);
      const inboundThreshold=Number(security.inbound_unique_ip_threshold||10);
      const inboundCls=inboundUniqueIps>inboundThreshold?'bad':'';
      const protocolRates=security.protocol_rates||{};
      const panelPairing=security.panel_pairing||{};
      const pairingText=panelPairing.detected?(panelPairing.approved?'白名单':((panelPairing.unapproved_domains||[]).join(',')||'发现特征')):'-';
      const listeningPorts=Array.isArray(security.listening_ports)?security.listening_ports.slice(0,8).join(','):'-';
      const exposureText=Array.isArray(security.network_exposure)&&security.network_exposure.length?security.network_exposure.slice(0,6).map(item=>`${item.listen||'?'}→${item.target||'?'}`).join(', '):'-';
      const suspiciousCount=Array.isArray(security.suspicious_processes)?security.suspicious_processes.length:0;
      const riskCount=Array.isArray(security.configuration_risks)?security.configuration_risks.length:0;
      const card=document.createElement('article');
      card.className='container-card';
      card.innerHTML=`<div class='container-head'><div><div class='container-name'>${escapeHtml(x.container_name||'-')}</div>`+
        `<div class='container-meta'>${escapeHtml(runtimeText)} · ID ${escapeHtml(x.container_id||'-')}</div></div>`+
        `<span class='pill ${x.alerts.stale?'pill-bad':'pill-ok'}'>${escapeHtml(offlineText)}</span></div>`+
        `<div class='metric-grid'>`+
        `<div class='metric'><span class='metric-label'>CPU</span><strong class='metric-value ${cpuCls}'>${formatSmallNumber(x.cpu_percent,2)}%</strong></div>`+
        `<div class='metric'><span class='metric-label'>内存</span><strong class='metric-value'>${formatSmallNumber(x.mem_percent,2)}%</strong></div>`+
        `<div class='metric'><span class='metric-label'>入站去重 IP</span><strong class='metric-value ${inboundCls}'>${inboundUniqueIps}</strong></div>`+
        `<div class='metric' title='${escapeHtml(connHint)}'><span class='metric-label'>连接数${connSeverity==='critical'?' · 严重':(connSeverity==='warning'?' · 告警':'')}</span><strong class='metric-value ${connCls}'>${Number(x.conn_count||0)}</strong></div>`+
        `<div class='metric'><span class='metric-label'>进程数</span><strong class='metric-value'>${Number(security.process_count||0)}</strong></div>`+
        `<div class='metric'><span class='metric-label'>RX</span><strong class='metric-value'>${formatSmallNumber(bpsToMbps(x.net_rx_bps),2)} Mbps</strong></div>`+
        `<div class='metric'><span class='metric-label'>TX</span><strong class='metric-value'>${formatSmallNumber(bpsToMbps(x.net_tx_bps),2)} Mbps</strong></div>`+
        `<div class='metric'><span class='metric-label'>容器根盘 总量/可用</span><strong class='metric-value'>${escapeHtml(containerDiskText)}</strong></div></div>`+
        `<div class='container-info-grid'>`+
        `<section class='info-block'><h4>流量与连接</h4><dl class='kv'><dt>RX pps</dt><dd>${formatSmallNumber(security.net_rx_pps,1)}</dd><dt>SYN_RECV</dt><dd>${Number(security.syn_recv_count||0)}</dd><dt>入站 IP</dt><dd class='${inboundCls}'>${inboundUniqueIps} / 阈值 ${inboundThreshold}</dd><dt>入站连接</dt><dd>${Number(security.incoming_established||0)}</dd><dt>出站 IP</dt><dd>${Number(security.outbound_unique_ips||0)}</dd><dt>TCP 建连/s</dt><dd>${formatSmallNumber(protocolRates.Tcp_ActiveOpens_per_second,1)}</dd><dt>TCP 失败/s</dt><dd>${formatSmallNumber(protocolRates.Tcp_AttemptFails_per_second,1)}</dd></dl></section>`+
        `<section class='info-block'><h4>端口与网络</h4><dl class='kv'><dt>监听端口</dt><dd>${escapeHtml(listeningPorts||'-')}</dd><dt>NAT/代理</dt><dd>${escapeHtml(exposureText)}</dd><dt>来源 Top3</dt><dd>${formatCountryStats(x.tcp_country_stats,x.udp_country_stats)}</dd></dl></section>`+
        `<section class='info-block'><h4>安全检查</h4><dl class='kv'><dt>面板对接</dt><dd class='${panelPairing.detected&&!panelPairing.approved?'bad':''}'>${escapeHtml(pairingText)}</dd><dt>可疑进程</dt><dd class='${suspiciousCount?'bad':''}'>${suspiciousCount}</dd><dt>配置风险</dt><dd class='${riskCount?'bad':''}'>${riskCount}</dd><dt>采样时间</dt><dd>${escapeHtml(x.timestamp_iso_utc8||'-')}</dd></dl></section></div>`+
        `<div class='container-actions'><button type='button' class='btn detail-button'>查看容器详情</button></div>`;
      card.querySelector('.detail-button').addEventListener('click',()=>{
        location.href=containerDetailUrl(host,x.runtime,x.project||'',x.container_name);
      });
      grid.appendChild(card);
    });
    panel.appendChild(grid);
    group.appendChild(toggle);
    group.appendChild(panel);
    hostList.appendChild(group);
    const isExpanded=expandedHosts.has(host);
    setHostExpanded(host,group,toggle,panel,isExpanded);
    toggle.addEventListener('click',()=>setHostExpanded(host,group,toggle,panel,!expandedHosts.has(host)));
  });
}
function closeDetail(){ document.getElementById('modal').style.display='none'; }
function buildPolyline(vals,maxv,w,h,pad){
  const useMax=Math.max(1,maxv);
  return vals.map((v,i)=>`${i*(w/Math.max(1,vals.length-1))},${(h-pad)-((v/useMax)*(h-pad*2))}`).join(' ');
}
function drawAxes(svg,w,h){
  const lines=[];
  for(let i=0;i<=5;i++){
    const y=(h-20)-(i*((h-40)/5));
    lines.push(`<line x1='0' y1='${y}' x2='${w}' y2='${y}' stroke='#29466f' stroke-width='1' />`);
  }
  svg.innerHTML=lines.join('');
}
function estimateStepSeconds(points){
  if(!points || points.length < 2) return 0;
  const intervals=[];
  for(let i=1;i<points.length;i++){
    intervals.push(Math.max(1, Number(points[i].timestamp||0)-Number(points[i-1].timestamp||0)));
  }
  return intervals.reduce((a,b)=>a+b,0)/intervals.length;
}
async function openDetail(host, runtime, project, container){
  const latestRes=await fetch('/api/v1/latest');
  const latestData=await latestRes.json();
  const target=(latestData.items||[]).find(x=>x.host_id===host&&x.runtime===runtime&&(x.project||'')===project&&x.container_name===container);
  const countryTop=formatCountryStats(target?.tcp_country_stats||[], target?.udp_country_stats||[]);
  const res=await fetch(`/api/v1/history?host_id=${encodeURIComponent(host)}&runtime=${encodeURIComponent(runtime)}&project=${encodeURIComponent(project)}&container_name=${encodeURIComponent(container)}`);
  const data=await res.json();
  const runtimeLabel=project ? `${runtime}/${project}` : runtime;
  document.getElementById('detail-title').innerText=`${host} / ${runtimeLabel} / ${container} 历史数据（TCP国家：${countryTop.replaceAll('<br/>', ', ')}）`;
  const pts=data.items||[];
  const recent=pts.slice(-80);
  const svg=document.getElementById('chart');
  const bandwidthSvg=document.getElementById('bandwidth');
  const trafficSvg=document.getElementById('traffic');
  const security=target?.security||{};
  const rates=security.protocol_rates||{};
  const topProcess=target?.top_cpu_process_command?
    `PID ${Number(target.top_cpu_process_pid||0)} · CPU ${formatSmallNumber(target.top_cpu_process_cpu_percent,2)}% · ${escapeHtml(target.top_cpu_process_command)}`:'未采集到高 CPU 进程';
  const suspicious=Array.isArray(security.suspicious_processes)?security.suspicious_processes:[];
  const risks=Array.isArray(security.configuration_risks)?security.configuration_risks:[];
  const exposures=Array.isArray(security.network_exposure)?security.network_exposure:[];
  document.getElementById('detail-current').innerHTML=`CPU ${formatSmallNumber(target?.cpu_percent,2)}% · 内存 ${formatSmallNumber(target?.mem_percent,2)}%<br/>连接 ${Number(target?.conn_count||0)} · 进程 ${Number(security.process_count||0)}<br/>入站去重 IP ${Number(security.inbound_unique_ips||0)} / 阈值 ${Number(security.inbound_unique_ip_threshold||10)}<br/>RX ${formatSmallNumber(bpsToMbps(target?.net_rx_bps),2)} Mbps / ${formatSmallNumber(security.net_rx_pps,1)} pps<br/>TX ${formatSmallNumber(bpsToMbps(target?.net_tx_bps),2)} Mbps<br/>TCP 建连 ${formatSmallNumber(rates.Tcp_ActiveOpens_per_second,1)}/s · 失败 ${formatSmallNumber(rates.Tcp_AttemptFails_per_second,1)}/s`;
  document.getElementById('detail-processes').innerHTML=`<div>${topProcess}</div>`+
    (suspicious.length?`<ul class='snapshot-list'>${suspicious.map(x=>`<li>PID ${Number(x.pid||0)} · ${escapeHtml(x.pattern||x.command||'可疑进程')}</li>`).join('')}</ul>`:'<div class="ok">未发现可疑进程特征</div>');
  document.getElementById('detail-risks').innerHTML=`监听端口：${escapeHtml((security.listening_ports||[]).join(', ')||'-')}<br/>`+
    `NAT/代理：${escapeHtml(exposures.map(x=>`${x.listen||'?'}→${x.target||'?'}`).join(', ')||'-')}`+
    (risks.length?`<ul class='snapshot-list'>${risks.map(x=>`<li>${escapeHtml(x.message||x.type||JSON.stringify(x))}</li>`).join('')}</ul>`:'<div class="ok">未发现配置风险</div>');
  if(!recent.length){
    svg.innerHTML = '';
    bandwidthSvg.innerHTML = '';
    trafficSvg.innerHTML = '';
    document.getElementById('modal').style.display='flex';
    return;
  }
  const cpuVals=recent.map(x=>Number(x.cpu_percent||0));
  const memVals=recent.map(x=>Number(x.mem_percent||0));
  const connVals=recent.map(x=>Number(x.conn_count||0));
  const rxMbpsVals=recent.map(x=>bpsToMbps(Number(x.net_rx_bps||0)));
  const txMbpsVals=recent.map(x=>bpsToMbps(Number(x.net_tx_bps||0)));
  const speedVals=rxMbpsVals.map((v,i)=>v+txMbpsVals[i]);
  const step=estimateStepSeconds(recent) || 300;
  let rxTotal=0; let txTotal=0;
  const rxBytesCum=recent.map((x,i)=>{
    const currentStep=i===0?step:Math.max(1, Number(recent[i].timestamp||0)-Number(recent[i-1].timestamp||0));
    rxTotal+=Number(x.net_rx_bps||0)*currentStep;
    return rxTotal;
  });
  const txBytesCum=recent.map((x,i)=>{
    const currentStep=i===0?step:Math.max(1, Number(recent[i].timestamp||0)-Number(recent[i-1].timestamp||0));
    txTotal+=Number(x.net_tx_bps||0)*currentStep;
    return txTotal;
  });

  drawAxes(svg,900,220);
  const cpuPoints=buildPolyline(cpuVals, Math.max(100, ...cpuVals, ...memVals), 900, 220, 20);
  const memPoints=buildPolyline(memVals, Math.max(100, ...cpuVals, ...memVals), 900, 220, 20);
  const connPoints=buildPolyline(connVals, Math.max(1, ...connVals), 900, 220, 20);
  const speedPoints=buildPolyline(speedVals, Math.max(1, ...speedVals), 900, 220, 20);
  svg.innerHTML += `
    <polyline fill='none' stroke='#4a90e2' stroke-width='2.5' points='${cpuPoints}' />
    <polyline fill='none' stroke='#16a085' stroke-width='2.5' points='${memPoints}' />
    <polyline fill='none' stroke='#9b59b6' stroke-width='2.5' points='${connPoints}' />
    <polyline fill='none' stroke='#f39c12' stroke-width='2.5' points='${speedPoints}' />
  `;

  drawAxes(bandwidthSvg,900,220);
  const rxPoints=buildPolyline(rxMbpsVals, Math.max(1, ...rxMbpsVals, ...txMbpsVals), 900, 220, 20);
  const txPoints=buildPolyline(txMbpsVals, Math.max(1, ...rxMbpsVals, ...txMbpsVals), 900, 220, 20);
  bandwidthSvg.innerHTML += `
    <polyline fill='none' stroke='#2ecc71' stroke-width='2.5' points='${rxPoints}' />
    <polyline fill='none' stroke='#4a90e2' stroke-width='2.5' points='${txPoints}' />
  `;

  drawAxes(trafficSvg,1200,280);
  const rxCumPoints=buildPolyline(rxBytesCum, Math.max(1, ...rxBytesCum, ...txBytesCum), 1200, 280, 20);
  const txCumPoints=buildPolyline(txBytesCum, Math.max(1, ...rxBytesCum, ...txBytesCum), 1200, 280, 20);
  trafficSvg.innerHTML += `
    <polyline fill='none' stroke='#2ecc71' stroke-width='2.5' points='${rxCumPoints}' />
    <polyline fill='none' stroke='#4a90e2' stroke-width='2.5' points='${txCumPoints}' />
  `;
  document.getElementById('modal').style.display='flex';
}
let openedFromUrl=false;
async function loadAndOpenRequestedDetail(){
  await load();
  if(openedFromUrl)return;
  const q=new URLSearchParams(location.search);
  if(q.get('detail')==='1'&&q.get('host')&&q.get('runtime')&&q.get('container')){
    openedFromUrl=true;
    await openDetail(q.get('host'),q.get('runtime'),q.get('project')||'',q.get('container'));
  }
}
loadAndOpenRequestedDetail(); loadAlerts(); setInterval(()=>{load();loadAlerts();}, 15000);
</script>
</body></html>
"""


def container_detail_page(request: Request = None, static_dir: Path | None = None) -> Any:
    spa_index = (static_dir / "index.html") if static_dir is not None else None
    if spa_index is not None and request is not None and spa_index.is_file():
        return FileResponse(spa_index)
    return """
<!doctype html>
<html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width, initial-scale=1'>
<title>Container Detail</title>
<style>
*{box-sizing:border-box}html,body{max-width:100%;overflow-x:hidden}
:root{color-scheme:dark;--bg:#020617;--surface:#0f172a;--surface-2:#172033;--surface-3:#1e293b;--border:#334155;--text:#f8fafc;--muted:#94a3b8;--accent:#38bdf8;--success:#22c55e;--danger:#ef4444;--focus:#7dd3fc}
body{margin:0;background:var(--bg);color:var(--text);font-family:system-ui,-apple-system,"Segoe UI",sans-serif;line-height:1.5}.skip-link{position:fixed;left:12px;top:-60px;z-index:10;background:var(--accent);color:#082f49;padding:10px 14px;border-radius:8px;font-weight:700}.skip-link:focus{top:12px}
.page{width:min(1500px,100%);margin:auto;padding:20px}.top{display:flex;align-items:flex-start;justify-content:space-between;gap:14px;margin-bottom:16px;padding:17px 18px;border:1px solid var(--border);border-radius:14px;background:linear-gradient(135deg,var(--surface),#111d34)}
h1{margin:0;font-size:24px;overflow-wrap:anywhere}.subtitle{color:var(--muted);margin-top:4px;overflow-wrap:anywhere}.actions{display:flex;align-items:center;justify-content:flex-end;gap:8px;flex-wrap:wrap}
    .btn{display:inline-flex;align-items:center;justify-content:center;min-height:44px;padding:8px 13px;border:1px solid var(--border);border-radius:8px;background:var(--surface-3);color:var(--text);text-decoration:none;cursor:pointer;font:inherit}.btn.primary{border-color:#0284c7;background:#075985}.btn:disabled{cursor:not-allowed;opacity:.58}
    .btn:not(:disabled):hover{filter:brightness(1.12)}.btn:focus-visible{outline:3px solid var(--focus);outline-offset:2px}.status{border:1px solid var(--border);border-radius:10px;background:var(--surface-2);padding:10px 12px;margin-bottom:14px;color:#cbd5e1}
.status.bad{border-color:#a84655;color:#ffadb8}.metrics{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;margin-bottom:14px}
.metric,.panel{min-width:0;border:1px solid var(--border);border-radius:12px;background:var(--surface);padding:13px}.metric span{display:block;color:var(--muted);font-size:12px}.metric strong{display:block;margin-top:4px;font-size:20px;overflow-wrap:anywhere;font-variant-numeric:tabular-nums}
.metric.metric-alert{border-color:#b91c1c;background:#2b0b12}.metric.metric-alert strong{color:#fca5a5}
.charts,.details{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px;margin-bottom:14px}.panel h2{font-size:16px;margin:0 0 10px}.panel h3{font-size:14px;margin:12px 0 6px;color:#9fc8ff}
.legend{display:flex;gap:14px;flex-wrap:wrap;color:#9fb5d5;font-size:12px;margin-bottom:7px}.dot{display:inline-block;width:9px;height:9px;border-radius:50%;margin-right:5px}
svg{width:100%;height:220px;border-top:1px solid #29466f}.kv{display:grid;grid-template-columns:minmax(115px,auto) minmax(0,1fr);gap:6px 10px;margin:0}.kv dt{color:#91a9cb}.kv dd{margin:0;text-align:right;overflow-wrap:anywhere}
.list{margin:6px 0 0 18px;padding:0}.ok{color:#72dfa7}.bad-text{color:#ff6b78}.samples{display:grid;gap:7px}.sample{display:grid;grid-template-columns:1.4fr repeat(5,minmax(75px,1fr));gap:8px;padding:8px;border:1px solid #274365;border-radius:8px;background:#101e36;font-size:12px}.sample span{overflow-wrap:anywhere}
.source,.version-pill{display:inline-flex;align-items:center;border:1px solid var(--border);border-radius:999px;padding:3px 9px;background:#111827;color:#cbd5e1;font-size:12px}.version-pill.ok{border-color:#166534;background:#052e16;color:#86efac}.version-pill.bad{border-color:#991b1b;background:#450a0a;color:#fca5a5}.version-pill.warn{border-color:#92400e;background:#451a03;color:#fcd34d}
    .comm-process-grid,.socket-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(280px,100%),1fr));gap:9px}.comm-process,.socket-card{min-width:0;border:1px solid #274365;border-radius:9px;background:#0b1220;padding:10px}.comm-process strong,.socket-head strong{overflow-wrap:anywhere}.comm-meta,.socket-meta{margin-top:4px;color:var(--muted);font-size:12px;overflow-wrap:anywhere}.socket-head{display:flex;justify-content:space-between;align-items:flex-start;gap:8px}.direction{display:inline-flex;border-radius:999px;padding:2px 7px;font-size:11px;border:1px solid var(--border)}.direction.inbound{border-color:#b91c1c;background:#450a0a;color:#fca5a5}.direction.outbound{border-color:#075985;background:#082f49;color:#7dd3fc}.comm-note{margin:0 0 10px;color:var(--muted);font-size:12px}
    .diagnostic{margin-bottom:14px;border-color:#315574;background:linear-gradient(135deg,#0f172a,#0b1d31)}.diagnostic-head{display:flex;align-items:flex-start;justify-content:space-between;gap:14px}.diagnostic-head p{margin:3px 0 0;color:var(--muted);font-size:12px}.diagnostic-state{margin:12px 0;padding:9px 11px;border:1px solid var(--border);border-radius:8px;background:#0b1220;color:#cbd5e1}.diagnostic-state.ok{border-color:#166534}.diagnostic-state.warn{border-color:#92400e;color:#fcd34d}.diagnostic-state.bad{border-color:#991b1b;color:#fca5a5}.deep-metrics{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:8px;margin-bottom:10px}.deep-metric{min-width:0;padding:9px;border:1px solid #274365;border-radius:8px;background:#101e36}.deep-metric span{display:block;color:var(--muted);font-size:11px}.deep-metric strong{display:block;margin-top:3px;overflow-wrap:anywhere}.deep-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px}.deep-section{min-width:0;border-top:1px solid #274365;padding-top:9px}.deep-section h3{margin:0 0 7px}.deep-list{display:grid;gap:6px}.deep-row{min-width:0;padding:8px;border:1px solid #253b59;border-radius:7px;background:#0b1220;font-size:12px;overflow-wrap:anywhere}.deep-row strong{color:#dbeafe}.deep-errors{margin-top:9px;color:#fca5a5;font-size:12px}
    @media(max-width:900px){.top{flex-direction:column}.charts,.details,.deep-grid{grid-template-columns:1fr}.sample{grid-template-columns:repeat(2,minmax(0,1fr))}.diagnostic-head{flex-direction:column}}
@media(max-width:520px){.page{padding:10px}.metrics{grid-template-columns:repeat(2,minmax(0,1fr))}.metric strong{font-size:17px}.kv{grid-template-columns:1fr}.kv dd{text-align:left}.actions{width:100%}.btn{flex:1}}
</style></head><body><a class='skip-link' href='#detail-main'>跳到主要内容</a><main id='detail-main' class='page'>
    <header class='top'><div><h1 id='title'>容器详情</h1><div id='subtitle' class='subtitle'>正在读取容器内部指标…</div></div><nav class='actions'><span id='detail-version' class='version-pill warn'>版本检查中</span><a class='btn' href='/stats'>返回统计页</a><a class='btn' href='/'>返回总览</a></nav></header>
    <div id='status' class='status'>正在加载最新采样与历史数据…</div>
    <section class='panel diagnostic' aria-labelledby='diagnostic-title'><div class='diagnostic-head'><div><h2 id='diagnostic-title'>按需深度上报</h2><p>仅在下一周期对当前 Incus、Podman 或 Runman 容器做一次有界快照；不抓包、不扫描文件，上报成功后自动恢复普通采集。</p></div><button id='request-diagnostic' class='btn primary' type='button' aria-label='请求当前容器在下一周期上报深度详情' onclick='requestDeepSample()'>请求深度上报</button></div><div id='diagnostic-state' class='diagnostic-state'>尚未请求深度上报。</div><div id='diagnostic-report'><div class='comm-note'>收到报告后将在这里显示瞬时流量、详细进程、连接 IP 和进程归属。</div></div></section>
<section id='metrics' class='metrics'></section>
<section class='charts'><article class='panel'><h2>容器 CPU / 内存历史</h2><div class='legend'><span><i class='dot' style='background:#4a90e2'></i>CPU%</span><span><i class='dot' style='background:#16a085'></i>内存%</span></div><svg id='resource-chart' viewBox='0 0 900 220' preserveAspectRatio='none'></svg></article><article class='panel'><h2>容器网络速率历史</h2><div class='legend'><span><i class='dot' style='background:#2ecc71'></i>RX Mbps</span><span><i class='dot' style='background:#f39c12'></i>TX Mbps</span></div><svg id='network-chart' viewBox='0 0 900 220' preserveAspectRatio='none'></svg></article></section>
<section class='details'><article class='panel'><h2>容器内部进程</h2><div id='processes'></div></article><article class='panel'><h2>容器网络命名空间</h2><dl id='network' class='kv'></dl></article><article class='panel'><h2>安全与面板检查</h2><div id='security'></div></article><article class='panel'><h2>容器文件系统</h2><dl id='filesystem' class='kv'></dl></article></section>
<section class='panel'><h2>通信进程与连接明细</h2><div id='communications'></div></section>
<section class='panel'><h2>最近采样</h2><div id='samples' class='samples'></div></section>
</main><script>
function esc(v){return String(v??'').replace(/[&<>'"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[c]))}
function fmtBytes(n){const x=Number(n||0);if(x<=0)return '0 B';const u=['B','KB','MB','GB','TB'];let i=0,v=x;while(v>=1024&&i<u.length-1){v/=1024;i++}return `${v.toFixed(v>=100?0:1)} ${u[i]}`}
function mbps(v){return Number(v||0)*8/1000000}function num(v,d=2){const n=Number(v||0);return Number.isFinite(n)?n.toFixed(d):'0.00'}
function linePoints(values,max,w=900,h=220,pad=18){return values.map((v,i)=>`${i*(w/Math.max(1,values.length-1))},${(h-pad)-(Number(v||0)/Math.max(1,max))*(h-pad*2)}`).join(' ')}
function drawChart(id,series){const svg=document.getElementById(id);const values=series.flatMap(x=>x.values);const max=Math.max(1,...values);let grid='';for(let i=0;i<=4;i++){const y=18+i*46;grid+=`<line x1='0' y1='${y}' x2='900' y2='${y}' stroke='#29466f' stroke-width='1'/>`}svg.innerHTML=grid+series.map(x=>`<polyline fill='none' stroke='${x.color}' stroke-width='2.5' points='${linePoints(x.values,max)}'/>`).join('')}
    function sourceText(runtime){if(runtime==='incus')return 'Incus 容器级 cgroup/OpenMetrics 与网络命名空间';if(runtime==='podman')return 'Podman 容器 stats 与网络命名空间';if(runtime==='runman')return 'Runman 代次绑定 guest exec 与网络命名空间';return 'Docker 仅提醒模式（不执行深度采集）'}
    function listHtml(items,empty,mapper){return items.length?`<ul class='list'>${items.map(mapper).join('')}</ul>`:`<div class='ok'>${esc(empty)}</div>`}
    let diagnosticSubmitting=false;
    function detailIdentity(){const q=new URLSearchParams(location.search);return {host_id:q.get('host')||'',runtime:q.get('runtime')||'',project:q.get('project')||'',container_name:q.get('container')||''}}
    function renderDiagnostic(data,runtime){
     const action=data?.action||null,sample=data?.sample||null,state=document.getElementById('diagnostic-state'),button=document.getElementById('request-diagnostic');
      const active=action&&['queued','dispatched'].includes(action.status);button.disabled=diagnosticSubmitting||active||!['incus','podman','runman'].includes(runtime);
     button.innerText=diagnosticSubmitting?'正在提交…':active?'等待上报中':'请求深度上报';
      if(!['incus','podman','runman'].includes(runtime)){state.className='diagnostic-state warn';state.innerText='Docker 默认仅提醒，不执行深度采集。'}
     else if(diagnosticSubmitting){state.className='diagnostic-state warn';state.innerText='正在提交一次性采样任务，请稍候…'}
     else if(action?.status==='queued'){state.className='diagnostic-state warn';state.innerText=`任务 #${action.id} 已排队，等待节点领取（通常 10 秒内）。`}
     else if(action?.status==='dispatched'){state.className='diagnostic-state warn';state.innerText=`任务 #${action.id} 已由节点领取，正在等待下一次上报。`}
     else if(action?.status==='succeeded'){state.className='diagnostic-state ok';state.innerText=`任务 #${action.id} 已完成 · ${action.updated_at_utc8||'-'}`}
     else if(action?.status==='failed'){state.className='diagnostic-state bad';state.innerText=`任务 #${action.id} 失败：${action.result_message||'节点未返回报告，可重试。'}`}
     else{state.className='diagnostic-state';state.innerText='尚未请求深度上报。'}
     const target=document.getElementById('diagnostic-report');if(!sample){target.innerHTML=`<div class='comm-note'>收到报告后将在这里显示瞬时流量、详细进程、连接 IP 和进程归属。</div>`;return}
      const rates=sample.network_rates||{},processes=sample.processes?.items||[],sockets=sample.communication_sockets||[],errors=sample.errors||[];
      const ipMap=new Map();for(const item of [...(sample.connection_ips||[]),...(sample.inbound_ips||[]),...(sample.outbound_ips||[])]){if(!item?.ip)continue;ipMap.set(item.ip,{...(ipMap.get(item.ip)||{}),...item})}const ips=[...ipMap.values()].sort((a,b)=>Math.max(Number(b.connections||0),Number(b.inbound||0),Number(b.outbound||0))-Math.max(Number(a.connections||0),Number(a.inbound||0),Number(a.outbound||0)));
     const metrics=[['报告时间',sample.report_timestamp_utc8||'-'],['瞬时 RX',`${num(mbps(rates.rx_bps))} Mbps`],['瞬时 TX',`${num(mbps(rates.tx_bps))} Mbps`],['RX / TX pps',`${num(rates.rx_pps,1)} / ${num(rates.tx_pps,1)}`],['进程数',Number(sample.process_count||0)],['连接 IP',Number(sample.unique_connection_ips||0)],['连接明细',Number(sample.connection_count||0)],['采样窗口',`${num(rates.sample_seconds,2)} 秒`]];
     const attribution=sample.connection_attribution||{};const expectedConnections=Math.max(Number(sample.connection_count||0),Number(attribution.expected_connection_count||0));const capturedSockets=attribution.captured_sockets==null?null:Number(attribution.captured_sockets);const attributionUnavailable=attribution.evidence_status==='unavailable'||(expectedConnections>0&&(capturedSockets===null||capturedSockets===0));const attributionSummary=Object.keys(attribution).length?`<section class='deep-section'><h3>连接发起方深度核验</h3><div class='comm-note'>${attributionUnavailable?'连接总数非零，但未采集到逐连接来源/PID 数据；发起方向未知，不能按 0 条判断。':`本机发起已确认 ${Number(attribution.confirmed_local_initiated||0)} 条 / 推定 ${Number(attribution.probable_local_initiated||0)} 条；外部发起已确认 ${Number(attribution.confirmed_remote_initiated||0)} 条；方向未知 ${Number(attribution.unknown_direction||0)} 条。进程/PID 已归属 ${Number(attribution.process_attributed_sockets||0)}/${Number(attribution.captured_sockets||0)} 条；conntrack 五元组确认 ${Number(attribution.conntrack_confirmed_sockets||0)} 条。`}${attribution.conntrack_available?'':'本次没有 conntrack 数据，已确认方向可能较少。'}${attribution.conntrack_snapshot_truncated||attribution.socket_snapshot_truncated?'采样达到上限，非全量结果。':''}</div></section>`:'';
      const processRows=processes.length?processes.map(x=>`<div class='deep-row'><strong>${esc(x.process||'unknown')} · PID ${Number(x.pid||0)}</strong><br/>用户 ${esc(x.user||'-')} · CPU ${num(x.cpu_percent)}% · RSS ${fmtBytes(x.rss_bytes)} · 状态 ${esc(x.state||'-')}<br/>${esc(x.command||'-')}</div>`).join(''):`<div class='deep-row'>未采集到进程明细。</div>`;
      const evidenceLabel=value=>({confirmed_conntrack_original_initiator:'conntrack 原始方向：本机进程发起',confirmed_conntrack_reply_acceptor:'conntrack 回复方向：远端发起',confirmed_syn_sent:'TCP SYN-SENT：本机发起',confirmed_syn_recv:'TCP SYN-RECV：远端发起',probable_local_listener_match:'匹配本地监听端口：推定远端入站',probable_established_non_listener:'已建立且本地非监听：推定本机发起',probable_connected_udp_listener_match:'匹配 UDP 监听端口：推定远端到达',probable_connected_udp_non_listener:'UDP 非监听 socket：推定本机发起'})[value]||value||'方向证据不足';
      const signalLabel=value=>({possible_multiport_probe:'疑似多端口探测（仅行为线索）',mixed_connection_evidence:'已建立与未应答连接并存',bidirectional_tcp_observed:'观察到 TCP 双向数据',unreplied_tcp_observed:'存在未应答 TCP 尝试',insufficient_transport_evidence:'传输层证据不足'})[value]||value||'';
      const confidenceLabel=value=>({confirmed:'方向已确认',probable:'方向推定',mixed:'证据冲突',unknown:'方向未知'})[value]||'方向未知';
      const ipRows=ips.length?ips.map(x=>{const network=x.network_evidence||{},proofs=[...(x.inbound_direction_evidence||[]),...(x.outbound_direction_evidence||[])],owners=(x.inbound_processes||[]).map(p=>`${p.process||'unknown'}${Number(p.pid||0)?` (PID ${Number(p.pid)})`:''}`);const signal=network.classification?`${signalLabel(network.classification)} · 已建立 ${Number(network.tcp_established_flows||0)} / 未应答 ${Number(network.tcp_unreplied_flows||0)} / 握手待完成 ${Number(network.tcp_handshake_pending_flows||0)} · 目标端口 ${(network.public_ports||[]).slice(0,12).join(', ')||'-'} · 回包 ${Number(network.reply_packets||0)}`:'';const evidenceSources=(network.evidence_sources||[]).join('、');return `<div class='deep-row'><strong>${esc(x.ip||'-')}</strong> · 连接 ${Number(x.connections||0)} · 入站 ${Number(x.inbound||0)} · 出站 ${Number(x.outbound||0)}<br/>入站发起方：${Number(x.inbound||0)?confidenceLabel(x.inbound_origin_confidence):'无入站 socket 记录'} · 接收进程：${esc(owners.join('、')||(x.processes||[]).join('、')||'未归属')}<br/>方向证据：${esc([...new Set(proofs)].map(evidenceLabel).join('；')||'未取得逐连接证据')}${signal?`<br/>扫描/握手线索：${esc(signal)} · 来源 ${esc(evidenceSources||'conntrack')}`:''}</div>`}).join(''):`<div class='deep-row'>采样瞬间没有可见的公网连接 IP。</div>`;
      const socketRows=sockets.length?sockets.slice(0,250).map(x=>{const origin=x.origin==='local_process'?'本机进程发起':x.origin==='remote_peer'?'远端发起':'发起方未知';const confidence=confidenceLabel(x.origin_confidence);const role=x.process_role==='initiator'?'本机进程角色：发起连接':x.process_role==='acceptor'?'本机进程角色：接受连接':'本机进程角色未知';return `<div class='deep-row'><strong>${esc(x.process||'unknown')} · PID ${Number(x.pid||0)||'-'}</strong> · ${esc(String(x.proto||'').toUpperCase())} · ${esc(x.state||'-')} · ${origin}（${confidence}）<br/>本地 ${esc(x.local||'-')} → 远端 ${esc(x.remote||'-')}<br/>${role} · 判定证据：${esc(evidenceLabel(x.direction_evidence))} · 进程归属：${Number(x.pid||0)>0?'已获得 PID':'不可用'}</div>`}).join(''):`<div class='deep-row'>采样瞬间没有活动连接明细。</div>`;
      const portEvidence=sample.inbound_port_evidence||[];const portRows=portEvidence.length?portEvidence.slice(0,50).map(x=>`<div class='deep-row'><strong>容器端口 ${Number(x.container_port||0)}</strong> · ${Number(x.connections||0)} 条聚合连接 · ${Number(x.source_ip_count||0)} 个来源 IP<br/>来源：${esc((x.source_ips||[]).join('、')||'-')}<br/>监听进程：${esc((x.process_listeners||[]).map(p=>`${p.process||'unknown'} (PID ${Number(p.pid||0)})`).join('、')||'未归属')} · 证据范围：同端口聚合，非逐连接匹配</div>`).join(''):`<div class='deep-row'>没有可用的 NAT/代理端口级来源关联。</div>`;
      target.innerHTML=`<div class='deep-metrics'>${metrics.map(x=>`<div class='deep-metric'><span>${esc(x[0])}</span><strong>${esc(x[1])}</strong></div>`).join('')}</div>${attributionSummary}<div class='comm-note'>本机 PID 说明容器内哪个进程持有 socket；conntrack 原始/回复五元组用于确认发起方向。发起方不等于善恶判断；“疑似探测”不会自动处罚客户。</div><div class='deep-grid'><section class='deep-section'><h3>进程快照（${processes.length}）</h3><div class='deep-list'>${processRows}</div></section><section class='deep-section'><h3>连接 IP 与网络行为（${ips.length}）</h3><div class='deep-list'>${ipRows}</div></section></div><section class='deep-section'><h3>逐连接方向与进程归属（${sockets.length}）</h3><div class='deep-list'>${socketRows}</div></section><section class='deep-section'><h3>端口级公网来源关联（${portEvidence.length}）</h3><p class='comm-note'>NAT/代理会隐藏原始来源时，按宿主机连接与容器目标端口聚合；这不是单条 socket 的精确对应。</p><div class='deep-list'>${portRows}</div></section>${errors.length?`<div class='deep-errors'>部分数据不可用：${esc(errors.join('；'))}</div>`:''}<p class='comm-note'>报告为单次有界元数据快照，进程最多 100 条、连接最多 250 条；命令行中的常见凭据字段已脱敏。</p>`;
    }
    async function requestDeepSample(){
     if(diagnosticSubmitting)return;const identity=detailIdentity(),button=document.getElementById('request-diagnostic'),state=document.getElementById('diagnostic-state');diagnosticSubmitting=true;button.disabled=true;button.innerText='正在提交…';state.className='diagnostic-state warn';state.innerText='正在提交一次性采样任务，请稍候…';
     try{const response=await fetch('/api/v1/containers/diagnostics',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(identity)});const data=await response.json();if(!response.ok)throw new Error(data.detail||`HTTP ${response.status}`);diagnosticSubmitting=false;renderDiagnostic({action:data.action,sample:null},identity.runtime);await loadDetail()}
     catch(error){diagnosticSubmitting=false;button.disabled=false;button.innerText='重试深度上报';state.className='diagnostic-state bad';state.innerText=`提交失败：${error.message||error}`}
    }
    async function loadDetail(){
 const q=new URLSearchParams(location.search),host=q.get('host')||'',runtime=q.get('runtime')||'',project=q.get('project')||'',container=q.get('container')||'';
 if(!host||!runtime||!container){document.getElementById('status').className='status bad';document.getElementById('status').innerText='详情参数不完整，请从总览或统计页重新进入。';return}
 document.getElementById('title').innerText=container;document.getElementById('subtitle').innerText=`${host} · ${project?`${runtime}/${project}`:runtime}`;
     const params=new URLSearchParams({host_id:host,runtime,project,container_name:container,minutes:'1440'}),diagnosticParams=new URLSearchParams({host_id:host,runtime,project,container_name:container});
     try{
      const [latestData,historyData,diagnosticData]=await Promise.all([fetch('/api/v1/latest?include_stale=true').then(r=>r.json()),fetch(`/api/v1/history?${params}`).then(r=>r.json()),fetch(`/api/v1/containers/diagnostics?${diagnosticParams}`).then(r=>r.json())]);
  const current=(latestData.items||[]).find(x=>x.host_id===host&&x.runtime===runtime&&(x.project||'')===project&&x.container_name===container);const allPts=historyData.items||[];const currentVersion=String(current?.agent_version||'unknown');const pts=currentVersion==='unknown'?allPts:allPts.filter(x=>String(x.agent_version||'unknown')===currentVersion);const excludedSamples=allPts.length-pts.length;
  const status=document.getElementById('status'),version=document.getElementById('detail-version');
  const clientVersion=String(current?.agent_version||'unknown'),serverVersion=String(latestData.server_version||'dev');
  if(clientVersion!=='unknown'&&clientVersion!=='dev'&&clientVersion===serverVersion){version.className='version-pill ok';version.innerText=`Client / Server v${serverVersion}`}
  else if(clientVersion==='unknown'||clientVersion==='dev'){version.className='version-pill warn';version.innerText=`Client 版本未知 · Server ${serverVersion==='dev'?'dev':`v${serverVersion}`}`}
      else{version.className='version-pill bad';version.innerText=`Client v${clientVersion} · Server v${serverVersion}`}
      renderDiagnostic(diagnosticData,runtime);
  if(current){status.innerHTML=`<span class='source'>${esc(sourceText(runtime))}</span>　最新采样 ${esc(current.timestamp_iso_utc8||'-')}${excludedSamples?`　已忽略 ${excludedSamples} 条旧版本口径样本`:''}${current.alerts?.stale?'　<span class="bad-text">当前离线或上报已过期</span>':''}`}
  else{status.className='status bad';status.innerText='未找到该容器的当前采样，仅显示保留的历史数据。'}
  const sec=current?.security||{},limit=Number(current?.mem_limit_bytes||0),used=Number(current?.mem_bytes||0),rootTotal=Number(current?.container_fs_root_total_bytes||0),rootAvail=Number(current?.container_fs_root_avail_bytes||0);
  const inboundUniqueIps=Number(sec.inbound_unique_ips||0),inboundThreshold=Number(sec.inbound_unique_ip_threshold||10),inboundAlert=inboundUniqueIps>inboundThreshold;
  const cards=[['CPU',`${num(current?.cpu_percent)}%`],['内存',`${num(current?.mem_percent)}%`],['内存 已用/总量',`${fmtBytes(used)} / ${fmtBytes(limit)}`],['RX',`${num(mbps(current?.net_rx_bps))} Mbps`],['TX',`${num(mbps(current?.net_tx_bps))} Mbps`],['入站去重 IP',`${inboundUniqueIps} / 阈值 ${inboundThreshold}`,inboundAlert?'metric-alert':''],['连接数',Number(current?.conn_count||0)],['进程数',Number(sec.process_count||0)],['有效 CPU',Number(current?.cpu_effective_cpus||0)||'未限制']];
  document.getElementById('metrics').innerHTML=cards.map(x=>`<article class='metric ${x[2]||''}'><span>${esc(x[0])}</span><strong>${esc(x[1])}</strong></article>`).join('');
  const recent=pts.slice(-80);drawChart('resource-chart',[{values:recent.map(x=>Number(x.cpu_percent||0)),color:'#4a90e2'},{values:recent.map(x=>Number(x.mem_percent||0)),color:'#16a085'}]);drawChart('network-chart',[{values:recent.map(x=>mbps(x.net_rx_bps)),color:'#2ecc71'},{values:recent.map(x=>mbps(x.net_tx_bps)),color:'#f39c12'}]);
  const suspicious=Array.isArray(sec.suspicious_processes)?sec.suspicious_processes:[];const top=current?.top_cpu_process_command?`PID ${Number(current.top_cpu_process_pid||0)} · CPU ${num(current.top_cpu_process_cpu_percent)}% · ${esc(current.top_cpu_process_command)}`:'未采集到高 CPU 进程';document.getElementById('processes').innerHTML=`<div>${top}</div>`+listHtml(suspicious,'未发现可疑进程',x=>`<li>PID ${Number(x.pid||0)} · ${esc(x.command||x.pattern||'')}</li>`);
  const countries=(arr)=>(Array.isArray(arr)&&arr.length?arr.slice(0,5).map(x=>`${x.country||'UN'} (${Number(x.connections||0)})`).join('、'):'-');const exposure=Array.isArray(sec.network_exposure)?sec.network_exposure:[];const inboundMode=sec.inbound_ip_observation==='host_conntrack'?'宿主机 NAT/conntrack 还原':'容器 socket 观察';const inboundTop=Array.isArray(sec.inbound_top_ips)?sec.inbound_top_ips:[];document.getElementById('network').innerHTML=`<dt>监听端口</dt><dd>${esc((sec.listening_ports||[]).join(', ')||'-')}</dd><dt>NAT/代理</dt><dd>${esc(exposure.map(x=>`${x.listen||'?'} → ${x.target||'?'}`).join(', ')||'-')}</dd><dt>入站去重 IP</dt><dd class='${inboundAlert?'bad-text':''}'>${inboundUniqueIps} / 阈值 ${inboundThreshold}</dd><dt>入站来源口径</dt><dd>${esc(inboundMode)}</dd><dt>主要入站来源</dt><dd>${esc(inboundTop.slice(0,10).map(x=>`${x.ip||'?'} (${Number(x.connections||0)})`).join('、')||'-')}</dd><dt>入站连接</dt><dd>${Number(sec.incoming_established||0)}</dd><dt>出站去重 IP</dt><dd>${Number(sec.outbound_unique_ips||0)}</dd><dt>TCP 来源</dt><dd>${esc(countries(current?.tcp_country_stats))}</dd><dt>UDP 来源</dt><dd>${esc(countries(current?.udp_country_stats))}</dd><dt>RX pps</dt><dd>${num(sec.net_rx_pps,1)}</dd><dt>SYN_RECV</dt><dd>${Number(sec.syn_recv_count||0)}</dd>`;
  const risks=Array.isArray(sec.configuration_risks)?sec.configuration_risks:[],pair=sec.panel_pairing||{},socks=sec.socks_proxy||{};const socksAuth={no_auth:'无认证',weak_password:'弱密码',configured:'已配置认证',unknown:'认证未知'}[socks.auth_mode||'unknown'];document.getElementById('security').innerHTML=`<div>面板对接：<strong class='${pair.detected&&!pair.approved?'bad-text':'ok'}'>${pair.detected?(pair.approved?'已放行':'检测到特征'):'未发现'}</strong></div><div>SOCKS 代理：<strong class='${socks.detected&&['no_auth','weak_password'].includes(socks.auth_mode)?'bad-text':'ok'}'>${socks.detected?`已识别 · ${esc(socksAuth)}${socks.public_exposure?' · 公网/NAT 暴露':''}`:'未发现'}</strong></div>`+listHtml(risks,'未发现配置风险',x=>`<li>${esc(x.message||x.code||'配置风险')}</li>`);
  const writableLayer=current?.container_disk_rw_available===true?fmtBytes(current?.container_disk_rw_bytes):'暂不可用';
  document.getElementById('filesystem').innerHTML=`<dt>根盘 已用/总量</dt><dd>${fmtBytes(Math.max(0,rootTotal-rootAvail))} / ${fmtBytes(rootTotal)}</dd><dt>根盘可用</dt><dd>${fmtBytes(rootAvail)}</dd><dt title="Podman 按存储驱动提供可写层大小；Runman 按 overlay upperdir 文件分配块统计，不包含只读镜像层">镜像可写层已分配</dt><dd>${writableLayer}</dd>`;
   const communicationProcesses=Array.isArray(sec.communication_processes)?sec.communication_processes:[],communicationSockets=Array.isArray(sec.communication_sockets)?sec.communication_sockets:[];
   const processCards=communicationProcesses.length?`<div class='comm-process-grid'>${communicationProcesses.map(x=>`<article class='comm-process'><strong>${esc(x.process||'unknown')} · PID ${Number(x.pid||0)||'-'}</strong><div class='comm-meta'>入站 ${Number(x.inbound_connections||0)} · 出站 ${Number(x.outbound_connections||0)} · 远端 IP ${Number(x.unique_remote_ips||0)}</div></article>`).join('')}</div>`:`<div class='ok'>${sec.communication_detail_available?'当前没有可归属的活动通信':'容器内缺少 ss，暂时无法归属到具体进程'}</div>`;
   const originName=x=>x.origin==='local_process'?'本机进程发起':x.origin==='remote_peer'?'远端发起':'发起方未知',originConfidence=x=>({confirmed:'已确认',probable:'推定',mixed:'证据冲突',unknown:'未知'})[x.origin_confidence]||'未知';
   const socketCards=communicationSockets.length?`<h3>活动连接（最多展示 ${communicationSockets.length} 条）</h3><div class='socket-grid'>${communicationSockets.slice(0,100).map(x=>`<article class='socket-card'><div class='socket-head'><strong>${esc(x.process||'unknown')} · PID ${Number(x.pid||0)||'-'}</strong><span class='direction ${x.direction==='inbound'?'inbound':'outbound'}'>${x.direction==='inbound'?'入站':x.direction==='outbound'?'出站':'未知'} · ${originConfidence(x)}</span></div><div class='socket-meta'>${esc(String(x.proto||'').toUpperCase())} · ${esc(x.state||'-')} · ${originName(x)}<br/>本地 ${esc(x.local||'-')}<br/>远端 ${esc(x.remote||'-')}<br/>证据：${esc(x.direction_evidence||'无')} · PID ${Number(x.pid||0)>0?'已归属':'不可用'}</div></article>`).join('')}</div>`:'';
   const sourceSignals=Array.isArray(sec.inbound_source_signals)?sec.inbound_source_signals:[],sourceLabel=x=>({possible_multiport_probe:'疑似多端口探测（线索）',mixed_connection_evidence:'已建立与未应答并存',bidirectional_tcp_observed:'观察到 TCP 双向数据',unreplied_tcp_observed:'未应答 TCP 尝试',insufficient_transport_evidence:'传输层证据不足'})[x]||x||'未知';
   const sourceSignalCards=sourceSignals.length?`<h3>入站来源行为线索</h3><div class='deep-list'>${sourceSignals.slice(0,20).map(x=>`<div class='deep-row'><strong>${esc(x.ip||'-')}</strong> · ${esc(sourceLabel(x.classification))}<br/>TCP 已建立 ${Number(x.tcp_established_flows||0)} · 未应答 ${Number(x.tcp_unreplied_flows||0)} · SYN_RECV ${Number(x.tcp_handshake_pending_flows||0)} · 回包 ${Number(x.reply_packets||0)}<br/>目标端口 ${(x.public_ports||[]).slice(0,16).map(v=>Number(v)).join(', ')||'-'} · 证据 ${esc((x.evidence_sources||[]).join('、')||'未知')} · ${esc(x.scope||'单次快照')}</div>`).join('')}</div>`:'';
   const inboundPortEvidence=Array.isArray(sec.inbound_port_evidence)?sec.inbound_port_evidence:[];
   const inboundPortCards=inboundPortEvidence.length?`<h3>端口级公网来源关联</h3><p class='comm-note'>NAT/代理恢复出的来源按容器目标端口聚合，不等于逐条 socket 精确关联。</p><div class='deep-list'>${inboundPortEvidence.slice(0,20).map(x=>`<div class='deep-row'><strong>容器端口 ${Number(x.container_port||0)}</strong> · ${Number(x.connections||0)} 条 · ${Number(x.source_ip_count||0)} 个来源<br/>${esc((x.source_ips||[]).join('、')||'-')}<br/>监听进程：${esc((x.process_listeners||[]).map(p=>`${p.process||'unknown'} PID ${Number(p.pid||0)}`).join('、')||'未归属')} · 端口聚合</div>`).join('')}</div>`:'';
   document.getElementById('communications').innerHTML=`<p class='comm-note'>宿主机 conntrack 读取 ${Number(sec.host_conntrack_snapshot_count||0)} 条${sec.host_conntrack_snapshot_truncated?'（已达到安全上限）':''}；容器 socket 读取 ${Number(sec.communication_snapshot_count||0)} 条${sec.communication_snapshot_truncated?'（已达到安全上限）':''}。均为单次有界元数据快照，不持续抓包。进程归属和连接发起方是两项不同证据；发起方向也不代表用户意图。</p>${processCards}${socketCards}${sourceSignalCards}${inboundPortCards}`;
  document.getElementById('samples').innerHTML=pts.length?pts.slice(-20).reverse().map(x=>`<div class='sample'><span>${esc(x.timestamp_iso_utc8||'-')}</span><span>CPU ${num(x.cpu_percent)}%</span><span>内存 ${num(x.mem_percent)}%</span><span>RX ${num(mbps(x.net_rx_bps))}M</span><span>TX ${num(mbps(x.net_tx_bps))}M</span><span>连接 ${Number(x.conn_count||0)}</span></div>`).join(''):`<div class='ok'>暂无历史采样</div>`;
 }catch(error){const status=document.getElementById('status');status.className='status bad';status.innerText=`详情加载失败：${error.message||error}`}
}
loadDetail();setInterval(loadDetail,15000);
</script></body></html>
"""


def stats_page(request: Request = None, static_dir: Path | None = None) -> Any:
    spa_index = (static_dir / "index.html") if static_dir is not None else None
    if spa_index is not None and request is not None and spa_index.is_file():
        return FileResponse(spa_index)
    return """
<!doctype html>
<html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width, initial-scale=1'><title>Container Stats</title>
<style>
*{box-sizing:border-box}html,body{max-width:100%;overflow-x:hidden}
:root{color-scheme:dark;--bg:#020617;--surface:#0f172a;--surface-2:#172033;--surface-3:#1e293b;--border:#334155;--text:#f8fafc;--muted:#94a3b8;--accent:#38bdf8;--focus:#7dd3fc}
body{font-family:system-ui,-apple-system,"Segoe UI",sans-serif;margin:0;background:var(--bg);color:var(--text);line-height:1.5}.page{width:min(1600px,100%);margin:auto;padding:20px}.skip-link{position:fixed;left:12px;top:-60px;z-index:10;background:var(--accent);color:#082f49;padding:10px 14px;border-radius:8px;font-weight:700}.skip-link:focus{top:12px}
.page-header{display:flex;justify-content:space-between;align-items:flex-start;gap:16px;padding:18px 20px;margin-bottom:16px;border:1px solid var(--border);border-radius:14px;background:linear-gradient(135deg,var(--surface),#111d34)}.page-header h1{margin:0;font-size:22px}.page-header p{margin:4px 0 0;color:var(--muted);font-size:13px}
.topbar{display:flex;gap:8px;align-items:center;justify-content:flex-end;flex-wrap:wrap}.topbar label{color:var(--muted);font-size:13px}.topbar input{width:110px;min-height:44px;padding:7px 9px;border:1px solid var(--border);border-radius:8px;background:#0b1220;color:var(--text)}.btn-link,.topbar button{display:inline-flex;align-items:center;justify-content:center;min-height:44px;padding:8px 13px;border:1px solid var(--border);border-radius:8px;background:var(--surface-3);color:var(--text);text-decoration:none;cursor:pointer}.btn-link:hover,.topbar button:hover{filter:brightness(1.12)}.btn-link:focus-visible,.topbar button:focus-visible,.topbar input:focus-visible{outline:3px solid var(--focus);outline-offset:2px}
.card-grid{display:grid;grid-template-columns:repeat(4,minmax(120px,1fr));gap:10px;margin-bottom:12px}
.card{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:14px 16px;color:var(--muted);font-size:12px}
.value{font-size:22px;font-weight:700;margin-top:6px}
.value{color:var(--text);font-variant-numeric:tabular-nums}.section{margin:14px 0;border:1px solid var(--border);border-radius:12px;background:var(--surface);overflow:hidden}.section h2{margin:0;padding:13px 15px;border-bottom:1px solid var(--border);background:var(--surface-2);font-size:16px}
table{border-collapse:collapse;width:100%;max-width:100%;table-layout:fixed;background:var(--surface);color:var(--text)}
th,td{border:1px solid var(--border);padding:8px;text-align:center;overflow-wrap:anywhere;word-break:break-word;font-size:12px}th{background:var(--surface-3);color:#cbd5e1}
a{color:#7dd3fc}.detail-link{display:inline-flex;align-items:center;justify-content:center;min-height:40px;border:1px solid var(--border);border-radius:7px;padding:5px 9px;text-decoration:none;background:var(--surface-3);color:var(--text)}.version-pill{display:inline-flex;align-items:center;border:1px solid #166534;border-radius:999px;padding:4px 9px;background:#052e16;color:#86efac;font-size:12px}.version-pill.warn{border-color:#92400e;background:#451a03;color:#fcd34d}
@media(max-width:800px){.page{padding:8px}.page-header{flex-direction:column;padding:14px}.topbar{justify-content:flex-start}.card-grid{grid-template-columns:repeat(2,minmax(0,1fr))}th,td{padding:5px;font-size:11px}#all-containers th:nth-child(6),#all-containers td:nth-child(6),#all-containers th:nth-child(7),#all-containers td:nth-child(7),#all-containers th:nth-child(9),#all-containers td:nth-child(9){display:none}}
@media(prefers-reduced-motion:reduce){*,*::before,*::after{transition:none!important;animation:none!important}}
</style>
</head><body><a class='skip-link' href='#stats-main'>跳到主要内容</a><main id='stats-main' class='page'>
<header class='page-header'><div><h1>数据统计</h1><p>资源、连接与累计流量分析；点击排查进入独立容器详情。</p></div><div class='topbar'>
  <span id='stats-server-version' class='version-pill warn'>Server 版本检查中</span>
  <label>统计窗口(分钟)：<input id='minutes' type='number' value='720' min='5' max='10080' /></label>
  <button onclick='loadStats()'>刷新</button>
  <a class='btn-link' href='/'>返回总览</a>
</div></header>
<div class='card-grid'>
  <div class='card'><div>容器数</div><div class='value' id='kpi-containers'>0</div></div>
  <div class='card'><div>样本数</div><div class='value' id='kpi-samples'>0</div></div>
  <div class='card'><div>建议采样间隔</div><div class='value' id='kpi-interval'>--</div></div>
  <div class='card'><div>窗口</div><div class='value' id='kpi-window'>--</div></div>
</div>

<section class='section'><h2>Top10：平均 CPU</h2>
  <table id='cpu-top'><thead><tr><th>主机</th><th>运行时</th><th>容器</th><th>平均 CPU%</th><th>峰值 CPU%</th><th>估算间隔(秒)</th><th>排查</th></tr></thead><tbody></tbody></table>
</section>

<section class='section'><h2>Top10：平均连接数</h2>
  <table id='conn-top'><thead><tr><th>主机</th><th>运行时</th><th>容器</th><th>平均连接</th><th>峰值连接</th><th>样本数</th><th>排查</th></tr></thead><tbody></tbody></table>
</section>

<section class='section'><h2>Top10：累计流量</h2>
  <table id='traffic-top'><thead><tr><th>主机</th><th>运行时</th><th>容器</th><th>累计 RX</th><th>累计 TX</th><th>累计总流量</th><th>排查</th></tr></thead><tbody></tbody></table>
</section>

<section class='section'><h2>全部容器</h2>
<table id='all-containers'><thead><tr><th>主机</th><th>运行时</th><th>容器</th><th>当前 CPU%</th><th>当前内存%</th><th>当前 RX</th><th>当前 TX</th><th>当前连接</th><th>样本数</th><th>排查</th></tr></thead><tbody></tbody></table>
</section>

<section class='section'><h2>主机汇总</h2>
<table id='host-summary'><thead><tr><th>主机</th><th>累计 RX</th><th>累计 TX</th><th>累计总流量</th><th>样本数</th></tr></thead><tbody></tbody></table>
</section>

<script>
function fmtBytes(n){
  const x = Number(n||0); if (x<=0) return '0 B';
  const units=['B','KB','MB','GB','TB']; let i=0; let v=x;
  while(v>=1024 && i<units.length-1){v/=1024;i++;}
  return `${v.toFixed(v>=100?0:1)} ${units[i]}`;
}
function escapeHtml(value){
  return String(value??'').replace(/[&<>'"]/g, ch=>({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[ch]));
}
function detailHref(x){
  const q=new URLSearchParams({host:x.host_id,runtime:x.runtime,project:x.project||'',container:x.container_name});
  return `/container-detail?${q.toString()}`;
}
function detailCell(x){
  return `<a class='detail-link' href='${escapeHtml(detailHref(x))}'>容器详情</a>`;
}
function renderRows(id, rows, mapper){
  const tb=document.querySelector(`#${id} tbody`);
  tb.innerHTML='';
  for(const row of rows){
    const tr=document.createElement('tr');
    tr.innerHTML=mapper(row);
    tb.appendChild(tr);
  }
}
async function loadStats(){
  const minutes=Math.max(5, Math.min(10080, Number(document.getElementById('minutes').value||720)));
  const res=await fetch(`/api/v1/stats?minutes=${minutes}`);
  const data=await res.json();
  const version=document.getElementById('stats-server-version'),serverVersion=String(data.server_version||'dev');
  version.className=`version-pill ${serverVersion==='dev'?'warn':''}`;
  version.innerText=serverVersion==='dev'?'Server dev':`Server v${serverVersion}`;
  document.getElementById('kpi-containers').innerText=data.container_count||0;
  document.getElementById('kpi-samples').innerText=data.samples||0;
  document.getElementById('kpi-interval').innerText=(data.recommendation?.suggested_interval_seconds||'--') + 's';
  document.getElementById('kpi-window').innerText=(data.window_minutes||minutes)+'m';

  renderRows('cpu-top', data.ranks?.avg_cpu_top10||[], x=>`
    <td>${x.host_id}</td><td>${x.project?`${x.runtime}/${x.project}`:x.runtime}</td><td>${x.container_name}</td>
    <td>${Number(x.avg.cpu_percent||0).toFixed(2)}</td>
    <td>${Number(x.max.cpu_percent||0).toFixed(2)}</td>
    <td>${Number(x.estimated_interval_seconds||0).toFixed(2)}</td>
    <td>${detailCell(x)}</td>
  `);
  renderRows('conn-top', data.ranks?.avg_conn_top10||[], x=>`
    <td>${x.host_id}</td><td>${x.project?`${x.runtime}/${x.project}`:x.runtime}</td><td>${x.container_name}</td>
    <td>${Number(x.avg.conn_count||0).toFixed(2)}</td>
    <td>${Number(x.max.conn_count||0)}</td>
    <td>${x.samples||0}</td>
    <td>${detailCell(x)}</td>
  `);
  renderRows('traffic-top', data.ranks?.traffic_top10||[], x=>`
    <td>${x.host_id}</td><td>${x.project?`${x.runtime}/${x.project}`:x.runtime}</td><td>${x.container_name}</td>
    <td>${fmtBytes(x.traffic_bytes.rx)}</td>
    <td>${fmtBytes(x.traffic_bytes.tx)}</td>
    <td>${fmtBytes(x.traffic_bytes.total)}</td>
    <td>${detailCell(x)}</td>
  `);
  renderRows('all-containers', data.containers||[], x=>`
    <td>${escapeHtml(x.host_id)}</td><td>${escapeHtml(x.project?`${x.runtime}/${x.project}`:x.runtime)}</td><td>${escapeHtml(x.container_name)}</td>
    <td>${Number(x.latest?.cpu_percent||0).toFixed(2)}</td><td>${Number(x.latest?.mem_percent||0).toFixed(2)}<br/><small>${fmtBytes(x.latest?.mem_bytes)} / ${fmtBytes(x.latest?.mem_limit_bytes)}</small></td>
    <td>${fmtBytes(x.latest?.net_rx_bps)}/s</td><td>${fmtBytes(x.latest?.net_tx_bps)}/s</td>
    <td>${Number(x.latest?.conn_count||0)}</td><td>${Number(x.samples||0)}</td><td>${detailCell(x)}</td>
  `);
  renderRows('host-summary', data.hosts||[], x=>`
    <td>${x.host_id}</td>
    <td>${fmtBytes(x.traffic_rx_bytes)}</td>
    <td>${fmtBytes(x.traffic_tx_bytes)}</td>
    <td>${fmtBytes(x.traffic_total_bytes)}</td>
    <td>${x.samples}</td>
  `);
}
loadStats();
</script>
</main></body></html>
"""


def attach(app: Any, static_dir_getter: Callable[[], Path]) -> None:
    @app.api_route("/alerts/history", methods=["GET", "HEAD"], response_class=HTMLResponse)
    def _security_alert_history_page(request: Request = None) -> Any:
        return security_alert_history_page(request, static_dir_getter())

    @app.api_route("/", methods=["GET", "HEAD"], response_class=HTMLResponse)
    def _dashboard(request: Request = None) -> Any:
        return dashboard(request, static_dir_getter())

    @app.api_route("/container-detail", methods=["GET", "HEAD"], response_class=HTMLResponse)
    def _container_detail_page(request: Request = None) -> Any:
        return container_detail_page(request, static_dir_getter())

    @app.api_route("/stats", methods=["GET", "HEAD"], response_class=HTMLResponse)
    def _stats_page(request: Request = None) -> Any:
        return stats_page(request, static_dir_getter())
