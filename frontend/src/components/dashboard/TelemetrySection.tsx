import React, { useState } from 'react';
import { Activity } from 'lucide-react';
import { AccessSource, SecurityStatusItem } from '../../api/types';
import { api, fmtNetSpeed, fmtNumber } from '../../api/client';

interface TelemetrySectionProps {
  telemetry: SecurityStatusItem[];
  onToast: (type: 'success' | 'error' | 'info', message: string) => void;
  onRefresh: () => void;
}

type Level = 'normal' | 'warning' | 'critical' | 'unknown';
const tones: Record<Level, string> = {
  normal: 'border-emerald-700 bg-emerald-950/30 text-emerald-300',
  warning: 'border-amber-700 bg-amber-950/30 text-amber-300',
  critical: 'border-red-700 bg-red-950/30 text-red-300',
  unknown: 'border-slate-700 bg-slate-950/30 text-slate-300',
};
const labels: Record<Level, string> = { normal: '正常', warning: '警告', critical: '危险', unknown: '未评估' };
const thresholdLevel = (value: number, warning: number, critical: number): Level =>
  value > critical ? 'critical' : value > warning ? 'warning' : 'normal';
const signalLevel = (t: SecurityStatusItem, pattern: RegExp): Level => {
  if (!t.enabled || t.stale) return 'unknown';
  const matches = (t.sample_alerts || []).filter(a => pattern.test(a.type || ''));
  return matches.some(a => a.severity === 'critical') ? 'critical'
    : matches.some(a => a.severity === 'warning') ? 'warning' : 'normal';
};
const Signal: React.FC<{ title: string; level: Level; children: React.ReactNode }> = ({ title, level, children }) =>
  <div className={`min-w-0 rounded-xl border p-3 ${tones[level]}`}>
    <div className="mb-2 flex flex-wrap items-center justify-between gap-2 font-semibold">
      <h4>{title}</h4><span className="text-[11px]">{labels[level]}</span>
    </div><div className="space-y-1.5 break-words text-xs leading-5 tabular-nums">{children}</div>
  </div>;

const HttpSource: React.FC<{ source: AccessSource }> = ({ source: s }) => {
  const requests = Number(s.requests || 0);
  const readable = Number(s.readable_files || 0) > 0;
  const issue = Number(s.parse_errors || 0) > 0;
  return <div className="min-w-0 rounded-lg border border-slate-700/70 p-2">
    <p className="break-all font-semibold">{s.label || '访问日志'}</p>
    {!readable ? <p className="text-slate-300">{s.unreadable_files ? '日志不可读：检查读取权限'
      : s.missing_files ? '日志文件不存在：检查 access log 路径'
      : s.container_readable_files ? '旧版仅上报容器日志状态，请更新采集客户端'
      : '未接入访问日志：请配置宿主机或容器日志路径'}</p> : <>
      <p>总 {fmtNumber(s.requests_per_second || 0, 1)} · 单 IP {fmtNumber(s.top_ip_requests_per_second || 0, 1)} rps</p>
      <p>4xx {requests ? ((s.status_4xx || 0) / requests * 100).toFixed(1) + '%' : '—'} · 5xx {requests ? ((s.status_5xx || 0) / requests * 100).toFixed(1) + '%' : '—'}</p>
      <p>本周期请求 {fmtNumber(requests, 0)} · 去重 IP {fmtNumber(s.unique_ips || 0, 0)}</p>
      {!requests && <p className="text-slate-300">本周期无新增请求，首次采样需等待下一周期。</p>}
    </>}
    {issue && <p className="text-amber-300">解析失败 {s.parse_errors} 行；统计可能不完整，请检查日志格式。</p>}
  </div>;
};

export const TelemetrySection: React.FC<TelemetrySectionProps> = ({ telemetry, onToast, onRefresh }) => {
  const [editing, setEditing] = useState<SecurityStatusItem | null>(null);
  const [deleting, setDeleting] = useState<SecurityStatusItem | null>(null);
  const [busy, setBusy] = useState(false);
  if (!telemetry?.length) return null;
  return <section className="mb-6 min-w-0 rounded-2xl border border-slate-800 bg-slate-900/60 shadow-sm">
    <header className="flex items-start gap-3 border-b border-slate-800 px-4 py-4">
      <Activity className="mt-0.5 h-5 w-5 shrink-0 text-sky-400" />
      <div className="min-w-0">
        <h2 className="text-sm font-bold text-slate-100">主机网络与安全遥测</h2>
        <p className="mt-1 text-xs leading-5 text-slate-300">按主机汇总受监控容器；HTTP 按日志来源展示。绿色正常 · 黄色警告 · 红色危险 · 灰色未采集或过期。</p>
      </div>
    </header>
    <div className="space-y-4 p-3">
      {telemetry.map(t => {
        const thresholds = t.thresholds || {};
        const events = t.sample_alerts || [];
        const networkEvents = events.filter(a => /^ddos_/.test(a.type || ''));
        const httpEvents = events.filter(a => /^(cc_|http_|web_scan)/.test(a.type || ''));
        const sources = t.access_sources || [];
        const readable = sources.some(s => Number(s.readable_files || 0) > 0);
        const connWarning = thresholds.connections_warning ?? 500;
        const connCritical = thresholds.connections_critical ?? 1000;
        const ipWarning = thresholds.inbound_ips_warning ?? 10;
        const ipCritical = thresholds.inbound_ips_critical ?? 20;
        const connPeak = t.today_peak_container_conn_count ?? 0;
        const detectedHttpLevel = signalLevel(t, /^(cc_|http_|web_scan)/);
        const httpLevel = !readable ? 'unknown' : detectedHttpLevel === 'normal' && sources.some(s => Number(s.parse_errors || 0) > 0) ? 'warning' : detectedHttpLevel;
        const visibleSources = readable ? sources.filter(s => Number(s.readable_files || 0) > 0) : sources.slice(0, 1);
        const peakTone = (value: number, warning: number, critical: number) =>
          t.stale || !t.enabled ? 'text-slate-300' : thresholdLevel(value, warning, critical) === 'critical' ? 'text-red-300'
            : thresholdLevel(value, warning, critical) === 'warning' ? 'text-amber-300' : 'text-emerald-300';
        return <article key={t.host_id} className="min-w-0 rounded-xl border border-slate-700 bg-slate-900/60 p-3 sm:p-4">
          <div className="mb-3 flex flex-wrap items-start justify-between gap-3">
            <div className="min-w-0 flex-1 basis-56">
              <h3 className="break-all text-sm font-semibold text-slate-100">{t.host_id}</h3>
              <p className="mt-1 break-words text-xs text-slate-300">采样：{t.timestamp_iso_utc8 || '—'} · 窗口 {t.interval_seconds || '—'} 秒
                {t.stale ? ' · 数据已过期' : !t.enabled ? ' · 安全采集未启用' : ''}</p>
            </div>
            <div className="flex flex-wrap gap-2">
              <button type="button" onClick={() => setEditing(t)} className="rounded-lg border border-sky-700 bg-sky-950/60 px-3 py-2 text-xs text-sky-300">配置</button>
              <button type="button" onClick={() => setDeleting(t)} className="rounded-lg border border-red-800 bg-red-950/40 px-3 py-2 text-xs text-red-300">删除</button>
            </div>
          </div>
          <div className="grid min-w-0 gap-3 [grid-template-columns:repeat(auto-fit,minmax(min(100%,240px),1fr))]">
            <Signal title="实时速率 / 今日峰值" level={signalLevel(t, /^ddos_(host_)?bandwidth$/)}>
              <p>↓ {fmtNetSpeed(t.rx_bps).mbps} · ↑ {fmtNetSpeed(t.tx_bps).mbps}</p>
              <p>今日峰值 ↓ {fmtNetSpeed(t.today_peak_rx_bps).mbps}</p>
              <p>今日峰值 ↑ {fmtNetSpeed(t.today_peak_tx_bps).mbps}</p>
              <p className="text-slate-300">受监控容器合计，非物理网卡总流量。</p>
            </Signal>
            <Signal title="DDoS 网络信号" level={signalLevel(t, /^ddos_/)}>
              <p>↓ {fmtNumber(t.rx_pps, 0)} pps · ↑ {fmtNumber(t.tx_pps, 0)} pps</p>
              <p>SYN_RECV {fmtNumber(t.syn_recv, 0)}</p>
              <p>本次 DDoS 事件 {networkEvents.length} 项</p>
              <p className="text-slate-300">包速率 ≥ {fmtNumber(thresholds.rx_pps_warning ?? 50000, 0)} pps、SYN ≥ {thresholds.syn_recv_warning ?? 200} 警告，达到 2 倍危险。</p>
            </Signal>
            <Signal title="CC / HTTP 信号" level={httpLevel}>
              <p>本次 HTTP 事件 {httpEvents.length} 项</p>
              {visibleSources.length ? visibleSources.map((s, i) => <HttpSource key={i} source={s} />) : <p>尚未收到日志采集状态</p>}
              {sources.length > visibleSources.length && <details><summary className="cursor-pointer text-slate-300">其余 {sources.length - visibleSources.length} 个来源未接入或不可读</summary>{sources.filter(s => !visibleSources.includes(s)).map((s, i) => <HttpSource key={i} source={s} />)}</details>}
              <p className="text-slate-300">来源分别计数，避免反向代理与应用重复计算。没有 HTTP 访问日志时无法从 TCP 流量推算请求数。</p>
            </Signal>
            <Signal title="今日单容器峰值" level={t.stale || !t.enabled ? 'unknown' : [thresholdLevel(connPeak, connWarning, connCritical), thresholdLevel(t.today_peak_inbound_ips, ipWarning, ipCritical)].includes('critical') ? 'critical' : [thresholdLevel(connPeak, connWarning, connCritical), thresholdLevel(t.today_peak_inbound_ips, ipWarning, ipCritical)].includes('warning') ? 'warning' : 'normal'}>
              <p><span className={peakTone(connPeak, connWarning, connCritical)}>最高连接 {fmtNumber(connPeak, 0)}</span> · <span className="text-slate-300">全容器合计峰值 {fmtNumber(t.today_peak_conn_count, 0)}</span></p>
              <p><span className={peakTone(t.today_peak_inbound_ips, ipWarning, ipCritical)}>最高入站 IP {fmtNumber(t.today_peak_inbound_ips, 0)}</span> · <span className="text-slate-300">最高出站 IP {fmtNumber(t.today_peak_outbound_ips, 0)}</span></p>
              <p className="text-slate-300">连接 &gt; {connWarning} / {connCritical}、入站 IP &gt; {ipWarning} / {ipCritical}：警告 / 危险。</p>
              <p className="text-slate-300">UTC+8 当日采样最大值；各项可能来自不同容器。推送使用触发当时的单容器值，峰值不代表当前仍异常。</p>
            </Signal>
          </div>
          <details className="mt-3 rounded-lg border border-slate-700 p-3 text-xs text-slate-300">
            <summary className="cursor-pointer font-semibold text-slate-100">查看本次采样事件（{events.length} 项，含普通提示）与阈值说明</summary>
            <div className="mt-3 space-y-2">
              {events.map((event, i) => <div key={i} className={`min-w-0 rounded-lg border p-3 break-words ${tones[event.severity === 'critical' ? 'critical' : event.severity === 'warning' ? 'warning' : 'unknown']}`}>
                <p className="font-semibold">{event.severity === 'critical' ? '危险' : event.severity === 'warning' ? '警告' : '提示'} · {event.title || event.type}</p>
                <p className="break-all">{[event.runtime, event.project, event.container_name].filter(Boolean).join('/') || '主机汇总'} · {event.message}</p>
                {event.threshold != null && <p>触发值 {String(event.value ?? '—')} · 阈值 {String(event.threshold)}</p>}
              </div>)}
              {!events.length && <p>本次采样无事件。</p>}
              <p>这里展示客户端本次采样检测结果；放行、已处置状态与历史推送请查看“告警历史”。</p>
              <p>HTTP 默认警告线：总 {thresholds.http_rps_warning ?? 100} rps、单 IP {thresholds.ip_rps_warning ?? 30} rps，2 倍为危险；4xx ≥ {((thresholds.http_4xx_warning ?? .5) * 100).toFixed(0)}%、5xx ≥ {((thresholds.http_5xx_warning ?? .05) * 100).toFixed(0)}% 警告，2 倍为危险（4xx 最高 100%）。比例检测至少需要 {thresholds.http_min_requests ?? 50} 次请求。</p>
              <p>这是可调的运维起始阈值，不是通用攻击判定标准。配置节点 ALERT_* 环境变量后重启客户端即可调整；旧版客户端需升级才能上报实际阈值及分来源数据。</p>
            </div>
          </details>
        </article>;
      })}
    </div>
    {editing && <HostConfigDialog host={editing} busy={busy} onClose={() => setEditing(null)} onSave={async config => {
      setBusy(true); try { await api.updateHostConfig(editing.host_id, config); onToast('success', '配置已下发，将在节点下次轮询时生效。'); setEditing(null); onRefresh(); } catch (e: any) { onToast('error', e.message || '配置下发失败'); } finally { setBusy(false); }
    }} />}
    {deleting && <HostDeleteDialog host={deleting} busy={busy} onClose={() => setDeleting(null)} onDelete={async mode => {
      setBusy(true); try { await api.deleteHost(deleting.host_id, mode); onToast('success', mode === 'uninstall' ? '已下发远程自卸载，节点确认后将从面板移除。' : '主机记录已删除。'); setDeleting(null); onRefresh(); } catch (e: any) { onToast('error', e.message || '删除失败'); } finally { setBusy(false); }
    }} />}
  </section>;
};

const HostConfigDialog: React.FC<{host: SecurityStatusItem; busy: boolean; onClose: () => void; onSave: (v: Record<string, any>) => void}> = ({ host, busy, onClose, onSave }) => {
  const c = host.host_config || {};
  const [name, setName] = useState(host.host_id);
  const [interval, setIntervalValue] = useState(String(c.report_interval || 300));
  const [runtimes, setRuntimes] = useState(String(c.container_runtimes || 'auto'));
  const [docker, setDocker] = useState(String(c.docker_monitor_mode || 'notice'));
  return <div role="dialog" aria-modal="true" className="fixed inset-0 z-50 grid place-items-center bg-slate-950/80 p-4"><form onSubmit={(e) => { e.preventDefault(); onSave({host_id:name, report_interval:Number(interval), container_runtimes:runtimes, docker_monitor_mode:docker}); }} className="w-full max-w-md rounded-2xl border border-slate-700 bg-slate-900 p-5 shadow-2xl"><h3 className="text-base font-bold">修改主机配置</h3><p className="mt-1 text-xs text-slate-400">改名不会产生新主机：系统以稳定 NODE_ID 合并历史数据。</p><label className="mt-4 block text-xs text-slate-300">显示名称<input value={name} onChange={(e) => setName(e.target.value)} className="mt-1 w-full rounded border border-slate-700 bg-slate-950 px-3 py-2" required /></label><label className="mt-3 block text-xs text-slate-300">上报间隔（秒）<input type="number" min="60" max="3600" value={interval} onChange={(e) => setIntervalValue(e.target.value)} className="mt-1 w-full rounded border border-slate-700 bg-slate-950 px-3 py-2" required /></label><label className="mt-3 block text-xs text-slate-300">运行时<input value={runtimes} onChange={(e) => setRuntimes(e.target.value)} className="mt-1 w-full rounded border border-slate-700 bg-slate-950 px-3 py-2" /></label><label className="mt-3 block text-xs text-slate-300">Docker 模式<select value={docker} onChange={(e) => setDocker(e.target.value)} className="mt-1 w-full rounded border border-slate-700 bg-slate-950 px-3 py-2"><option value="notice">仅提示</option><option value="full">完整采集</option><option value="off">关闭</option></select></label><div className="mt-5 flex justify-end gap-2"><button type="button" onClick={onClose} className="rounded border border-slate-700 px-3 py-2 text-sm">取消</button><button disabled={busy} className="rounded bg-sky-600 px-3 py-2 text-sm font-semibold">{busy ? '下发中…' : '保存并下发'}</button></div></form></div>;
};

const HostDeleteDialog: React.FC<{host: SecurityStatusItem; busy: boolean; onClose: () => void; onDelete: (m: 'uninstall' | 'records_only') => void}> = ({ host, busy, onClose, onDelete }) => {
  const [confirm, setConfirm] = useState(''); const [mode, setMode] = useState<'uninstall' | 'records_only'>('uninstall');
  return <div role="dialog" aria-modal="true" className="fixed inset-0 z-50 grid place-items-center bg-slate-950/80 p-4"><div className="w-full max-w-md rounded-2xl border border-rose-900/70 bg-slate-900 p-5 shadow-2xl"><h3 className="text-base font-bold text-rose-200">删除主机</h3><p className="mt-2 text-xs leading-5 text-slate-300">“远程卸载”会让节点停止并删除 Narwhal Client、配置和自动更新单元；不会修改容器或业务服务。仅删记录会保留节点 Agent，下一次上报会重新出现。</p><label className="mt-4 flex gap-2 text-sm"><input type="radio" checked={mode==='uninstall'} onChange={() => setMode('uninstall')} />远程卸载 Client（推荐）</label><label className="mt-2 flex gap-2 text-sm"><input type="radio" checked={mode==='records_only'} onChange={() => setMode('records_only')} />只删除面板记录</label><label className="mt-4 block text-xs">输入完整主机名确认：<b>{host.host_id}</b><input value={confirm} onChange={(e) => setConfirm(e.target.value)} className="mt-1 w-full rounded border border-slate-700 bg-slate-950 px-3 py-2" /></label><div className="mt-5 flex justify-end gap-2"><button onClick={onClose} className="rounded border border-slate-700 px-3 py-2 text-sm">取消</button><button disabled={busy || confirm !== host.host_id} onClick={() => onDelete(mode)} className="rounded bg-rose-700 px-3 py-2 text-sm font-semibold disabled:opacity-50">{busy ? '处理中…' : '确认删除'}</button></div></div></div>;
};

