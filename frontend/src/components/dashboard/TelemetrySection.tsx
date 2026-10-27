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
const coverageLabel = (value?: string) => value === 'complete' ? '完整'
  : value === 'partial' ? '部分' : value === 'unavailable' ? '不可用' : '未提供';
const thresholdLevel = (value: number, warning: number, critical: number): Level =>
  value >= critical ? 'critical' : value >= warning ? 'warning' : 'normal';
const signalLevel = (t: SecurityStatusItem, pattern: RegExp): Level => {
  if (!t.enabled || t.stale) return 'unknown';
  const matches = (t.sample_alerts || []).filter(a => pattern.test(a.type || ''));
  return matches.some(a => a.severity === 'critical') ? 'critical'
    : matches.some(a => a.severity === 'warning') ? 'warning' : 'normal';
};
const hostAuditLevel = (t: SecurityStatusItem): Level => {
  if (!t.enabled || t.stale || !t.host_audit?.enabled) return 'unknown';
  const sshOnly = t.host_audit.scope === 'agent_container';
  const alerts = (t.sample_alerts || []).filter(a => sshOnly
    ? /^(host_security_finding|host_integrity_change|host_ssh_login)$/.test(a.type || '')
    : /^(host_vulnerability|host_security_finding|host_integrity_change|host_ssh_login)$/.test(a.type || ''));
  if (alerts.some(a => a.severity === 'critical') || Number(t.host_audit.vulnerability_scan?.critical_count || 0) > 0
    || Number(t.host_audit.security_indicator_scan?.critical_count || 0) > 0) return 'critical';
  if (alerts.some(a => a.severity === 'warning')) return 'warning';
  if (sshOnly) {
    if (t.host_audit.snapshot_status === 'partial' || t.host_audit.ssh_log_status === 'unavailable'
      || t.host_audit.security_indicator_scan?.coverage === 'partial') return 'warning';
    if (t.host_audit.snapshot_status === 'unavailable') return 'unknown';
    return 'normal';
  }
  if (t.host_audit.snapshot_status === 'partial' || t.host_audit.ssh_log_status === 'unavailable'
    || t.host_audit.vulnerability_scan?.coverage === 'partial'
    || t.host_audit.security_indicator_scan?.coverage === 'partial') return 'warning';
  if (t.host_audit.snapshot_status === 'unavailable' || t.host_audit.vulnerability_scan?.coverage === 'unavailable'
    || t.host_audit.security_indicator_scan?.coverage === 'unavailable') return 'unknown';
  return 'normal';
};
const auditTime = (value?: number) => value
  ? new Date(value * 1000).toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai', hour12: false })
  : '尚无完整扫描记录';
const durationDays = (seconds?: number) => {
  const value = Math.max(0, Number(seconds || 0));
  return value < 86400 ? '不足 1 天' : `${(value / 86400).toFixed(1)} 天`;
};
const vulnerabilityRepair = (finding: { package?: string; source?: string }, osId: string) => {
  const pkg = finding?.package || '<包名>';
  if (finding?.source === 'lockfile' || finding?.source === 'manifest') {
    return { command: '更新项目依赖声明与锁文件，重新构建并部署应用；不要用系统包管理器修复项目锁文件命中。', impact: '会改变应用依赖版本，需按项目流程重新构建/发布。' };
  }
  if (finding?.source === 'installed') {
    return { command: `先检查虚拟环境中的 ${pkg}，再使用项目采用的 pip/uv/Poetry 工具升级并同步锁文件。`, impact: '可能影响依赖该 Python 包的程序；不要用 sudo pip 覆盖系统 Python。' };
  }
  const id = (osId || '').toLowerCase();
  if (['debian', 'ubuntu', 'linuxmint', 'raspbian'].includes(id)) {
    return { command: `先核对发行版安全公告与已安装版本，再执行：sudo apt update && sudo apt install --only-upgrade <包名>（包名：${pkg}）。`, impact: '更新可能重启相关服务；若是内核/SSH 组件，安排维护窗口并准备控制台访问。' };
  }
  if (id === 'alpine') return { command: `核对 Alpine 安全公告与 apk policy 后执行：sudo apk upgrade <包名>（包名：${pkg}）。`, impact: '可能更新依赖包或重启关联服务；更新前检查变更清单。' };
  if (['rhel', 'rocky', 'almalinux', 'fedora', 'centos'].includes(id)) return { command: `核对发行版公告后执行：sudo dnf upgrade <包名>（包名：${pkg}）。`, impact: '可能更新依赖包或重启服务；内核更新通常需要计划重启。' };
  return { command: '先根据当前发行版的安全公告确认修复版本，再使用该发行版的包管理器更新对应软件包。', impact: '影响取决于软件包；更新可能重启相关服务。' };
};
const Signal: React.FC<{ title: string; level: Level; children: React.ReactNode }> = ({ title, level, children }) =>
  <div className={`w-full min-w-0 rounded-xl border p-3 ${tones[level]}`}>
    <div className="mb-2 flex flex-wrap items-center justify-between gap-2 font-semibold">
      <h4>{title}</h4><span className="text-[11px]">{labels[level]}</span>
    </div><div className="space-y-1.5 wrap-break-word text-xs leading-5 tabular-nums">{children}</div>
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
  return <section className="mb-6 min-w-0 rounded-2xl border border-slate-800 bg-slate-900/60 shadow-xs">
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
        const hostAudit = t.host_audit;
        const vulnerabilityScan = hostAudit?.vulnerability_scan;
        const indicatorScan = hostAudit?.security_indicator_scan;
        const sshOnlyAudit = hostAudit?.scope === 'agent_container';
        const hostAuditEvents = hostAudit?.recent_events || [];
        const hostFindings = hostAudit?.recent_findings || [];
        const securityIndicators = hostAudit?.recent_indicators || [];
        const hostOsId = hostAudit?.os?.id || '';
        const vulnerabilityCount = Number(vulnerabilityScan?.finding_count || 0);
        const vulnerabilityCriticalCount = Number(vulnerabilityScan?.critical_count || 0);
        const indicatorCount = Number(indicatorScan?.finding_count || 0);
        const indicatorCriticalCount = Number(indicatorScan?.critical_count || 0);
        const auditAdvice: string[] = [];
        if (!hostAudit?.enabled) {
          auditAdvice.push(t.stale
            ? '样本已过期：先恢复 Agent 上报，再依据新样本判断。'
            : !t.enabled
              ? '主机安全采集未启用：启用安全采集并等待下一次上报。'
              : '缺少审计数据：升级 Agent、确认主机审计已启用，然后等待下一次上报。');
        } else {
          if (hostAudit.snapshot_status === 'partial' || hostAudit.snapshot_status === 'unavailable') {
            auditAdvice.push('基线采集不完整：检查 Agent 是否以 root 运行及扫描错误，修复后等待新采样。');
          }
          if (hostAudit.ssh_log_status === 'unavailable' || hostAudit.ssh_log_status === 'partial') {
            auditAdvice.push('SSH 日志不可完整读取：检查 journald/auth.log 的存在与 Agent 读取权限。');
          }
          if (!sshOnlyAudit && vulnerabilityCount > 0) {
            auditAdvice.push(`漏洞匹配 ${fmtNumber(vulnerabilityCount, 0)} 项（严重 ${fmtNumber(vulnerabilityCriticalCount, 0)}）：先核对实际安装版本与发行版公告；确认受影响后更新系统包/应用依赖并复扫。Debian/Ubuntu 可用 sudo apt update && sudo apt install --only-upgrade <包名>；Python 依赖应更新项目锁文件后部署。`);
          }
          if (!sshOnlyAudit && indicatorCount > 0) {
            auditAdvice.push(securityIndicators.find(finding => finding.guidance)?.guidance
              || `配置/供应链检查有 ${fmtNumber(indicatorCount, 0)} 项线索：按证据路径与预期配置核对；确认未经授权后先备份再修复，不要仅凭 IOC 名称直接删除服务。`);
          }
          if (hostAuditEvents.length > 0) {
            auditAdvice.push('核对账户、SSH 公钥及登录来源是否对应你的近期操作；不认识的变更先查明来源，再撤销授权或恢复配置。');
          }
          if (!auditAdvice.length) {
            const coverageComplete = hostAudit.snapshot_status === 'ready'
              && hostAudit.ssh_log_status === 'available'
              && (sshOnlyAudit || (vulnerabilityScan?.coverage === 'complete' && indicatorScan?.coverage === 'complete'));
            auditAdvice.push(coverageComplete
              ? '本次完整覆盖未报告待处理项；保持系统与依赖更新，继续按计划复查。'
              : '当前没有明确修复项，但扫描覆盖不完整；先按下方提示补齐采集，不能据此判断无风险。');
          }
        }
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
        const connLvl = thresholdLevel(connPeak, connWarning, connCritical);
        const ipLvl = thresholdLevel(t.today_peak_inbound_ips, ipWarning, ipCritical);
        const peakLevel: Level =
          t.stale || !t.enabled
            ? 'unknown'
            : (connLvl === 'critical' || ipLvl === 'critical')
            ? 'critical'
            : (connLvl === 'warning' || ipLvl === 'warning')
            ? 'warning'
            : 'normal';
        const auditLevel = hostAuditLevel(t);
        const auditLabel = labels[auditLevel];
        const gfw = t.gfw_reachability || {};
        const gfwStatus = gfw.status || 'unassessed';
        const gfwLevel: Level = gfwStatus === 'blocked' ? 'critical'
          : gfwStatus === 'investigating' ? 'warning'
          : gfwStatus === 'normal' || gfwStatus === 'recovered' ? 'normal' : 'unknown';
        const gfwLabels: Record<string, string> = {
          blocked: 'GFW Blocked · 国内探测异常', investigating: gfw.last_known_state === 'blocked' ? '状态待复核' : '疑似受阻 · 连续确认中',
          normal: '国内外可达', recovered: '已恢复', stale: '数据过期', unassessed: '待评估',
        };
        const gfwLastState = gfw.last_known_state === 'blocked' ? 'GFW Blocked' : gfw.last_known_state === 'recovered' ? '已恢复' : gfw.last_known_state === 'normal' ? '国内外可达' : '未评估';
        const gfwDuration = gfwStatus === 'blocked' ? `持续 ${durationDays(gfw.duration_seconds)}`
          : gfwStatus === 'recovered' ? `恢复 ${durationDays(gfw.duration_seconds)}`
          : gfwStatus === 'normal' ? `正常 ${durationDays(gfw.duration_seconds)}`
          : gfwStatus === 'investigating' && gfw.last_known_state === 'blocked' ? `最近确认阻断：${auditTime(gfw.last_sample_at)} · 当前证据待复核`
          : gfwStatus === 'investigating' && gfw.pending_block_rounds ? `失败迹象 ${gfw.pending_block_rounds}/3 轮`
          : gfwStatus === 'investigating' ? '连通性证据待复核'
          : gfwStatus === 'stale' ? `上次状态：${gfwLastState}` : '需要配置探测点与公网端口';
        const gfwEvidence = gfw.evidence || [];
        const comparedEndpoint = gfwEvidence.find(item => item.status === 'blocked') || gfwEvidence.find(item => item.status === 'normal') || gfwEvidence[0];

        return <article key={t.host_id} className="min-w-0 rounded-xl border border-slate-700 bg-slate-900/60 p-3 sm:p-4">
          <div className="mb-3 flex flex-wrap items-start justify-between gap-3">
            <div className="min-w-0 flex-1 basis-56">
              <h3 className="break-all text-sm font-semibold text-slate-100">{t.host_id}</h3>
              <p className="mt-1 wrap-break-word text-xs text-slate-300">采样：{t.timestamp_iso_utc8 || '—'} · 窗口 {t.interval_seconds || '—'} 秒
                {t.stale ? ' · 数据已过期' : !t.enabled ? ' · 安全采集未启用' : ''}</p>
            </div>
            <div className="flex flex-wrap gap-2">
              <button type="button" onClick={() => setEditing(t)} className="rounded-lg border border-sky-700 bg-sky-950/60 px-3 py-1.5 text-xs text-sky-300 hover:bg-sky-900/60 transition-colors focus:outline-hidden focus:ring-2 focus:ring-sky-400">配置</button>
              <button type="button" onClick={() => setDeleting(t)} className="rounded-lg border border-red-800 bg-red-950/40 px-3 py-1.5 text-xs text-red-300 hover:bg-red-900/60 transition-colors focus:outline-hidden focus:ring-2 focus:ring-red-400">删除</button>
            </div>
          </div>
          <div className="mb-3 flex flex-wrap gap-2 text-[11px]">
            <span className={`rounded-full border px-2 py-1 ${tones[peakLevel]}`}>网络峰值：{labels[peakLevel]}</span>
            <span className={`rounded-full border px-2 py-1 ${tones[httpLevel]}`}>CC / HTTP：{labels[httpLevel]}</span>
            <span className={`rounded-full border px-2 py-1 ${tones[auditLevel]}`}>主机审计：{auditLabel}</span>
            <span className="rounded-full border border-slate-700 px-2 py-1 text-slate-300">最高连接 {fmtNumber(connPeak, 0)} · 事件 {events.length}</span>
          </div>
          <section className={`mb-3 min-w-0 rounded-xl border p-3 ${tones[gfwLevel]}`} aria-label="国内连通性与 GFW 状态">
            <div className="flex min-w-0 flex-wrap items-start justify-between gap-2">
              <div className="min-w-0">
                <h4 className="font-semibold">国内连通性 <span className="ml-1 text-xs">{gfwLabels[gfwStatus] || '待评估'}</span></h4>
                <p className="mt-1 text-xs">{gfwDuration}{gfwStatus === 'blocked' && gfw.blocked_count ? ` · 历史阻断 ${gfw.blocked_count} 次` : ''}</p>
              </div>
              {gfw.last_sample_at ? <span className="text-[11px] text-slate-400">采样 {auditTime(gfw.last_sample_at)}</span> : null}
            </div>
            {comparedEndpoint ? <div className="mt-2 flex min-w-0 flex-wrap items-center gap-x-3 gap-y-1 rounded-lg border border-slate-700/70 bg-slate-950/30 px-2 py-1.5 text-xs">
              <span className="font-mono text-slate-200">{comparedEndpoint.ip}:{comparedEndpoint.port}</span>
              {comparedEndpoint.interface && <span className="text-slate-400">网卡 {comparedEndpoint.interface}</span>}
              <span>国内成功 {comparedEndpoint.mainland?.success || 0}/{comparedEndpoint.mainland?.total || 0}</span>
              <span>海外成功 {comparedEndpoint.overseas?.success || 0}/{comparedEndpoint.overseas?.total || 0}</span>
            </div> : null}
            {gfwStatus === 'blocked' && Number(gfw.last_normal_duration_seconds || 0) > 0 && <p className="mt-2 text-xs">上次恢复后正常运行 {durationDays(gfw.last_normal_duration_seconds)}，之后再次出现国内不可达。</p>}
            {(gfwStatus === 'stale' || gfwStatus === 'investigating') && <p className="mt-2 text-xs">{gfw.reason || (gfwStatus === 'stale' ? '探测数据已过期；保留上次状态供查看，不把离线或缺少样本算作恢复。' : '本轮证据不足；不确认阻断或恢复，也不把未知样本计入持续时间。')}</p>}
            {gfwStatus === 'unassessed' && <p className="mt-2 text-xs">{gfw.reason || '需要至少 2 个国内、1 个海外探测点，并发现明确的公网 TCP 端口映射。'}</p>}
            <p className="mt-2 text-[11px] leading-4 opacity-80">判断依据是同一公网 TCP 端点的跨区域连通性；这是网络信号，不足以单独证明具体封锁来源。</p>
            {gfw.history && gfw.history.length > 0 && <details className="mt-2 rounded-lg border border-slate-700/70 bg-slate-950/20 px-2 py-1.5">
              <summary className="cursor-pointer text-xs font-medium">阻断 / 恢复历史（{gfw.history.length} 条）</summary>
              <div className="mt-2 grid min-w-0 gap-2 sm:grid-cols-2 xl:grid-cols-3">
                {gfw.history.slice(0, 6).map((event, index) => <div key={`${event.event_type}-${event.at}-${index}`} className="min-w-0 rounded-md border border-slate-700/70 p-2 text-[11px]">
                  <p className="font-semibold">{event.event_type === 'blocked' ? '开始阻断' : '确认恢复'} · {auditTime(event.at)}</p>
                  {event.event_type === 'recovered' && <p>本次持续 {durationDays(event.duration_seconds)}</p>}
                  {event.event_type === 'blocked' && Number(event.normal_duration_seconds || 0) > 0 && <p>此前正常 {durationDays(event.normal_duration_seconds)}</p>}
                </div>)}
              </div>
            </details>}
          </section>
          <details className="rounded-lg border border-slate-800 bg-slate-950/30 p-3">
            <summary className="cursor-pointer text-xs font-semibold text-slate-200 focus:outline-hidden focus:ring-2 focus:ring-sky-400">展开网络信号、主机安全证据与修复建议</summary>
            <div className="mt-3 space-y-3">
          <div className="grid min-w-0 gap-3 grid-cols-[repeat(auto-fit,minmax(min(100%,240px),1fr))]">
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
            <Signal title="今日单容器峰值" level={peakLevel}>
              <p><span className={peakTone(connPeak, connWarning, connCritical)}>最高连接 {fmtNumber(connPeak, 0)}</span> · <span className="text-slate-300">全容器合计峰值 {fmtNumber(t.today_peak_conn_count, 0)}</span></p>
              <p><span className={peakTone(t.today_peak_inbound_ips, ipWarning, ipCritical)}>最高入站 IP {fmtNumber(t.today_peak_inbound_ips, 0)}</span> · <span className="text-slate-300">最高出站 IP {fmtNumber(t.today_peak_outbound_ips, 0)}</span></p>
              <p className="text-slate-300">连接 ≥ {connWarning} / {connCritical}、入站 IP ≥ {ipWarning} / {ipCritical}：警告 / 危险。</p>
              <p className="text-slate-300">UTC+8 当日采样最大值；各项可能来自不同容器。推送使用触发当时的单容器值，峰值不代表当前仍异常。</p>
            </Signal>
          </div>
          <div className="mt-3 grid min-w-0 gap-3 grid-cols-[repeat(auto-fit,minmax(min(100%,240px),1fr))]">
          <div className="col-span-full min-w-0">
            <Signal title={sshOnlyAudit ? '小鸡 SSH 安全检查' : '母鸡完整性、漏洞与威胁指标'} level={auditLevel}>
              {!hostAudit?.enabled ? <>
                <p>{auditAdvice[0]}</p>
                <p className="text-slate-300">修复后等待 Agent 下一次上报，再检查本卡状态。</p>
              </> : <>
                <p className="text-slate-300">{sshOnlyAudit ? '小鸡 SSH 登录与配置专项检查。' : '母鸡账户/SSH 基线、系统与 Python 漏洞、供应链及配置检查。'}</p>
                <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
                  <div className="min-w-0 rounded-lg border border-slate-700/70 bg-slate-950/30 p-2">
                    <p className="text-[11px] text-slate-300">主机基线</p>
                    <p className="break-words font-semibold">{hostAudit.baseline_pending ? '建立中' : hostAudit.snapshot_status === 'ready' ? `正常 · ${fmtNumber(hostAudit.user_accounts || 0, 0)} 账户 / ${fmtNumber(hostAudit.ssh_key_count || 0, 0)} SSH Key` : '采集不完整'}</p>
                  </div>
                  {!sshOnlyAudit && <div className="min-w-0 rounded-lg border border-slate-700/70 bg-slate-950/30 p-2">
                    <p className="text-[11px] text-slate-300">系统 / Python 漏洞</p>
                    <p className="break-words font-semibold">{coverageLabel(vulnerabilityScan?.coverage)} · {fmtNumber(vulnerabilityCount, 0)} 项 / 严重 {fmtNumber(vulnerabilityCriticalCount, 0)}</p>
                  </div>}
                  <div className="min-w-0 rounded-lg border border-slate-700/70 bg-slate-950/30 p-2">
                    <p className="text-[11px] text-slate-300">{sshOnlyAudit ? 'SSH 配置复核' : '供应链 / 配置线索'}</p>
                    <p className="break-words font-semibold">{coverageLabel(indicatorScan?.coverage)} · {fmtNumber(indicatorCount, 0)} 项 / 严重 {fmtNumber(indicatorCriticalCount, 0)}</p>
                  </div>
                  <div className="min-w-0 rounded-lg border border-slate-700/70 bg-slate-950/30 p-2">
                    <p className="text-[11px] text-slate-300">SSH 登录日志</p>
                    <p className="break-words font-semibold">{hostAudit.ssh_log_status === 'available' ? `已接入 · 新来源 ${fmtNumber(hostAudit.new_ssh_login_events || 0, 0)}` : hostAudit.ssh_log_status === 'partial' ? '部分可读' : '不可用'}</p>
                  </div>
                </div>
                <div className="rounded-lg border border-sky-700/50 bg-sky-950/20 p-2">
                  <p className="font-semibold text-sky-200">怎么处理</p>
                  <ul className="list-disc space-y-1 pl-4 text-slate-200">
                    {auditAdvice.slice(0, 3).map((advice, index) => <li key={index} className="break-words">{advice}</li>)}
                  </ul>
                </div>
                <details className="rounded-lg border border-slate-700/70 p-2">
                  <summary className="cursor-pointer font-semibold">查看证据、扫描时间与修复细节</summary>
                  <div className="mt-2 space-y-2">
                    <p className="text-slate-300">漏洞最近完整扫描：{auditTime(vulnerabilityScan?.checked_at)} · 已检查 {fmtNumber(vulnerabilityScan?.packages_checked || 0, 0)} 个软件包。OSV 查询发送软件包名称与版本，不包含主机名、IP、账户或配置内容。</p>
                    {hostAuditEvents.length > 0 && <div className="rounded-lg border border-slate-700/70 p-2">
                      <p className="font-semibold">本次 SSH / 主机变化</p>
                      {hostAuditEvents.slice(0, 4).map((event, index) => <p key={(event.type || 'event') + '-' + index} className="break-all">{event.title || event.type}：{event.message}</p>)}
                    </div>}
                    {!sshOnlyAudit && hostFindings.length > 0 && <div className="rounded-lg border border-slate-700/70 p-2">
                      <p className="font-semibold">漏洞匹配（显示前 {Math.min(hostFindings.length, 12)} 条，共 {fmtNumber(vulnerabilityCount, 0)} 项）</p>
                      <div className="mt-2 space-y-2">
                        {hostFindings.slice(0, 12).map((finding, index) => { const repair = vulnerabilityRepair(finding, hostOsId); return <div key={(finding.ecosystem || '') + '-' + (finding.package || '') + '-' + (finding.version || '') + '-' + (finding.id || index)} className="border-t border-slate-700/70 pt-2">
                          <p className="break-all font-semibold">{finding.severity === 'critical' ? '严重' : '待复核'} · {finding.cve || finding.id || 'OSV 公告'} · {finding.package}@{finding.version} · {finding.source === 'system' ? '系统软件' : finding.source === 'installed' ? '已安装 Python 包' : finding.source === 'manifest' ? 'Maven 清单（非锁定）' : '依赖锁文件'}</p>
                          {finding.summary && <p className="text-slate-300">{finding.summary}</p>}
                          <p className="mt-1 break-words text-sky-200">建议步骤：{repair.command}</p>
                          <p className="text-slate-400">影响：{repair.impact}</p>
                        </div>; })}
                      </div>
                      <p className="mt-2 text-slate-300">先核对实际安装版本及发行版公告；锁文件命中不代表已安装或运行，发行版也可能回移补丁。确认受影响后更新补丁，再重新扫描。</p>
                    </div>}
                    {!sshOnlyAudit && securityIndicators.length > 0 && <div className="rounded-lg border border-slate-700/70 p-2">
                      <p className="font-semibold">供应链 / 配置复核（显示前 {Math.min(securityIndicators.length, 12)} 类）</p>
                      <div className="mt-2 space-y-2">
                        {securityIndicators.slice(0, 12).map((finding, index) => <div key={finding.id || finding.rule || index} className="border-t border-slate-700/70 pt-2">
                          <p className={`break-all font-semibold ${finding.severity === 'critical' ? 'text-red-300' : finding.severity === 'warning' ? 'text-amber-300' : ''}`}>{finding.severity === 'critical' ? '严重' : finding.severity === 'warning' ? '待复核' : '提示'} · {finding.component || '主机安全检查'} · {finding.title} {Number(finding.instance_count || 0) > 1 ? `（${finding.instance_count} 处）` : ''}</p>
                          {(finding.evidence || []).slice(0, 3).map((evidence, i) => <p key={i} className="break-all text-slate-300">证据位置：{evidence}</p>)}
                          {finding.guidance && <p className="text-slate-200">处理建议：{finding.guidance}</p>}
                          {finding.reference && <a className="text-sky-300 underline" href={finding.reference} target="_blank" rel="noreferrer">查看上游公告</a>}
                        </div>)}
                      </div>
                      <p className="mt-2 text-slate-300">IOC 与配置文本命中是复核线索，不等同已确认入侵；先核实证据路径和预期配置，确认未经授权后备份并修复。</p>
                    </div>}
                    {vulnerabilityScan?.error && <p className="text-amber-200">漏洞扫描提示：{vulnerabilityScan.error}</p>}
                    {indicatorScan?.error && <p className="text-amber-200">补充扫描提示：{indicatorScan.error}</p>}
                    <p className="text-slate-300">系统：{hostOsId || '发行版未知'} {hostAudit.os?.version_id || ''} · 漏洞扫描上次尝试 {auditTime(vulnerabilityScan?.last_attempt_at)}。OSV 匹配仅是待复核项；修复后在运维中心 → 采集健康点击“请求只读复扫”。复扫不会自动安装更新。</p>
                    <p className="text-slate-300">SSH 日志：{hostAudit.ssh_log_status === 'available' ? `可读 · 本周期 ${fmtNumber(hostAudit.ssh_events_last_period || 0, 0)} 次成功登录` : '未完整接入，无法据此排除未知登录来源。'} 完整性问题请先确认 Agent 权限和日志可读性，再等待新一轮采样。</p>
                  </div>
                </details>
              </>}
            </Signal>
          </div>
          </div>
          <details className="mt-3 rounded-lg border border-slate-700 p-3 text-xs text-slate-300">
            <summary className="cursor-pointer font-semibold text-slate-100">查看本次采样事件（{events.length} 项，含普通提示）与阈值说明</summary>
            <div className="mt-3 space-y-2">
              {events.map((event, i) => <div key={i} className={`min-w-0 rounded-lg border p-3 wrap-break-word ${tones[event.severity === 'critical' ? 'critical' : event.severity === 'warning' ? 'warning' : 'unknown']}`}>
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

const HostConfigDialog: React.FC<{
  host: SecurityStatusItem;
  busy: boolean;
  onClose: () => void;
  onSave: (v: Record<string, any>) => void;
}> = ({ host, busy, onClose, onSave }) => {
  const c = host.host_config || {};
  const [name, setName] = useState(host.host_id);
  const [interval, setIntervalValue] = useState(String(c.report_interval || 300));
  const [runtimes, setRuntimes] = useState(String(c.container_runtimes || 'auto'));
  const [docker, setDocker] = useState(String(c.docker_monitor_mode || 'notice'));

  React.useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && !busy) {
        onClose();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [busy, onClose]);

  return (
    <div
      role="presentation"
      className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/80 p-4 backdrop-blur-xs"
      onClick={(e) => {
        if (e.target === e.currentTarget && !busy) onClose();
      }}
    >
      <div
        role="dialog"
        aria-modal="true"
        aria-labelledby="host-config-dialog-title"
        className="w-full max-w-md rounded-2xl border border-slate-700 bg-slate-900 p-5 shadow-2xl"
      >
        <form
          onSubmit={(e) => {
            e.preventDefault();
            onSave({
              host_id: name,
              report_interval: Number(interval),
              container_runtimes: runtimes,
              docker_monitor_mode: docker,
            });
          }}
        >
          <h3 id="host-config-dialog-title" className="text-base font-bold text-slate-100">
            修改主机配置
          </h3>
          <p className="mt-1 text-xs text-slate-400 leading-relaxed">
            改名不会产生新主机：系统以稳定 NODE_ID 合并历史数据。
          </p>

          <label className="mt-4 block text-xs font-medium text-slate-300">
            显示名称
            <input
              value={name}
              onChange={(e) => setName(e.target.value)}
              className="mt-1.5 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-slate-100 focus:outline-hidden focus:ring-2 focus:ring-sky-500 font-mono text-xs"
              required
            />
          </label>

          <label className="mt-3 block text-xs font-medium text-slate-300">
            上报间隔（秒）
            <input
              type="number"
              min="60"
              max="3600"
              value={interval}
              onChange={(e) => setIntervalValue(e.target.value)}
              className="mt-1.5 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-slate-100 focus:outline-hidden focus:ring-2 focus:ring-sky-500 font-mono text-xs"
              required
            />
          </label>

          <label className="mt-3 block text-xs font-medium text-slate-300">
            运行时 (auto / incus / podman / docker)
            <input
              value={runtimes}
              onChange={(e) => setRuntimes(e.target.value)}
              className="mt-1.5 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-slate-100 focus:outline-hidden focus:ring-2 focus:ring-sky-500 font-mono text-xs"
            />
          </label>

          <label className="mt-3 block text-xs font-medium text-slate-300">
            Docker 模式
            <select
              value={docker}
              onChange={(e) => setDocker(e.target.value)}
              className="mt-1.5 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-slate-100 focus:outline-hidden focus:ring-2 focus:ring-sky-500 text-xs"
            >
              <option value="notice">仅提示 (notice)</option>
              <option value="full">完整采集 (full)</option>
              <option value="off">关闭 (off)</option>
            </select>
          </label>

          <div className="mt-5 flex justify-end gap-2">
            <button
              type="button"
              onClick={onClose}
              disabled={busy}
              className="rounded-lg border border-slate-700 bg-slate-800 px-3.5 py-2 text-xs font-medium text-slate-300 hover:bg-slate-750 transition-colors focus:outline-hidden focus:ring-2 focus:ring-sky-400 disabled:opacity-50"
            >
              取消
            </button>
            <button
              type="submit"
              disabled={busy}
              className="rounded-lg bg-sky-600 px-4 py-2 text-xs font-semibold text-white hover:bg-sky-500 transition-colors focus:outline-hidden focus:ring-2 focus:ring-sky-400 disabled:opacity-50 shadow-xs"
            >
              {busy ? '下发中…' : '保存并下发'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};

const HostDeleteDialog: React.FC<{
  host: SecurityStatusItem;
  busy: boolean;
  onClose: () => void;
  onDelete: (m: 'uninstall' | 'records_only') => void;
}> = ({ host, busy, onClose, onDelete }) => {
  const [confirm, setConfirm] = useState('');
  const [mode, setMode] = useState<'uninstall' | 'records_only'>('uninstall');

  React.useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && !busy) {
        onClose();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [busy, onClose]);

  return (
    <div
      role="presentation"
      className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/80 p-4 backdrop-blur-xs"
      onClick={(e) => {
        if (e.target === e.currentTarget && !busy) onClose();
      }}
    >
      <div
        role="dialog"
        aria-modal="true"
        aria-labelledby="host-delete-dialog-title"
        className="w-full max-w-md rounded-2xl border border-rose-900/70 bg-slate-900 p-5 shadow-2xl"
      >
        <h3 id="host-delete-dialog-title" className="text-base font-bold text-rose-200">
          删除主机
        </h3>
        <p className="mt-2 text-xs leading-5 text-slate-300">
          “远程卸载”会让节点停止并删除 Narwhal Client、配置和自动更新单元；不会修改容器或业务服务。仅删记录会保留节点 Agent，下一次上报会重新出现。
        </p>

        <div className="mt-4 space-y-2">
          <label className="flex items-center gap-2 text-xs text-slate-200 cursor-pointer">
            <input
              type="radio"
              name="delete_mode"
              checked={mode === 'uninstall'}
              onChange={() => setMode('uninstall')}
              className="accent-rose-500"
            />
            <span>远程卸载 Client（推荐）</span>
          </label>
          <label className="flex items-center gap-2 text-xs text-slate-200 cursor-pointer">
            <input
              type="radio"
              name="delete_mode"
              checked={mode === 'records_only'}
              onChange={() => setMode('records_only')}
              className="accent-rose-500"
            />
            <span>只删除面板记录</span>
          </label>
        </div>

        <label className="mt-4 block text-xs text-slate-300">
          输入完整主机名确认：<b className="text-rose-300 font-mono select-all">{host.host_id}</b>
          <input
            value={confirm}
            onChange={(e) => setConfirm(e.target.value)}
            placeholder={`请输入 ${host.host_id}`}
            className="mt-1.5 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-slate-100 font-mono text-xs focus:outline-hidden focus:ring-2 focus:ring-rose-500"
          />
        </label>

        <div className="mt-5 flex justify-end gap-2">
          <button
            type="button"
            onClick={onClose}
            disabled={busy}
            className="rounded-lg border border-slate-700 bg-slate-800 px-3.5 py-2 text-xs font-medium text-slate-300 hover:bg-slate-750 transition-colors focus:outline-hidden focus:ring-2 focus:ring-sky-400 disabled:opacity-50"
          >
            取消
          </button>
          <button
            type="button"
            disabled={busy || confirm !== host.host_id}
            onClick={() => onDelete(mode)}
            className="rounded-lg bg-rose-700 px-4 py-2 text-xs font-semibold text-white hover:bg-rose-600 transition-colors focus:outline-hidden focus:ring-2 focus:ring-rose-400 disabled:opacity-50 shadow-xs"
          >
            {busy ? '处理中…' : '确认删除'}
          </button>
        </div>
      </div>
    </div>
  );
};

