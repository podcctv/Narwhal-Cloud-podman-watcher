import React, { useEffect, useState } from 'react';
import {
  X,
  Box,
  Activity,
  Cpu,
  HardDrive,
  Network,
  Shield,
  AlertTriangle,
  Ban,
  Check,
  CheckCircle2,
  ArrowUpDown,
  Radio,
  ArrowDownLeft,
  ArrowUpRight,
  Gauge,
  Unlock,
  Mail,
  Save,
} from 'lucide-react';
import { ContainerItem, ContainerIdentity, HistoryPoint, DiagnosticData, SecurityAlert } from '../../api/types';
import { api, fmtBytes, fmtNumber, fmtMbps } from '../../api/client';
import { StatusBadge } from '../common/StatusBadge';
import { ResourceChart } from './ResourceChart';
import { NetworkChart } from './NetworkChart';
import { DiagnosticPanel } from './DiagnosticPanel';
import { ConfirmDialog } from '../common/ConfirmDialog';
import { AdmissionStatus } from './AdmissionStatus';
import { ConnectionEvidenceTimeline } from './ConnectionEvidenceTimeline';

interface ContainerDrawerProps {
  identity: ContainerIdentity | null;
  activeAlerts?: SecurityAlert[];
  onClose: () => void;
  serverVersion: string;
  onToast: (type: 'success' | 'error' | 'info', message: string) => void;
  onRefresh: () => void;
}

const RESOURCE_GUARD_STATES: Record<string, string> = {
  normal: '正常',
  watching: '持续采样中',
  waiting_for_host_pressure: '等待母鸡压力佐证',
  limited: '限额已读回确认',
  active: '限额已读回确认',
  limit_failed: '限额未确认',
  limited_unverified: '限额待读回',
  limit_unverified: '限额待读回',
  restore_failed: '恢复失败',
  restored: '原限额已恢复',
  manual_override: '检测到人工修改',
  manual_reset: '人工恢复原限额',
  state_unavailable: '保护状态不可读',
  sampling_unavailable: '采样不可用',
  disabled: '未启用',
  applying: '正在应用并核验',
  escalating: '正在升级并核验',
  restoring: '正在恢复并核验',
  limit_readback_unavailable: '无法读取限额',
  waiting_for_other_limit: '等待其他容器保护结束',
  retry_wait: '等待自动重试',
  orphaned_cgroup: '旧容器限额归属待核实',
  unavailable: '数据不可用',
  warming: '正在建立采样基线',
};

const guardTone = (state?: string) => {
  if (['limited', 'active'].includes(state || '')) return 'border-sky-500/30 bg-sky-950/30 text-sky-200';
  if (['limit_failed', 'limited_unverified', 'limit_unverified', 'restore_failed', 'state_unavailable', 'sampling_unavailable', 'limit_readback_unavailable', 'orphaned_cgroup', 'unavailable'].includes(state || '')) {
    return 'border-rose-500/30 bg-rose-950/20 text-rose-200';
  }
  if (['watching', 'waiting_for_host_pressure', 'applying', 'escalating', 'restoring', 'waiting_for_other_limit', 'retry_wait', 'warming'].includes(state || '')) {
    return 'border-amber-500/30 bg-amber-950/20 text-amber-200';
  }
  if (['normal', 'restored', 'manual_reset'].includes(state || '')) return 'border-emerald-500/25 bg-emerald-950/15 text-emerald-200';
  return 'border-slate-700 bg-slate-900/60 text-slate-300';
};

const guardStateLabel = (state?: string) => RESOURCE_GUARD_STATES[state || ''] || '状态待核实';

const formatIoRate = (value?: string | number) => {
  if (value === 'max' || value === undefined || value === null || value === '') return '不限';
  const parsed = Number(value);
  return Number.isFinite(parsed) ? `${fmtBytes(parsed)}/秒` : '未知';
};

const formatIoLimit = (value?: Record<string, string>) => {
  if (!value) return '暂无读回数据';
  return `读 ${formatIoRate(value.rbps)} · 写 ${formatIoRate(value.wbps)} · 读 IOPS ${value.riops || '不限'} · 写 IOPS ${value.wiops || '不限'}`;
};

const formatMinutes = (seconds?: number) => {
  if (!Number.isFinite(Number(seconds)) || Number(seconds) <= 0) return '0 分钟';
  const minutes = Math.max(1, Math.round(Number(seconds) / 60));
  return `${minutes} 分钟`;
};

export const ContainerDrawer: React.FC<ContainerDrawerProps> = ({
  identity,
  activeAlerts = [],
  onClose,
  serverVersion,
  onToast,
  onRefresh,
}) => {
  const [container, setContainer] = useState<ContainerItem | null>(null);
  const [history, setHistory] = useState<HistoryPoint[]>([]);
  const [diagnostic, setDiagnostic] = useState<DiagnosticData | null>(null);
  const [isDrawerActionLoading, setIsDrawerActionLoading] = useState(false);
  const [pendingDecision, setPendingDecision] = useState<'deny' | 'allow_silent' | 'resolve' | 'release_udp_throttle' | null>(null);
  const [userEmail, setUserEmail] = useState('');
  const [userNote, setUserNote] = useState('');
  const [isSavingUserNote, setIsSavingUserNote] = useState(false);

  useEffect(() => {
    setUserEmail(container?.user_email || '');
    setUserNote(container?.user_note || '');
  }, [container?.container_id, container?.user_email, container?.user_note]);

  const saveUserNote = async () => {
    if (!identity || !container?.container_id) return;
    setIsSavingUserNote(true);
    try {
      const preserveUpstreamEmail = container.user_email_source === 'upstream'
        && userEmail.trim() === (container.user_email || '');
      const saved = await api.saveContainerUserNote({ ...identity, container_id: container.container_id }, {
        // Keep an unchanged API-sourced email automatic; saving a note should
        // not silently convert the upstream value into a manual override.
        user_email: preserveUpstreamEmail ? '' : userEmail.trim(),
        user_note: userNote.trim(),
      });
      let refreshedUserNote = null;
      try {
        refreshedUserNote = await api.getContainerUserNote({ ...identity, container_id: container.container_id });
      } catch {
        // Saving succeeded; a failed metadata refresh must not turn it into an error.
      }
      const fallbackSource = preserveUpstreamEmail ? 'upstream' : userEmail.trim() ? 'manual' : '';
      setContainer((current) => current ? {
        ...current,
        ...saved,
        ...(refreshedUserNote || {}),
        user_email_source: refreshedUserNote?.user_email_source ?? fallbackSource,
      } : current);
      onToast('success', saved.user_email || saved.user_note ? '用户邮箱与备注已保存，可通过全局搜索定位容器' : '用户邮箱与备注已清除');
      onRefresh();
    } catch (err: any) {
      onToast('error', `保存用户备注失败：${err.message || err}`);
    } finally {
      setIsSavingUserNote(false);
    }
  };

  const handleDrawerDisposition = async (
    decision: 'deny' | 'allow_silent' | 'resolve' | 'release_udp_throttle'
  ) => {
    if (!identity) return;
    setIsDrawerActionLoading(true);
    try {
      const currentAlert = activeActionableAlert;
      const res = await api.dispositionContainer(
        { ...identity, alert_id: currentAlert?.id ?? identity.alert_id },
        decision,
      );
      onToast(
        'success',
        decision === 'deny'
          ? (res.queued ? '处置指令已下发节点执行' : '安全处置已更新')
          : decision === 'resolve'
          ? '风险已标记为已解决'
          : decision === 'release_udp_throttle'
          ? (res.queued ? 'UDP 限速解除指令已下发节点执行' : '已解除 UDP 限速')
          : '已成功添加放行策略'
      );
      const latestData = await api.getLatest(true);
      const found = latestData.items.find(
        (c) =>
          c.host_id === identity.host_id &&
          c.runtime === identity.runtime &&
          (c.project || '') === (identity.project || '') &&
          c.container_name === identity.container_name &&
          (!identity.container_id || c.container_id === identity.container_id)
      );
      setContainer(found || null);
    } catch (err: any) {
      onToast('error', `操作失败：${err.message || err}`);
    } finally {
      setIsDrawerActionLoading(false);
    }
  };

  useEffect(() => {
    if (!identity) {
      setContainer(null);
      setHistory([]);
      setDiagnostic(null);
      return;
    }

    let isMounted = true;
    setContainer(null);

    const loadData = async () => {
      try {
        const [latestData, histData, diagData] = await Promise.all([
          api.getLatest(true),
          api.getContainerHistory(identity, 1440),
          api.getContainerDiagnostic(identity),
        ]);

        if (!isMounted) return;

        const found = latestData.items.find(
          (c) =>
            c.host_id === identity.host_id &&
            c.runtime === identity.runtime &&
            (c.project || '') === (identity.project || '') &&
            c.container_name === identity.container_name &&
            (!identity.container_id || c.container_id === identity.container_id)
        );

        setContainer(found || null);
        setHistory(histData.items || []);
        setDiagnostic(diagData);
      } catch (err: any) {
        if (isMounted) {
          onToast('error', `加载容器指标失败：${err.message || err}`);
        }
      }
    };

    loadData();

    // Refresh every 15s when drawer is open
    const interval = setInterval(loadData, 15000);
    return () => {
      isMounted = false;
      clearInterval(interval);
    };
  }, [identity]);

  if (!identity) return null;

  const sec = container?.security || {};
  const inIps = sec.inbound_unique_ips || 0;
  const inThresh = sec.inbound_unique_ip_threshold || 10;
  const inIpAlert = inIps > inThresh;

  const agentVersion = container?.agent_version || 'unknown';
  const isVersionMatch =
    agentVersion !== 'unknown' &&
    agentVersion !== 'dev' &&
    agentVersion === serverVersion;

  const socks = sec.socks_proxy;
  const pairing = sec.panel_pairing;
  const cpuGuard = sec.cpu_guard;
  const ioGuard = sec.io_guard;
  const activeActionableAlert = activeAlerts.find((alert) => {
    if (
      alert.host_id !== identity.host_id ||
      alert.runtime !== identity.runtime ||
      (alert.project || '') !== (identity.project || '') ||
      alert.container_name !== identity.container_name ||
      alert.status !== 'active'
    ) return false;
    const details = alert.details || {};
    if (alert.type === 'socks_weak_auth') {
      return ['no_auth', 'weak_password'].includes(details.socks_auth_mode) && (details.socks_processes || []).length > 0;
    }
    if (alert.type === 'unauthorized_panel_pairing') {
      return (details.process_patterns || []).length > 0 || (details.config_files || []).length > 0;
    }
    if (alert.type === 'malicious_process') {
      return (details.malicious_processes || []).some((item: any) => item?.process === 'xmrig');
    }
    return false;
  });
  const confirmationCopy = pendingDecision === 'release_udp_throttle'
    ? { title: '确认立即解除 UDP 限速？', description: `将立即移除 ${identity.container_name} 的 Linux tc 限速规则并恢复全速。`, confirmLabel: '解除限速', tone: 'primary' as const }
    : pendingDecision === 'deny'
    ? { title: '确认定向处置？', description: `仅处理 ${identity.container_name} 中已识别的违规进程、服务或配置，不会停止容器。`, confirmLabel: '确认处置', tone: 'danger' as const }
    : pendingDecision === 'allow_silent'
    ? { title: '确认放行策略？', description: '当前风险会被持续放行且不再提醒；可在告警历史中撤销。', confirmLabel: '确认放行', tone: 'primary' as const }
    : { title: '确认标记为已解决？', description: '活动告警将转入历史记录；再次检测到风险时仍会重新告警。', confirmLabel: '标记已解决', tone: 'primary' as const };

  return (
    <div className="fixed inset-0 z-50 overflow-hidden" role="dialog" aria-modal="true" aria-labelledby="container-drawer-title">
      {/* Backdrop */}
      <div
        onClick={onClose}
        className="absolute inset-0 bg-slate-950/70 backdrop-blur-xs transition-opacity animate-in fade-in duration-200"
      />

      {/* Slide-over Drawer Panel */}
      <div className="absolute inset-y-0 right-0 flex max-w-full pl-0 sm:pl-10">
        <div className="min-w-0 w-screen max-w-2xl transform bg-slate-900 border-l border-slate-800 shadow-2xl transition-transform animate-in slide-in-from-right duration-250 flex flex-col">
          {/* Drawer Header */}
          <div className="flex items-center justify-between border-b border-slate-800 bg-slate-950/80 px-6 py-4">
            <div className="flex items-center gap-3 min-w-0">
              <div className="rounded-xl bg-sky-950/80 p-2.5 text-sky-400 border border-sky-500/30 shrink-0">
                <Box className="h-5 w-5" />
              </div>
              <div className="min-w-0">
                <div className="flex items-center gap-2 flex-wrap">
                  <h2 id="container-drawer-title" className="text-base font-bold text-slate-100 truncate">
                    {identity.container_name}
                  </h2>
                  <StatusBadge
                    status={container?.alerts?.stale ? 'stale' : 'healthy'}
                    size="sm"
                    pulse={!container?.alerts?.stale}
                  />
                  <span
                    className={`rounded-full border px-2 py-0.2 text-[10px] font-mono font-medium ${
                      isVersionMatch
                        ? 'border-emerald-500/30 bg-emerald-950/50 text-emerald-400'
                        : 'border-amber-500/30 bg-amber-950/50 text-amber-400'
                    }`}
                  >
                    Agent v{agentVersion}
                  </span>
                </div>
                <div className="flex items-center gap-2 text-xs text-slate-400 mt-0.5">
                  <span className="font-mono">{identity.host_id}</span>
                  <span>•</span>
                  <span>
                    {identity.project ? `${identity.runtime}/${identity.project}` : identity.runtime}
                  </span>
                </div>
              </div>
            </div>

            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={onClose}
                aria-label="关闭容器详情"
                className="flex h-11 w-11 items-center justify-center rounded-lg text-slate-400 transition-colors hover:bg-slate-800 hover:text-slate-100 focus:outline-hidden focus:ring-2 focus:ring-sky-400"
                title="关闭抽屉 (Esc)"
              >
                <X className="h-5 w-5" />
              </button>
            </div>
          </div>

          {/* Drawer Scrollable Body */}
          <div className="flex-1 overflow-y-auto p-6 space-y-6">
            <AdmissionStatus data={sec.admission} stale={container?.alerts?.stale} />
            {(identity.runtime === 'incus' || identity.runtime === 'podman') && (
              <section className="rounded-xl border border-sky-500/25 bg-sky-950/20 p-4 space-y-3">
                <div className="flex items-start gap-3">
                  <div className="rounded-lg border border-sky-500/30 bg-sky-500/10 p-2 text-sky-300">
                    <Mail className="h-4 w-4" />
                  </div>
                  <div className="min-w-0 flex-1">
                    <h3 className="text-sm font-semibold text-slate-100">用户邮箱与备注</h3>
                    <p className="mt-1 text-xs leading-relaxed text-slate-400">用于搜索、人工核对和后续封禁定位；保存信息不会自动停止或限制容器。</p>
                  </div>
                </div>
                <label className="block space-y-1.5">
                  <span className="flex items-center gap-2 text-xs font-medium text-slate-300">
                    用户邮箱
                    {container?.user_email_source === 'upstream' && <span className="rounded-full border border-sky-500/30 bg-sky-500/10 px-2 py-0.5 text-[10px] text-sky-300">上游 API 自动同步</span>}
                    {container?.user_email_source === 'manual' && <span className="rounded-full border border-slate-600 bg-slate-800 px-2 py-0.5 text-[10px] text-slate-400">手工备注</span>}
                    {container?.user_email_source === 'unmatched' && <span className="rounded-full border border-amber-500/30 bg-amber-500/10 px-2 py-0.5 text-[10px] text-amber-300">上游实例未匹配</span>}
                  </span>
                  <input
                    type="email"
                    maxLength={254}
                    value={userEmail}
                    onChange={(event) => setUserEmail(event.target.value)}
                    placeholder="例如 user@example.com"
                    disabled={!container?.container_id || Boolean(container?.alerts?.stale)}
                    className="w-full rounded-lg border border-slate-700 bg-slate-950/70 px-3 py-2 text-sm text-slate-100 placeholder:text-slate-500 focus:border-sky-500 focus:outline-hidden focus:ring-1 focus:ring-sky-500/40 disabled:opacity-50"
                  />
                  {container?.user_email_source === 'unmatched' && container.user_email_status && (
                    <p className="text-[11px] leading-relaxed text-amber-300">{container.user_email_status}。系统不会按容器名称猜邮箱；请核对上游实例 UUID，或手工补充邮箱。</p>
                  )}
                </label>
                <label className="block space-y-1.5">
                  <span className="text-xs font-medium text-slate-300">内部备注 <span className="font-normal text-slate-500">（可选，最多 500 字）</span></span>
                  <textarea
                    value={userNote}
                    maxLength={500}
                    onChange={(event) => setUserNote(event.target.value)}
                    placeholder="记录订单号、沟通情况或封禁核对信息"
                    rows={2}
                    disabled={!container?.container_id || Boolean(container?.alerts?.stale)}
                    className="w-full resize-y rounded-lg border border-slate-700 bg-slate-950/70 px-3 py-2 text-sm text-slate-100 placeholder:text-slate-500 focus:border-sky-500 focus:outline-hidden focus:ring-1 focus:ring-sky-500/40 disabled:opacity-50"
                  />
                </label>
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <p className="text-[11px] text-slate-500">Ctrl+K 全局搜索可直接输入邮箱或备注内容。</p>
                  <button
                    type="button"
                    onClick={saveUserNote}
                    disabled={isSavingUserNote || !container?.container_id || Boolean(container?.alerts?.stale)}
                    className="inline-flex items-center gap-1.5 rounded-lg border border-sky-500/50 bg-sky-600/20 px-3 py-2 text-xs font-semibold text-sky-200 hover:bg-sky-600/30 disabled:cursor-not-allowed disabled:opacity-50"
                  >
                    <Save className="h-3.5 w-3.5" />
                    {isSavingUserNote ? '保存中…' : '保存备注'}
                  </button>
                </div>
              </section>
            )}
            {/* Quick KPI Cards Grid */}
            <div className="grid grid-cols-3 gap-3 font-mono text-xs">
              <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-3">
                <span className="text-slate-400 flex items-center gap-1 text-[11px] mb-1">
                  <Cpu className="h-3.5 w-3.5 text-sky-400" /> CPU 占用
                </span>
                <span className="text-lg font-bold text-slate-100 tabular-nums">
                  {fmtNumber(container?.cpu_percent)}%
                </span>
              </div>

              <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-3">
                <span className="text-slate-400 flex items-center gap-1 text-[11px] mb-1">
                  <HardDrive className="h-3.5 w-3.5 text-emerald-400" /> 内存使用
                </span>
                <span className="text-lg font-bold text-slate-100 tabular-nums">
                  {fmtNumber(container?.mem_percent)}%
                </span>
                <span className="text-[10px] text-slate-500 block truncate">
                  {fmtBytes(container?.mem_bytes)} / {fmtBytes(container?.mem_limit_bytes)}
                </span>
              </div>

              <div
                className={`rounded-xl border p-3 ${
                  inIpAlert
                    ? 'border-rose-500/40 bg-rose-950/30 text-rose-300'
                    : 'border-slate-800 bg-slate-950/60'
                }`}
              >
                <span className="text-slate-400 flex items-center gap-1 text-[11px] mb-1">
                  <Network className="h-3.5 w-3.5 text-amber-400" /> 入站去重 IP
                </span>
                <span className={`text-lg font-bold tabular-nums ${inIpAlert ? 'text-rose-400' : 'text-slate-100'}`}>
                  {inIps}
                </span>
                <span className="text-[10px] text-slate-500 block">
                  阈值：{inThresh} IPs
                </span>
              </div>
            </div>

            {(identity.runtime === 'incus' || identity.runtime === 'podman') && (
              <section className="rounded-xl border border-slate-800 bg-slate-950/50 p-4 space-y-3">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div>
                    <h3 className="flex items-center gap-2 text-sm font-semibold text-slate-100">
                      <Gauge className="h-4 w-4 text-sky-300" />
                      CPU 与磁盘 I/O 自动保护
                    </h3>
                    <p className="mt-1 text-[11px] text-slate-400">显示触发依据、已读回限额与恢复进度；保护信号不等于客户滥用认定。</p>
                  </div>
                  <span className="rounded-full border border-slate-700 bg-slate-900 px-2 py-1 text-[10px] text-slate-300">仅 Incus / Podman</span>
                </div>

                <div className="grid grid-cols-1 gap-3 lg:grid-cols-2">
                  <div className={`min-w-0 rounded-lg border p-3 space-y-2 ${guardTone(cpuGuard?.state)}`}>
                    <div className="flex items-center justify-between gap-2">
                      <span className="flex items-center gap-1.5 text-xs font-semibold"><Cpu className="h-3.5 w-3.5" />CPU 保护</span>
                      <span className="rounded-full border border-current/20 px-2 py-0.5 text-[10px]">{guardStateLabel(cpuGuard?.state)}</span>
                    </div>
                    <p className="text-[11px] leading-relaxed text-slate-300">
                      当前 {cpuGuard?.container_cpu_percent ?? cpuGuard?.current_cpu_percent ?? container?.cpu_percent ?? 0}%
                      {cpuGuard?.effective_cpus ? ` · 配额容量 ${fmtNumber(cpuGuard.effective_cpus, 2)} 核` : ''}
                      {cpuGuard?.host_busy_percent !== undefined && cpuGuard.host_busy_percent !== null ? ` · 母鸡忙碌 ${fmtNumber(cpuGuard.host_busy_percent, 1)}%` : ''}
                    </p>
                    {cpuGuard?.state === 'watching' && (
                      <p className="text-[11px] text-amber-200">持续高占用 {cpuGuard.high_samples ?? 0}/{cpuGuard.required_samples ?? 0} 次，已观察 {formatMinutes(cpuGuard.confirmed_duration_seconds)}。</p>
                    )}
                    {['limited', 'limit_unverified', 'limited_unverified', 'limit_failed', 'restore_failed', 'escalating', 'restoring'].includes(cpuGuard?.state || '') && (
                      <div className="rounded-md border border-slate-700/80 bg-slate-950/50 p-2 text-[11px] space-y-1">
                        <p>原限额：<span className="font-mono text-slate-100">{cpuGuard?.original_limit || '未记录'}</span></p>
                        <p>当前限额：<span className="font-mono text-slate-100">{cpuGuard?.active_limit || '等待读回'}</span>{cpuGuard?.tier ? ` · 第 ${cpuGuard.tier} 阶（约原容量 ${cpuGuard.tier_percent_of_original ?? '-'}%）` : ''}</p>
                        <p>恢复条件：低占用连续 {cpuGuard?.recovery_samples ?? 0}/{cpuGuard?.recovery_samples_required ?? 0} 次，观察窗口 {formatMinutes(cpuGuard?.recovery_duration_seconds)}。</p>
                      </div>
                    )}
                    {cpuGuard?.top_process?.process && (
                      <p className="text-[11px] text-slate-300">主要进程：<span className="font-mono text-sky-200">{cpuGuard.top_process.process}</span>{cpuGuard.top_process.pid ? ` · PID ${cpuGuard.top_process.pid}` : ''}{cpuGuard.top_process.cpu_percent !== undefined ? ` · ${fmtNumber(cpuGuard.top_process.cpu_percent, 1)}%` : ''}</p>
                    )}
                    <p className="text-[11px] leading-relaxed text-slate-400">{cpuGuard?.message || cpuGuard?.action?.message || (cpuGuard?.state === 'normal' ? '当前未达到持续保护条件。' : '等待 Agent 采样与读回状态。')}</p>
                    {cpuGuard?.recheck_interval_seconds ? <p className="text-[10px] text-slate-500">每约 {formatMinutes(cpuGuard.recheck_interval_seconds)} 复查一次。</p> : null}
                  </div>

                  <div className={`min-w-0 rounded-lg border p-3 space-y-2 ${guardTone(ioGuard?.state)}`}>
                    <div className="flex items-center justify-between gap-2">
                      <span className="flex items-center gap-1.5 text-xs font-semibold"><HardDrive className="h-3.5 w-3.5" />磁盘 I/O 保护</span>
                      <span className="rounded-full border border-current/20 px-2 py-0.5 text-[10px]">{guardStateLabel(ioGuard?.state)}</span>
                    </div>
                    <p className="text-[11px] leading-relaxed text-slate-300">
                      {ioGuard?.device ? `设备 ${ioGuard.device}` : '设备待识别'}
                      {ioGuard?.device_busy_percent !== undefined && ioGuard.device_busy_percent !== null ? ` · 磁盘忙碌 ${fmtNumber(ioGuard.device_busy_percent, 1)}%` : ''}
                      {ioGuard?.dominant_share_percent !== undefined ? ` · 容器占比 ${fmtNumber(ioGuard.dominant_share_percent, 1)}%` : ''}
                    </p>
                    {ioGuard?.state === 'watching' && (
                      <p className="text-[11px] text-amber-200">持续压力 {ioGuard.sample_count ?? 0}/{ioGuard.required_samples ?? 0} 次，已观察 {formatMinutes(ioGuard.confirmed_duration_seconds)}。</p>
                    )}
                    {['active', 'applying', 'escalating', 'restoring', 'restore_failed', 'retry_wait'].includes(ioGuard?.state || '') && (
                      <div className="rounded-md border border-slate-700/80 bg-slate-950/50 p-2 text-[11px] space-y-1">
                        <p>原 I/O 限额：<span className="font-mono text-slate-100">{formatIoLimit(ioGuard?.original_limit)}</span></p>
                        <p>{['active', 'restore_failed'].includes(ioGuard?.state || '') ? '已读回生效限额' : '待确认限额'}：<span className="font-mono text-slate-100">{['active', 'restore_failed'].includes(ioGuard?.state || '') ? formatIoLimit(ioGuard?.active_limit) : '尚未确认；保留最后一次读回值'}</span>{ioGuard?.tier ? ` · 第 ${ioGuard.tier} 阶（约基线 ${ioGuard.tier_percent_of_baseline ?? '-'}%）` : ''}</p>
                        <p>恢复条件：低压力连续 {ioGuard?.recovery_samples ?? 0}/{ioGuard?.recovery_samples_required ?? 0} 次，观察窗口 {formatMinutes(ioGuard?.recovery_duration_seconds)}。</p>
                        {ioGuard?.retry_after_seconds ? <p className="text-amber-200">约 {formatMinutes(ioGuard.retry_after_seconds)} 后自动重试。</p> : null}
                      </div>
                    )}
                    {ioGuard?.observed_rates && (
                      <p className="text-[11px] text-slate-300">当前读/写：{formatIoRate(ioGuard.observed_rates.rbps)} / {formatIoRate(ioGuard.observed_rates.wbps)}；IOPS {fmtNumber(ioGuard.observed_rates.riops, 0)} / {fmtNumber(ioGuard.observed_rates.wiops, 0)}。</p>
                    )}
                    <p className="text-[11px] leading-relaxed text-slate-400">{ioGuard?.message || (ioGuard?.state === 'normal' ? '当前未达到持续宿主机磁盘压力及容器归属条件。' : '等待 Agent 采样与读回状态。')}</p>
                    {ioGuard?.recheck_interval_seconds ? <p className="text-[10px] text-slate-500">每约 {formatMinutes(ioGuard.recheck_interval_seconds)} 复查一次。</p> : null}
                  </div>
                </div>
              </section>
            )}

            {/* Visual Charts: CPU & Memory */}
            <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-4">
              <h3 className="text-xs font-bold text-slate-200 mb-2 flex items-center gap-2">
                <Activity className="h-4 w-4 text-sky-400" />
                <span>CPU 与内存历史趋势 (24h)</span>
              </h3>
              <ResourceChart history={history} />
            </div>

            {/* Visual Charts: Network Bandwidth */}
            <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-4">
              <h3 className="text-xs font-bold text-slate-200 mb-2 flex items-center gap-2">
                <Network className="h-4 w-4 text-emerald-400" />
                <span>实时吞吐速率趋势 (RX & TX)</span>
              </h3>
              <NetworkChart history={history} />
            </div>

            {/* Protocol Breakdown & Traffic Symmetry */}
            <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-4 space-y-3">
              <div className="flex items-center justify-between">
                <h3 className="text-xs font-bold text-slate-200 flex items-center gap-2">
                  <Activity className="h-4 w-4 text-sky-400" />
                  <span>协议流量拆分与流量对称性</span>
                </h3>
                {container?.alerts?.traffic_imbalance ? (
                  <span className="text-[11px] font-bold text-rose-300 bg-rose-500/10 border border-rose-500/30 px-2 py-0.5 rounded-full flex items-center gap-1">
                    <ArrowUpDown className="h-3 w-3 text-rose-400" />
                    <span>入出失衡 {container.alerts.traffic_imbalance_ratio}x ({container.alerts.traffic_imbalance_direction === 'outbound_heavy' ? '出栈偏高' : '入栈偏高'})</span>
                  </span>
                ) : (
                  <span className="text-[11px] font-medium text-emerald-400 bg-emerald-500/10 border border-emerald-500/20 px-2 py-0.5 rounded-full flex items-center gap-1">
                    <CheckCircle2 className="h-3 w-3" />
                    <span>入出栈流量均衡</span>
                  </span>
                )}
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 font-mono text-xs">
                {/* TCP Traffic Card */}
                <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-3">
                  <span className="text-slate-400 block text-[11px] mb-1 text-blue-400 font-semibold">
                    TCP 协议流量
                  </span>
                  <div className="flex items-center justify-between text-slate-200">
                    <span className="flex items-center text-emerald-400" title="TCP 入栈速率">
                      <ArrowDownLeft className="h-3.5 w-3.5 mr-0.5" />
                      {fmtMbps(container?.tcp_rx_bps)} Mbps
                    </span>
                    <span className="flex items-center text-sky-400" title="TCP 出栈速率">
                      <ArrowUpRight className="h-3.5 w-3.5 mr-0.5" />
                      {fmtMbps(container?.tcp_tx_bps)} Mbps
                    </span>
                  </div>
                </div>

                {/* UDP Traffic Card */}
                <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-3">
                  <span className="text-slate-400 block text-[11px] mb-1 text-violet-400 font-semibold">
                    UDP 协议流量
                  </span>
                  <div className="flex items-center justify-between text-slate-200">
                    <span className="flex items-center text-emerald-400" title="UDP 入栈速率">
                      <ArrowDownLeft className="h-3.5 w-3.5 mr-0.5" />
                      {fmtMbps(container?.udp_rx_bps)} Mbps
                    </span>
                    <span className="flex items-center text-sky-400" title="UDP 出栈速率">
                      <ArrowUpRight className="h-3.5 w-3.5 mr-0.5" />
                      {fmtMbps(container?.udp_tx_bps)} Mbps
                    </span>
                  </div>
                </div>

                {/* Hysteria 2 (hy2) Status Card */}
                <div className={`rounded-lg border p-3 ${
                  container?.security?.hy2_protocol?.detected || container?.alerts?.hy2_detected
                    ? 'border-violet-500/40 bg-violet-950/20 text-violet-300'
                    : 'border-slate-800 bg-slate-900/60 text-slate-300'
                }`}>
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-[11px] font-semibold text-violet-400 flex items-center gap-1">
                      <Radio className="h-3 w-3" />
                      Hysteria 2 协议
                    </span>
                    {(container?.security?.hy2_protocol?.detected || container?.alerts?.hy2_detected) && (
                      <span className="text-[10px] font-bold bg-violet-500/20 border border-violet-500/40 px-1.5 py-0.2 rounded-sm text-violet-200">
                        {container?.security?.hy2_protocol?.confidence === 'confirmed' ? '已确认' : '疑似'}
                      </span>
                    )}
                  </div>
                  <div className="text-[11px] mt-1">
                    {container?.security?.hy2_protocol?.detected || container?.alerts?.hy2_detected ? (
                      <div>
                        <span>UDP 并发：{container?.security?.hy2_protocol?.udp_concurrency ?? container?.alerts?.hy2_concurrency ?? 0}</span>
                        {container?.security?.hy2_protocol?.process && (
                          <span className="text-slate-400 ml-1.5">({container.security.hy2_protocol.process})</span>
                        )}
                      </div>
                    ) : (
                      <span className="text-slate-500">未发现运行特征</span>
                    )}
                  </div>
                </div>

                {/* UDP Throttle & Anti-Abuse Control Card */}
                {(container?.alerts?.udp_throttled || sec.udp_throttle?.throttled || container?.security?.hy2_protocol?.detected || container?.alerts?.hy2_detected) && (
                  <div className={`col-span-1 sm:col-span-2 rounded-lg border p-3 ${
                    container?.alerts?.udp_throttled || sec.udp_throttle?.throttled
                      ? 'border-rose-500/50 bg-rose-950/30 text-rose-200'
                      : 'border-slate-800 bg-slate-900/60 text-slate-300'
                  }`}>
                    <div className="flex items-center justify-between mb-1.5">
                      <span className="text-[11px] font-semibold flex items-center gap-1.5">
                        <Gauge className={`h-3.5 w-3.5 ${
                          container?.alerts?.udp_throttled || sec.udp_throttle?.throttled ? 'text-rose-400' : 'text-slate-400'
                        }`} />
                        <span>UDP 流量管控与限速</span>
                      </span>
                      {container?.alerts?.udp_throttled || sec.udp_throttle?.throttled ? (
                        <span className="text-[10px] font-bold bg-rose-500/20 border border-rose-500/50 px-2 py-0.5 rounded-sm text-rose-300 animate-pulse">
                          限速生效中: {container?.alerts?.udp_throttle_rate_mbps ?? sec.udp_throttle?.rate_mbps ?? 10} Mbps
                        </span>
                      ) : (
                        <span className="text-[10px] font-medium bg-emerald-500/10 border border-emerald-500/30 px-2 py-0.5 rounded-sm text-emerald-400">
                          全速运行 (自动防滥用保护中)
                        </span>
                      )}
                    </div>
                    {container?.alerts?.udp_throttled || sec.udp_throttle?.throttled ? (
                      <div className="space-y-2 mt-2">
                        <p className="text-[11px] text-rose-300/90 leading-relaxed">
                          {sec.udp_throttle?.reason || '因持续 3 分钟上下行严重失衡且高 UDP 并发触发靶向限速。已保护 TCP 与 SSH 保持千兆线速。'}
                        </p>
                        <div className="flex items-center justify-between pt-1 border-t border-rose-500/20 text-[10px] text-rose-300/70 font-mono">
                          <span>剩余冷却时间：约 {Math.ceil((container?.alerts?.udp_throttle_remaining_seconds ?? sec.udp_throttle?.remaining_seconds ?? 0) / 60)} 分钟</span>
                          <span>24h内违规：第 {container?.alerts?.udp_throttle_violation_count ?? sec.udp_throttle?.violation_count ?? 1} 次</span>
                        </div>
                        <div className="pt-1">
                          <button
                            type="button"
                            disabled={isDrawerActionLoading}
                            onClick={() => setPendingDecision('release_udp_throttle')}
                            className="flex items-center gap-1.5 rounded-lg border border-sky-500/50 bg-sky-950/80 px-3 py-1.5 text-xs font-semibold text-sky-200 hover:bg-sky-900 transition-all disabled:opacity-50 shadow-xs"
                          >
                            <Unlock className="h-3.5 w-3.5 text-sky-400" />
                            <span>立即解除限速</span>
                          </button>
                        </div>
                      </div>
                    ) : (
                      <div className="text-[11px] text-slate-400 mt-1">
                        双向流量均衡或低并发的正常 HY2 用户享有 100% 自动豁免保护，不限制 UDP 速率。
                      </div>
                    )}
                  </div>
                )}
              </div>
            </div>

            {/* Security Checks & Surface Risk */}
            <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-4 space-y-3">
              <h3 className="text-xs font-bold text-slate-200 flex items-center gap-2">
                <Shield className="h-4 w-4 text-amber-400" />
                <span>安全合规与暴露面排查</span>
              </h3>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
                {/* SOCKS Check */}
                <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-3">
                  <span className="text-slate-400 block text-[11px]">SOCKS 代理服务</span>
                  <div className="mt-1 font-semibold">
                    {socks?.detected ? (
                      <span className="text-amber-400">
                        已检测 · {socks.auth_mode === 'no_auth' ? '无认证 (高危)' : socks.auth_mode === 'weak_password' ? '弱密码 (高危)' : socks.auth_mode}
                        {socks.public_exposure && ' · 公网暴露'}
                      </span>
                    ) : (
                      <span className="text-emerald-400">未发现可疑 SOCKS 代理</span>
                    )}
                  </div>
                </div>

                {/* Panel Pairing */}
                <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-3">
                  <span className="text-slate-400 block text-[11px]">第三方控制面板对接</span>
                  <div className="mt-1 font-semibold">
                    {pairing?.detected ? (
                      <span className={pairing.approved ? 'text-emerald-400' : 'text-rose-400'}>
                        {pairing.approved ? '已放行对接' : '检测到未授权面板特征'}
                      </span>
                    ) : (
                      <span className="text-emerald-400">未发现异常对接</span>
                    )}
                  </div>
                </div>
              </div>

              {/* If Risk is detected in SOCKS or Panel, show Quick Disposition Controls */}
              {activeActionableAlert &&
                ((socks?.detected && (socks.auth_mode === 'no_auth' || socks.auth_mode === 'weak_password')) ||
                  (pairing?.detected && !pairing.approved)) && (
                <div className="rounded-xl border border-rose-500/50 bg-rose-950/40 p-3.5 space-y-2.5">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2 text-rose-300 font-bold text-xs">
                      <AlertTriangle className="h-4 w-4 text-rose-400 animate-pulse" />
                      <span>检测到非合规安全风险需处置</span>
                    </div>
                  </div>
                  <p className="text-[11px] text-slate-300">
                    {socks?.detected && socks.auth_mode === 'no_auth'
                      ? '当前容器正在运行开放且无认证的 SOCKS 代理服务，极易被利用为跳板。'
                      : socks?.detected && socks.auth_mode === 'weak_password'
                      ? '当前容器正在运行弱密码 SOCKS 代理服务，容易被撞库后滥用为跳板。'
                      : pairing?.detected && !pairing.approved
                      ? '当前容器检测到未经放行的第三方机场节点对接活动与内部特征。'
                      : '检测到运行风险，建议定向处置或加入安全白名单。'}
                  </p>
                  <div className="flex items-center gap-2 pt-1 flex-wrap">
                    <button
                      type="button"
                      disabled={isDrawerActionLoading}
                      onClick={() => setPendingDecision('deny')}
                      className="flex items-center gap-1.5 rounded-lg border border-rose-500/60 bg-rose-950/90 px-3 py-1.5 text-xs font-semibold text-rose-200 hover:bg-rose-900 transition-all disabled:opacity-50 shadow-xs"
                    >
                      <Ban className="h-3.5 w-3.5" />
                      <span>{isDrawerActionLoading ? '处理中...' : '定向处置违规服务'}</span>
                    </button>
                    <button
                      type="button"
                      disabled={isDrawerActionLoading}
                      onClick={() => setPendingDecision('allow_silent')}
                      className="flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-800/90 px-3 py-1.5 text-xs font-medium text-slate-300 hover:bg-slate-750 transition-all disabled:opacity-50"
                    >
                      <Check className="h-3.5 w-3.5 text-emerald-400" />
                      <span>放行此策略</span>
                    </button>
                    <button
                      type="button"
                      disabled={isDrawerActionLoading}
                      onClick={() => setPendingDecision('resolve')}
                      className="flex items-center gap-1.5 rounded-lg border border-emerald-500/40 bg-emerald-950/40 px-3 py-1.5 text-xs font-medium text-emerald-300 hover:bg-emerald-900/60 transition-all disabled:opacity-50"
                    >
                      <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400" />
                      <span>标记已解决</span>
                    </button>
                  </div>
                </div>
              )}

              {/* Listening Ports & Exposure */}
              <div className="font-mono text-xs space-y-1 text-slate-300 pt-1">
                <div className="flex justify-between py-1 border-t border-slate-800/80">
                  <span className="text-slate-500">监听端口</span>
                  <span className="truncate max-w-xs">
                    {(sec.listening_ports || []).join(', ') || '无对外开放端口'}
                  </span>
                </div>
                <div className="flex justify-between py-1 border-t border-slate-800/80">
                  <span className="text-slate-500">NAT 暴露映射</span>
                  <span className="truncate max-w-xs">
                    {(sec.network_exposure || [])
                      .map((x) => `${x.listen} → ${x.target}`)
                      .join(', ') || '内部隔离'}
                  </span>
                </div>
                <div className="flex justify-between py-1 border-t border-slate-800/80">
                  <span className="text-slate-500">最高 CPU 进程</span>
                  <span className="text-sky-300 truncate max-w-xs" title={container?.top_cpu_process_command}>
                    {container?.top_cpu_process_command
                      ? `PID ${container.top_cpu_process_pid} (${fmtNumber(container.top_cpu_process_cpu_percent)}%) · ${container.top_cpu_process_command}`
                      : '无显著负载进程'}
                  </span>
                </div>
              </div>
            </div>

            <ConnectionEvidenceTimeline identity={identity} />

            {/* On-Demand Diagnostic Panel */}
            <DiagnosticPanel
              identity={identity}
              diagnostic={diagnostic}
              isStale={Boolean(container?.alerts?.stale)}
              onRefresh={() => {
                api.getContainerDiagnostic(identity).then(setDiagnostic);
              }}
              onToast={onToast}
            />
          </div>
        </div>
      </div>
      <ConfirmDialog
        open={Boolean(pendingDecision)}
        {...confirmationCopy}
        isSubmitting={isDrawerActionLoading}
        onCancel={() => setPendingDecision(null)}
        onConfirm={async () => {
          if (!pendingDecision) return;
          const decision = pendingDecision;
          await handleDrawerDisposition(decision);
          setPendingDecision(null);
        }}
      />
    </div>
  );
};
