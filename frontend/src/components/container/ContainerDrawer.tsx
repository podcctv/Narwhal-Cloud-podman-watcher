import React, { useEffect, useRef, useState } from 'react';
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
import { ContainerItem, ContainerIdentity, HistoryPoint, DiagnosticData, ProtocolGuardSummary, SecurityAlert } from '../../api/types';
import { api, fmtBytes, fmtNumber, fmtMbps } from '../../api/client';
import { StatusBadge } from '../common/StatusBadge';
import { ResourceChart } from './ResourceChart';
import { NetworkChart } from './NetworkChart';
import { DiagnosticPanel } from './DiagnosticPanel';
import { ConfirmDialog } from '../common/ConfirmDialog';
import { AdmissionStatus } from './AdmissionStatus';
import { ConnectionEvidenceTimeline } from './ConnectionEvidenceTimeline';
import { hasContainerResourceOrProtectionActivity, hasContainerProtocolGuard } from '../dashboard/ContainerStateBadges';
import { evaluateContainerRisk } from '../dashboard/HostContainerList';

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
  waiting_for_host_psi: '等待母鸡 PSI 佐证',
  waiting_for_pressure: '等待内存压力',
  waiting_for_other_limit: '等待其他资源保护结束',
  limited: '限额已读回确认',
  active: '限额已读回确认',
  limit_failed: '限额未确认',
  limited_unverified: '限额待读回',
  limit_unverified: '限额待读回',
  restore_failed: '恢复失败',
  restored: '原限额已恢复',
  manual_override: '检测到人工修改',
  manual_reset: '人工恢复原限额',
  cooldown: '恢复后冷却中',
  state_unavailable: '保护状态不可读',
  sampling_unavailable: '采样不可用',
  disabled: '未启用',
  applying: '正在应用并核验',
  escalating: '正在升级并核验',
  restoring: '正在恢复并核验',
  limit_readback_unavailable: '无法读取限额',
  retry_wait: '等待自动重试',
  orphaned_cgroup: '旧容器限额归属待核实',
  unavailable: '数据不可用',
  warming: '正在建立采样基线',
  unsupported: '不支持自动保护',
  psi_unavailable: 'PSI 采样不可用',
  existing_limit_stricter: '保留现有限额',
  apply_unverified: '限额结果待核验',
};

const guardTone = (state?: string) => {
  if (['limited', 'active'].includes(state || '')) return 'border-sky-500/30 bg-sky-950/30 text-sky-200';
  if (['limit_failed', 'limited_unverified', 'limit_unverified', 'restore_failed', 'state_unavailable', 'sampling_unavailable', 'limit_readback_unavailable', 'orphaned_cgroup', 'unavailable', 'apply_unverified'].includes(state || '')) {
    return 'border-rose-500/30 bg-rose-950/20 text-rose-200';
  }
  if (['watching', 'waiting_for_host_pressure', 'waiting_for_host_psi', 'waiting_for_pressure', 'applying', 'escalating', 'restoring', 'waiting_for_other_limit', 'retry_wait', 'warming', 'cooldown', 'psi_unavailable'].includes(state || '')) {
    return 'border-amber-500/30 bg-amber-950/20 text-amber-200';
  }
  if (['normal', 'restored', 'manual_reset'].includes(state || '')) return 'border-emerald-500/25 bg-emerald-950/15 text-emerald-200';
  return 'border-slate-700 bg-slate-900/60 text-slate-300';
};

const guardStateLabel = (state?: string) => RESOURCE_GUARD_STATES[state || ''] || '状态待核实';
const psiPercent = (source: any, resource: 'cpu' | 'memory' | 'io') => {
  const item = source?.[resource];
  const value = item?.some?.avg10;
  return item?.status === 'ready' && Number.isFinite(Number(value)) ? `${fmtNumber(Number(value), 2)}%` : '不可用';
};

const formatIoRate = (value?: string | number) => {
  if (value === 'max') return '不限';
  if (value === undefined || value === null || value === '') return '未知';
  const parsed = Number(value);
  return Number.isFinite(parsed) ? `${fmtBytes(parsed)}/秒` : '未知';
};

const formatIoCount = (value?: string | number) => {
  if (value === 'max') return '不限';
  if (value === undefined || value === null || value === '') return '未知';
  const parsed = Number(value);
  return Number.isFinite(parsed) ? `${parsed} 次/秒` : '未知';
};

const formatIoLimit = (value?: Record<string, string>) => {
  if (!value) return '暂无读回数据';
  return `读 ${formatIoRate(value.rbps)} · 写 ${formatIoRate(value.wbps)} · 读 IOPS ${formatIoCount(value.riops)} · 写 IOPS ${formatIoCount(value.wiops)}`;
};

const formatMemoryHigh = (value?: string | number | null) => {
  if (value === 'max') return '不限';
  if (value === undefined || value === null || value === '') return '未知';
  const parsed = Number(value);
  return Number.isFinite(parsed) ? fmtBytes(parsed) : '未知';
};

const formatMetricPercent = (value?: number | null) =>
  value == null || !Number.isFinite(value) ? '—' : `${fmtNumber(value, 1)}%`;

const formatMetricBytes = (value?: number | null) =>
  value == null || !Number.isFinite(value) ? '—' : fmtBytes(value);

const formatAlertValue = (value: unknown) => {
  const formatted = typeof value === 'string' ? value : JSON.stringify(value) ?? String(value);
  return formatted.length > 240 ? `${formatted.slice(0, 237)}…` : formatted;
};

const protocolGuardState = (summary?: ProtocolGuardSummary) => {
  if (!summary) return { label: '未上报管控状态', tone: 'border-slate-700 bg-slate-900/60 text-slate-300' };
  switch (summary.state) {
    case 'blocked': return { label: '阻断已核验', tone: 'border-emerald-500/30 bg-emerald-950/20 text-emerald-200' };
    case 'partial': return { label: '部分阻断', tone: 'border-rose-500/40 bg-rose-950/30 text-rose-200' };
    case 'unverified': return { label: '阻断待核验', tone: 'border-amber-500/40 bg-amber-950/30 text-amber-200' };
    case 'release_pending': return { label: '放行待核验', tone: 'border-amber-500/40 bg-amber-950/30 text-amber-200' };
    case 'not_detected': return summary.detected
      ? { label: '检测状态冲突', tone: 'border-amber-500/40 bg-amber-950/30 text-amber-200' }
      : { label: '未检测到目标协议', tone: 'border-slate-700 bg-slate-900/60 text-slate-300' };
    default: return { label: summary.state ? '状态待核实' : '未上报管控状态', tone: 'border-slate-700 bg-slate-900/60 text-slate-300' };
  }
};

const formatProtocolEndpoint = (endpoint: { proto?: string; port?: number; pid?: number; process?: string }) => {
  const protocol = endpoint.proto ? `${endpoint.proto.toUpperCase()}/` : '';
  const port = endpoint.port == null ? '端口未知' : `${endpoint.port}`;
  const process = endpoint.process ? ` · ${endpoint.process}` : '';
  const pid = endpoint.pid ? ` (PID ${endpoint.pid})` : '';
  return `${protocol}${port}${process}${pid}`;
};

const ProtocolGuardCard: React.FC<{ label: 'VMess' | 'Trojan'; summary?: ProtocolGuardSummary }> = ({ label, summary }) => {
  const state = protocolGuardState(summary);
  const configured = summary?.configured_endpoints;
  const blocked = summary?.blocked_endpoints;
  const pending = summary?.pending_endpoints;
  const evidence = summary?.evidence_chain;
  const evidenceItems: Array<[string, string]> = [];
  if (evidence?.configuration) evidenceItems.push(['配置', evidence.configuration]);
  if (evidence?.process_owner_and_listener) evidenceItems.push(['进程与监听', evidence.process_owner_and_listener]);
  if (evidence?.public_exposure) evidenceItems.push(['公网暴露', evidence.public_exposure]);
  if (evidence?.firewall_readback) evidenceItems.push(['防火墙读回', evidence.firewall_readback]);
  if (evidence?.listener_inventory_source) evidenceItems.push(['监听清单来源', evidence.listener_inventory_source]);
  if (evidence?.listener_inventory_reason) evidenceItems.push(['监听清单说明', evidence.listener_inventory_reason]);
  if (evidence?.pending_endpoint_count != null) evidenceItems.push(['待核验端点数', String(evidence.pending_endpoint_count)]);
  const endpoints = [
    ...(blocked || []).map((endpoint) => ({ ...endpoint, status: '已阻断' })),
    ...(pending || []).map((endpoint) => ({ ...endpoint, status: '待核验' })),
  ];

  return (
    <article className="min-w-0 rounded-lg border border-slate-800 bg-slate-900/60 p-3 space-y-2">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h4 className="text-xs font-semibold text-slate-100">{label}</h4>
        <span className={`rounded-full border px-2 py-0.5 text-[10px] ${state.tone}`}>{state.label}</span>
      </div>
      <p className="text-[11px] text-slate-400">
        配置端点 {configured?.length ?? '—'} · 已阻断 {blocked?.length ?? '—'} · 待核验 {pending?.length ?? '—'}
      </p>
      {summary?.reason && <p className="text-[11px] leading-relaxed text-slate-300">{summary.reason}</p>}
      {endpoints.length > 0 && (
        <ul className="space-y-1 border-t border-slate-800 pt-2 text-[10px] text-slate-300">
          {endpoints.map((endpoint, index) => (
            <li key={`${endpoint.status}-${endpoint.proto || ''}-${endpoint.port || 0}-${endpoint.pid || 0}-${index}`} className="flex min-w-0 items-start justify-between gap-2">
              <span className="min-w-0 break-all font-mono">{formatProtocolEndpoint(endpoint)}</span>
              <span className={endpoint.status === '已阻断' ? 'shrink-0 text-emerald-300' : 'shrink-0 text-amber-300'}>{endpoint.status}</span>
            </li>
          ))}
        </ul>
      )}
      {evidenceItems.length > 0 && (
        <dl className="grid gap-1 border-t border-slate-800 pt-2 text-[10px] sm:grid-cols-2">
          {evidenceItems.map(([name, value]) => (
            <div key={name} className="min-w-0">
              <dt className="text-slate-500">{name}</dt>
              <dd className="break-words text-slate-300">{value}</dd>
            </div>
          ))}
        </dl>
      )}
      {!summary && <p className="text-[10px] text-slate-500">当前容器数据未提供此协议的管控结果，不能据此判断为已阻断或未检测到。</p>}
    </article>
  );
};

const formatMinutes = (seconds?: number) => {
  if (seconds == null || !Number.isFinite(Number(seconds))) return '未知';
  if (Number(seconds) <= 0) return '0 分钟';
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
  const drawerPanelRef = useRef<HTMLDivElement>(null);
  const closeButtonRef = useRef<HTMLButtonElement>(null);
  const onCloseRef = useRef(onClose);
  const pendingDecisionRef = useRef(pendingDecision);

  useEffect(() => {
    onCloseRef.current = onClose;
  }, [onClose]);

  useEffect(() => {
    pendingDecisionRef.current = pendingDecision;
  }, [pendingDecision]);

  useEffect(() => {
    if (!identity) return;
    const previousFocus = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    const previousBodyOverflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    closeButtonRef.current?.focus();

    const handleDialogKeyDown = (event: KeyboardEvent) => {
      // A nested confirmation owns Escape and Tab while it is open.
      if (pendingDecisionRef.current) return;
      if (event.key === 'Escape') {
        event.preventDefault();
        onCloseRef.current();
        return;
      }
      if (event.key !== 'Tab') return;

      const panel = drawerPanelRef.current;
      if (!panel) return;
      const focusable = Array.from(panel.querySelectorAll<HTMLElement>(
        'a[href], button:not([disabled]), input:not([disabled]), textarea:not([disabled]), select:not([disabled]), [tabindex]:not([tabindex="-1"])'
      )).filter((element) => element.getClientRects().length > 0);
      if (!focusable.length) {
        event.preventDefault();
        panel.focus();
        return;
      }
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (event.shiftKey && (document.activeElement === first || !panel.contains(document.activeElement))) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && (document.activeElement === last || !panel.contains(document.activeElement))) {
        event.preventDefault();
        first.focus();
      }
    };

    document.addEventListener('keydown', handleDialogKeyDown);
    return () => {
      document.removeEventListener('keydown', handleDialogKeyDown);
      document.body.style.overflow = previousBodyOverflow;
      if (previousFocus?.isConnected) previousFocus.focus();
    };
  }, [identity?.host_id, identity?.runtime, identity?.project, identity?.container_name]);

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

  const isGuardRuntime = identity.runtime === 'incus' || identity.runtime === 'podman';
  const sec = container?.security || {};
  const inIps = sec.inbound_unique_ips == null || !Number.isFinite(sec.inbound_unique_ips) ? null : sec.inbound_unique_ips;
  const inThresh = sec.inbound_unique_ip_threshold || 10;
  const inIpAlert = inIps !== null && inIps > inThresh;

  const agentVersion = container?.agent_version || 'unknown';
  const isVersionMatch =
    agentVersion !== 'unknown' &&
    agentVersion !== 'dev' &&
    agentVersion === serverVersion;

  const socks = sec.socks_proxy;
  const pairing = sec.panel_pairing;
  const cpuGuard = sec.cpu_guard;
  const ioGuard = sec.io_guard;
  const memoryGuard = sec.memory_guard;
  const resourcePressure = sec.resource_pressure;
  const containerAlerts = activeAlerts.filter((alert) =>
    alert.host_id === identity.host_id &&
    alert.runtime === identity.runtime &&
    (alert.project || '') === (identity.project || '') &&
    alert.container_name === identity.container_name &&
    alert.status === 'active'
  );
  const protocolGuardSummaries = [sec.vmess_guard, sec.trojan_guard];
  const protocolGuardNeedsReview = protocolGuardSummaries.some((guard) =>
    ['partial', 'unverified', 'release_pending'].includes(guard?.state || '') ||
    Boolean(guard?.detected && guard.state !== 'blocked')
  );
  const failedGuardStates = ['limit_failed', 'limited_unverified', 'limit_unverified', 'restore_failed', 'limit_readback_unavailable', 'orphaned_cgroup', 'apply_unverified'];
  const resourceGuardFailed = [cpuGuard, memoryGuard, ioGuard].some((guard) => failedGuardStates.includes(guard?.state || ''));
  const drawerRisk = container && isGuardRuntime ? evaluateContainerRisk(container, activeAlerts) : null;
  const hasConfigurationRisk = (sec.configuration_risks?.length ?? 0) > 0;
  const hasOperationalFinding = Boolean(
    container?.alerts?.cpu || container?.alerts?.memory || container?.alerts?.disk
  );
  const drawerIsStale = Boolean(container?.alerts?.stale || container?.alerts?.host_stale);
  const drawerHasCriticalFinding = Boolean(drawerRisk?.isCritical || resourceGuardFailed);
  const drawerHasWarningFinding = Boolean(drawerRisk?.hasRisk || hasConfigurationRisk || hasOperationalFinding || protocolGuardNeedsReview || resourceGuardFailed);
  const drawerHasProtectionState = container
    ? hasContainerResourceOrProtectionActivity(container, activeAlerts) || hasContainerProtocolGuard(container)
    : false;
  const drawerStatus = (() => {
    if (!container) return 'info';
    if (!isGuardRuntime) return container.alerts?.stale ? 'stale' : 'healthy';
    if (drawerIsStale) return 'stale';
    if (drawerHasCriticalFinding) return 'critical';
    if (drawerHasWarningFinding) return 'warning';
    return drawerHasProtectionState ? 'info' : 'healthy';
  })();
  const drawerStatusLabel = !container
    ? '加载中'
    : isGuardRuntime && drawerStatus === 'info'
    ? '存在管控状态'
    : undefined;
  const cpuGuardCurrent = cpuGuard?.container_cpu_percent ?? cpuGuard?.current_cpu_percent ?? container?.cpu_percent;
  const hy2Confidence = sec.hy2_protocol?.confidence ?? container?.alerts?.hy2_confidence;
  const hy2ConfidenceLabel = hy2Confidence === 'confirmed'
    ? '已确认'
    : hy2Confidence === 'suspected'
    ? '疑似'
    : hy2Confidence === 'none'
    ? '未分级'
    : '置信度未知';
  const udpThrottleRate = container?.alerts?.udp_throttle_rate_mbps ?? sec.udp_throttle?.rate_mbps;
  const udpThrottleRemaining = container?.alerts?.udp_throttle_remaining_seconds ?? sec.udp_throttle?.remaining_seconds;
  const udpThrottleCount = container?.alerts?.udp_throttle_violation_count ?? sec.udp_throttle?.violation_count;
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
        aria-hidden="true"
        className="absolute inset-0 bg-slate-950/70 backdrop-blur-xs transition-opacity animate-in fade-in duration-200"
      />

      {/* Slide-over Drawer Panel */}
      <div className="absolute inset-y-0 right-0 flex max-w-full pl-0 sm:pl-10">
        <div ref={drawerPanelRef} tabIndex={-1} className="min-w-0 w-screen max-w-2xl transform bg-slate-900 border-l border-slate-800 shadow-2xl transition-transform animate-in slide-in-from-right duration-250 flex flex-col">
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
                    status={drawerStatus}
                    label={drawerStatusLabel}
                    size="sm"
                    pulse={drawerStatus === 'healthy'}
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
                ref={closeButtonRef}
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
                  {formatMetricPercent(container?.cpu_percent)}
                </span>
              </div>

              <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-3">
                <span className="text-slate-400 flex items-center gap-1 text-[11px] mb-1">
                  <HardDrive className="h-3.5 w-3.5 text-emerald-400" /> 内存使用
                </span>
                <span className="text-lg font-bold text-slate-100 tabular-nums">
                  {formatMetricPercent(container?.mem_percent)}
                </span>
                <span className="text-[10px] text-slate-500 block truncate">
                  {formatMetricBytes(container?.mem_bytes)} / {formatMetricBytes(container?.mem_limit_bytes)}
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
                  {inIps ?? (sec.communication_detail_available === false ? '不可用' : '—')}
                </span>
                <span className="text-[10px] text-slate-500 block">
                  阈值：{inThresh} IPs
                </span>
              </div>
            </div>

            {container && isGuardRuntime && (
              <section className="rounded-xl border border-slate-800 bg-slate-950/50 p-4 space-y-3" aria-label="容器活动告警与保护信号">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div>
                    <h3 className="flex items-center gap-2 text-sm font-semibold text-slate-100">
                      <Shield className="h-4 w-4 text-amber-300" />
                      告警与保护信号
                    </h3>
                    <p className="mt-1 text-[11px] text-slate-400">
                      {drawerIsStale ? '数据已过期，以下为最近一次匹配记录。' : '展示服务端当前匹配到的活动告警；保护信号不等于违规认定。'}
                    </p>
                  </div>
                  <span className="rounded-full border border-slate-700 bg-slate-900 px-2 py-1 text-[10px] tabular-nums text-slate-300">{containerAlerts.length} 项</span>
                </div>
                {containerAlerts.length === 0 ? (
                  <p className="rounded-lg border border-dashed border-slate-800 px-3 py-3 text-xs text-slate-400">暂无匹配的活动告警。资源保护与协议阻断状态请查看下方卡片。</p>
                ) : (
                  <ul className="space-y-2">
                    {containerAlerts.map((alert) => (
                      <li key={alert.id} className={`rounded-lg border p-3 ${alert.protection_only ? 'border-sky-800/70 bg-sky-950/20' : alert.severity === 'critical' ? 'border-rose-800/70 bg-rose-950/20' : 'border-amber-800/60 bg-amber-950/15'}`}>
                        <div className="flex flex-wrap items-center gap-2">
                          <span className={`rounded-full border px-2 py-0.5 text-[10px] ${alert.protection_only ? 'border-sky-700 bg-sky-950/70 text-sky-200' : alert.severity === 'critical' ? 'border-rose-700 bg-rose-950/70 text-rose-200' : 'border-amber-700 bg-amber-950/70 text-amber-200'}`}>
                            {alert.protection_only ? '保护信号' : alert.severity === 'critical' ? '严重告警' : alert.severity === 'info' ? '提示' : '安全告警'}
                          </span>
                          <span className="text-[10px] text-slate-500">{alert.type}</span>
                        </div>
                        <h4 className="mt-2 text-xs font-semibold text-slate-100">{alert.title || alert.type}</h4>
                        <p className="mt-1 break-words text-[11px] leading-relaxed text-slate-300">{alert.message}</p>
                        {(alert.value != null || alert.threshold != null) && (
                          <p className="mt-1 text-[10px] tabular-nums text-slate-400">
                            {alert.value != null ? `当前值：${formatAlertValue(alert.value)}` : ''}
                            {alert.value != null && alert.threshold != null ? ' · ' : ''}
                            {alert.threshold != null ? `阈值：${formatAlertValue(alert.threshold)}` : ''}
                          </p>
                        )}
                      </li>
                    ))}
                  </ul>
                )}
              </section>
            )}

            {(identity.runtime === 'incus' || identity.runtime === 'podman') && (
              <section className="rounded-xl border border-slate-800 bg-slate-950/50 p-4 space-y-3">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div>
                    <h3 className="flex items-center gap-2 text-sm font-semibold text-slate-100">
                      <Gauge className="h-4 w-4 text-sky-300" />
                      CPU、内存与磁盘 I/O 自动保护
                    </h3>
                    <p className="mt-1 text-[11px] text-slate-400">显示触发依据、已读回限额与恢复进度；保护信号不等于客户滥用认定。</p>
                  </div>
                  <span className="rounded-full border border-slate-700 bg-slate-900 px-2 py-1 text-[10px] text-slate-300">仅 Incus / Podman</span>
                </div>

                <div className="grid grid-cols-1 gap-3 lg:grid-cols-2 2xl:grid-cols-3">
                  <div className={`min-w-0 rounded-lg border p-3 space-y-2 ${guardTone(cpuGuard?.state)}`}>
                    <div className="flex items-center justify-between gap-2">
                      <span className="flex items-center gap-1.5 text-xs font-semibold"><Cpu className="h-3.5 w-3.5" />CPU 保护</span>
                      <span className="rounded-full border border-current/20 px-2 py-0.5 text-[10px]">{guardStateLabel(cpuGuard?.state)}</span>
                    </div>
                    <p className="text-[11px] leading-relaxed text-slate-300">
                      当前 {formatMetricPercent(cpuGuardCurrent)}
                      {cpuGuard?.effective_cpus ? ` · 配额容量 ${fmtNumber(cpuGuard.effective_cpus, 2)} 核` : ''}
                      {cpuGuard?.host_busy_percent !== undefined && cpuGuard.host_busy_percent !== null ? ` · 母鸡忙碌 ${fmtNumber(cpuGuard.host_busy_percent, 1)}%` : ''}
                      {cpuGuard?.host_cpu_psi_some_avg10 != null ? ` · 母鸡 CPU PSI ${fmtNumber(cpuGuard.host_cpu_psi_some_avg10, 2)}%` : cpuGuard?.host_pressure_basis === 'host_busy_psi_unavailable_fallback' ? ' · PSI 不可用，按母鸡忙碌率兼容判断' : ''}
                    </p>
                    {cpuGuard?.state === 'watching' && (
                      <p className="text-[11px] text-amber-200">持续高占用 {cpuGuard.high_samples ?? '—'}/{cpuGuard.required_samples ?? '—'} 次，已观察 {formatMinutes(cpuGuard.confirmed_duration_seconds)}。</p>
                    )}
                    {['limited', 'limit_unverified', 'limited_unverified', 'limit_failed', 'restore_failed', 'escalating', 'restoring'].includes(cpuGuard?.state || '') && (
                      <div className="rounded-md border border-slate-700/80 bg-slate-950/50 p-2 text-[11px] space-y-1">
                        <p>原限额：<span className="font-mono text-slate-100">{cpuGuard?.original_limit || '未记录'}</span></p>
                        <p>策略目标：<span className="font-mono text-slate-100">{cpuGuard?.expected_limit || cpuGuard?.active_limit || '等待读回'}</span>{cpuGuard?.tier ? ` · 第 ${cpuGuard.tier} 阶（约原容量 ${cpuGuard.tier_percent_of_original ?? '-'}%）` : ''}</p>
                        <p>内核当前读回：<span className="font-mono text-slate-100">{cpuGuard?.actual_limit || '暂不可读'}</span> · {cpuGuard?.readback_confirmed ? `已核实${cpuGuard.readback_confirmed_at ? ` · ${new Date(cpuGuard.readback_confirmed_at * 1000).toLocaleString('zh-CN', { hour12: false })}` : ''}` : '尚未确认目标值'}</p>
                        <p>恢复条件：低占用连续 {cpuGuard?.recovery_samples ?? '—'}/{cpuGuard?.recovery_samples_required ?? '—'} 次，观察窗口 {formatMinutes(cpuGuard?.recovery_duration_seconds)}。</p>
                      </div>
                    )}
                    {cpuGuard?.top_process?.process && (
                      <p className="text-[11px] text-slate-300">主要进程：<span className="font-mono text-sky-200">{cpuGuard.top_process.process}</span>{cpuGuard.top_process.pid ? ` · PID ${cpuGuard.top_process.pid}` : ''}{cpuGuard.top_process.cpu_percent !== undefined ? ` · ${fmtNumber(cpuGuard.top_process.cpu_percent, 1)}%` : ''}</p>
                    )}
                    <p className="text-[11px] leading-relaxed text-slate-400">{cpuGuard?.message || cpuGuard?.action?.message || (cpuGuard?.state === 'normal' ? '当前未达到持续保护条件。' : '等待 Agent 采样与读回状态。')}</p>
                    {cpuGuard?.recheck_interval_seconds ? <p className="text-[10px] text-slate-500">每约 {formatMinutes(cpuGuard.recheck_interval_seconds)} 复查一次。</p> : null}
                  </div>

                  <div className={`min-w-0 rounded-lg border p-3 space-y-2 ${guardTone(memoryGuard?.state)}`}>
                    <div className="flex items-center justify-between gap-2">
                      <span className="flex items-center gap-1.5 text-xs font-semibold"><Activity className="h-3.5 w-3.5" />内存保护</span>
                      <span className="rounded-full border border-current/20 px-2 py-0.5 text-[10px]">{guardStateLabel(memoryGuard?.state)}</span>
                    </div>
                    <p className="text-[11px] leading-relaxed text-slate-300">
                      当前 {memoryGuard?.memory_current_bytes != null ? fmtBytes(memoryGuard.memory_current_bytes) : '未知'}
                      {memoryGuard?.memory_max_bytes != null ? ` / ${fmtBytes(memoryGuard.memory_max_bytes)}` : ' / 未设上限'}
                      {memoryGuard?.memory_used_percent != null ? ` · ${fmtNumber(memoryGuard.memory_used_percent, 1)}%` : ''}
                    </p>
                    <p className="text-[11px] text-slate-300">
                      内存 PSI：母鸡 {memoryGuard?.host_psi_some_avg10 != null ? `${fmtNumber(memoryGuard.host_psi_some_avg10, 1)}%` : '不可用'}
                      {' · '}容器 {memoryGuard?.container_psi_some_avg10 != null ? `${fmtNumber(memoryGuard.container_psi_some_avg10, 1)}%` : '不可用'}
                    </p>
                    {memoryGuard?.state === 'watching' && (
                      <p className="text-[11px] text-amber-200">高内存与 PSI 持续 {memoryGuard.high_samples ?? '—'}/{memoryGuard.required_samples ?? '—'} 次，已观察 {formatMinutes(memoryGuard.confirmed_duration_seconds)}。</p>
                    )}
                    {['active', 'applying', 'escalating', 'restoring', 'restore_failed', 'apply_unverified'].includes(memoryGuard?.state || '') && (
                      <div className="rounded-md border border-slate-700/80 bg-slate-950/50 p-2 text-[11px] space-y-1">
                        <p>原 memory.high：<span className="font-mono text-slate-100">{formatMemoryHigh(memoryGuard?.original_limit)}</span></p>
                        <p>当前 memory.high：<span className="font-mono text-slate-100">{formatMemoryHigh(memoryGuard?.active_limit)}</span>{memoryGuard?.tier ? ` · 第 ${memoryGuard.tier} 阶（约 memory.max 的 ${memoryGuard.tier_percent_of_max ?? '-'}%）` : ''}</p>
                        <p>恢复条件：低 PSI 连续 {memoryGuard?.recovery_samples ?? '—'}/{memoryGuard?.recovery_samples_required ?? '—'} 次，观察窗口 {formatMinutes(memoryGuard?.recovery_duration_seconds)}。</p>
                      </div>
                    )}
                    {memoryGuard?.state === 'cooldown' && memoryGuard.retry_after_seconds ? (
                      <p className="text-[11px] text-amber-200">原限额已恢复，约 {formatMinutes(memoryGuard.retry_after_seconds)} 后重新评估。</p>
                    ) : null}
                    <p className="text-[11px] leading-relaxed text-slate-400">{memoryGuard?.message || (memoryGuard?.state === 'normal' ? '当前未达到持续内存压力保护条件。' : '等待 Agent 采样与限额读回。')}</p>
                  </div>

                  <div className={`min-w-0 rounded-lg border p-3 space-y-2 ${guardTone(ioGuard?.state)}`}>
                    <div className="flex items-center justify-between gap-2">
                      <span className="flex items-center gap-1.5 text-xs font-semibold"><HardDrive className="h-3.5 w-3.5" />磁盘 I/O 保护</span>
                      <span className="rounded-full border border-current/20 px-2 py-0.5 text-[10px]">{guardStateLabel(ioGuard?.state)}</span>
                    </div>
                    <p className="text-[11px] leading-relaxed text-slate-300">
                      {ioGuard?.device ? `设备 ${ioGuard.device}` : '设备待识别'}
                      {ioGuard?.device_busy_percent !== undefined && ioGuard.device_busy_percent !== null ? ` · 磁盘忙碌 ${fmtNumber(ioGuard.device_busy_percent, 1)}%` : ''}
                      {ioGuard?.host_io_psi_some_avg10 != null ? ` · 母鸡 I/O PSI ${fmtNumber(ioGuard.host_io_psi_some_avg10, 2)}%` : ioGuard?.host_pressure_basis === 'device_busy_fallback_psi_unavailable' ? ' · PSI 不可用，按设备忙碌率兼容判断' : ''}
                      {ioGuard?.dominant_share_percent !== undefined ? ` · 容器占比 ${fmtNumber(ioGuard.dominant_share_percent, 1)}%` : ''}
                    </p>
                    {ioGuard?.state === 'watching' && (
                      <p className="text-[11px] text-amber-200">持续压力 {ioGuard.sample_count ?? '—'}/{ioGuard.required_samples ?? '—'} 次，已观察 {formatMinutes(ioGuard.confirmed_duration_seconds)}。</p>
                    )}
                    {['active', 'applying', 'escalating', 'restoring', 'restore_failed', 'retry_wait'].includes(ioGuard?.state || '') && (
                      <div className="rounded-md border border-slate-700/80 bg-slate-950/50 p-2 text-[11px] space-y-1">
                        <p>原 I/O 限额：<span className="font-mono text-slate-100">{formatIoLimit(ioGuard?.original_limit)}</span></p>
                        <p>策略目标：<span className="font-mono text-slate-100">{formatIoLimit(ioGuard?.expected_limit || ioGuard?.active_limit)}</span>{ioGuard?.tier ? ` · 第 ${ioGuard.tier} 阶（约基线 ${ioGuard.tier_percent_of_baseline ?? '-'}%）` : ''}</p>
                        <p>内核当前读回：<span className="font-mono text-slate-100">{ioGuard?.actual_limit ? formatIoLimit(ioGuard.actual_limit) : '暂不可读'}</span> · {ioGuard?.readback_confirmed ? `已核实${ioGuard.readback_confirmed_at ? ` · ${new Date(ioGuard.readback_confirmed_at * 1000).toLocaleString('zh-CN', { hour12: false })}` : ''}` : '尚未确认目标值'}</p>
                        <p>恢复条件：低压力连续 {ioGuard?.recovery_samples ?? '—'}/{ioGuard?.recovery_samples_required ?? '—'} 次，观察窗口 {formatMinutes(ioGuard?.recovery_duration_seconds)}。</p>
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
                <div className="rounded-lg border border-slate-800 bg-slate-950/40 p-3 text-[11px] text-slate-300">
                  <p className="font-semibold text-slate-200">PSI 等待压力（近 10 秒）</p>
                  <p className="mt-1">母鸡 CPU / 内存 / 磁盘 I/O：{psiPercent(resourcePressure?.host, 'cpu')} · {psiPercent(resourcePressure?.host, 'memory')} · {psiPercent(resourcePressure?.host, 'io')}</p>
                  <p>容器 CPU / 内存 / 磁盘 I/O：{psiPercent(resourcePressure?.container, 'cpu')} · {psiPercent(resourcePressure?.container, 'memory')} · {psiPercent(resourcePressure?.container, 'io')}</p>
                  <p className="mt-1 text-sky-200">{resourcePressure?.explanation || resourcePressure?.container?.reason || '等待新版 Agent 上报 PSI；部分旧内核或 cgroup 配置不提供该指标。'}</p>
                  <p className="mt-1 text-slate-500">PSI 表示任务因资源压力而等待的时间比例；它辅助区分持续计算与资源争用，不用于认定用户行为。</p>
                </div>
              </section>
            )}

            {container && isGuardRuntime && (
              <section className="rounded-xl border border-slate-800 bg-slate-950/50 p-4 space-y-3" aria-label="VMess 与 Trojan 协议管控">
                <div>
                  <h3 className="flex items-center gap-2 text-sm font-semibold text-slate-100">
                    <Shield className="h-4 w-4 text-violet-300" />
                    VMess / Trojan 阻断状态
                  </h3>
                  <p className="mt-1 text-[11px] text-slate-400">区分已读回阻断、部分阻断和待核验端点；缺少 Agent 状态时不会显示为已阻断。</p>
                </div>
                <div className="grid gap-3 md:grid-cols-2">
                  <ProtocolGuardCard label="VMess" summary={sec.vmess_guard} />
                  <ProtocolGuardCard label="Trojan" summary={sec.trojan_guard} />
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
                      {container?.tcp_rx_bps == null ? '—' : `${fmtMbps(container.tcp_rx_bps)} Mbps`}
                    </span>
                    <span className="flex items-center text-sky-400" title="TCP 出栈速率">
                      <ArrowUpRight className="h-3.5 w-3.5 mr-0.5" />
                      {container?.tcp_tx_bps == null ? '—' : `${fmtMbps(container.tcp_tx_bps)} Mbps`}
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
                      {container?.udp_rx_bps == null ? '—' : `${fmtMbps(container.udp_rx_bps)} Mbps`}
                    </span>
                    <span className="flex items-center text-sky-400" title="UDP 出栈速率">
                      <ArrowUpRight className="h-3.5 w-3.5 mr-0.5" />
                      {container?.udp_tx_bps == null ? '—' : `${fmtMbps(container.udp_tx_bps)} Mbps`}
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
                        {hy2ConfidenceLabel}
                      </span>
                    )}
                  </div>
                  <div className="text-[11px] mt-1">
                    {container?.security?.hy2_protocol?.detected || container?.alerts?.hy2_detected ? (
                      <div>
                        <span>UDP 并发：{container?.security?.hy2_protocol?.udp_concurrency ?? container?.alerts?.hy2_concurrency ?? '—'}</span>
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
                          {udpThrottleRate == null ? '限速生效中（速率未知）' : `限速生效中: ${udpThrottleRate} Mbps`}
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
                          <span>剩余冷却时间：{udpThrottleRemaining == null ? '未知' : `约 ${Math.ceil(udpThrottleRemaining / 60)} 分钟`}</span>
                          <span>24h 限速触发：{udpThrottleCount == null ? '未知' : `${udpThrottleCount} 次`}</span>
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
                        当前未触发 UDP 限速，限速状态以 Agent 回报为准。
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
