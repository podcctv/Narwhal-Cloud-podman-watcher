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
  Snowflake,
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
import { ContainerResourceLimitControls } from './ContainerResourceLimitControls';
import { SocketAbuseEvidence, extractSocketAbuseAssessment } from '../alerts/SocketAbuseEvidence';
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

type DrawerSectionId =
  | 'drawer-sec-resources'
  | 'drawer-sec-admission'
  | 'drawer-sec-compliance'
  | 'drawer-sec-evidence'
  | 'drawer-sec-diagnostic';

const DRAWER_SECTIONS: Array<{ id: DrawerSectionId; label: string }> = [
  { id: 'drawer-sec-resources', label: '资源监控' },
  { id: 'drawer-sec-admission', label: '网络准入' },
  { id: 'drawer-sec-compliance', label: '服务合规' },
  { id: 'drawer-sec-evidence', label: '连接证据' },
  { id: 'drawer-sec-diagnostic', label: '实时诊断' },
];

const RESOURCE_GUARD_STATES: Record<string, string> = {
  normal: '正常',
  watching: '持续采样中',
  waiting_for_host_pressure: '等待母鸡压力佐证',
  waiting_for_host_psi: '等待母鸡 PSI 佐证',
  waiting_for_pressure: '等待内存压力',
  waiting_for_other_limit: '等待其他资源保护结束',
  limited: '限额已读回确认',
  manual_limited: '主动限额已读回',
  active: '限额已读回确认',
  limit_failed: '限额未确认',
  apply_failed: '限额应用失败',
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
  if (['limited', 'manual_limited', 'active'].includes(state || '')) return 'border-[#9ccaff] bg-[#e8f3ff]/75 text-[#0657b8]';
  if ([
    'limit_failed',
    'apply_failed',
    'limited_unverified',
    'limit_unverified',
    'restore_failed',
    'state_unavailable',
    'sampling_unavailable',
    'limit_readback_unavailable',
    'orphaned_cgroup',
    'unavailable',
    'apply_unverified',
  ].includes(state || '')) {
    return 'border-[#f1b4bf] bg-[#ffeef1] text-[#b41835]';
  }
  if ([
    'watching',
    'waiting_for_host_pressure',
    'waiting_for_host_psi',
    'waiting_for_pressure',
    'applying',
    'escalating',
    'restoring',
    'waiting_for_other_limit',
    'retry_wait',
    'warming',
    'cooldown',
    'psi_unavailable',
  ].includes(state || '')) {
    return 'border-[#e8bf70] bg-[#fef6e4] text-[#9a5b00]';
  }
  if (['normal', 'restored', 'manual_reset'].includes(state || '')) {
    return 'border-[#b4e4dc] bg-[#e6f7f4]/75 text-[#147468]';
  }
  return 'border-[#cedae7] bg-[#f4f8fd] text-[#31485e]';
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

const formatIoLimit = (value?: string | Record<string, string>) => {
  if (!value) return '暂无读回数据';
  if (typeof value === 'string') {
    const trimmed = value.trim();
    if (!trimmed) return '暂无读回数据';
    const parsed: Record<string, string> = {};
    for (const tok of trimmed.split(/\s+/)) {
      const [k, v] = tok.split('=');
      if (k && v) parsed[k] = v;
    }
    if (!parsed.rbps && !parsed.wbps && !parsed.riops && !parsed.wiops) {
      return trimmed;
    }
    return `读 ${formatIoRate(parsed.rbps)} · 写 ${formatIoRate(parsed.wbps)} · 读 IOPS ${formatIoCount(parsed.riops)} · 写 IOPS ${formatIoCount(parsed.wiops)}`;
  }
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
  if (!summary) return { label: '未上报管控状态', tone: 'border-[#cedae7] bg-[#eef3f9] text-[#31485e]' };
  switch (summary.state) {
    case 'blocked':
      return { label: '阻断已核验', tone: 'border-[#b4e4dc] bg-[#e6f7f4] text-[#147468]' };
    case 'partial':
      return { label: '部分阻断', tone: 'border-[#f1b4bf] bg-[#ffeef1] text-[#b41835]' };
    case 'unverified':
      return summary.detected
        ? { label: '阻断待核验', tone: 'border-[#e8bf70] bg-[#fef6e4] text-[#9a5b00]' }
        : { label: '未检测到 (扫描待核验)', tone: 'border-[#cedae7] bg-[#eef3f9] text-[#31485e]' };
    case 'release_pending':
      return { label: '放行待核验', tone: 'border-[#e8bf70] bg-[#fef6e4] text-[#9a5b00]' };
    case 'not_detected':
      return summary.detected
        ? { label: '检测状态冲突', tone: 'border-[#e8bf70] bg-[#fef6e4] text-[#9a5b00]' }
        : { label: '未检测到目标协议', tone: 'border-[#cedae7] bg-[#eef3f9] text-[#31485e]' };
    default:
      return {
        label: summary.state ? '状态待核实' : '未上报管控状态',
        tone: 'border-[#cedae7] bg-[#eef3f9] text-[#31485e]',
      };
  }
};

const endpointReasonLabels: Record<string, string> = {
  shared_configured_port: '共用配置端口 (防误杀)',
  shared_live_listener: '共用监听端口 (防误杀)',
  live_listener_not_confirmed: '实时监听未匹配',
  listener_protocol_or_owner_ambiguous: '协议或进程归属不明确',
  process_start_generation_unavailable: '进程代次待核验',
  process_changed_during_config_scan: '进程在扫描期间变化',
  config_not_known_before_process_start: '配置在进程启动后更新',
  configuration_scan_incomplete: '配置扫描不完整',
  listener_inventory_incomplete: '实时监听清单不完整',
  container_namespace_unavailable: '网络命名空间不可用',
  container_namespace_changed: '网络命名空间已变化',
  previous_guard_rule_preserved: '保留旧阻断规则',
  firewall_permission_denied: '缺少防火墙权限',
  firewall_kernel_unsupported: '内核规则不支持',
  firewall_apply_failed: '规则下发失败',
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
  const endpoints: Array<{
    status: string;
    proto?: string;
    port?: number;
    pid?: number;
    process?: string;
    reason?: string;
  }> = [
    ...(blocked || []).map((endpoint) => ({ ...endpoint, status: '已阻断' })),
    ...(pending || []).map((endpoint) => ({ ...endpoint, status: '待核验' })),
  ];

  return (
    <article className="min-w-0 space-y-2 rounded-xl border border-[#d2dfec] bg-[#f4f8fd] p-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h4 className="text-xs font-extrabold text-[#0e233c]">{label}</h4>
        <span className={`rounded-full border px-2 py-0.5 text-[10px] font-bold ${state.tone}`}>{state.label}</span>
      </div>
      <p className="text-[11px] font-medium text-[#4a607a]">
        配置端点 {configured?.length ?? '—'} · 已阻断 {blocked?.length ?? '—'} · 待核验 {pending?.length ?? '—'}
      </p>
      {summary?.reason && <p className="text-[11px] leading-relaxed text-[#31485e]">{summary.reason}</p>}
      {endpoints.length > 0 && (
        <ul className="space-y-1 border-t border-[#d2dfec] pt-2 text-[10px] text-[#0b1636]">
          {endpoints.map((endpoint, index) => {
            const reasonText = endpoint.reason ? (endpointReasonLabels[endpoint.reason] || endpoint.reason) : '';
            return (
              <li
                key={`${endpoint.status}-${endpoint.proto || ''}-${endpoint.port || 0}-${endpoint.pid || 0}-${index}`}
                className="flex min-w-0 items-start justify-between gap-2"
              >
                <span className="min-w-0 break-all font-mono">
                  {formatProtocolEndpoint(endpoint)}
                  {reasonText && (
                    <span className="ml-1.5 font-sans text-[9px] text-[#4a607a]" title={`待核实原因代号: ${endpoint.reason}`}>
                      ({reasonText})
                    </span>
                  )}
                </span>
                <span className={endpoint.status === '已阻断' ? 'shrink-0 font-bold text-[#147468]' : 'shrink-0 font-bold text-[#9a5b00]'}>
                  {endpoint.status}
                </span>
              </li>
            );
          })}
        </ul>
      )}
      {evidenceItems.length > 0 && (
        <dl className="grid gap-1.5 border-t border-[#d2dfec] pt-2 text-[10px] sm:grid-cols-2">
          {evidenceItems.map(([name, value]) => (
            <div key={name} className="min-w-0">
              <dt className="font-semibold text-[#4a607a]">{name}</dt>
              <dd className="break-words text-[#0b1636]">{value}</dd>
            </div>
          ))}
        </dl>
      )}
      {!summary && (
        <p className="text-[10px] text-[#4a607a]">
          当前容器数据未提供此协议的管控结果，不能据此判断为已阻断或未检测到。
        </p>
      )}
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
  const [pendingDecision, setPendingDecision] = useState<
    | 'deny'
    | 'allow_silent'
    | 'resolve'
    | 'release_udp_throttle'
    | 'freeze_container'
    | 'unfreeze_container'
    | 'apply_udp_blackhole'
    | 'release_udp_blackhole'
    | null
  >(null);
  const [userEmail, setUserEmail] = useState('');
  const [userNote, setUserNote] = useState('');
  const [isSavingUserNote, setIsSavingUserNote] = useState(false);
  const [activeAnchor, setActiveAnchor] = useState<DrawerSectionId>('drawer-sec-resources');

  const drawerPanelRef = useRef<HTMLDivElement>(null);
  const drawerBodyRef = useRef<HTMLDivElement>(null);
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

  const jumpToSection = (sectionId: DrawerSectionId) => {
    setActiveAnchor(sectionId);
    const target = drawerBodyRef.current?.querySelector<HTMLElement>(`#${sectionId}`);
    if (!target) return;
    const reduceMotion = typeof window !== 'undefined' && window.matchMedia?.('(prefers-reduced-motion: reduce)').matches;
    target.scrollIntoView({ behavior: reduceMotion ? 'auto' : 'smooth', block: 'start' });
  };

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
    decision: 'deny' | 'allow_silent' | 'resolve' | 'release_udp_throttle' | 'freeze_container' | 'unfreeze_container' | 'apply_udp_blackhole' | 'release_udp_blackhole' | string
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
          ? (res.queued ? '恢复指令已下发节点执行' : '已解除 UDP 限速')
          : decision === 'freeze_container'
          ? (res.queued ? '挂起冻结指令已下发节点' : '容器进程已成功挂起冻结')
          : decision === 'unfreeze_container'
          ? (res.queued ? '解除冻结指令已下发节点' : '容器已解除冻结恢复运行')
          : decision === 'apply_udp_blackhole'
          ? (res.queued ? 'UDP 黑洞指令已下发节点' : '出站 UDP 专项阻断已生效')
          : decision === 'release_udp_blackhole'
          ? (res.queued ? '解除 UDP 黑洞指令已下发' : '出站 UDP 阻断已解除')
          : '已成功应用操作'
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

  const isGuardRuntime = identity.runtime === 'incus' || identity.runtime === 'podman' || identity.runtime === 'runman';
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
    ? { title: '确认解除 UDP 限速？', description: `将移除 ${identity.container_name} 的 Linux tc 限速规则并恢复全速。`, confirmLabel: '解除限速', tone: 'primary' as const }
    : pendingDecision === 'freeze_container'
    ? { title: '确认挂起冻结容器进程？', description: `将通过 cgroup v2 挂起 ${identity.container_name} 的全部线程，不杀死进程，内存现场与取证状态完好保留。`, confirmLabel: '挂起冻结', tone: 'danger' as const }
    : pendingDecision === 'unfreeze_container'
    ? { title: '确认解除冻结恢复运行？', description: `将通过 cgroup v2 唤醒 ${identity.container_name} 的全部挂起进程恢复正常运行。`, confirmLabel: '解除冻结', tone: 'primary' as const }
    : pendingDecision === 'apply_udp_blackhole'
    ? { title: '确认实施出站 UDP 专项阻断？', description: `将在 ${identity.container_name} 的网络命名空间中定向丢弃出站 UDP 流量，保留 TCP/SSH 正常入站与管理。`, confirmLabel: '实施 UDP 阻断', tone: 'danger' as const }
    : pendingDecision === 'release_udp_blackhole'
    ? { title: '确认解除出站 UDP 阻断？', description: `将恢复 ${identity.container_name} 的正常出站 UDP 流量。`, confirmLabel: '解除阻断', tone: 'primary' as const }
    : pendingDecision === 'deny'
    ? { title: '确认处置封禁？', description: `对 ${identity.container_name} 确认违规处置，停止违规行为。`, confirmLabel: '确认处置', tone: 'danger' as const }
    : pendingDecision === 'allow_silent'
    ? { title: '确认放行不处置？', description: '当前放行后不再提醒，在告警历史中显示。', confirmLabel: '确认放行', tone: 'primary' as const }
    : { title: '确认标记为已解决？', description: '活动告警将转入历史记录，再次检测到异常时仍会恢复告警。', confirmLabel: '标为已解决', tone: 'primary' as const };

  return (
    <div className="fixed inset-0 z-50 overflow-hidden" role="dialog" aria-modal="true" aria-labelledby="container-drawer-title">
      {/* Backdrop */}
      <div
        onClick={onClose}
        aria-hidden="true"
        className="absolute inset-0 bg-[#02182f]/60 backdrop-blur-xs transition-opacity animate-in fade-in duration-200"
      />

      {/* Slide-over Drawer Panel (RackNerd ctrl. Light-Ice Workspace) */}
      <div className="absolute inset-y-0 right-0 flex max-w-full pl-0 sm:pl-10">
        <div
          ref={drawerPanelRef}
          tabIndex={-1}
          className="flex min-w-0 w-screen max-w-full sm:max-w-2xl flex-col border-l border-[#cedae7] bg-[#f2f7ff] text-[#0b1636] shadow-2xl transition-transform animate-in slide-in-from-right duration-250"
        >
          {/* Sticky Midnight RackNerd Header + Quick-Jump Pills */}
          <div className="sticky top-0 z-20 shrink-0 border-b border-white/10 bg-[linear-gradient(125deg,#163957,#0e233c_58%,#0c1c30)] text-[#e6f4ff] shadow-md">
            <div className="flex items-center justify-between gap-3 px-4 pt-3.5 pb-2.5 sm:px-6 sm:pt-4">
              <div className="flex min-w-0 items-center gap-3">
                <div className="shrink-0 rounded-xl border border-[#54c7ff]/35 bg-[#087bff]/20 p-2.5 text-[#54c7ff]">
                  <Box className="h-5 w-5" aria-hidden="true" />
                </div>
                <div className="min-w-0">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="rounded bg-[#087bff] px-1.5 py-0.5 font-mono text-[10px] font-extrabold tracking-tight text-white">
                      ctrl.
                    </span>
                    <h2 id="container-drawer-title" className="truncate text-base font-extrabold text-white">
                      {identity.container_name}
                    </h2>
                    <StatusBadge
                      status={drawerStatus}
                      label={drawerStatusLabel}
                      size="sm"
                      pulse={drawerStatus === 'healthy'}
                    />
                    <span
                      className={`rounded-full border px-2 py-0.5 font-mono text-[10px] font-bold ${
                        isVersionMatch
                          ? 'border-emerald-400/40 bg-emerald-500/15 text-emerald-200'
                          : 'border-amber-400/40 bg-amber-500/15 text-amber-200'
                      }`}
                    >
                      Agent v{agentVersion}
                    </span>
                  </div>
                  <div className="mt-0.5 flex flex-wrap items-center gap-2 text-xs text-[#b7d6f2]">
                    <span className="font-mono font-semibold">{identity.host_id}</span>
                    <span aria-hidden="true">•</span>
                    <span>
                      {identity.project ? `${identity.runtime}/${identity.project}` : identity.runtime}
                    </span>
                  </div>
                </div>
              </div>

              <button
                ref={closeButtonRef}
                type="button"
                onClick={onClose}
                aria-label="关闭容器详情"
                className="flex h-11 w-11 shrink-0 items-center justify-center rounded-xl border border-white/15 bg-white/10 text-[#e6f4ff] transition-colors hover:bg-white/20 hover:text-white focus:outline-hidden focus:ring-2 focus:ring-[#54c7ff]"
                title="关闭抽屉 (Esc)"
              >
                <X className="h-5 w-5" />
              </button>
            </div>

            {/* Quick-jump section anchor pills */}
            <nav
              aria-label="容器详情分区导航"
              className="flex items-center gap-1.5 overflow-x-auto border-t border-white/10 bg-[#031d3d]/65 px-4 py-2 sm:px-6"
            >
              {DRAWER_SECTIONS.map((secItem) => {
                const isActive = activeAnchor === secItem.id;
                return (
                  <button
                    key={secItem.id}
                    type="button"
                    onClick={() => jumpToSection(secItem.id)}
                    aria-current={isActive ? 'location' : undefined}
                    className={`shrink-0 rounded-full border px-3 py-1 text-[11px] font-bold transition-colors ${
                      isActive
                        ? 'border-[#54c7ff] bg-[#087bff] text-white shadow-xs'
                        : 'border-white/15 bg-white/8 text-[#c9e0f5] hover:border-[#54c7ff]/60 hover:bg-white/15 hover:text-white'
                    }`}
                  >
                    {secItem.label}
                  </button>
                );
              })}
            </nav>
          </div>

          {/* Drawer Scrollable Body */}
          <div ref={drawerBodyRef} className="flex-1 space-y-5 overflow-y-auto p-4 sm:space-y-6 sm:p-6">
            {/* Section 1: 资源监控 */}
            <div id="drawer-sec-resources" className="scroll-mt-4 space-y-5">
              {/* Quick KPI Cards Grid */}
              <div className="grid grid-cols-1 gap-2.5 font-mono text-xs sm:grid-cols-3 sm:gap-3">
                <div className="overflow-hidden rounded-[14px] border border-[#cedae7] bg-white shadow-xs">
                  <div className="flex items-center gap-1.5 border-b border-[#d2dfec] bg-[#f4f8fd] px-3 py-2 font-sans text-[11px] font-extrabold uppercase tracking-wider text-[#0657b8]">
                    <Cpu className="h-3.5 w-3.5 text-[#087bff]" aria-hidden="true" /> CPU 占用
                  </div>
                  <div className="p-3">
                    <span className="text-xl font-extrabold text-[#0b1636] tabular-nums">
                      {formatMetricPercent(container?.cpu_percent)}
                    </span>
                  </div>
                </div>

                <div className="overflow-hidden rounded-[14px] border border-[#cedae7] bg-white shadow-xs">
                  <div className="flex items-center gap-1.5 border-b border-[#d2dfec] bg-[#f4f8fd] px-3 py-2 font-sans text-[11px] font-extrabold uppercase tracking-wider text-[#147468]">
                    <HardDrive className="h-3.5 w-3.5 text-[#147468]" aria-hidden="true" /> 内存使用
                  </div>
                  <div className="p-3">
                    <span className="text-xl font-extrabold text-[#0b1636] tabular-nums">
                      {formatMetricPercent(container?.mem_percent)}
                    </span>
                    <span className="mt-0.5 block truncate text-[10px] font-semibold text-[#4a607a] tabular-nums">
                      {formatMetricBytes(container?.mem_bytes)} / {formatMetricBytes(container?.mem_limit_bytes)}
                    </span>
                  </div>
                </div>

                <div
                  className={`overflow-hidden rounded-[14px] border shadow-xs ${
                    inIpAlert
                      ? 'border-[#f1b4bf] bg-[#ffeef1] text-[#b41835]'
                      : 'border-[#cedae7] bg-white'
                  }`}
                >
                  <div
                    className={`flex items-center gap-1.5 border-b px-3 py-2 font-sans text-[11px] font-extrabold uppercase tracking-wider ${
                      inIpAlert
                        ? 'border-[#f1b4bf] bg-[#fddce2] text-[#b41835]'
                        : 'border-[#d2dfec] bg-[#f4f8fd] text-[#9a5b00]'
                    }`}
                  >
                    <Network className="h-3.5 w-3.5 text-[#ff6b00]" aria-hidden="true" /> 入站去重 IP
                  </div>
                  <div className="p-3">
                    <span className={`text-xl font-extrabold tabular-nums ${inIpAlert ? 'text-[#b41835]' : 'text-[#0b1636]'}`}>
                      {inIps ?? (sec.communication_detail_available === false ? '不可用' : '—')}
                    </span>
                    <span className={`mt-0.5 block text-[10px] font-semibold tabular-nums ${inIpAlert ? 'text-[#881337]' : 'text-[#4a607a]'}`}>
                      阈值：{inThresh} IPs
                    </span>
                  </div>
                </div>
              </div>

              {identity.runtime === 'runman' && (
                <section className="rn2-card bg-white p-4" aria-label="Runman 可写层占用">
                  <div className="flex items-center gap-2 text-sm font-extrabold text-[#0e233c]">
                    <HardDrive className="h-4 w-4 text-[#087bff]" aria-hidden="true" />
                    Runman 可写层占用
                  </div>
                  <p className="mt-2 font-mono text-sm font-bold tabular-nums text-[#0b1636]">
                    {container?.container_disk_rw_available
                      ? container.container_disk_rw_logical_available
                        ? `${formatMetricBytes(container.container_disk_rw_logical_file_bytes)} / ${formatMetricBytes(container.container_disk_rw_bytes)}`
                        : `逻辑文件量不可用 · ${formatMetricBytes(container.container_disk_rw_bytes)}`
                      : '当前样本不可用'}
                  </p>
                  <p className="mt-1 text-[11px] text-[#4a607a]">
                    普通文件逻辑内容 / upperdir 已分配块；不含目录、符号链接、xattr 和 whiteout 归档开销，与 Podman SizeRw 不保证逐字节等价。
                  </p>
                </section>
              )}

              {identity.runtime === 'runman' && (
                <section className="rn2-card bg-white p-4" aria-label="Runman 磁盘镜像占用">
                  <div className="flex items-center gap-2 text-sm font-extrabold text-[#0e233c]">
                    <HardDrive className="h-4 w-4 text-[#147468]" aria-hidden="true" />
                    Runman 磁盘镜像占用
                  </div>
                  <p className="mt-2 font-mono text-sm font-bold tabular-nums text-[#0b1636]">
                    {container?.container_disk_backing_image_available
                      ? `${formatMetricBytes(container.container_disk_backing_image_allocated_bytes)} / ${formatMetricBytes(container.container_disk_backing_image_logical_bytes)}`
                      : '当前样本不可用'}
                  </p>
                  <p className="mt-1 text-[11px] text-[#4a607a]">
                    已分配块 / 镜像逻辑容量；该值来自宿主机 disk.img 文件分配量。
                  </p>
                </section>
              )}

              {/* Visual Charts: CPU & Memory */}
              <div className="rn2-card bg-white p-4">
                <h3 className="mb-2 flex items-center gap-2 text-xs font-extrabold text-[#0e233c]">
                  <Activity className="h-4 w-4 text-[#087bff]" aria-hidden="true" />
                  <span>CPU 与内存历史趋势 (24h)</span>
                </h3>
                <ResourceChart history={history} />
              </div>

              {/* Visual Charts: Network Bandwidth */}
              <div className="rn2-card bg-white p-4">
                <h3 className="mb-2 flex items-center gap-2 text-xs font-extrabold text-[#0e233c]">
                  <Network className="h-4 w-4 text-[#147468]" aria-hidden="true" />
                  <span>实时吞吐速率趋势 (RX & TX)</span>
                </h3>
                <NetworkChart history={history} />
              </div>

              {/* Protocol Breakdown & Traffic Symmetry */}
              <div className="rn2-card space-y-3 bg-white p-4">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <h3 className="flex items-center gap-2 text-xs font-extrabold text-[#0e233c]">
                    <Activity className="h-4 w-4 text-[#087bff]" aria-hidden="true" />
                    <span>协议流量拆分与流量对称性</span>
                  </h3>
                  {container?.alerts?.traffic_imbalance ? (
                    <span className="flex items-center gap-1 rounded-full border border-[#f1b4bf] bg-[#ffeef1] px-2.5 py-0.5 text-[11px] font-bold text-[#b41835]">
                      <ArrowUpDown className="h-3 w-3" aria-hidden="true" />
                      <span>
                        入出失衡 {container.alerts.traffic_imbalance_ratio}x (
                        {container.alerts.traffic_imbalance_direction === 'outbound_heavy' ? '出栈偏高' : '入栈偏高'})
                      </span>
                    </span>
                  ) : (
                    <span className="flex items-center gap-1 rounded-full border border-[#b4e4dc] bg-[#e6f7f4] px-2.5 py-0.5 text-[11px] font-bold text-[#147468]">
                      <CheckCircle2 className="h-3 w-3" aria-hidden="true" />
                      <span>入出栈流量均衡</span>
                    </span>
                  )}
                </div>

                <div className="grid grid-cols-1 gap-3 font-mono text-xs sm:grid-cols-3">
                  {/* TCP Traffic Card */}
                  <div className="rounded-xl border border-[#d2dfec] bg-[#f4f8fd] p-3">
                    <span className="mb-1 block font-sans text-[11px] font-bold text-[#0657b8]">
                      TCP 协议流量
                    </span>
                    <div className="flex items-center justify-between text-[#0b1636]">
                      <span className="flex items-center font-bold text-[#147468]" title="TCP 入栈速率">
                        <ArrowDownLeft className="mr-0.5 h-3.5 w-3.5" aria-hidden="true" />
                        {container?.tcp_rx_bps == null ? '—' : `${fmtMbps(container.tcp_rx_bps)} Mbps`}
                      </span>
                      <span className="flex items-center font-bold text-[#087bff]" title="TCP 出栈速率">
                        <ArrowUpRight className="mr-0.5 h-3.5 w-3.5" aria-hidden="true" />
                        {container?.tcp_tx_bps == null ? '—' : `${fmtMbps(container.tcp_tx_bps)} Mbps`}
                      </span>
                    </div>
                  </div>

                  {/* UDP Traffic Card */}
                  <div className="rounded-xl border border-[#d2dfec] bg-[#f4f8fd] p-3">
                    <span className="mb-1 block font-sans text-[11px] font-bold text-[#4b3da5]">
                      UDP 协议流量
                    </span>
                    <div className="flex items-center justify-between text-[#0b1636]">
                      <span className="flex items-center font-bold text-[#147468]" title="UDP 入栈速率">
                        <ArrowDownLeft className="mr-0.5 h-3.5 w-3.5" aria-hidden="true" />
                        {container?.udp_rx_bps == null ? '—' : `${fmtMbps(container.udp_rx_bps)} Mbps`}
                      </span>
                      <span className="flex items-center font-bold text-[#087bff]" title="UDP 出栈速率">
                        <ArrowUpRight className="mr-0.5 h-3.5 w-3.5" aria-hidden="true" />
                        {container?.udp_tx_bps == null ? '—' : `${fmtMbps(container.udp_tx_bps)} Mbps`}
                      </span>
                    </div>
                  </div>

                  {/* Hysteria 2 (hy2) Status Card */}
                  <div
                    className={`rounded-xl border p-3 ${
                      container?.security?.hy2_protocol?.detected || container?.alerts?.hy2_detected
                        ? 'border-[#d3c2f7] bg-[#f5f0ff] text-[#4c2889]'
                        : 'border-[#d2dfec] bg-[#f4f8fd] text-[#31485e]'
                    }`}
                  >
                    <div className="mb-1 flex items-center justify-between gap-1">
                      <span className="flex items-center gap-1 font-sans text-[11px] font-bold text-[#5b34b0]">
                        <Radio className="h-3 w-3" aria-hidden="true" />
                        Hysteria 2 协议
                      </span>
                      {(container?.security?.hy2_protocol?.detected || container?.alerts?.hy2_detected) && (
                        <span className="rounded border border-[#c4b1f4] bg-white px-1.5 py-0.5 text-[10px] font-bold text-[#5b34b0]">
                          {hy2ConfidenceLabel}
                        </span>
                      )}
                    </div>
                    <div className="mt-1 text-[11px]">
                      {container?.security?.hy2_protocol?.detected || container?.alerts?.hy2_detected ? (
                        <div>
                          <span className="font-bold">
                            UDP 并发：{container?.security?.hy2_protocol?.udp_concurrency ?? container?.alerts?.hy2_concurrency ?? '—'}
                          </span>
                          {container?.security?.hy2_protocol?.process && (
                            <span className="ml-1.5 text-[#4a607a]">({container.security.hy2_protocol.process})</span>
                          )}
                        </div>
                      ) : (
                        <span className="font-sans text-[#4a607a]">未发现运行特征</span>
                      )}
                    </div>
                  </div>

                  {/* UDP Throttle & Anti-Abuse Control Card */}
                  {(container?.alerts?.udp_throttled || sec.udp_throttle?.throttled || container?.security?.hy2_protocol?.detected || container?.alerts?.hy2_detected) && (
                    <div
                      className={`col-span-1 rounded-xl border p-3 sm:col-span-3 ${
                        container?.alerts?.udp_throttled || sec.udp_throttle?.throttled
                          ? 'border-[#f1b4bf] bg-[#ffeef1] text-[#b41835]'
                          : 'border-[#d2dfec] bg-[#f4f8fd] text-[#31485e]'
                      }`}
                    >
                      <div className="mb-1.5 flex flex-wrap items-center justify-between gap-2">
                        <span className="flex items-center gap-1.5 font-sans text-[11px] font-bold">
                          <Gauge
                            className={`h-3.5 w-3.5 ${
                              container?.alerts?.udp_throttled || sec.udp_throttle?.throttled ? 'text-[#b41835]' : 'text-[#4a607a]'
                            }`}
                            aria-hidden="true"
                          />
                          <span>UDP 流量管控与限速</span>
                        </span>
                        {container?.alerts?.udp_throttled || sec.udp_throttle?.throttled ? (
                          <span className="animate-pulse rounded border border-[#f1b4bf] bg-white px-2 py-0.5 text-[10px] font-extrabold text-[#b41835]">
                            {udpThrottleRate == null ? '限速生效中（速率未知）' : `限速生效中: ${udpThrottleRate} Mbps`}
                          </span>
                        ) : (
                          <span className="rounded border border-[#b4e4dc] bg-[#e6f7f4] px-2 py-0.5 text-[10px] font-bold text-[#147468]">
                            全速运行 (自动防滥用保护中)
                          </span>
                        )}
                      </div>
                      {container?.alerts?.udp_throttled || sec.udp_throttle?.throttled ? (
                        <div className="mt-2 space-y-2 font-sans">
                          <p className="text-[11px] leading-relaxed text-[#881337]">
                            {sec.udp_throttle?.reason || '因持续 3 分钟上下行严重失衡且高 UDP 并发触发靶向限速。已保护 TCP 与 SSH 保持千兆线速。'}
                          </p>
                          <div className="flex flex-wrap items-center justify-between gap-2 border-t border-[#f1b4bf] pt-2 font-mono text-[10px] text-[#881337]">
                            <span>
                              剩余冷却时间：{udpThrottleRemaining == null ? '未知' : `约 ${Math.ceil(udpThrottleRemaining / 60)} 分钟`}
                            </span>
                            <span>24h 限速触发：{udpThrottleCount == null ? '未知' : `${udpThrottleCount} 次`}</span>
                          </div>
                          <div className="pt-1">
                            <button
                              type="button"
                              disabled={isDrawerActionLoading}
                              onClick={() => setPendingDecision('release_udp_throttle')}
                              className="rn2-btn rn2-btn-sm rn2-btn-blue min-h-11 disabled:opacity-50"
                            >
                              <Unlock className="h-3.5 w-3.5" aria-hidden="true" />
                              <span>立即解除限速</span>
                            </button>
                          </div>
                        </div>
                      ) : (
                        <div className="mt-1 font-sans text-[11px] text-[#4a607a]">
                          当前未触发 UDP 限速，限速状态以 Agent 回报为准。
                        </div>
                      )}
                    </div>
                  )}
                </div>
              </div>

              {(identity.runtime === 'incus' || identity.runtime === 'podman' || identity.runtime === 'runman') && (
                <section className="rn2-card space-y-3 bg-white p-4">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div>
                      <h3 className="flex items-center gap-2 text-sm font-extrabold text-[#0e233c]">
                        <Gauge className="h-4 w-4 text-[#087bff]" aria-hidden="true" />
                        CPU、内存与磁盘 I/O 自动保护
                      </h3>
                      <p className="mt-1 text-[11px] text-[#4a607a]">
                        显示触发依据、已读回限额与恢复进度；保护信号不等于客户滥用认定。
                      </p>
                    </div>
                    <span className="rounded-full border border-[#cedae7] bg-[#f4f8fd] px-2.5 py-1 text-[10px] font-bold text-[#31485e]">
                      Incus / Podman / Runman
                    </span>
                  </div>

                  <div className="grid grid-cols-1 gap-3 lg:grid-cols-2 2xl:grid-cols-3">
                    <div className={`min-w-0 space-y-2 rounded-xl border p-3 ${guardTone(cpuGuard?.state)}`}>
                      <div className="flex items-center justify-between gap-2">
                        <span className="flex items-center gap-1.5 text-xs font-extrabold">
                          <Cpu className="h-3.5 w-3.5" aria-hidden="true" />CPU 保护
                        </span>
                        <span className="rounded-full border border-current/25 bg-white/80 px-2 py-0.5 text-[10px] font-bold">
                          {guardStateLabel(cpuGuard?.state)}
                        </span>
                      </div>
                      <p className="text-[11px] leading-relaxed text-[#0b1636]">
                        当前 {formatMetricPercent(cpuGuardCurrent)}
                        {cpuGuard?.effective_cpus ? ` · 配额容量 ${fmtNumber(cpuGuard.effective_cpus, 2)} 核` : ''}
                        {cpuGuard?.host_busy_percent !== undefined && cpuGuard.host_busy_percent !== null
                          ? ` · 母鸡忙碌 ${fmtNumber(cpuGuard.host_busy_percent, 1)}%`
                          : ''}
                        {cpuGuard?.host_cpu_psi_some_avg10 != null
                          ? ` · 母鸡 CPU PSI ${fmtNumber(cpuGuard.host_cpu_psi_some_avg10, 2)}%`
                          : cpuGuard?.host_pressure_basis === 'host_busy_psi_unavailable_fallback'
                            ? ' · PSI 不可用，按母鸡忙碌率兼容判断'
                            : ''}
                      </p>
                      {cpuGuard?.state === 'watching' && (
                        <p className="text-[11px] font-semibold text-[#9a5b00]">
                          持续高占用 {cpuGuard.high_samples ?? '—'}/{cpuGuard.required_samples ?? '—'} 次，已观察{' '}
                          {formatMinutes(cpuGuard.confirmed_duration_seconds)}。
                        </p>
                      )}
                      {['limited', 'manual_limited', 'apply_failed', 'limit_unverified', 'limited_unverified', 'limit_failed', 'restore_failed', 'escalating', 'restoring'].includes(cpuGuard?.state || '') && (
                        <div className="space-y-1 rounded-lg border border-[#d2dfec] bg-white p-2.5 text-[11px] text-[#31485e]">
                          {cpuGuard?.effective_source && cpuGuard.effective_source !== 'none' && (
                            <p>
                              裁决来源：
                              <span className="ml-1 font-bold text-[#0657b8]">
                                {cpuGuard.effective_source === 'auto_over_manual'
                                  ? '主动限制 + 自动保护联合收紧'
                                  : cpuGuard.effective_source === 'manual'
                                  ? `主动限制 (${cpuGuard.manual_mode === 'lock' ? '锁定' : '协同联动'})`
                                  : '自动保护'}
                              </span>
                            </p>
                          )}
                          <p>原限额：<span className="font-mono font-bold text-[#0b1636]">{cpuGuard?.original_limit || '未记录'}</span></p>
                          <p>
                            策略目标：<span className="font-mono font-bold text-[#0b1636]">{cpuGuard?.expected_limit || cpuGuard?.active_limit || '等待读回'}</span>
                            {cpuGuard?.tier ? ` · 第 ${cpuGuard.tier} 阶（约原容量 ${cpuGuard.tier_percent_of_original ?? '-'}%）` : ''}
                          </p>
                          <p>
                            内核当前读回：<span className="font-mono font-bold text-[#0b1636]">{cpuGuard?.actual_limit || '暂不可读'}</span> ·{' '}
                            {cpuGuard?.readback_confirmed
                              ? `已核实${cpuGuard.readback_confirmed_at ? ` · ${new Date(cpuGuard.readback_confirmed_at * 1000).toLocaleString('zh-CN', { hour12: false })}` : ''}`
                              : '尚未确认目标值'}
                          </p>
                          <p>
                            恢复条件：低占用连续 {cpuGuard?.recovery_samples ?? '—'}/{cpuGuard?.recovery_samples_required ?? '—'} 次，观察窗口{' '}
                            {formatMinutes(cpuGuard?.recovery_duration_seconds)}。
                          </p>
                        </div>
                      )}
                      {cpuGuard?.top_process?.process && (
                        <p className="text-[11px] text-[#31485e]">
                          主要进程：<span className="font-mono font-bold text-[#0657b8]">{cpuGuard.top_process.process}</span>
                          {cpuGuard.top_process.pid ? ` · PID ${cpuGuard.top_process.pid}` : ''}
                          {cpuGuard.top_process.cpu_percent !== undefined ? ` · ${fmtNumber(cpuGuard.top_process.cpu_percent, 1)}%` : ''}
                        </p>
                      )}
                      <p className="text-[11px] leading-relaxed text-[#4a607a]">
                        {cpuGuard?.message || cpuGuard?.action?.message || (cpuGuard?.state === 'normal' ? '当前未达到持续保护条件。' : '等待 Agent 采样与读回状态。')}
                      </p>
                      {cpuGuard?.recheck_interval_seconds ? (
                        <p className="text-[10px] text-[#4a607a]">每约 {formatMinutes(cpuGuard.recheck_interval_seconds)} 复查一次。</p>
                      ) : null}
                    </div>

                    <div className={`min-w-0 space-y-2 rounded-xl border p-3 ${guardTone(memoryGuard?.state)}`}>
                      <div className="flex items-center justify-between gap-2">
                        <span className="flex items-center gap-1.5 text-xs font-extrabold">
                          <Activity className="h-3.5 w-3.5" aria-hidden="true" />内存保护
                        </span>
                        <span className="rounded-full border border-current/25 bg-white/80 px-2 py-0.5 text-[10px] font-bold">
                          {guardStateLabel(memoryGuard?.state)}
                        </span>
                      </div>
                      <p className="text-[11px] leading-relaxed text-[#0b1636]">
                        当前 {memoryGuard?.memory_current_bytes != null ? fmtBytes(memoryGuard.memory_current_bytes) : '未知'}
                        {memoryGuard?.memory_max_bytes != null ? ` / ${fmtBytes(memoryGuard.memory_max_bytes)}` : ' / 未设上限'}
                        {memoryGuard?.memory_used_percent != null ? ` · ${fmtNumber(memoryGuard.memory_used_percent, 1)}%` : ''}
                      </p>
                      <p className="text-[11px] text-[#31485e]">
                        内存 PSI：母鸡 {memoryGuard?.host_psi_some_avg10 != null ? `${fmtNumber(memoryGuard.host_psi_some_avg10, 1)}%` : '不可用'}
                        {' · '}容器 {memoryGuard?.container_psi_some_avg10 != null ? `${fmtNumber(memoryGuard.container_psi_some_avg10, 1)}%` : '不可用'}
                      </p>
                      {memoryGuard?.state === 'watching' && (
                        <p className="text-[11px] font-semibold text-[#9a5b00]">
                          高内存与 PSI 持续 {memoryGuard.high_samples ?? '—'}/{memoryGuard.required_samples ?? '—'} 次，已观察{' '}
                          {formatMinutes(memoryGuard.confirmed_duration_seconds)}。
                        </p>
                      )}
                      {['active', 'limited', 'manual_limited', 'apply_failed', 'applying', 'escalating', 'restoring', 'restore_failed', 'apply_unverified'].includes(memoryGuard?.state || '') && (
                        <div className="space-y-1 rounded-lg border border-[#d2dfec] bg-white p-2.5 text-[11px] text-[#31485e]">
                          {memoryGuard?.effective_source && memoryGuard.effective_source !== 'none' && (
                            <p>
                              裁决来源：
                              <span className="ml-1 font-bold text-[#0657b8]">
                                {memoryGuard.effective_source === 'auto_over_manual'
                                  ? '主动限制 + 自动保护联合收紧'
                                  : memoryGuard.effective_source === 'manual'
                                  ? `主动限制 (${memoryGuard.manual_mode === 'lock' ? '锁定' : '协同联动'})`
                                  : '自动保护'}
                              </span>
                            </p>
                          )}
                          <p>原 memory.high：<span className="font-mono font-bold text-[#0b1636]">{formatMemoryHigh(memoryGuard?.original_limit)}</span></p>
                          <p>
                            当前 memory.high：<span className="font-mono font-bold text-[#0b1636]">{formatMemoryHigh(memoryGuard?.active_limit)}</span>
                            {memoryGuard?.tier ? ` · 第 ${memoryGuard.tier} 阶（约 memory.max 的 ${memoryGuard.tier_percent_of_max ?? '-'}%）` : ''}
                          </p>
                          <p>
                            恢复条件：低 PSI 连续 {memoryGuard?.recovery_samples ?? '—'}/{memoryGuard?.recovery_samples_required ?? '—'} 次，观察窗口{' '}
                            {formatMinutes(memoryGuard?.recovery_duration_seconds)}。
                          </p>
                        </div>
                      )}
                      {memoryGuard?.state === 'cooldown' && memoryGuard.retry_after_seconds ? (
                        <p className="text-[11px] font-semibold text-[#9a5b00]">
                          原限额已恢复，约 {formatMinutes(memoryGuard.retry_after_seconds)} 后重新评估。
                        </p>
                      ) : null}
                      <p className="text-[11px] leading-relaxed text-[#4a607a]">
                        {memoryGuard?.message || (memoryGuard?.state === 'normal' ? '当前未达到持续内存压力保护条件。' : '等待 Agent 采样与限额读回。')}
                      </p>
                    </div>

                    <div className={`min-w-0 space-y-2 rounded-xl border p-3 ${guardTone(ioGuard?.state)}`}>
                      <div className="flex items-center justify-between gap-2">
                        <span className="flex items-center gap-1.5 text-xs font-extrabold">
                          <HardDrive className="h-3.5 w-3.5" aria-hidden="true" />磁盘 I/O 保护
                        </span>
                        <span className="rounded-full border border-current/25 bg-white/80 px-2 py-0.5 text-[10px] font-bold">
                          {guardStateLabel(ioGuard?.state)}
                        </span>
                      </div>
                      <p className="text-[11px] leading-relaxed text-[#0b1636]">
                        {ioGuard?.device ? `设备 ${ioGuard.device}` : ioGuard?.state === 'normal' ? '常规读写 (未触发限额)' : '设备待识别'}
                        {ioGuard?.device_busy_percent !== undefined && ioGuard.device_busy_percent !== null
                          ? ` · 磁盘忙碌 ${fmtNumber(ioGuard.device_busy_percent, 1)}%`
                          : ''}
                        {ioGuard?.host_io_psi_some_avg10 != null
                          ? ` · 母鸡 I/O PSI ${fmtNumber(ioGuard.host_io_psi_some_avg10, 2)}%`
                          : ioGuard?.host_pressure_basis === 'device_busy_fallback_psi_unavailable'
                            ? ' · PSI 不可用，按设备忙碌率兼容判断'
                            : ''}
                        {ioGuard?.dominant_share_percent !== undefined ? ` · 容器占比 ${fmtNumber(ioGuard.dominant_share_percent, 1)}%` : ''}
                      </p>
                      {ioGuard?.state === 'watching' && (
                        <p className="text-[11px] font-semibold text-[#9a5b00]">
                          持续压力 {ioGuard.sample_count ?? '—'}/{ioGuard.required_samples ?? '—'} 次，已观察{' '}
                          {formatMinutes(ioGuard.confirmed_duration_seconds)}。
                        </p>
                      )}
                      {['active', 'limited', 'manual_limited', 'apply_failed', 'applying', 'escalating', 'restoring', 'restore_failed', 'retry_wait'].includes(ioGuard?.state || '') && (
                        <div className="space-y-1 rounded-lg border border-[#d2dfec] bg-white p-2.5 text-[11px] text-[#31485e]">
                          {ioGuard?.effective_source && ioGuard.effective_source !== 'none' && (
                            <p>
                              裁决来源：
                              <span className="ml-1 font-bold text-[#0657b8]">
                                {ioGuard.effective_source === 'auto_over_manual'
                                  ? '主动限制 + 自动保护联合收紧'
                                  : ioGuard.effective_source === 'manual'
                                  ? `主动限制 (${ioGuard.manual_mode === 'lock' ? '锁定' : '协同联动'})`
                                  : '自动保护'}
                              </span>
                            </p>
                          )}
                          <p>原 I/O 限额：<span className="font-mono font-bold text-[#0b1636]">{formatIoLimit(ioGuard?.original_limit)}</span></p>
                          <p>
                            策略目标：<span className="font-mono font-bold text-[#0b1636]">{formatIoLimit(ioGuard?.expected_limit || ioGuard?.active_limit)}</span>
                            {ioGuard?.tier ? ` · 第 ${ioGuard.tier} 阶（约基线 ${ioGuard.tier_percent_of_baseline ?? '-'}%）` : ''}
                          </p>
                          <p>
                            内核当前读回：<span className="font-mono font-bold text-[#0b1636]">{ioGuard?.actual_limit ? formatIoLimit(ioGuard.actual_limit) : '暂不可读'}</span> ·{' '}
                            {ioGuard?.readback_confirmed
                              ? `已核实${ioGuard.readback_confirmed_at ? ` · ${new Date(ioGuard.readback_confirmed_at * 1000).toLocaleString('zh-CN', { hour12: false })}` : ''}`
                              : '尚未确认目标值'}
                          </p>
                          <p>
                            恢复条件：低压力连续 {ioGuard?.recovery_samples ?? '—'}/{ioGuard?.recovery_samples_required ?? '—'} 次，观察窗口{' '}
                            {formatMinutes(ioGuard?.recovery_duration_seconds)}。
                          </p>
                          {ioGuard?.retry_after_seconds ? (
                            <p className="font-semibold text-[#9a5b00]">约 {formatMinutes(ioGuard.retry_after_seconds)} 后自动重试。</p>
                          ) : null}
                        </div>
                      )}
                      {ioGuard?.observed_rates && (
                        <p className="text-[11px] text-[#31485e]">
                          当前读/写：{formatIoRate(ioGuard.observed_rates.rbps)} / {formatIoRate(ioGuard.observed_rates.wbps)}；IOPS{' '}
                          {fmtNumber(ioGuard.observed_rates.riops, 0)} / {fmtNumber(ioGuard.observed_rates.wiops, 0)}。
                        </p>
                      )}
                      <p className="text-[11px] leading-relaxed text-[#4a607a]">
                        {ioGuard?.message || (ioGuard?.state === 'normal' ? '当前未达到持续宿主机磁盘压力及容器归属条件。' : '等待 Agent 采样与读回状态。')}
                      </p>
                      {ioGuard?.recheck_interval_seconds ? (
                        <p className="text-[10px] text-[#4a607a]">每约 {formatMinutes(ioGuard.recheck_interval_seconds)} 复查一次。</p>
                      ) : null}
                    </div>
                  </div>

                  <div className="rounded-xl border border-[#d2dfec] bg-[#f4f8fd] p-3 text-[11px] text-[#31485e]">
                    <p className="font-extrabold text-[#0e233c]">PSI 等待压力（近 10 秒）</p>
                    <p className="mt-1">
                      母鸡 CPU / 内存 / 磁盘 I/O：{psiPercent(resourcePressure?.host, 'cpu')} · {psiPercent(resourcePressure?.host, 'memory')} ·{' '}
                      {psiPercent(resourcePressure?.host, 'io')}
                    </p>
                    <p>
                      容器 CPU / 内存 / 磁盘 I/O：{psiPercent(resourcePressure?.container, 'cpu')} · {psiPercent(resourcePressure?.container, 'memory')} ·{' '}
                      {psiPercent(resourcePressure?.container, 'io')}
                    </p>
                    <p className="mt-1 font-medium text-[#0657b8]">
                      {resourcePressure?.explanation || resourcePressure?.container?.reason || '等待新版 Agent 上报 PSI；部分旧内核或 cgroup 配置不提供该指标。'}
                    </p>
                    <p className="mt-1 text-[#4a607a]">PSI 表示任务因资源压力而等待的时间比例；它辅助区分持续计算与资源争用，不用于认定用户行为。</p>
                  </div>

                  <ContainerResourceLimitControls
                    identity={identity}
                    container={container}
                    onToast={onToast}
                    onRefresh={onRefresh}
                  />
                </section>
              )}
            </div>

            {/* Section 2: 网络准入 */}
            <div id="drawer-sec-admission" className="scroll-mt-4">
              <AdmissionStatus data={sec.admission} stale={container?.alerts?.stale} />
            </div>

            {/* Section 3: 服务合规 */}
            <div id="drawer-sec-compliance" className="scroll-mt-4 space-y-5">
              {Array.isArray(sec.service_audit?.services) && sec.service_audit.services.length > 0 && (
                <section className="rn2-card space-y-2.5 bg-white p-4">
                  <div className="flex items-center justify-between gap-2">
                    <h3 className="text-sm font-extrabold text-[#0e233c]">容器服务配置画像（已脱敏）</h3>
                    {(sec.service_audit.violations_count || 0) > 0 ? (
                      <span className="rounded-full border border-[#f1b4bf] bg-[#ffeef1] px-2.5 py-0.5 text-[10px] font-bold text-[#b41835] tabular-nums">
                        {sec.service_audit.violations_count} 项违规配置
                      </span>
                    ) : (
                      <span className="rounded-full border border-[#b4e4dc] bg-[#e6f7f4] px-2.5 py-0.5 text-[10px] font-bold text-[#147468]">
                        配置合规
                      </span>
                    )}
                  </div>
                  <div className="space-y-2">
                    {sec.service_audit.services.map((svc: any, idx: number) => (
                      <div key={`${svc.engine}-${svc.pid}-${idx}`} className="space-y-1.5 rounded-xl border border-[#d2dfec] bg-[#f4f8fd] px-3 py-2.5 text-xs text-[#31485e]">
                        <div className="flex items-center justify-between">
                          <span className="font-mono font-bold text-[#0657b8]">{svc.engine}</span>
                          <span className="text-[11px] font-semibold text-[#4a607a] tabular-nums">PID {svc.pid}</span>
                        </div>
                        {Array.isArray(svc.inbounds) && svc.inbounds.length > 0 && (
                          <div className="flex flex-wrap gap-1.5">
                            {svc.inbounds.map((inb: any, j: number) => (
                              <span
                                key={j}
                                className="rounded border border-[#cedae7] bg-white px-2 py-0.5 font-mono text-[11px] font-semibold text-[#0b1636]"
                              >
                                {inb.protocol}:{inb.port || 0}
                                {Array.isArray(inb.sni_list) && inb.sni_list.length > 0 ? ` · SNI=${inb.sni_list.join(',')}` : ''}
                                {!inb.auth_configured ? ' · 无认证' : ''}
                              </span>
                            ))}
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                </section>
              )}

              {(identity.runtime === 'incus' || identity.runtime === 'podman' || identity.runtime === 'runman') && (
                <section className="rn2-card space-y-3 bg-white p-4">
                  <div className="flex items-start gap-3">
                    <div className="rounded-xl border border-[#9ccaff] bg-[#e8f3ff] p-2 text-[#0657b8]">
                      <Mail className="h-4 w-4" aria-hidden="true" />
                    </div>
                    <div className="min-w-0 flex-1">
                      <h3 className="text-sm font-extrabold text-[#0e233c]">用户邮箱与备注</h3>
                      <p className="mt-1 text-xs leading-relaxed text-[#4a607a]">
                        用于搜索、人工核对和后续封禁定位；保存信息不会自动停止或限制容器。
                      </p>
                    </div>
                  </div>
                  <label className="block space-y-1.5">
                    <span className="flex flex-wrap items-center gap-2 text-xs font-bold text-[#31485e]">
                      用户邮箱
                      {container?.user_email_source === 'upstream' && (
                        <span className="rounded-full border border-[#9ccaff] bg-[#e8f3ff] px-2 py-0.5 text-[10px] font-bold text-[#0657b8]">
                          上游 API 自动同步
                        </span>
                      )}
                      {container?.user_email_source === 'manual' && (
                        <span className="rounded-full border border-[#cedae7] bg-[#eef3f9] px-2 py-0.5 text-[10px] font-bold text-[#31485e]">
                          手工备注
                        </span>
                      )}
                      {container?.user_email_source === 'unmatched' && (
                        <span className="rounded-full border border-[#e8bf70] bg-[#fef6e4] px-2 py-0.5 text-[10px] font-bold text-[#9a5b00]">
                          {container.user_email_status?.startsWith('上游已匹配此实例') ? '上游已匹配实例 (待补邮箱)' : '上游实例未匹配'}
                        </span>
                      )}
                    </span>
                    <input
                      type="email"
                      maxLength={254}
                      value={userEmail}
                      onChange={(event) => setUserEmail(event.target.value)}
                      placeholder="例如 user@example.com"
                      disabled={!container?.container_id || Boolean(container?.alerts?.stale)}
                      className="rn2-input"
                    />
                    {container?.user_email_source === 'unmatched' && container.user_email_status && (
                      <p className="text-[11px] leading-relaxed font-medium text-[#9a5b00]">
                        {container.user_email_status.replace(/。+$/, '')}。系统不会按容器名称猜邮箱；请核对上游实例 UUID，或手工补充邮箱。
                      </p>
                    )}
                  </label>
                  <label className="block space-y-1.5">
                    <span className="text-xs font-bold text-[#31485e]">
                      内部备注 <span className="font-normal text-[#4a607a]">（可选，最多 500 字）</span>
                    </span>
                    <textarea
                      value={userNote}
                      maxLength={500}
                      onChange={(event) => setUserNote(event.target.value)}
                      placeholder="记录订单号、沟通情况或封禁核对信息"
                      rows={2}
                      disabled={!container?.container_id || Boolean(container?.alerts?.stale)}
                      className="w-full resize-y rounded-[10px] border border-[#cedae7] bg-white px-3.5 py-2.5 text-sm text-[#0b1636] placeholder:text-[#697b9c] focus:border-[#087bff] focus:outline-hidden focus:ring-2 focus:ring-[#087bff]/20 disabled:opacity-50"
                    />
                  </label>
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <p className="text-[11px] text-[#4a607a]">Ctrl+K 全局搜索可直接输入邮箱或备注内容。</p>
                    <button
                      type="button"
                      onClick={saveUserNote}
                      disabled={isSavingUserNote || !container?.container_id || Boolean(container?.alerts?.stale)}
                      className="rn2-btn rn2-btn-sm rn2-btn-blue min-h-11"
                    >
                      <Save className="h-3.5 w-3.5" aria-hidden="true" />
                      {isSavingUserNote ? '保存中…' : '保存备注'}
                    </button>
                  </div>
                </section>
              )}

              {container && isGuardRuntime && (
                <section className="rn2-card space-y-3 bg-white p-4" aria-label="容器活动告警与保护信号">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div>
                      <h3 className="flex items-center gap-2 text-sm font-extrabold text-[#0e233c]">
                        <Shield className="h-4 w-4 text-[#d97706]" aria-hidden="true" />
                        告警与保护信号
                      </h3>
                      <p className="mt-1 text-[11px] text-[#4a607a]">
                        {drawerIsStale ? '数据已过期，以下为最近一次匹配记录。' : '展示服务端当前匹配到的活动告警；保护信号不等于违规认定。'}
                      </p>
                    </div>
                    <span className="rounded-full border border-[#cedae7] bg-[#f4f8fd] px-2.5 py-1 text-[10px] font-bold tabular-nums text-[#31485e]">
                      {containerAlerts.length} 项
                    </span>
                  </div>
                  {containerAlerts.length === 0 ? (
                    <p className="rounded-xl border border-dashed border-[#cedae7] bg-[#f4f8fd] px-3 py-3 text-xs text-[#4a607a]">
                      暂无匹配的活动告警。资源保护与协议阻断状态请查看上方与下方卡片。
                    </p>
                  ) : (
                    <ul className="space-y-2">
                      {containerAlerts.map((alert) => (
                        <li
                          key={alert.id}
                          className={`rounded-xl border p-3 ${
                            alert.protection_only
                              ? 'border-[#9ccaff] bg-[#e8f3ff]/65'
                              : alert.severity === 'critical'
                                ? 'border-[#f1b4bf] bg-[#ffeef1]'
                                : 'border-[#e8bf70] bg-[#fef6e4]'
                          }`}
                        >
                          <div className="flex flex-wrap items-center gap-2">
                            <span
                              className={`rounded-full border bg-white px-2 py-0.5 text-[10px] font-bold ${
                                alert.protection_only
                                  ? 'border-[#9ccaff] text-[#0657b8]'
                                  : alert.severity === 'critical'
                                    ? 'border-[#f1b4bf] text-[#b41835]'
                                    : 'border-[#e8bf70] text-[#9a5b00]'
                              }`}
                            >
                              {alert.protection_only ? '保护信号' : alert.severity === 'critical' ? '严重告警' : alert.severity === 'info' ? '提示' : '安全告警'}
                            </span>
                            <span className="font-mono text-[10px] font-semibold text-[#4a607a]">{alert.type}</span>
                          </div>
                          <h4 className="mt-2 text-xs font-extrabold text-[#0b1636]">{alert.title || alert.type}</h4>
                          <p className="mt-1 break-words text-[11px] leading-relaxed text-[#31485e]">{alert.message}</p>
                          <SocketAbuseEvidence alert={alert} compact />
                          {(alert.value != null || alert.threshold != null) && (
                            <p className="mt-1 text-[10px] font-medium tabular-nums text-[#4a607a]">
                              {alert.value != null ? `当前值：${formatAlertValue(alert.value)}` : ''}
                              {alert.value != null && alert.threshold != null ? ' · ' : ''}
                              {alert.threshold != null ? `阈值：${formatAlertValue(alert.threshold)}` : ''}
                            </p>
                          )}
                        </li>
                      ))}
                    </ul>
                  )}
                  {sec?.socket_abuse && !containerAlerts.some((alert) => Boolean(extractSocketAbuseAssessment(alert))) && (
                    <SocketAbuseEvidence assessment={sec.socket_abuse} compact />
                  )}
                </section>
              )}

              {container && isGuardRuntime && (
                <section className="rn2-card space-y-3 bg-white p-4" aria-label="VMess 与 Trojan 协议管控">
                  <div>
                    <h3 className="flex items-center gap-2 text-sm font-extrabold text-[#0e233c]">
                      <Shield className="h-4 w-4 text-[#5b34b0]" aria-hidden="true" />
                      VMess / Trojan 阻断状态
                    </h3>
                    <p className="mt-1 text-[11px] text-[#4a607a]">区分已读回阻断、部分阻断和待核验端点；缺少 Agent 状态时不会显示为已阻断。</p>
                  </div>
                  <div className="grid gap-3 md:grid-cols-2">
                    <ProtocolGuardCard label="VMess" summary={sec.vmess_guard} />
                    <ProtocolGuardCard label="Trojan" summary={sec.trojan_guard} />
                  </div>
                </section>
              )}

              {/* Sensitive Dropped Files Alert */}
              {Array.isArray(sec.sensitive_file_events) && sec.sensitive_file_events.length > 0 && (
                <div className="rounded-[14px] border border-[#f1b4bf] bg-[#ffeef1] p-4 text-[#b41835]">
                  <div className="mb-2 flex items-center justify-between gap-2">
                    <span className="flex items-center gap-1.5 text-xs font-extrabold text-[#b41835]">
                      <AlertTriangle className="h-4 w-4" aria-hidden="true" />
                      <span>检测到敏感目录可执行文件落地 ({sec.sensitive_file_events.length} 个)</span>
                    </span>
                    <span className="animate-pulse rounded border border-[#f1b4bf] bg-white px-2 py-0.5 text-[10px] font-extrabold text-[#b41835]">
                      高危落地
                    </span>
                  </div>
                  <div className="space-y-1.5">
                    {sec.sensitive_file_events.map((evt, idx) => (
                      <div key={idx} className="flex items-center justify-between gap-2 rounded-lg border border-[#f1b4bf] bg-white p-2.5 font-mono text-xs">
                        <div className="min-w-0 truncate">
                          <span className="font-bold text-[#0b1636]">{evt.filename}</span>
                          <span className="ml-2 text-[11px] text-[#4a607a]">{evt.path}</span>
                        </div>
                        <div className="flex shrink-0 items-center gap-2 text-[11px]">
                          {evt.is_elf && (
                            <span className="rounded border border-[#f1b4bf] bg-[#ffeef1] px-1.5 py-0.5 font-bold text-[#b41835]">
                              ELF
                            </span>
                          )}
                          <span className="text-[#31485e]">{evt.size_bytes} B</span>
                          {evt.sha256_prefix && <span className="font-mono text-[#4a607a]">{evt.sha256_prefix}...</span>}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Phase 1 Kernel Defense & Containment Controls */}
              <div className="rn2-card space-y-3 bg-white p-4">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <span className="flex items-center gap-1.5 text-xs font-extrabold text-[#0e233c]">
                    <Shield className="h-4 w-4 text-[#087bff]" aria-hidden="true" />
                    <span>容器内核防护与应急阻断 (Phase 1 核心防线)</span>
                  </span>
                  <span className="font-mono text-[10px] font-semibold text-[#4a607a]">
                    cgroup v2 · NetNS · Host Veth
                  </span>
                </div>

                <div className="grid grid-cols-1 gap-3 text-xs sm:grid-cols-2">
                  {/* Freeze Control */}
                  <div className="flex flex-col justify-between rounded-xl border border-[#d2dfec] bg-[#f4f8fd] p-3">
                    <div>
                      <div className="flex items-center justify-between gap-2">
                        <span className="flex items-center gap-1.5 font-bold text-[#0e233c]">
                          <Snowflake className="h-3.5 w-3.5 text-[#087bff]" aria-hidden="true" />
                          进程冻结挂起
                        </span>
                        {sec.freeze_guard?.frozen ? (
                          <span className="animate-pulse rounded border border-[#9ccaff] bg-[#e8f3ff] px-1.5 py-0.5 text-[10px] font-bold text-[#0657b8]">
                            已冻结 (frozen 1)
                          </span>
                        ) : (
                          <span className="rounded border border-[#cedae7] bg-white px-1.5 py-0.5 text-[10px] font-semibold text-[#4a607a]">
                            正常运行
                          </span>
                        )}
                      </div>
                      <p className="mt-1.5 text-[11px] leading-relaxed text-[#4a607a]">
                        瞬间定格容器所有线程，内存现场与取证完整保留，不破坏进程。
                      </p>
                    </div>
                    <div className="mt-2 border-t border-[#d2dfec] pt-2.5">
                      {sec.freeze_guard?.frozen ? (
                        <button
                          type="button"
                          disabled={isDrawerActionLoading}
                          onClick={() => setPendingDecision('unfreeze_container')}
                          className="rn2-btn rn2-btn-sm rn2-btn-blue min-h-11 w-full disabled:opacity-50"
                        >
                          <Unlock className="h-3.5 w-3.5" aria-hidden="true" />
                          <span>解除冻结恢复</span>
                        </button>
                      ) : (
                        <button
                          type="button"
                          disabled={isDrawerActionLoading}
                          onClick={() => setPendingDecision('freeze_container')}
                          className="flex min-h-11 w-full items-center justify-center gap-1.5 rounded-[10px] border border-[#9ccaff] bg-white px-3 py-2 text-xs font-bold text-[#0657b8] transition-colors hover:border-[#087bff] hover:bg-[#e8f3ff] disabled:opacity-50"
                        >
                          <Snowflake className="h-3.5 w-3.5" aria-hidden="true" />
                          <span>挂起冻结进程</span>
                        </button>
                      )}
                    </div>
                  </div>

                  {/* UDP Blackhole Control */}
                  <div className="flex flex-col justify-between rounded-xl border border-[#d2dfec] bg-[#f4f8fd] p-3">
                    <div>
                      <div className="flex items-center justify-between gap-2">
                        <span className="flex items-center gap-1.5 font-bold text-[#0e233c]">
                          <Gauge className="h-3.5 w-3.5 text-[#d97706]" aria-hidden="true" />
                          出站 UDP 专项阻断
                        </span>
                        {sec.udp_blackhole?.active ? (
                          <span className="rounded border border-[#e8bf70] bg-[#fef6e4] px-1.5 py-0.5 text-[10px] font-bold text-[#9a5b00]">
                            阻断中 (放行DNS)
                          </span>
                        ) : (
                          <span className="rounded border border-[#cedae7] bg-white px-1.5 py-0.5 text-[10px] font-semibold text-[#4a607a]">
                            全速放行
                          </span>
                        )}
                      </div>
                      <p className="mt-1.5 text-[11px] leading-relaxed text-[#4a607a]">
                        定向切断容器出站 UDP 洪水与放大攻击，保留 TCP、SSH 及入站通道。
                      </p>
                    </div>
                    <div className="mt-2 border-t border-[#d2dfec] pt-2.5">
                      {sec.udp_blackhole?.active ? (
                        <button
                          type="button"
                          disabled={isDrawerActionLoading}
                          onClick={() => setPendingDecision('release_udp_blackhole')}
                          className="rn2-btn rn2-btn-sm rn2-btn-orange min-h-11 w-full disabled:opacity-50"
                        >
                          <Unlock className="h-3.5 w-3.5" aria-hidden="true" />
                          <span>解除 UDP 阻断</span>
                        </button>
                      ) : (
                        <button
                          type="button"
                          disabled={isDrawerActionLoading}
                          onClick={() => setPendingDecision('apply_udp_blackhole')}
                          className="flex min-h-11 w-full items-center justify-center gap-1.5 rounded-[10px] border border-[#e8bf70] bg-white px-3 py-2 text-xs font-bold text-[#9a5b00] transition-colors hover:border-[#d97706] hover:bg-[#fef6e4] disabled:opacity-50"
                        >
                          <Shield className="h-3.5 w-3.5" aria-hidden="true" />
                          <span>实施 UDP 黑洞</span>
                        </button>
                      )}
                    </div>
                  </div>
                </div>

                {/* Anti-IP Spoof Status Bar */}
                <div className="flex flex-wrap items-center justify-between gap-2 border-t border-[#e1ebf4] pt-2.5 text-[11px]">
                  <span className="flex items-center gap-1.5 font-medium text-[#31485e]">
                    <Shield className="h-3.5 w-3.5 text-[#147468]" aria-hidden="true" />
                    宿主机 Veth 源地址反欺骗校验 (Anti-IP Spoofing)
                  </span>
                  {sec.anti_spoof?.active ? (
                    <span className="flex items-center gap-1 font-bold text-[#147468]">
                      <Check className="h-3.5 w-3.5" aria-hidden="true" /> 已启用 strict rp_filter 与源 IP 白名单
                    </span>
                  ) : (
                    <span className="font-medium text-[#4a607a]">内核标准转发模式</span>
                  )}
                </div>
              </div>

              {/* Security Checks & Surface Risk */}
              <div className="rn2-card space-y-3 bg-white p-4">
                <h3 className="flex items-center gap-2 text-xs font-extrabold text-[#0e233c]">
                  <Shield className="h-4 w-4 text-[#d97706]" aria-hidden="true" />
                  <span>安全合规与暴露面排查</span>
                </h3>

                <div className="grid grid-cols-1 gap-3 text-xs sm:grid-cols-2">
                  {/* SOCKS Check */}
                  <div className="rounded-xl border border-[#d2dfec] bg-[#f4f8fd] p-3">
                    <span className="block text-[11px] font-semibold text-[#4a607a]">SOCKS 代理服务</span>
                    <div className="mt-1 font-bold">
                      {socks?.detected ? (
                        <span className="text-[#9a5b00]">
                          已检测 · {socks.auth_mode === 'no_auth' ? '无认证 (高危)' : socks.auth_mode === 'weak_password' ? '弱密码 (高危)' : socks.auth_mode}
                          {socks.public_exposure && ' · 公网暴露'}
                        </span>
                      ) : (
                        <span className="text-[#147468]">未发现可疑 SOCKS 代理</span>
                      )}
                    </div>
                  </div>

                  {/* Panel Pairing */}
                  <div className="rounded-xl border border-[#d2dfec] bg-[#f4f8fd] p-3">
                    <span className="block text-[11px] font-semibold text-[#4a607a]">第三方控制面板对接</span>
                    <div className="mt-1 font-bold">
                      {pairing?.detected ? (
                        <span className={pairing.approved ? 'text-[#147468]' : 'text-[#b41835]'}>
                          {pairing.approved ? '已放行对接' : '检测到未授权面板特征'}
                        </span>
                      ) : (
                        <span className="text-[#147468]">未发现异常对接</span>
                      )}
                    </div>
                  </div>
                </div>

                {/* If Risk is detected in SOCKS or Panel, show Quick Disposition Controls */}
                {activeActionableAlert &&
                  ((socks?.detected && (socks.auth_mode === 'no_auth' || socks.auth_mode === 'weak_password')) ||
                    (pairing?.detected && !pairing.approved)) && (
                    <div className="space-y-2.5 rounded-xl border border-[#f1b4bf] bg-[#ffeef1] p-3.5">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2 text-xs font-extrabold text-[#b41835]">
                          <AlertTriangle className="h-4 w-4 animate-pulse" aria-hidden="true" />
                          <span>检测到非合规安全风险需处置</span>
                        </div>
                      </div>
                      <p className="text-[11px] leading-relaxed text-[#881337]">
                        {socks?.detected && socks.auth_mode === 'no_auth'
                          ? '当前容器正在运行开放且无认证的 SOCKS 代理服务，极易被利用为跳板。'
                          : socks?.detected && socks.auth_mode === 'weak_password'
                            ? '当前容器正在运行弱密码 SOCKS 代理服务，容易被撞库后滥用为跳板。'
                            : pairing?.detected && !pairing.approved
                              ? '当前容器检测到未经放行的第三方机场节点对接活动与内部特征。'
                              : '检测到运行风险，建议定向处置或加入安全白名单。'}
                      </p>
                      <div className="flex flex-wrap items-center gap-2 pt-1">
                        <button
                          type="button"
                          disabled={isDrawerActionLoading}
                          onClick={() => setPendingDecision('deny')}
                          className="rn2-btn rn2-btn-sm rn2-btn-danger min-h-11 disabled:opacity-50"
                        >
                          <Ban className="h-3.5 w-3.5" aria-hidden="true" />
                          <span>{isDrawerActionLoading ? '处理中...' : '定向处置违规服务'}</span>
                        </button>
                        <button
                          type="button"
                          disabled={isDrawerActionLoading}
                          onClick={() => setPendingDecision('allow_silent')}
                          className="rn2-btn rn2-btn-sm rn2-btn-ghost min-h-11 disabled:opacity-50"
                        >
                          <Check className="h-3.5 w-3.5 text-[#147468]" aria-hidden="true" />
                          <span>放行此策略</span>
                        </button>
                        <button
                          type="button"
                          disabled={isDrawerActionLoading}
                          onClick={() => setPendingDecision('resolve')}
                          className="inline-flex min-h-11 items-center gap-1.5 rounded-[10px] border border-[#b4e4dc] bg-[#e6f7f4] px-3 py-1.5 text-xs font-bold text-[#147468] transition-colors hover:bg-[#d2efe9] disabled:opacity-50"
                        >
                          <CheckCircle2 className="h-3.5 w-3.5" aria-hidden="true" />
                          <span>标记已解决</span>
                        </button>
                      </div>
                    </div>
                  )}

                {/* Listening Ports & Exposure */}
                <div className="space-y-1 pt-1 font-mono text-xs text-[#0b1636]">
                  {container?.network_addresses && container.network_addresses.length > 0 && (
                    <div className="flex items-center justify-between gap-2 border-t border-[#e1ebf4] py-1.5">
                      <span className="font-sans font-semibold text-[#4a607a]">网络 IP</span>
                      <span className="min-w-0 max-w-xs break-all select-all text-right font-bold text-[#0657b8]">
                        {container.network_addresses.join(', ')}
                      </span>
                    </div>
                  )}
                  <div className="flex items-center justify-between gap-2 border-t border-[#e1ebf4] py-1.5">
                    <span className="font-sans font-semibold text-[#4a607a]">监听端口</span>
                    <span className="max-w-xs truncate text-right text-[#0b1636]">
                      {(sec.listening_ports || []).join(', ') || '无对外开放端口'}
                    </span>
                  </div>
                  <div className="flex items-center justify-between gap-2 border-t border-[#e1ebf4] py-1.5">
                    <span className="font-sans font-semibold text-[#4a607a]">NAT 暴露映射</span>
                    <span className="max-w-xs truncate text-right text-[#0b1636]">
                      {(sec.network_exposure || [])
                        .map((x) => `${x.listen} → ${x.target}`)
                        .join(', ') || '内部隔离'}
                    </span>
                  </div>
                  <div className="flex items-center justify-between gap-2 border-t border-[#e1ebf4] py-1.5">
                    <span className="font-sans font-semibold text-[#4a607a]">最高 CPU 进程</span>
                    <span className="max-w-xs truncate text-right font-semibold text-[#0657b8]" title={container?.top_cpu_process_command}>
                      {container?.top_cpu_process_command
                        ? `PID ${container.top_cpu_process_pid} (${fmtNumber(container.top_cpu_process_cpu_percent)}%) · ${container.top_cpu_process_command}`
                        : '无显著负载进程'}
                    </span>
                  </div>
                </div>
              </div>
            </div>

            {/* Section 4: 连接证据 */}
            <div id="drawer-sec-evidence" className="scroll-mt-4">
              <ConnectionEvidenceTimeline identity={identity} />
            </div>

            {/* Section 5: 实时诊断 */}
            <div id="drawer-sec-diagnostic" className="scroll-mt-4">
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
