import React from 'react';
import { ContainerItem, SecurityAlert } from '../../api/types';

type SignalTone = 'danger' | 'warning' | 'info' | 'success' | 'muted';

interface ContainerSignal {
  key: string;
  label: string;
  title: string;
  tone: SignalTone;
}

interface ContainerStateBadgesProps {
  container: ContainerItem;
  activeAlerts?: SecurityAlert[];
  maxVisible?: number;
  className?: string;
}

type GuardLike = {
  state?: string;
  detected?: boolean;
  message?: string;
  reason?: string;
  active_limit?: unknown;
  blocked_endpoints?: unknown[];
  pending_endpoints?: unknown[];
};

const toneClasses: Record<SignalTone, string> = {
  danger: 'border-rose-500/40 bg-rose-950/50 text-rose-200',
  warning: 'border-amber-500/35 bg-amber-950/40 text-amber-200',
  info: 'border-sky-500/35 bg-sky-950/40 text-sky-200',
  success: 'border-emerald-500/30 bg-emerald-950/30 text-emerald-200',
  muted: 'border-slate-700 bg-slate-900 text-slate-300',
};

const matchingAlerts = (container: ContainerItem, alerts: SecurityAlert[] = []) => alerts.filter((alert) =>
  alert.host_id === container.host_id &&
  alert.runtime === container.runtime &&
  (alert.project || '') === (container.project || '') &&
  alert.container_name === container.container_name &&
  alert.status === 'active'
);

const RESOURCE_GUARD_LABELS = [
  { key: 'cpu_guard', label: 'CPU' },
  { key: 'memory_guard', label: '内存' },
  { key: 'io_guard', label: '磁盘 I/O' },
] as const;

const RESOURCE_GUARD_FAILURE_STATES = ['limit_failed', 'limited_unverified', 'limit_unverified', 'restore_failed', 'limit_readback_unavailable', 'orphaned_cgroup', 'apply_unverified'];
const PROTOCOL_GUARD_REVIEW_STATES = ['partial', 'unverified', 'release_pending'];

const supportsContainerGuards = (container: ContainerItem) =>
  container.runtime === 'incus' || container.runtime === 'podman';

const resourceGuardSignal = (label: string, guard: GuardLike | undefined): ContainerSignal | null => {
  if (!guard) return null;
  const state = String(guard.state || 'unavailable');
  if (['normal', 'disabled'].includes(state)) return null;

  let summary = '状态待核实';
  let tone: SignalTone = 'muted';
  if (['limited', 'active'].includes(state)) {
    summary = '限额已读回';
    tone = 'info';
  } else if (['watching', 'warming', 'waiting_for_host_pressure', 'waiting_for_host_psi', 'waiting_for_pressure', 'waiting_for_other_limit', 'applying', 'escalating', 'restoring', 'retry_wait', 'cooldown'].includes(state)) {
    summary = state === 'watching' || state === 'warming' ? '持续观察' : '保护处理中';
    tone = 'warning';
  } else if (['limit_failed', 'limited_unverified', 'limit_unverified', 'restore_failed', 'limit_readback_unavailable', 'orphaned_cgroup', 'apply_unverified'].includes(state)) {
    summary = '保护核验异常';
    tone = 'danger';
  } else if (['restored', 'manual_reset'].includes(state)) {
    summary = '限额已恢复';
    tone = 'success';
  } else if (state === 'existing_limit_stricter') {
    summary = '保留更严格限额';
    tone = 'success';
  } else if (state === 'manual_override') {
    summary = '人工修改待核实';
    tone = 'warning';
  } else if (['state_unavailable', 'sampling_unavailable', 'unavailable', 'unsupported', 'psi_unavailable'].includes(state)) {
    summary = '状态不可用';
    tone = 'muted';
  }

  return {
    key: `${label}-${state}`,
    label: `${label} ${summary}`,
    title: [guard.message, `状态：${state}`, typeof guard.active_limit === 'string' ? `当前限额：${guard.active_limit}` : ''].filter(Boolean).join(' · '),
    tone,
  };
};

const protocolGuardSignal = (label: 'VMess' | 'Trojan', guard: GuardLike | undefined): ContainerSignal | null => {
  if (!guard || (!guard.detected && !guard.state)) return null;
  const state = String(guard.state || '');
  if (state === 'not_detected' && !guard.detected) return null;

  const presentation: Record<string, { summary: string; tone: SignalTone }> = {
    blocked: { summary: '阻断已核验', tone: 'success' },
    partial: { summary: '部分阻断', tone: 'danger' },
    unverified: { summary: '阻断待核验', tone: 'warning' },
    release_pending: { summary: '放行待核验', tone: 'warning' },
    not_detected: { summary: '未检测到', tone: 'muted' },
  };
  const result = state === 'not_detected' && guard.detected
    ? { summary: '检测状态冲突', tone: 'warning' as const }
    : presentation[state] || {
    summary: guard.detected ? '已检测' : '状态待核实',
    tone: guard.detected ? 'warning' as const : 'muted' as const,
  };
  const blockedCount = Array.isArray(guard.blocked_endpoints) ? guard.blocked_endpoints.length : null;
  const pendingCount = Array.isArray(guard.pending_endpoints) ? guard.pending_endpoints.length : null;
  const endpointSummary = [
    blockedCount === null ? '' : `已阻断端点 ${blockedCount}`,
    pendingCount === null ? '' : `待核验端点 ${pendingCount}`,
  ].filter(Boolean).join(' · ');
  return {
    key: `${label}-${state || 'unknown'}`,
    label: `${label} ${result.summary}`,
    title: [guard.reason, endpointSummary, `状态：${state || '未上报'}`].filter(Boolean).join(' · '),
    tone: result.tone,
  };
};

export const hasContainerProtocolGuard = (container: ContainerItem): boolean => {
  if (!supportsContainerGuards(container)) return false;
  const security = container.security || {};
  return [security.vmess_guard, security.trojan_guard].some((guard) =>
    Boolean(guard && (guard.detected || (guard.state && guard.state !== 'not_detected')))
  );
};

export const hasContainerResourceAlert = (container: ContainerItem): boolean =>
  supportsContainerGuards(container) && Boolean(container.alerts?.cpu || container.alerts?.memory || container.alerts?.disk);

export const hasContainerResourceGuardFailure = (container: ContainerItem): boolean => {
  if (!supportsContainerGuards(container)) return false;
  const security = container.security || {};
  return RESOURCE_GUARD_LABELS.some(({ key }) => RESOURCE_GUARD_FAILURE_STATES.includes(security[key]?.state || ''));
};

export const hasContainerProtocolGuardNeedsReview = (container: ContainerItem): boolean => {
  if (!supportsContainerGuards(container)) return false;
  const security = container.security || {};
  return [security.vmess_guard, security.trojan_guard].some((guard) =>
    PROTOCOL_GUARD_REVIEW_STATES.includes(guard?.state || '') ||
    Boolean(guard?.detected && guard.state !== 'blocked')
  );
};

export const hasContainerResourceOrProtectionActivity = (container: ContainerItem, alerts: SecurityAlert[] = []): boolean => {
  const security = container.security || {};
  const relatedAlerts = matchingAlerts(container, alerts);
  const isGuardRuntime = supportsContainerGuards(container);
  const hasGuardState = isGuardRuntime && RESOURCE_GUARD_LABELS.some(({ key }) => {
    const state = security[key]?.state;
    return Boolean(state && state !== 'normal' && state !== 'disabled');
  });
  return Boolean(
    hasGuardState ||
    hasContainerResourceAlert(container) ||
    (isGuardRuntime && (security.udp_throttle?.throttled || container.alerts?.udp_throttled)) ||
    (isGuardRuntime && relatedAlerts.some((alert) => alert.protection_only))
  );
};

const buildSignals = (container: ContainerItem, alerts: SecurityAlert[]): ContainerSignal[] => {
  const security = container.security || {};
  const signals: ContainerSignal[] = [];
  const add = (key: string, label: string, tone: SignalTone, title = label) => signals.push({ key, label, tone, title });
  const guards = supportsContainerGuards(container)
    ? RESOURCE_GUARD_LABELS
        .map(({ key, label }) => resourceGuardSignal(label, security[key]))
        .filter((signal): signal is ContainerSignal => Boolean(signal))
    : [];
  const protocolGuards = supportsContainerGuards(container)
    ? [
        protocolGuardSignal('VMess', security.vmess_guard),
        protocolGuardSignal('Trojan', security.trojan_guard),
      ].filter((signal): signal is ContainerSignal => Boolean(signal))
    : [];

  protocolGuards.forEach((signal) => signals.push(signal));
  guards.forEach((signal) => signals.push(signal));

  const relatedAlerts = matchingAlerts(container, alerts);
  const securityAlerts = relatedAlerts.filter((alert) => !alert.protection_only);
  const protectionAlerts = relatedAlerts.filter((alert) => alert.protection_only);
  if (securityAlerts.length) {
    add('security-alerts', `安全告警 ${securityAlerts.length}`, 'danger', securityAlerts.map((alert) => alert.title || alert.message).join(' · '));
  }
  if (protectionAlerts.length) {
    add('protection-alerts', `保护信号 ${protectionAlerts.length}`, 'info', protectionAlerts.map((alert) => alert.title || alert.message).join(' · '));
  }

  if (supportsContainerGuards(container) && (container.alerts?.udp_throttled || security.udp_throttle?.throttled)) {
    const rate = container.alerts?.udp_throttle_rate_mbps ?? security.udp_throttle?.rate_mbps;
    add('udp-throttle', rate == null ? 'UDP 限速生效' : `UDP 限速 ${rate} Mbps`, 'info', security.udp_throttle?.reason || 'UDP 定向限速当前生效');
  }
  if (container.alerts?.cpu) add('cpu-alert', 'CPU 高负载', 'warning');
  if (container.alerts?.memory) add('memory-alert', '内存压力', 'warning');
  if (container.alerts?.disk) add('disk-alert', '磁盘压力', 'warning');
  if (container.alerts?.conn) add('connection-alert', '连接异常', 'warning');
  const connectionCount = container.conn_count;
  if (!container.alerts?.conn && Number.isFinite(connectionCount) && connectionCount! > 1500) {
    add('connection-flood', `并发连接 ${connectionCount}`, 'danger', `当前并发连接数：${connectionCount}`);
  }
  const inboundIps = security.inbound_unique_ips;
  const inboundThreshold = security.inbound_unique_ip_threshold ?? 10;
  if (Number.isFinite(inboundIps) && inboundIps! > inboundThreshold) {
    add('inbound-fanout', `入站 IP ${inboundIps}/${inboundThreshold}`, inboundIps! >= inboundThreshold * 2 ? 'danger' : 'warning');
  }
  const hy2Concurrency = container.alerts?.hy2_concurrency ?? security.hy2_protocol?.udp_concurrency;
  if ((container.alerts?.hy2_detected || security.hy2_protocol?.detected) && Number.isFinite(hy2Concurrency) && hy2Concurrency! >= 50) {
    add('hy2-concurrency', `HY2 并发 ${hy2Concurrency}`, hy2Concurrency! >= 200 ? 'danger' : 'warning', `Hysteria 2 UDP 并发：${hy2Concurrency}`);
  }

  const socks = security.socks_proxy;
  if (socks?.detected && ['no_auth', 'weak_password'].includes(socks.auth_mode)) {
    add('socks-risk', socks.auth_mode === 'no_auth' ? 'SOCKS 无认证' : 'SOCKS 弱认证', 'danger', `认证方式：${socks.auth_mode}${socks.public_exposure ? ' · 公网暴露' : ''}`);
  }
  if (security.panel_pairing?.detected && !security.panel_pairing.approved) {
    add('panel-pairing', '未授权面板对接', 'danger');
  }
  if (security.suspicious_processes?.length) {
    add('suspicious-processes', `可疑进程 ${security.suspicious_processes.length}`, 'danger', security.suspicious_processes.map((item) => item.command || item.pattern || '可疑进程').join(' · '));
  }
  if (security.configuration_risks?.length) {
    add('configuration-risks', `配置风险 ${security.configuration_risks.length}`, 'warning', security.configuration_risks.map((item) => item.message || item.code || '配置风险').join(' · '));
  }
  return signals;
};

export const ContainerStateBadges: React.FC<ContainerStateBadgesProps> = ({
  container,
  activeAlerts = [],
  maxVisible = 5,
  className = '',
}) => {
  if (!supportsContainerGuards(container)) return null;
  const signals = buildSignals(container, activeAlerts);
  if (!signals.length) return null;
  const visibleSignals = signals.slice(0, Math.max(1, maxVisible));
  const hiddenSignals = signals.slice(visibleSignals.length);

  return (
    <div role="group" className={`flex min-w-0 flex-wrap items-center gap-1 ${className}`} aria-label="容器资源、保护与告警状态">
      {visibleSignals.map((signal) => (
        <span
          key={signal.key}
          title={signal.title}
          className={`inline-flex max-w-full items-center rounded-md border px-1.5 py-0.5 text-[10px] leading-tight ${toneClasses[signal.tone]}`}
        >
          <span className="truncate">{signal.label}</span>
        </span>
      ))}
      {hiddenSignals.length > 0 && (
        <span
          title={hiddenSignals.map((signal) => `${signal.label}: ${signal.title}`).join('\n')}
          className="inline-flex items-center rounded-md border border-slate-700 bg-slate-900 px-1.5 py-0.5 text-[10px] text-slate-300"
        >
          +{hiddenSignals.length} 项
        </span>
      )}
    </div>
  );
};
