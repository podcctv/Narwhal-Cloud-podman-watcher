import React, { useMemo, useState } from 'react';
import {
  Box,
  Cpu,
  HardDrive,
  ChevronDown,
  ArrowDownLeft,
  ArrowUpRight,
  AlertTriangle,
  AlertCircle,
  Radio,
  ArrowUpDown,
  Sparkles,
  Ban,
  Gauge,
  Network,
} from 'lucide-react';
import { ContainerItem, ContainerIdentity, SecurityAlert } from '../../api/types';
import { fmtBytes, fmtMbps } from '../../api/client';
import { ContainerRiskInfo } from './HostContainerList';
import { AdmissionStatus } from '../container/AdmissionStatus';
import { ContainerStateBadges, hasContainerResourceAlert, hasContainerResourceOrProtectionActivity, hasContainerProtocolGuard, hasContainerResourceGuardFailure, hasContainerProtocolGuardNeedsReview } from './ContainerStateBadges';

const PROXY_SOFTWARE_LABELS: Record<string, string> = {
  xray: 'Xray-core',
  v2ray: 'V2Ray',
  'sing-box': 'sing-box',
  hysteria: 'Hysteria',
  'hysteria-server': 'Hysteria',
  mihomo: 'Mihomo / Clash Meta',
  clash: 'Clash',
  gost: 'GOST',
  trojan: 'Trojan',
  'trojan-go': 'Trojan-Go',
  'ss-server': 'Shadowsocks',
  shadowsocks: 'Shadowsocks',
  microsocks: 'MicroSocks',
  danted: 'Dante SOCKS',
  sockd: 'Dante SOCKS',
  '3proxy': '3proxy',
  'x-ui': 'X-ui',
  's-ui': 'S-ui',
};

const APP_PROTOCOL_LABELS: Record<string, string> = {
  vless: 'VLESS',
  vmess: 'VMess',
  trojan: 'Trojan',
  shadowsocks: 'Shadowsocks',
  socks: 'SOCKS',
  mixed: 'Mixed',
  http: 'HTTP',
  hysteria: 'Hysteria',
  hysteria2: 'Hysteria 2',
  tuic: 'TUIC',
  naive: 'NaiveProxy',
  wireguard: 'WireGuard',
  tun: 'TUN',
  'dokodemo-door': 'Dokodemo-door',
  anytls: 'AnyTLS',
};

interface ContainerCardCompactProps {
  container: ContainerItem;
  risk: ContainerRiskInfo;
  activeAlerts?: SecurityAlert[];
  onSelect: (id: ContainerIdentity) => void;
  onQuickDisposition?: (target: ContainerIdentity, decision: 'deny' | 'allow_silent') => void;
  isSubmitting?: boolean;
}

export const ContainerCardCompact: React.FC<ContainerCardCompactProps> = ({
  container: c,
  risk,
  activeAlerts = [],
  onSelect,
  onQuickDisposition,
  isSubmitting = false,
}) => {
  const isStale = Boolean(c.alerts?.stale);
  const hasResourceAlert = hasContainerResourceAlert(c);
  const hasResourceGuardFailure = hasContainerResourceGuardFailure(c);
  const hasProtocolGuardNeedsReview = hasContainerProtocolGuardNeedsReview(c);
  const hasProtectionState = hasContainerResourceOrProtectionActivity(c, activeAlerts) || hasContainerProtocolGuard(c);
  const cpu = typeof c.cpu_percent === 'number' && Number.isFinite(c.cpu_percent) ? c.cpu_percent : null;
  const mem = typeof c.mem_percent === 'number' && Number.isFinite(c.mem_percent) ? c.mem_percent : null;
  const memUsed = typeof c.mem_bytes === 'number' && Number.isFinite(c.mem_bytes) ? fmtBytes(c.mem_bytes) : '—';
  const memLimit = typeof c.mem_limit_bytes === 'number' && Number.isFinite(c.mem_limit_bytes) ? fmtBytes(c.mem_limit_bytes) : '—';
  const rxMbps = typeof c.net_rx_bps === 'number' && Number.isFinite(c.net_rx_bps) ? fmtMbps(c.net_rx_bps) : null;
  const txMbps = typeof c.net_tx_bps === 'number' && Number.isFinite(c.net_tx_bps) ? fmtMbps(c.net_tx_bps) : null;
  const sec = c.security || {};
  const udpThrottleRate = c.alerts?.udp_throttle_rate_mbps ?? sec.udp_throttle?.rate_mbps;
  const udpThrottleRemaining = c.alerts?.udp_throttle_remaining_seconds ?? sec.udp_throttle?.remaining_seconds;
  const [servicesExpanded, setServicesExpanded] = useState(false);
  const serviceListeners = useMemo(() => {
    const seen = new Set<string>();
    return (Array.isArray(sec.service_listeners) ? sec.service_listeners : []).filter((item) => {
      const key = `${item.proto || ''}|${item.port || 0}|${item.pid || 0}|${item.process || ''}|${item.local || ''}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
  }, [sec.service_listeners]);

  const applicationProtocolsFor = (listener: (typeof serviceListeners)[number]) => {
    const configured = listener.application_protocol_evidence === 'config_matches_live_pid_and_port' && Array.isArray(listener.application_protocols)
      ? listener.application_protocols.map((protocol) => APP_PROTOCOL_LABELS[protocol] || protocol.toUpperCase())
      : [];
    if (configured.length > 0) return { labels: configured, evidence: '配置与当前进程、监听端口匹配' };

    const hy2 = sec.hy2_protocol;
    const hy2Ports = Array.isArray(hy2?.listening_udp_ports) ? hy2.listening_udp_ports.map(Number) : [];
    if (
      hy2?.detected &&
      String(hy2.process || '').toLowerCase() === String(listener.process || '').toLowerCase() &&
      hy2Ports.includes(Number(listener.port))
    ) {
      return { labels: ['Hysteria 2'], evidence: `流量特征检测（${hy2.confidence || '未分级'}）` };
    }

    const socksListener = Array.isArray(sec.socks_proxy?.service_listeners)
      ? sec.socks_proxy.service_listeners.find((item: any) =>
          Number(item.pid || 0) === Number(listener.pid || 0) &&
          Number(item.port || 0) === Number(listener.port || 0) &&
          String(item.proto || '').toLowerCase() === String(listener.proto || '').toLowerCase()
        )
      : null;
    if (socksListener) {
      return { labels: ['SOCKS'], evidence: socksListener.verification === 'greeting_only' ? '实时 SOCKS 握手探测' : '进程/配置线索' };
    }

    return { labels: [], evidence: '未从安全配置证据中确认应用协议' };
  };

  const serviceInventoryState = sec.service_inventory_state || 'unavailable';
  const serviceSummary = serviceListeners.length
    ? `${serviceListeners.length} 个监听端点`
    : serviceInventoryState === 'complete'
    ? '未发现监听服务'
    : serviceInventoryState === 'partial'
    ? '采集不完整'
    : '等待客户端采集';

  const protocolPortSummary = (() => {
    const byProtocol = new Map<string, Set<number>>();
    const shortLabel = (value: string) => {
      const lower = value.toLowerCase();
      if (lower.includes('hysteria')) return 'HY2';
      if (lower.includes('socks')) return 'SOCKS';
      if (lower === 'vless') return 'VLESS';
      if (lower === 'vmess') return 'VMess';
      if (lower.includes('wireguard')) return 'WireGuard';
      if (lower.includes('openvpn')) return 'OpenVPN';
      if (lower.includes('shadowsocks')) return 'SS';
      return value;
    };
    for (const listener of serviceListeners) {
      const port = Number(listener.port || 0);
      if (!Number.isInteger(port) || port < 1 || port > 65535) continue;
      for (const label of applicationProtocolsFor(listener).labels) {
        const key = shortLabel(label);
        const ports = byProtocol.get(key) || new Set<number>();
        ports.add(port);
        byProtocol.set(key, ports);
      }
    }
    return Array.from(byProtocol, ([label, ports]) => ({ label, count: ports.size }));
  })();

  const identity: ContainerIdentity = {
    host_id: c.host_id,
    runtime: c.runtime,
    project: c.project,
    container_name: c.container_name,
    alert_id: risk.actionableAlert?.id,
  };

  // Card theme based on risk severity (Light-Ice body + Midnight header)
  let cardBorder = 'border-[#cedae7] hover:border-[#087bff]';
  let accentBar = 'bg-[#94a3b8]';

  if (risk.isCritical || hasResourceGuardFailure) {
    cardBorder = 'border-[#f5a3b3] hover:border-[#dc2626]';
    accentBar = 'bg-[#dc2626]';
  } else if (!isStale && (risk.isWarning || hasResourceAlert || hasProtocolGuardNeedsReview)) {
    cardBorder = 'border-[#f7d58b] hover:border-[#d97706]';
    accentBar = 'bg-[#ff6b00]';
  } else if (!isStale && hasProtectionState) {
    cardBorder = 'border-[#087bff]/55 hover:border-[#087bff]';
    accentBar = 'bg-[#087bff]';
  } else if (!isStale) {
    accentBar = 'bg-[#147468]';
  }

  return (
    <article
      className={`rn2-card group relative flex flex-col justify-between overflow-hidden transition-colors ${cardBorder}`}
    >
      {/* Left Accent Health Bar */}
      <div className={`absolute bottom-0 left-0 top-0 z-10 w-1 ${accentBar} transition-colors`} />

      <div>
        {/* Section 1: Midnight Header Strip */}
        <div className="bg-[linear-gradient(125deg,#163957,#0e233c_58%,#0c1c30)] py-2 pl-3.5 pr-3 text-[#e6f4ff]">
          <div className="flex min-w-0 items-center justify-between gap-1.5">
            {/* Title & Runtime */}
            <div className="flex min-w-0 flex-1 items-center gap-1.5">
              <Box
                className={`h-3.5 w-3.5 shrink-0 ${
                  risk.isCritical || hasResourceGuardFailure
                    ? 'text-rose-300'
                    : risk.isWarning || hasResourceAlert || hasProtocolGuardNeedsReview
                    ? 'text-amber-300'
                    : 'text-[#54c7ff]'
                }`}
                aria-hidden="true"
              />
              <h4 className="min-w-0 flex-1">
                <button
                  type="button"
                  aria-label={`打开容器 ${c.container_name} 详情`}
                  onClick={(event) => {
                    event.stopPropagation();
                    onSelect(identity);
                  }}
                  className={`block w-full truncate text-left font-mono text-xs font-bold transition-colors focus-visible:outline-hidden focus-visible:ring-1 focus-visible:ring-[#54c7ff] ${
                    risk.isCritical
                      ? 'text-rose-200 hover:text-white'
                      : 'text-white hover:text-[#54c7ff]'
                  }`}
                  title={`${c.container_name} (${c.runtime}${c.project ? `/${c.project}` : ''})`}
                >
                  {c.container_name}
                </button>
              </h4>
              <span className="shrink-0 rounded-sm border border-[#54c7ff]/30 bg-[#02182f]/75 px-1 py-0.5 font-mono text-[9px] leading-none text-[#cde8ff]">
                {c.runtime}
              </span>
            </div>

            {/* Badges Cluster */}
            <div className="flex shrink-0 items-center gap-1">
              {(c.alerts?.hy2_detected || sec.hy2_protocol?.detected) && (
                <span
                  className="flex items-center gap-0.5 rounded-full border border-violet-400/50 bg-violet-500/25 px-1.5 py-0.5 font-mono text-[9px] font-bold leading-none text-violet-100"
                  title={`检测到 Hysteria 2 协议 (UDP并发: ${c.alerts?.hy2_concurrency ?? sec.hy2_protocol?.udp_concurrency ?? '未知'})`}
                >
                  <Radio className="h-2.5 w-2.5" aria-hidden="true" />
                  <span>HY2</span>
                </span>
              )}

              {(c.alerts?.udp_throttled || sec.udp_throttle?.throttled) && (
                <span
                  className="flex items-center gap-0.5 rounded-full border border-rose-400/60 bg-rose-500/25 px-1.5 py-0.5 font-mono text-[9px] font-bold leading-none text-rose-100"
                  title={`UDP 靶向限速生效中: ${udpThrottleRate == null ? '速率未知' : `${udpThrottleRate} Mbps`} (${udpThrottleRemaining == null ? '剩余时间未知' : `剩余约 ${Math.ceil(udpThrottleRemaining / 60)} 分钟`})`}
                >
                  <Gauge className="h-2.5 w-2.5" aria-hidden="true" />
                  <span>{udpThrottleRate == null ? 'UDP 限速' : `限速 ${udpThrottleRate}M`}</span>
                </span>
              )}

              {c.alerts?.traffic_imbalance && (
                <span
                  className="flex items-center gap-0.5 rounded-full border border-amber-400/50 bg-amber-500/25 px-1.5 py-0.5 font-mono text-[9px] font-bold leading-none text-amber-100"
                  title={`出入流量失衡: ${c.alerts.traffic_imbalance_ratio}x (${
                    c.alerts.traffic_imbalance_direction === 'outbound_heavy' ? '出栈严重偏高' : '入栈严重偏高'
                  })`}
                >
                  <ArrowUpDown className="h-2.5 w-2.5" aria-hidden="true" />
                  <span>{c.alerts.traffic_imbalance_ratio}x</span>
                </span>
              )}

              {risk.isCritical ? (
                <span
                  className="flex items-center gap-0.5 rounded-full border border-rose-400/60 bg-rose-500/30 px-1.5 py-0.5 text-[9px] font-bold leading-none text-rose-100"
                  title={risk.reasons.join(' · ')}
                >
                  <AlertTriangle className="h-2.5 w-2.5" aria-hidden="true" />
                  <span>异常 {risk.reasons.length}</span>
                </span>
              ) : risk.isWarning ? (
                <span
                  className="flex items-center gap-0.5 rounded-full border border-amber-400/60 bg-amber-500/25 px-1.5 py-0.5 text-[9px] font-bold leading-none text-amber-100"
                  title={risk.reasons.join(' · ')}
                >
                  <AlertCircle className="h-2.5 w-2.5" aria-hidden="true" />
                  <span>预警 {risk.reasons.length}</span>
                </span>
              ) : isStale ? (
                <span className="rounded-full border border-white/20 bg-white/10 px-1.5 py-0.5 text-[9px] font-medium leading-none text-[#cbd5e1]">
                  离线
                </span>
              ) : null}
            </div>
          </div>
        </div>

        {/* Light-Ice Body */}
        <div className="space-y-2 p-3 pl-3.5 pt-2.5">
          <ContainerStateBadges container={c} activeAlerts={activeAlerts} maxVisible={4} />
          {risk.reasons.length > 0 && (
            <p className="truncate text-[10px] font-semibold text-[#b41835]" title={risk.reasons.join(' · ')}>
              {risk.reasons.slice(0, 2).join(' · ')}{risk.reasons.length > 2 ? ` · +${risk.reasons.length - 2} 项` : ''}
            </p>
          )}

          {/* Section 2: Recessed Dual CPU & Memory Spec Cells */}
          <div className="grid grid-cols-2 divide-x divide-[#d2dfec] rounded-lg border border-[#d2dfec] bg-[#f4f8fd] font-mono text-[10px]">
            {/* CPU Meter */}
            <div className="p-2">
              <div className="mb-1 flex items-center justify-between text-[#697b9c]">
                <span className="flex items-center gap-0.5 uppercase tracking-wider">
                  <Cpu className="h-2.5 w-2.5 text-[#087bff]" aria-hidden="true" /> CPU
                </span>
                <span
                  className={`font-bold tabular-nums ${
                    cpu !== null && cpu > 80 ? 'text-[#b41835]' : 'text-[#0b1636]'
                  }`}
                >
                  {cpu === null ? '—' : `${cpu.toFixed(1)}%`}
                </span>
              </div>
              <div className="h-1.5 w-full overflow-hidden rounded-full bg-[#e2ecf6]">
                <div
                  className={`h-full transition-all duration-300 ${
                    cpu === null ? 'bg-[#cbd7e6]' : cpu > 80 ? 'bg-[#dc2626]' : 'bg-[#087bff]'
                  }`}
                  style={{ width: `${Math.min(100, Math.max(0, cpu ?? 0))}%` }}
                />
              </div>
            </div>

            {/* RAM Meter */}
            <div className="p-2">
              <div className="mb-1 flex items-center justify-between text-[#697b9c]">
                <span className="flex items-center gap-0.5 uppercase tracking-wider">
                  <HardDrive className="h-2.5 w-2.5 text-[#147468]" aria-hidden="true" /> RAM
                </span>
                <span
                  className={`font-bold tabular-nums ${
                    mem !== null && mem > 90 ? 'text-[#9a5b00]' : 'text-[#0b1636]'
                  }`}
                  title={`${memUsed} / ${memLimit}`}
                >
                  {mem === null ? '—' : `${mem.toFixed(1)}%`}
                </span>
              </div>
              <div className="h-1.5 w-full overflow-hidden rounded-full bg-[#e2ecf6]">
                <div
                  className={`h-full transition-all duration-300 ${
                    mem === null ? 'bg-[#cbd7e6]' : mem > 90 ? 'bg-[#d97706]' : 'bg-[#147468]'
                  }`}
                  style={{ width: `${Math.min(100, Math.max(0, mem ?? 0))}%` }}
                />
              </div>
            </div>
          </div>

          {/* Section 3: Recessed Bandwidth & Protocol Split */}
          <div className="rounded-lg border border-[#d2dfec] bg-[#f4f8fd] px-2.5 py-1.5 font-mono text-[10px]">
            <div className="flex items-center justify-between tabular-nums">
              <span
                className="flex items-center font-bold text-[#147468]"
                title={`入栈总速率 (RX): ${rxMbps === null ? '不可用' : `${rxMbps} Mbps`}`}
              >
                <ArrowDownLeft className="mr-0.5 h-3 w-3 shrink-0" aria-hidden="true" />
                {rxMbps === null ? '—' : `${rxMbps}M`}
              </span>

              <span
                className="flex items-center font-bold text-[#087bff]"
                title={`出栈总速率 (TX): ${txMbps === null ? '不可用' : `${txMbps} Mbps`}`}
              >
                <ArrowUpRight className="mr-0.5 h-3 w-3 shrink-0" aria-hidden="true" />
                {txMbps === null ? '—' : `${txMbps}M`}
              </span>

              <span className="text-[9px] font-semibold text-[#4a607a] tabular-nums" title={`外部连接数: ${c.conn_count ?? '不可用'}`}>
                {c.conn_count ?? '—'}c
              </span>
            </div>

            <div className="mt-1 flex items-center justify-between border-t border-[#dce5ef] pt-1 font-mono text-[9px] text-[#4a607a]">
              <span title={`TCP 流量: ↓ ${c.tcp_rx_bps == null ? '不可用' : `${fmtMbps(c.tcp_rx_bps)}M`} / ↑ ${c.tcp_tx_bps == null ? '不可用' : `${fmtMbps(c.tcp_tx_bps)}M`}`}>
                <span className="font-bold text-[#0657b8]">T:</span> {c.tcp_rx_bps == null ? '—' : fmtMbps(c.tcp_rx_bps)}/{c.tcp_tx_bps == null ? '—' : fmtMbps(c.tcp_tx_bps)}M
              </span>
              <span title={`UDP 流量: ↓ ${c.udp_rx_bps == null ? '不可用' : `${fmtMbps(c.udp_rx_bps)}M`} / ↑ ${c.udp_tx_bps == null ? '不可用' : `${fmtMbps(c.udp_tx_bps)}M`}`}>
                <span className="font-bold text-violet-700">U:</span> {c.udp_rx_bps == null ? '—' : fmtMbps(c.udp_rx_bps)}/{c.udp_tx_bps == null ? '—' : fmtMbps(c.udp_tx_bps)}M
              </span>
            </div>
          </div>

          {/* Service inventory */}
          <div className="rounded-lg border border-[#d2dfec] bg-[#f4f8fd] px-2.5 py-1.5">
            <button
              type="button"
              aria-expanded={servicesExpanded}
              onClick={(event) => {
                event.stopPropagation();
                setServicesExpanded((expanded) => !expanded);
              }}
              className="flex w-full items-center gap-1.5 rounded text-left text-[10px] text-[#0b1636] focus-visible:outline-hidden focus-visible:ring-1 focus-visible:ring-[#087bff]"
              title="展开查看容器监听服务、所属进程、端口与协议证据"
            >
              <Network className="h-3 w-3 shrink-0 text-[#087bff]" aria-hidden="true" />
              <span className="font-bold text-[#0b1636]">服务 / 代理</span>
              <span className="min-w-0 flex-1 truncate text-right font-mono text-[#4a607a] tabular-nums">
                {serviceSummary}
              </span>
              <ChevronDown className={`h-3 w-3 shrink-0 text-[#697b9c] transition-transform ${servicesExpanded ? 'rotate-180' : ''}`} aria-hidden="true" />
            </button>

            <div className="mt-1 flex min-w-0 flex-wrap items-center gap-1 rounded-md border border-[#dce5ef] bg-white px-1.5 py-1" aria-label="已确认协议及各自使用的端口数">
              <span className="mr-0.5 shrink-0 text-[9px] font-semibold text-[#697b9c]">协议端口</span>
              {protocolPortSummary.length ? protocolPortSummary.map(item => (
                <span key={item.label} className="rounded border border-violet-300 bg-violet-50 px-1.5 py-0.5 text-[9px] font-semibold text-violet-800" title={`${item.label}：${item.count} 个不同监听端口；仅展示与实时进程/端口匹配的配置或协议证据`}>
                  {item.label} ×{item.count}
                </span>
              )) : (
                <span className="text-[9px] text-[#697b9c]">
                  {serviceListeners.length ? '协议待核实' : serviceInventoryState === 'complete' ? '未发现已确认代理协议' : '等待采集'}
                </span>
              )}
            </div>

            {servicesExpanded && (
              <div className="mt-1.5 space-y-1 border-t border-[#dce5ef] pt-1.5">
                {serviceListeners.length > 0 ? (
                  <>
                    {serviceListeners.slice(0, 6).map((listener, index) => {
                      const processName = String(listener.process || '').toLowerCase();
                      const software = PROXY_SOFTWARE_LABELS[processName] || listener.process || '进程未归属';
                      const application = applicationProtocolsFor(listener);
                      const transport = String(listener.proto || 'unknown').toUpperCase();
                      return (
                        <div key={`${listener.proto}-${listener.port}-${listener.pid}-${index}`} className="rounded-md border border-[#dce5ef] bg-white px-2 py-1">
                          <div className="flex min-w-0 flex-wrap items-center gap-1">
                            <span className="max-w-full truncate text-[10px] font-bold text-[#0b1636]" title={listener.process || '内核监听表已发现端口，但未能归属到进程'}>
                              {software}
                            </span>
                            <span className="rounded border border-[#a9d1ff] bg-[#e8f3ff] px-1 py-0.5 font-mono text-[9px] font-semibold text-[#0657b8]">
                              {transport} · {listener.port || '?'}
                            </span>
                            {application.labels.length > 0 ? (
                              application.labels.map((label) => (
                                <span key={label} className="rounded border border-violet-300 bg-violet-50 px-1 py-0.5 text-[9px] font-semibold text-violet-800" title={application.evidence}>
                                  {label}
                                </span>
                              ))
                            ) : (
                              <span className="text-[9px] text-[#697b9c]" title={application.evidence}>应用协议未核实</span>
                            )}
                            {listener.vmess_block_state === 'blocked' && application.labels.some((label) => label.toLowerCase() === 'vmess') && (
                              <span className="rounded border border-[#f9b8c4] bg-[#ffeef1] px-1 py-0.5 text-[9px] font-bold text-[#b41835]" title={listener.vmess_block_message || '只阻断此容器内已确认的 VMess 入站端口，未停止其他服务'}>
                                VMess 已阻断
                              </span>
                            )}
                            {listener.trojan_block_state === 'blocked' && application.labels.some((label) => label.toLowerCase() === 'trojan') && (
                              <span className="rounded border border-[#f9b8c4] bg-[#ffeef1] px-1 py-0.5 text-[9px] font-bold text-[#b41835]" title={listener.trojan_block_message || '只阻断此容器内已确认的 Trojan 入站端口，未停止其他服务'}>
                                Trojan 已阻断
                              </span>
                            )}
                          </div>
                          <div className="mt-0.5 flex flex-wrap items-center gap-x-2 font-mono text-[9px] text-[#697b9c]">
                            <span>{listener.local || '监听地址未采集'}</span>
                            {listener.pid ? <span>PID {listener.pid}</span> : <span>进程归属未知</span>}
                            {application.labels.length > 0 && <span>{application.evidence}</span>}
                          </div>
                        </div>
                      );
                    })}
                    {serviceListeners.length > 6 && (
                      <p className="text-[9px] text-[#697b9c]">另有 {serviceListeners.length - 6} 个端点未在卡片展开区显示；点击卡片可进入容器详情。</p>
                    )}
                  </>
                ) : serviceInventoryState === 'complete' ? (
                  <p className="text-[9px] text-[#697b9c]">本轮采样未发现 TCP/UDP 监听端口。</p>
                ) : serviceInventoryState === 'partial' ? (
                  <p className="text-[9px] font-medium text-[#9a5b00]">本轮服务采集不完整；请更新 Agent 或检查容器内 ss/进程权限。</p>
                ) : (
                  <p className="text-[9px] text-[#697b9c]">客户端尚未提供服务清单数据，升级 Agent 后会显示。</p>
                )}
                <p className="pt-0.5 text-[9px] leading-4 text-[#697b9c]">
                  TCP/UDP 是传输协议；VLESS、VMess 等仅在配置协议与实时 PID/端口对应时展示，否则不猜测。
                </p>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Section 4: Admission & Card Footer */}
      <div className="space-y-2 px-3 pb-3 pl-3.5">
        <AdmissionStatus data={sec.admission} stale={isStale} compact />
        <div className="flex items-center justify-between gap-1 border-t border-[#dce5ef] pt-2 text-[10px]">
          {/* Left: Risk Summary or Timestamp */}
          <div className="min-w-0 flex-1">
            {risk.hasRisk && risk.reasons.length > 0 ? (
              <span
                className={`block truncate font-semibold ${
                  risk.isCritical ? 'text-[#b41835]' : 'text-[#9a5b00]'
                }`}
                title={risk.reasons.join('\n')}
              >
                {risk.reasons[0]}
              </span>
            ) : hasResourceGuardFailure ? (
              <span className="block truncate font-semibold text-[#b41835]" title="自动资源保护未通过核验">自动保护核验失败</span>
            ) : hasProtocolGuardNeedsReview ? (
              <span className="block truncate font-semibold text-[#9a5b00]" title="VMess / Trojan 阻断状态仍需核验">协议阻断待核验</span>
            ) : hasResourceAlert ? (
              <span className="block truncate font-semibold text-[#9a5b00]" title={[
                c.alerts?.cpu ? 'CPU 高负载' : '',
                c.alerts?.memory ? '内存压力' : '',
                c.alerts?.disk ? '磁盘压力' : '',
              ].filter(Boolean).join(' · ')}>
                {[c.alerts?.cpu ? 'CPU 高负载' : '', c.alerts?.memory ? '内存压力' : '', c.alerts?.disk ? '磁盘压力' : ''].filter(Boolean).join(' · ')}
              </span>
            ) : (
              <span className="font-mono text-[9px] text-[#697b9c]">
                {c.timestamp_iso_utc8?.split(' ')[1] || '时间未知'} · {sec.process_count ?? '—'}p
              </span>
            )}
          </div>

          {/* Right: Action Buttons */}
          <div className="flex shrink-0 items-center gap-1" onClick={(e) => e.stopPropagation()}>
            {risk.canRemediate && onQuickDisposition && (
              <button
                type="button"
                disabled={isSubmitting}
                onClick={() => onQuickDisposition(identity, 'deny')}
                className="flex items-center gap-0.5 rounded-md border border-[#f9b8c4] bg-[#ffeef1] px-1.5 py-0.5 text-[10px] font-bold text-[#b41835] transition-colors hover:bg-[#ffe4e6] disabled:opacity-50"
                title="定向处置违规服务或进程"
              >
                <Ban className="h-2.5 w-2.5" aria-hidden="true" />
                <span>处置</span>
              </button>
            )}

            <button
              type="button"
              onClick={() => onSelect(identity)}
              className="flex items-center gap-0.5 rounded-md border border-[#a9d1ff] bg-[#e8f3ff] px-1.5 py-0.5 text-[10px] font-semibold text-[#0657b8] transition-colors hover:border-[#087bff] hover:bg-[#d7eaff]"
              title="查看容器深度诊断面板"
            >
              <Sparkles className="h-2.5 w-2.5 text-[#087bff]" aria-hidden="true" />
              <span>排查</span>
            </button>
          </div>
        </div>
      </div>
    </article>
  );
};
