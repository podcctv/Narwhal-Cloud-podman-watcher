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
import { ContainerItem, ContainerIdentity } from '../../api/types';
import { fmtBytes, fmtMbps } from '../../api/client';
import { ContainerRiskInfo } from './HostContainerList';
import { AdmissionStatus } from '../container/AdmissionStatus';

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
  onSelect: (id: ContainerIdentity) => void;
  onQuickDisposition?: (target: ContainerIdentity, decision: 'deny' | 'allow_silent') => void;
  isSubmitting?: boolean;
}

export const ContainerCardCompact: React.FC<ContainerCardCompactProps> = ({
  container: c,
  risk,
  onSelect,
  onQuickDisposition,
  isSubmitting = false,
}) => {
  const isStale = Boolean(c.alerts?.stale);
  const cpu = c.cpu_percent || 0;
  const mem = c.mem_percent || 0;
  const memUsed = fmtBytes(c.mem_bytes);
  const memLimit = fmtBytes(c.mem_limit_bytes);
  const rxMbps = fmtMbps(c.net_rx_bps);
  const txMbps = fmtMbps(c.net_tx_bps);
  const sec = c.security || {};
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
    const configured = Array.isArray(listener.application_protocols)
      ? listener.application_protocols.map((protocol) => APP_PROTOCOL_LABELS[protocol] || protocol.toUpperCase())
      : [];
    if (configured.length > 0) return { labels: configured, evidence: '进程配置与当前 PID/端口匹配' };

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

  const identity: ContainerIdentity = {
    host_id: c.host_id,
    runtime: c.runtime,
    project: c.project,
    container_name: c.container_name,
    alert_id: risk.actionableAlert?.id,
  };

  // Card theme based on risk severity
  let cardBorder = 'border-slate-800/90 bg-slate-900/90 hover:border-sky-500/60 shadow-xs';
  let accentBar = 'bg-slate-700';

  if (risk.isCritical) {
    cardBorder =
      'border-rose-500/60 bg-linear-to-b from-rose-950/30 via-slate-900/95 to-slate-900 shadow-[0_0_15px_rgba(244,63,94,0.12)] hover:border-rose-400';
    accentBar = 'bg-rose-500 shadow-[0_0_8px_rgba(244,63,94,0.6)]';
  } else if (risk.isWarning) {
    cardBorder =
      'border-amber-500/50 bg-linear-to-b from-amber-950/20 via-slate-900/95 to-slate-900 shadow-[0_0_12px_rgba(245,158,11,0.08)] hover:border-amber-400';
    accentBar = 'bg-amber-400 shadow-[0_0_6px_rgba(245,158,11,0.5)]';
  } else if (!isStale) {
    accentBar = 'bg-emerald-500/80';
  }

  return (
    <div
      role="button"
      tabIndex={0}
      onClick={() => onSelect(identity)}
      onKeyDown={(e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          onSelect(identity);
        }
      }}
      className={`group relative flex flex-col justify-between rounded-xl border p-3 transition-all cursor-pointer select-none overflow-hidden focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-sky-400 ${cardBorder}`}
    >
      {/* Top Left Accent Health Pill */}
      <div className={`absolute left-0 top-0 bottom-0 w-1 ${accentBar} transition-colors`} />

      {/* Section 1: Card Header */}
      <div className="pl-1">
        <div className="flex items-center justify-between gap-1.5 min-w-0">
          {/* Title & Runtime */}
          <div className="flex items-center gap-1.5 min-w-0 flex-1">
            <Box
              className={`h-3.5 w-3.5 shrink-0 ${
                risk.isCritical
                  ? 'text-rose-400'
                  : risk.isWarning
                  ? 'text-amber-400'
                  : 'text-sky-400'
              }`}
            />
            <h4
              className={`font-mono text-xs font-bold truncate transition-colors ${
                risk.isCritical
                  ? 'text-rose-200 group-hover:text-rose-100'
                  : 'text-slate-100 group-hover:text-sky-300'
              }`}
              title={`${c.container_name} (${c.runtime}${c.project ? `/${c.project}` : ''})`}
            >
              {c.container_name}
            </h4>
            <span className="shrink-0 rounded-sm bg-slate-800/90 px-1 py-0.2 font-mono text-[9px] text-slate-400 border border-slate-700/50">
              {c.runtime}
            </span>
          </div>

          {/* Badges Cluster (Single-line slot) */}
          <div className="flex items-center gap-1 shrink-0">
            {/* HY2 Badge */}
            {(c.alerts?.hy2_detected || sec.hy2_protocol?.detected) && (
              <span
                className="flex items-center gap-0.5 rounded-full bg-violet-500/20 border border-violet-500/40 px-1.5 py-0.2 text-[9px] font-bold text-violet-300 font-mono shadow-xs"
                title={`检测到 Hysteria 2 协议 (UDP并发: ${c.alerts?.hy2_concurrency ?? sec.hy2_protocol?.udp_concurrency ?? 0})`}
              >
                <Radio className="h-2.5 w-2.5 text-violet-400" />
                <span>HY2</span>
              </span>
            )}

            {/* UDP Throttle Badge */}
            {(c.alerts?.udp_throttled || sec.udp_throttle?.throttled) && (
              <span
                className="flex items-center gap-0.5 rounded-full bg-rose-500/20 border border-rose-500/60 px-1.5 py-0.2 text-[9px] font-bold text-rose-300 font-mono shadow-xs animate-pulse"
                title={`UDP 靶向限速生效中: ${c.alerts?.udp_throttle_rate_mbps ?? sec.udp_throttle?.rate_mbps ?? 10}Mbps (剩余约 ${Math.ceil((c.alerts?.udp_throttle_remaining_seconds ?? sec.udp_throttle?.remaining_seconds ?? 0) / 60)} 分钟)`}
              >
                <Gauge className="h-2.5 w-2.5 text-rose-400" />
                <span>限速 {c.alerts?.udp_throttle_rate_mbps ?? sec.udp_throttle?.rate_mbps ?? 10}M</span>
              </span>
            )}

            {/* Traffic Imbalance Badge */}
            {c.alerts?.traffic_imbalance && (
              <span
                className="flex items-center gap-0.5 rounded-full bg-amber-500/20 border border-amber-500/40 px-1.5 py-0.2 text-[9px] font-bold text-amber-300 font-mono"
                title={`出入流量失衡: ${c.alerts.traffic_imbalance_ratio}x (${
                  c.alerts.traffic_imbalance_direction === 'outbound_heavy' ? '出栈严重偏高' : '入栈严重偏高'
                })`}
              >
                <ArrowUpDown className="h-2.5 w-2.5 text-amber-400" />
                <span>{c.alerts.traffic_imbalance_ratio}x</span>
              </span>
            )}

            {/* Risk Badge */}
            {risk.isCritical ? (
              <span
                className="flex items-center gap-0.5 rounded-full bg-rose-500/20 border border-rose-500/50 px-1.5 py-0.2 text-[9px] font-bold text-rose-300 shadow-xs"
                title={risk.reasons.join(' · ')}
              >
                <AlertTriangle className="h-2.5 w-2.5 text-rose-400 animate-pulse" />
                <span>异常</span>
              </span>
            ) : risk.isWarning ? (
              <span
                className="flex items-center gap-0.5 rounded-full bg-amber-500/20 border border-amber-500/40 px-1.5 py-0.2 text-[9px] font-bold text-amber-300 shadow-xs"
                title={risk.reasons.join(' · ')}
              >
                <AlertCircle className="h-2.5 w-2.5 text-amber-400" />
                <span>预警</span>
              </span>
            ) : isStale ? (
              <span className="rounded-full bg-slate-800 border border-slate-700 px-1.5 py-0.2 text-[9px] font-medium text-slate-400">
                离线
              </span>
            ) : null}
          </div>
        </div>

        {/* Section 2: Dual CPU & Memory Meter */}
        <div className="mt-2.5 grid grid-cols-2 gap-2 text-[10px] font-mono">
          {/* CPU Meter */}
          <div>
            <div className="flex items-center justify-between text-slate-400 mb-0.5">
              <span className="flex items-center gap-0.5">
                <Cpu className="h-2.5 w-2.5 text-slate-500" /> CPU
              </span>
              <span
                className={`font-bold tabular-nums ${
                  cpu > 80 ? 'text-rose-400' : 'text-slate-200'
                }`}
              >
                {cpu.toFixed(1)}%
              </span>
            </div>
            <div className="h-1 w-full rounded-full bg-slate-800/80 overflow-hidden">
              <div
                className={`h-full transition-all duration-300 ${
                  cpu > 80 ? 'bg-rose-500' : 'bg-sky-400'
                }`}
                style={{ width: `${Math.min(100, Math.max(0, cpu))}%` }}
              />
            </div>
          </div>

          {/* RAM Meter */}
          <div>
            <div className="flex items-center justify-between text-slate-400 mb-0.5">
              <span className="flex items-center gap-0.5">
                <HardDrive className="h-2.5 w-2.5 text-slate-500" /> 内存
              </span>
              <span
                className={`font-bold tabular-nums ${
                  mem > 90 ? 'text-amber-400' : 'text-slate-200'
                }`}
                title={`${memUsed} / ${memLimit}`}
              >
                {mem.toFixed(1)}%
              </span>
            </div>
            <div className="h-1 w-full rounded-full bg-slate-800/80 overflow-hidden">
              <div
                className={`h-full transition-all duration-300 ${
                  mem > 90 ? 'bg-amber-400' : 'bg-emerald-400'
                }`}
                style={{ width: `${Math.min(100, Math.max(0, mem))}%` }}
              />
            </div>
          </div>
        </div>

        {/* Section 3: Bandwidth & Protocol Split */}
        <div className="mt-2 rounded-lg bg-slate-950/70 border border-slate-800/80 px-2 py-1 font-mono text-[10px]">
          <div className="flex items-center justify-between tabular-nums">
            {/* Download RX */}
            <span
              className="flex items-center text-emerald-400 font-semibold"
              title={`入栈总速率 (RX): ${rxMbps} Mbps`}
            >
              <ArrowDownLeft className="h-3 w-3 mr-0.5 text-emerald-400/80 shrink-0" />
              {rxMbps}M
            </span>

            {/* Upload TX */}
            <span
              className="flex items-center text-sky-400 font-semibold"
              title={`出栈总速率 (TX): ${txMbps} Mbps`}
            >
              <ArrowUpRight className="h-3 w-3 mr-0.5 text-sky-400/80 shrink-0" />
              {txMbps}M
            </span>

            {/* Conns */}
            <span className="text-slate-400 text-[9px] tabular-nums" title={`外部连接数: ${c.conn_count || 0}`}>
              {c.conn_count || 0}c
            </span>
          </div>

          {/* Protocol Split Sub-row */}
          <div className="flex items-center justify-between text-[9px] text-slate-400/90 border-t border-slate-800/60 pt-0.5 mt-0.5 font-mono">
            <span title={`TCP 流量: ↓ ${fmtMbps(c.tcp_rx_bps)}M / ↑ ${fmtMbps(c.tcp_tx_bps)}M`}>
              <span className="text-blue-400/90">T:</span> {fmtMbps(c.tcp_rx_bps)}/{fmtMbps(c.tcp_tx_bps)}M
            </span>
            <span title={`UDP 流量: ↓ ${fmtMbps(c.udp_rx_bps)}M / ↑ ${fmtMbps(c.udp_tx_bps)}M`}>
              <span className="text-violet-400/90">U:</span> {fmtMbps(c.udp_rx_bps)}/{fmtMbps(c.udp_tx_bps)}M
            </span>
          </div>
        </div>

        {/* Service inventory: process-owned listener ports, with conservative protocol labels. */}
        <div className="mt-1.5 rounded-lg border border-slate-800/80 bg-slate-950/50 px-2 py-1.5">
          <button
            type="button"
            aria-expanded={servicesExpanded}
            onClick={(event) => {
              event.stopPropagation();
              setServicesExpanded((expanded) => !expanded);
            }}
            className="flex w-full items-center gap-1.5 text-left text-[10px] text-slate-300 focus-visible:outline-hidden focus-visible:ring-1 focus-visible:ring-sky-400 rounded"
            title="展开查看容器监听服务、所属进程、端口与协议证据"
          >
            <Network className="h-3 w-3 shrink-0 text-cyan-400" />
            <span className="font-semibold text-slate-200">服务 / 代理</span>
            <span className="min-w-0 flex-1 truncate text-right font-mono text-slate-400 tabular-nums">
              {serviceSummary}
            </span>
            <ChevronDown className={`h-3 w-3 shrink-0 text-slate-500 transition-transform ${servicesExpanded ? 'rotate-180' : ''}`} />
          </button>

          {servicesExpanded && (
            <div className="mt-1.5 space-y-1 border-t border-slate-800/70 pt-1.5">
              {serviceListeners.length > 0 ? (
                <>
                  {serviceListeners.slice(0, 6).map((listener, index) => {
                    const processName = String(listener.process || '').toLowerCase();
                    const software = PROXY_SOFTWARE_LABELS[processName] || listener.process || '进程未归属';
                    const application = applicationProtocolsFor(listener);
                    const transport = String(listener.proto || 'unknown').toUpperCase();
                    return (
                      <div key={`${listener.proto}-${listener.port}-${listener.pid}-${index}`} className="rounded-md bg-slate-900/80 px-1.5 py-1">
                        <div className="flex min-w-0 flex-wrap items-center gap-1">
                          <span className="max-w-full truncate text-[10px] font-semibold text-slate-200" title={listener.process || '内核监听表已发现端口，但未能归属到进程'}>
                            {software}
                          </span>
                          <span className="rounded border border-sky-800/70 bg-sky-950/50 px-1 py-0.5 font-mono text-[9px] text-sky-300">
                            {transport} · {listener.port || '?'}
                          </span>
                          {application.labels.length > 0 ? (
                            application.labels.map((label) => (
                              <span key={label} className="rounded border border-violet-800/70 bg-violet-950/40 px-1 py-0.5 text-[9px] text-violet-300" title={application.evidence}>
                                {label}
                              </span>
                            ))
                          ) : (
                            <span className="text-[9px] text-slate-500" title={application.evidence}>应用协议未核实</span>
                          )}
                        </div>
                        <div className="mt-0.5 flex flex-wrap items-center gap-x-2 text-[9px] font-mono text-slate-500">
                          <span>{listener.local || '监听地址未采集'}</span>
                          {listener.pid ? <span>PID {listener.pid}</span> : <span>进程归属未知</span>}
                          {application.labels.length > 0 && <span>{application.evidence}</span>}
                        </div>
                      </div>
                    );
                  })}
                  {serviceListeners.length > 6 && (
                    <p className="text-[9px] text-slate-500">另有 {serviceListeners.length - 6} 个端点未在卡片展开区显示；点击卡片可进入容器详情。</p>
                  )}
                </>
              ) : serviceInventoryState === 'complete' ? (
                <p className="text-[9px] text-slate-400">本轮采样未发现 TCP/UDP 监听端口。</p>
              ) : serviceInventoryState === 'partial' ? (
                <p className="text-[9px] text-amber-300">本轮服务采集不完整；请更新 Agent 或检查容器内 ss/进程权限。</p>
              ) : (
                <p className="text-[9px] text-slate-500">客户端尚未提供服务清单数据，升级 Agent 后会显示。</p>
              )}
              <p className="pt-0.5 text-[9px] leading-4 text-slate-500">
                TCP/UDP 是传输协议；VLESS、VMess 等仅在配置协议与实时 PID/端口对应时展示，否则不猜测。
              </p>
            </div>
          )}
        </div>
      </div>

      {/* Section 4: Card Footer (Risk Indicator or Timestamp + Actions) */}
      <AdmissionStatus data={sec.admission} stale={isStale} compact />
      <div className="pl-1 mt-2 pt-1.5 border-t border-slate-800/70 flex items-center justify-between gap-1 text-[10px]">
        {/* Left: Risk Summary or Timestamp */}
        <div className="min-w-0 flex-1">
          {risk.hasRisk && risk.reasons.length > 0 ? (
            <span
              className={`block truncate font-medium ${
                risk.isCritical ? 'text-rose-300' : 'text-amber-300'
              }`}
              title={risk.reasons.join('\n')}
            >
              {risk.reasons[0]}
            </span>
          ) : (
            <span className="font-mono text-slate-400 text-[9px]">
              {c.timestamp_iso_utc8?.split(' ')[1] || '实时'} · {sec.process_count || 0}p
            </span>
          )}
        </div>

        {/* Right: Action Buttons */}
        <div className="flex items-center gap-1 shrink-0" onClick={(e) => e.stopPropagation()}>
          {risk.canRemediate && onQuickDisposition && (
            <button
              type="button"
              disabled={isSubmitting}
              onClick={() => onQuickDisposition(identity, 'deny')}
              className="flex items-center gap-0.5 rounded-sm px-1.5 py-0.5 font-semibold text-[10px] bg-rose-950/80 text-rose-300 border border-rose-500/40 hover:bg-rose-900 transition-colors focus-visible:outline-hidden focus-visible:ring-1 focus-visible:ring-rose-400 disabled:opacity-50"
              title="定向处置违规服务或进程"
            >
              <Ban className="h-2.5 w-2.5 text-rose-400" />
              <span>处置</span>
            </button>
          )}

          <button
            type="button"
            onClick={() => onSelect(identity)}
            className="flex items-center gap-0.5 rounded-sm px-1.5 py-0.5 font-medium text-[10px] bg-slate-800/90 text-sky-300 border border-slate-700/70 hover:bg-slate-750 hover:text-sky-200 transition-colors focus-visible:outline-hidden focus-visible:ring-1 focus-visible:ring-sky-400"
            title="查看容器深度诊断面板"
          >
            <Sparkles className="h-2.5 w-2.5 text-sky-400" />
            <span>排查</span>
          </button>
        </div>
      </div>
    </div>
  );
};
