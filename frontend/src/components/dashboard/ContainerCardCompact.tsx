import React from 'react';
import {
  Box,
  Cpu,
  HardDrive,
  ArrowDownLeft,
  ArrowUpRight,
  AlertTriangle,
  AlertCircle,
  Radio,
  ArrowUpDown,
  Sparkles,
  Ban,
  Gauge,
} from 'lucide-react';
import { ContainerItem, ContainerIdentity } from '../../api/types';
import { fmtBytes, fmtMbps } from '../../api/client';
import { ContainerRiskInfo } from './HostContainerList';

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

  const identity: ContainerIdentity = {
    host_id: c.host_id,
    runtime: c.runtime,
    project: c.project,
    container_name: c.container_name,
  };

  // Card theme based on risk severity
  let cardBorder = 'border-slate-800/90 bg-slate-900/90 hover:border-sky-500/60 shadow-sm';
  let accentBar = 'bg-slate-700';

  if (risk.isCritical) {
    cardBorder =
      'border-rose-500/60 bg-gradient-to-b from-rose-950/30 via-slate-900/95 to-slate-900 shadow-[0_0_15px_rgba(244,63,94,0.12)] hover:border-rose-400';
    accentBar = 'bg-rose-500 shadow-[0_0_8px_rgba(244,63,94,0.6)]';
  } else if (risk.isWarning) {
    cardBorder =
      'border-amber-500/50 bg-gradient-to-b from-amber-950/20 via-slate-900/95 to-slate-900 shadow-[0_0_12px_rgba(245,158,11,0.08)] hover:border-amber-400';
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
      className={`group relative flex flex-col justify-between rounded-xl border p-3 transition-all cursor-pointer select-none overflow-hidden focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-sky-400 ${cardBorder}`}
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
            <span className="shrink-0 rounded bg-slate-800/90 px-1 py-0.2 font-mono text-[9px] text-slate-400 border border-slate-700/50">
              {c.runtime}
            </span>
          </div>

          {/* Badges Cluster (Single-line slot) */}
          <div className="flex items-center gap-1 shrink-0">
            {/* HY2 Badge */}
            {(c.alerts?.hy2_detected || sec.hy2_protocol?.detected) && (
              <span
                className="flex items-center gap-0.5 rounded-full bg-violet-500/20 border border-violet-500/40 px-1.5 py-0.2 text-[9px] font-bold text-violet-300 font-mono shadow-sm"
                title={`检测到 Hysteria 2 协议 (UDP并发: ${c.alerts?.hy2_concurrency ?? sec.hy2_protocol?.udp_concurrency ?? 0})`}
              >
                <Radio className="h-2.5 w-2.5 text-violet-400" />
                <span>HY2</span>
              </span>
            )}

            {/* UDP Throttle Badge */}
            {(c.alerts?.udp_throttled || sec.udp_throttle?.throttled) && (
              <span
                className="flex items-center gap-0.5 rounded-full bg-rose-500/20 border border-rose-500/60 px-1.5 py-0.2 text-[9px] font-bold text-rose-300 font-mono shadow-sm animate-pulse"
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
                className="flex items-center gap-0.5 rounded-full bg-rose-500/20 border border-rose-500/50 px-1.5 py-0.2 text-[9px] font-bold text-rose-300 shadow-sm"
                title={risk.reasons.join(' · ')}
              >
                <AlertTriangle className="h-2.5 w-2.5 text-rose-400 animate-pulse" />
                <span>异常</span>
              </span>
            ) : risk.isWarning ? (
              <span
                className="flex items-center gap-0.5 rounded-full bg-amber-500/20 border border-amber-500/40 px-1.5 py-0.2 text-[9px] font-bold text-amber-300 shadow-sm"
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
      </div>

      {/* Section 4: Card Footer (Risk Indicator or Timestamp + Actions) */}
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
          {risk.hasRisk && onQuickDisposition && (
            <button
              type="button"
              disabled={isSubmitting}
              onClick={() => onQuickDisposition(identity, 'deny')}
              className="flex items-center gap-0.5 rounded px-1.5 py-0.5 font-semibold text-[10px] bg-rose-950/80 text-rose-300 border border-rose-500/40 hover:bg-rose-900 transition-colors focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-rose-400 disabled:opacity-50"
              title="定向处置违规服务或进程"
            >
              <Ban className="h-2.5 w-2.5 text-rose-400" />
              <span>处置</span>
            </button>
          )}

          <button
            type="button"
            onClick={() => onSelect(identity)}
            className="flex items-center gap-0.5 rounded px-1.5 py-0.5 font-medium text-[10px] bg-slate-800/90 text-sky-300 border border-slate-700/70 hover:bg-slate-750 hover:text-sky-200 transition-colors focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-sky-400"
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
