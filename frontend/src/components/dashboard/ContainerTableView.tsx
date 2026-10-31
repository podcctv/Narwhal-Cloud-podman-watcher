import React, { useState, useMemo } from 'react';
import {
  ArrowDownLeft,
  ArrowUpRight,
  AlertTriangle,
  AlertCircle,
  Radio,
  ArrowUpDown,
  Sparkles,
  Ban,
  ArrowUp,
  ArrowDown,
  Gauge,
} from 'lucide-react';
import { ContainerItem, ContainerIdentity, SecurityAlert } from '../../api/types';
import { fmtBytes, fmtMbps } from '../../api/client';
import { evaluateContainerRisk } from './HostContainerList';
import { ContainerStateBadges, hasContainerResourceOrProtectionActivity, hasContainerResourceAlert, hasContainerProtocolGuard, hasContainerResourceGuardFailure, hasContainerProtocolGuardNeedsReview } from './ContainerStateBadges';

interface ContainerTableViewProps {
  containers: ContainerItem[];
  activeAlerts?: SecurityAlert[];
  onSelect: (id: ContainerIdentity) => void;
  onQuickDisposition?: (target: ContainerIdentity, decision: 'deny' | 'allow_silent') => void;
  isSubmitting?: boolean;
}

type SortField = 'name' | 'cpu' | 'mem' | 'rx' | 'tx' | 'conns' | 'risk';
type SortOrder = 'asc' | 'desc';

export const ContainerTableView: React.FC<ContainerTableViewProps> = ({
  containers,
  activeAlerts = [],
  onSelect,
  onQuickDisposition,
  isSubmitting = false,
}) => {
  const [sortField, setSortField] = useState<SortField>('risk');
  const [sortOrder, setSortOrder] = useState<SortOrder>('desc');

  const handleSort = (field: SortField) => {
    if (sortField === field) {
      setSortOrder((prev) => (prev === 'asc' ? 'desc' : 'asc'));
    } else {
      setSortField(field);
      setSortOrder('desc');
    }
  };

  const sortedContainers = useMemo(() => {
    const list = [...containers];
    list.sort((a, b) => {
      const riskA = evaluateContainerRisk(a, activeAlerts);
      const riskB = evaluateContainerRisk(b, activeAlerts);

      let valA: number | string | null = null;
      let valB: number | string | null = null;

      switch (sortField) {
        case 'name':
          valA = a.container_name.toLowerCase();
          valB = b.container_name.toLowerCase();
          break;
        case 'cpu':
          valA = Number.isFinite(a.cpu_percent) ? a.cpu_percent! : null;
          valB = Number.isFinite(b.cpu_percent) ? b.cpu_percent! : null;
          break;
        case 'mem':
          valA = Number.isFinite(a.mem_percent) ? a.mem_percent! : null;
          valB = Number.isFinite(b.mem_percent) ? b.mem_percent! : null;
          break;
        case 'rx':
          valA = Number.isFinite(a.net_rx_bps) ? a.net_rx_bps! : null;
          valB = Number.isFinite(b.net_rx_bps) ? b.net_rx_bps! : null;
          break;
        case 'tx':
          valA = Number.isFinite(a.net_tx_bps) ? a.net_tx_bps! : null;
          valB = Number.isFinite(b.net_tx_bps) ? b.net_tx_bps! : null;
          break;
        case 'conns':
          valA = Number.isFinite(a.conn_count) ? a.conn_count! : null;
          valB = Number.isFinite(b.conn_count) ? b.conn_count! : null;
          break;
        case 'risk':
        default:
          valA = riskA.sortWeight;
          valB = riskB.sortWeight;
          break;
      }

      if (valA === null) return valB === null ? 0 : 1;
      if (valB === null) return -1;
      if (typeof valA === 'string' && typeof valB === 'string') {
        return sortOrder === 'asc' ? valA.localeCompare(valB) : valB.localeCompare(valA);
      }
      return sortOrder === 'asc' ? Number(valA) - Number(valB) : Number(valB) - Number(valA);
    });
    return list;
  }, [containers, activeAlerts, sortField, sortOrder]);

  const renderSortIndicator = (field: SortField) => {
    if (sortField !== field) {
      return <ArrowUpDown className="h-3 w-3 opacity-30 group-hover:opacity-70" />;
    }
    return sortOrder === 'asc' ? (
      <ArrowUp className="h-3 w-3 text-sky-400" />
    ) : (
      <ArrowDown className="h-3 w-3 text-sky-400" />
    );
  };

  const renderSortHeader = (field: SortField, label: string) => (
    <th scope="col" aria-sort={sortField === field ? (sortOrder === 'asc' ? 'ascending' : 'descending') : 'none'}>
      <button
        type="button"
        onClick={() => handleSort(field)}
        aria-label={`按${label}排序`}
        className="group flex w-full items-center gap-1 px-2 py-2.5 text-left hover:text-slate-200 focus-visible:outline-hidden focus-visible:ring-1 focus-visible:ring-inset focus-visible:ring-sky-400"
      >
        <span>{label}</span>
        {renderSortIndicator(field)}
      </button>
    </th>
  );

  return (
    <div className="overflow-x-auto rounded-xl border border-slate-800 bg-slate-950/70 shadow-inner">
      <table className="w-full text-left border-collapse text-xs">
        <thead>
          <tr className="border-b border-slate-800/90 bg-slate-900/90 text-[11px] font-semibold text-slate-400 font-mono">
            <th scope="col" className="py-2.5 pl-3 pr-2 w-8">状态</th>
            {renderSortHeader('name', '容器名称 / 运行时')}
            {renderSortHeader('cpu', 'CPU')}
            {renderSortHeader('mem', '内存 (Used / Limit)')}
            {renderSortHeader('rx', '入栈 (RX)')}
            {renderSortHeader('tx', '出栈 (TX)')}
            {renderSortHeader('conns', '连接 / 进程')}
            <th scope="col" className="py-2.5 px-2">协议与特征</th>
            {renderSortHeader('risk', '安全诊断')}
            <th scope="col" className="py-2.5 pr-3 pl-2 text-right">操作</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-800/60 font-mono">
          {sortedContainers.map((c) => {
            const risk = evaluateContainerRisk(c, activeAlerts);
            const isStale = Boolean(c.alerts?.stale);
            const hasResourceAlert = !isStale && hasContainerResourceAlert(c);
            const hasProtectionOrProtocol = !isStale && (hasContainerResourceOrProtectionActivity(c, activeAlerts) || hasContainerProtocolGuard(c));
            const hasResourceGuardFailure = !isStale && hasContainerResourceGuardFailure(c);
            const hasProtocolGuardNeedsReview = !isStale && hasContainerProtocolGuardNeedsReview(c);
            const cpu = typeof c.cpu_percent === 'number' && Number.isFinite(c.cpu_percent) ? c.cpu_percent : null;
            const mem = typeof c.mem_percent === 'number' && Number.isFinite(c.mem_percent) ? c.mem_percent : null;
            const memUsed = typeof c.mem_bytes === 'number' && Number.isFinite(c.mem_bytes) ? fmtBytes(c.mem_bytes) : '—';
            const memLimit = typeof c.mem_limit_bytes === 'number' && Number.isFinite(c.mem_limit_bytes) ? fmtBytes(c.mem_limit_bytes) : '—';
            const rxMbps = typeof c.net_rx_bps === 'number' && Number.isFinite(c.net_rx_bps) ? fmtMbps(c.net_rx_bps) : null;
            const txMbps = typeof c.net_tx_bps === 'number' && Number.isFinite(c.net_tx_bps) ? fmtMbps(c.net_tx_bps) : null;
            const sec = c.security || {};
            const udpThrottleRate = c.alerts?.udp_throttle_rate_mbps ?? sec.udp_throttle?.rate_mbps;

            const identity: ContainerIdentity = {
              host_id: c.host_id,
              runtime: c.runtime,
              project: c.project,
              container_name: c.container_name,
              alert_id: risk.actionableAlert?.id,
            };

            let rowBg = 'hover:bg-slate-900/70 transition-colors';
            if (risk.isCritical || hasResourceGuardFailure) {
              rowBg = 'bg-rose-950/20 hover:bg-rose-950/40 transition-colors';
            } else if (risk.isWarning || hasResourceAlert || hasProtocolGuardNeedsReview) {
              rowBg = 'bg-amber-950/15 hover:bg-amber-950/30 transition-colors';
            }

            return (
              <tr
                key={`${c.host_id}-${c.runtime}-${c.project || ''}-${c.container_name}`}
                onClick={() => onSelect(identity)}
                className={`cursor-pointer group ${rowBg}`}
              >
                {/* 1. Status Dot */}
                <td className="py-2 pl-3 pr-2 whitespace-nowrap">
                  <span
                    className={`inline-block h-2 w-2 rounded-full ${
                      risk.isCritical || hasResourceGuardFailure
                        ? 'bg-rose-500 animate-pulse shadow-[0_0_6px_rgba(244,63,94,0.8)]'
                        : risk.isWarning || hasProtocolGuardNeedsReview
                        ? 'bg-amber-400 shadow-[0_0_5px_rgba(245,158,11,0.7)]'
                        : isStale
                        ? 'bg-slate-600'
                        : hasResourceAlert
                        ? 'bg-amber-400 shadow-[0_0_5px_rgba(245,158,11,0.7)]'
                        : hasProtectionOrProtocol
                        ? 'bg-sky-400'
                        : 'bg-emerald-400 shadow-[0_0_5px_rgba(34,197,94,0.6)]'
                    }`}
                    title={
                      risk.isCritical || hasResourceGuardFailure
                        ? '存在严重安全风险或自动保护核验失败'
                        : isStale
                        ? '数据已离线'
                        : risk.isWarning || hasProtocolGuardNeedsReview
                        ? '存在运行预警'
                        : hasResourceAlert
                        ? '存在 CPU、内存或磁盘资源告警'
                        : hasProtectionOrProtocol
                        ? '存在资源保护或协议管控状态'
                        : '运行正常'
                    }
                  />
                </td>

                {/* 2. Container Name & Runtime */}
                <td className="py-2 px-2 whitespace-nowrap">
                  <div className="flex items-center gap-1.5">
                    <button
                      type="button"
                      onClick={(event) => {
                        event.stopPropagation();
                        onSelect(identity);
                      }}
                      aria-label={`打开容器 ${c.container_name} 详情`}
                      className={`font-bold text-xs truncate max-w-[180px] sm:max-w-[240px] ${
                        risk.isCritical
                          ? 'text-rose-200 group-hover:text-rose-100'
                          : 'text-slate-100 group-hover:text-sky-300'
                      } rounded-sm text-left focus-visible:outline-hidden focus-visible:ring-1 focus-visible:ring-sky-400`}
                      title={c.container_name}
                    >
                      {c.container_name}
                    </button>
                    <span className="rounded-sm bg-slate-800 px-1 py-0.2 text-[9px] text-slate-400 border border-slate-700/50">
                      {c.runtime}
                    </span>
                  </div>
                </td>

                {/* 3. CPU */}
                <td className="py-2 px-2 whitespace-nowrap">
                  <div className="flex items-center gap-2">
                    <span
                      className={`tabular-nums font-semibold w-10 ${
                        cpu !== null && cpu > 80 ? 'text-rose-400 font-bold' : 'text-slate-200'
                      }`}
                    >
                      {cpu === null ? '—' : `${cpu.toFixed(1)}%`}
                    </span>
                    <div className="hidden sm:block h-1 w-12 rounded-full bg-slate-800 overflow-hidden">
                      <div
                        className={`h-full ${cpu === null ? 'bg-slate-700' : cpu > 80 ? 'bg-rose-500' : 'bg-sky-400'}`}
                        style={{ width: `${Math.min(100, Math.max(0, cpu ?? 0))}%` }}
                      />
                    </div>
                  </div>
                </td>

                {/* 4. Memory */}
                <td className="py-2 px-2 whitespace-nowrap">
                  <div className="flex items-center gap-2">
                    <span
                      className={`tabular-nums font-semibold ${
                        mem !== null && mem > 90 ? 'text-amber-400 font-bold' : 'text-slate-200'
                      }`}
                    >
                      {mem === null ? '—' : `${mem.toFixed(1)}%`}
                    </span>
                    <span className="text-[10px] text-slate-400 tabular-nums">
                      ({memUsed} / {memLimit})
                    </span>
                  </div>
                </td>

                {/* 5. Inbound (RX) */}
                <td className="py-2 px-2 whitespace-nowrap tabular-nums">
                  <div className="flex items-center gap-1 text-emerald-400 font-semibold">
                    <ArrowDownLeft className="h-3 w-3 text-emerald-400/80" />
                    <span>{rxMbps === null ? '—' : `${rxMbps}M`}</span>
                    <span className="text-[9px] text-slate-400 font-normal ml-1">
                      (T:{c.tcp_rx_bps == null ? '—' : fmtMbps(c.tcp_rx_bps)}/U:{c.udp_rx_bps == null ? '—' : fmtMbps(c.udp_rx_bps)})
                    </span>
                  </div>
                </td>

                {/* 6. Outbound (TX) */}
                <td className="py-2 px-2 whitespace-nowrap tabular-nums">
                  <div className="flex items-center gap-1 text-sky-400 font-semibold">
                    <ArrowUpRight className="h-3 w-3 text-sky-400/80" />
                    <span>{txMbps === null ? '—' : `${txMbps}M`}</span>
                    <span className="text-[9px] text-slate-400 font-normal ml-1">
                      (T:{c.tcp_tx_bps == null ? '—' : fmtMbps(c.tcp_tx_bps)}/U:{c.udp_tx_bps == null ? '—' : fmtMbps(c.udp_tx_bps)})
                    </span>
                  </div>
                </td>

                {/* 7. Conns / Procs */}
                <td className="py-2 px-2 whitespace-nowrap tabular-nums text-slate-300">
                  <span className="font-semibold">{c.conn_count ?? '—'}</span>
                  <span className="text-slate-400 text-[10px]"> conn</span>
                  <span className="text-slate-600 mx-1">·</span>
                  <span className="text-slate-400 text-[10px]">{sec.process_count ?? '—'} proc</span>
                </td>

                {/* 8. Protocol & Badges */}
                <td className="py-2 px-2 whitespace-nowrap">
                  <div className="flex items-center gap-1">
                    {(c.alerts?.hy2_detected || sec.hy2_protocol?.detected) && (
                      <span
                        className="inline-flex items-center gap-0.5 rounded-full bg-violet-500/20 border border-violet-500/40 px-1.5 py-0.2 text-[9px] font-bold text-violet-300"
                        title="Hysteria 2 协议活跃"
                      >
                        <Radio className="h-2.5 w-2.5 text-violet-400" />
                        <span>HY2</span>
                      </span>
                    )}

                    {(c.alerts?.udp_throttled || sec.udp_throttle?.throttled) && (
                      <span
                        className="inline-flex items-center gap-0.5 rounded-full bg-rose-500/20 border border-rose-500/60 px-1.5 py-0.2 text-[9px] font-bold text-rose-300 animate-pulse"
                        title={`UDP 靶向限速生效中: ${udpThrottleRate == null ? '速率未知' : `${udpThrottleRate} Mbps`}`}
                      >
                        <Gauge className="h-2.5 w-2.5 text-rose-400" />
                        <span>{udpThrottleRate == null ? 'UDP 限速' : `限速 ${udpThrottleRate}M`}</span>
                      </span>
                    )}

                    {c.alerts?.traffic_imbalance && (
                      <span
                        className="inline-flex items-center gap-0.5 rounded-full bg-amber-500/20 border border-amber-500/40 px-1.5 py-0.2 text-[9px] font-bold text-amber-300"
                        title={`出入流量失衡 ${c.alerts.traffic_imbalance_ratio}x`}
                      >
                        <ArrowUpDown className="h-2.5 w-2.5 text-amber-400" />
                        <span>{c.alerts.traffic_imbalance_ratio}x</span>
                      </span>
                    )}

                  </div>
                  <ContainerStateBadges container={c} activeAlerts={activeAlerts} maxVisible={5} className="mt-1" />
                </td>

                {/* 9. Security Diagnostics */}
                <td className="py-2 px-2 whitespace-nowrap">
                  {risk.hasRisk ? (
                    <div className="flex max-w-[240px] flex-wrap items-center gap-1" title={risk.reasons.join(' · ')}>
                      {risk.isCritical ? (
                        <span className="inline-flex items-center gap-1 rounded-sm bg-rose-950/70 border border-rose-500/40 px-1.5 py-0.2 text-[10px] font-bold text-rose-300">
                          <AlertTriangle className="h-2.5 w-2.5 text-rose-400 shrink-0" />
                          <span>{risk.reasons.length} 项</span>
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 rounded-sm bg-amber-950/70 border border-amber-500/40 px-1.5 py-0.2 text-[10px] font-bold text-amber-300">
                          <AlertCircle className="h-2.5 w-2.5 text-amber-400 shrink-0" />
                          <span>{risk.reasons.length} 项</span>
                        </span>
                      )}
                      {risk.reasons.slice(0, 2).map((reason, index) => (
                        <span key={`${index}-${reason}`} className="max-w-[190px] truncate rounded-sm border border-slate-700 bg-slate-900 px-1.5 py-0.5 text-[10px] text-slate-300" title={reason}>{reason}</span>
                      ))}
                    </div>
                  ) : (
                    <span className="text-[10px] text-slate-400">暂无活动风险告警</span>
                  )}
                </td>

                {/* 10. Actions */}
                <td
                  className="py-2 pr-3 pl-2 text-right whitespace-nowrap"
                  onClick={(e) => e.stopPropagation()}
                >
                  <div className="flex items-center justify-end gap-1.5">
                    {risk.canRemediate && onQuickDisposition && (
                      <button
                        type="button"
                        disabled={isSubmitting}
                        onClick={() => onQuickDisposition(identity, 'deny')}
                        className="flex items-center gap-1 rounded-sm px-2 py-0.5 text-[10px] font-semibold bg-rose-950/80 text-rose-300 border border-rose-500/40 hover:bg-rose-900 transition-colors focus-visible:outline-hidden focus-visible:ring-1 focus-visible:ring-rose-400 disabled:opacity-50"
                        title="定向处置违规进程或服务"
                      >
                        <Ban className="h-2.5 w-2.5 text-rose-400" />
                        <span>处置</span>
                      </button>
                    )}

                    <button
                      type="button"
                      onClick={() => onSelect(identity)}
                      className="flex items-center gap-1 rounded-sm px-2 py-0.5 text-[10px] font-medium bg-slate-800 text-sky-300 border border-slate-700 hover:bg-slate-750 hover:text-sky-200 transition-colors focus-visible:outline-hidden focus-visible:ring-1 focus-visible:ring-sky-400"
                      title="打开深度排查抽屉"
                    >
                      <Sparkles className="h-2.5 w-2.5 text-sky-400" />
                      <span>排查</span>
                    </button>
                  </div>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
};
