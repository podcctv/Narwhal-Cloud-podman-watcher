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
import { ContainerItem, ContainerIdentity } from '../../api/types';
import { fmtBytes, fmtMbps } from '../../api/client';
import { evaluateContainerRisk } from './HostContainerList';

interface ContainerTableViewProps {
  containers: ContainerItem[];
  onSelect: (id: ContainerIdentity) => void;
  onQuickDisposition?: (target: ContainerIdentity, decision: 'deny' | 'allow_silent') => void;
  isSubmitting?: boolean;
}

type SortField = 'name' | 'cpu' | 'mem' | 'rx' | 'tx' | 'conns' | 'risk';
type SortOrder = 'asc' | 'desc';

export const ContainerTableView: React.FC<ContainerTableViewProps> = ({
  containers,
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
      const riskA = evaluateContainerRisk(a);
      const riskB = evaluateContainerRisk(b);

      let valA: number | string = 0;
      let valB: number | string = 0;

      switch (sortField) {
        case 'name':
          valA = a.container_name.toLowerCase();
          valB = b.container_name.toLowerCase();
          break;
        case 'cpu':
          valA = a.cpu_percent || 0;
          valB = b.cpu_percent || 0;
          break;
        case 'mem':
          valA = a.mem_percent || 0;
          valB = b.mem_percent || 0;
          break;
        case 'rx':
          valA = a.net_rx_bps || 0;
          valB = b.net_rx_bps || 0;
          break;
        case 'tx':
          valA = a.net_tx_bps || 0;
          valB = b.net_tx_bps || 0;
          break;
        case 'conns':
          valA = a.conn_count || 0;
          valB = b.conn_count || 0;
          break;
        case 'risk':
        default:
          valA = riskA.sortWeight;
          valB = riskB.sortWeight;
          break;
      }

      if (typeof valA === 'string' && typeof valB === 'string') {
        return sortOrder === 'asc' ? valA.localeCompare(valB) : valB.localeCompare(valA);
      }
      return sortOrder === 'asc' ? Number(valA) - Number(valB) : Number(valB) - Number(valA);
    });
    return list;
  }, [containers, sortField, sortOrder]);

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

  return (
    <div className="overflow-x-auto rounded-xl border border-slate-800 bg-slate-950/70 shadow-inner">
      <table className="w-full text-left border-collapse text-xs">
        <thead>
          <tr className="border-b border-slate-800/90 bg-slate-900/90 text-[11px] font-semibold text-slate-400 font-mono">
            <th className="py-2.5 pl-3 pr-2 w-8">状态</th>
            <th
              className="py-2.5 px-2 cursor-pointer select-none group hover:text-slate-200"
              onClick={() => handleSort('name')}
            >
              <div className="flex items-center gap-1">
                <span>容器名称 / 运行时</span>
                {renderSortIndicator('name')}
              </div>
            </th>
            <th
              className="py-2.5 px-2 cursor-pointer select-none group hover:text-slate-200"
              onClick={() => handleSort('cpu')}
            >
              <div className="flex items-center gap-1">
                <span>CPU</span>
                {renderSortIndicator('cpu')}
              </div>
            </th>
            <th
              className="py-2.5 px-2 cursor-pointer select-none group hover:text-slate-200"
              onClick={() => handleSort('mem')}
            >
              <div className="flex items-center gap-1">
                <span>内存 (Used / Limit)</span>
                {renderSortIndicator('mem')}
              </div>
            </th>
            <th
              className="py-2.5 px-2 cursor-pointer select-none group hover:text-slate-200"
              onClick={() => handleSort('rx')}
            >
              <div className="flex items-center gap-1">
                <span>入栈 (RX)</span>
                {renderSortIndicator('rx')}
              </div>
            </th>
            <th
              className="py-2.5 px-2 cursor-pointer select-none group hover:text-slate-200"
              onClick={() => handleSort('tx')}
            >
              <div className="flex items-center gap-1">
                <span>出栈 (TX)</span>
                {renderSortIndicator('tx')}
              </div>
            </th>
            <th
              className="py-2.5 px-2 cursor-pointer select-none group hover:text-slate-200"
              onClick={() => handleSort('conns')}
            >
              <div className="flex items-center gap-1">
                <span>连接 / 进程</span>
                {renderSortIndicator('conns')}
              </div>
            </th>
            <th className="py-2.5 px-2">协议与特征</th>
            <th
              className="py-2.5 px-2 cursor-pointer select-none group hover:text-slate-200"
              onClick={() => handleSort('risk')}
            >
              <div className="flex items-center gap-1">
                <span>安全诊断</span>
                {renderSortIndicator('risk')}
              </div>
            </th>
            <th className="py-2.5 pr-3 pl-2 text-right">操作</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-800/60 font-mono">
          {sortedContainers.map((c) => {
            const risk = evaluateContainerRisk(c);
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

            let rowBg = 'hover:bg-slate-900/70 transition-colors';
            if (risk.isCritical) {
              rowBg = 'bg-rose-950/20 hover:bg-rose-950/40 transition-colors';
            } else if (risk.isWarning) {
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
                      risk.isCritical
                        ? 'bg-rose-500 animate-pulse shadow-[0_0_6px_rgba(244,63,94,0.8)]'
                        : risk.isWarning
                        ? 'bg-amber-400 shadow-[0_0_5px_rgba(245,158,11,0.7)]'
                        : isStale
                        ? 'bg-slate-600'
                        : 'bg-emerald-400 shadow-[0_0_5px_rgba(34,197,94,0.6)]'
                    }`}
                    title={
                      risk.isCritical
                        ? '存在严重安全风险'
                        : risk.isWarning
                        ? '存在运行预警'
                        : isStale
                        ? '数据已离线'
                        : '运行正常'
                    }
                  />
                </td>

                {/* 2. Container Name & Runtime */}
                <td className="py-2 px-2 whitespace-nowrap">
                  <div className="flex items-center gap-1.5">
                    <span
                      className={`font-bold text-xs truncate max-w-[180px] sm:max-w-[240px] ${
                        risk.isCritical
                          ? 'text-rose-200 group-hover:text-rose-100'
                          : 'text-slate-100 group-hover:text-sky-300'
                      }`}
                      title={c.container_name}
                    >
                      {c.container_name}
                    </span>
                    <span className="rounded bg-slate-800 px-1 py-0.2 text-[9px] text-slate-400 border border-slate-700/50">
                      {c.runtime}
                    </span>
                  </div>
                </td>

                {/* 3. CPU */}
                <td className="py-2 px-2 whitespace-nowrap">
                  <div className="flex items-center gap-2">
                    <span
                      className={`tabular-nums font-semibold w-10 ${
                        cpu > 80 ? 'text-rose-400 font-bold' : 'text-slate-200'
                      }`}
                    >
                      {cpu.toFixed(1)}%
                    </span>
                    <div className="hidden sm:block h-1 w-12 rounded-full bg-slate-800 overflow-hidden">
                      <div
                        className={`h-full ${cpu > 80 ? 'bg-rose-500' : 'bg-sky-400'}`}
                        style={{ width: `${Math.min(100, Math.max(0, cpu))}%` }}
                      />
                    </div>
                  </div>
                </td>

                {/* 4. Memory */}
                <td className="py-2 px-2 whitespace-nowrap">
                  <div className="flex items-center gap-2">
                    <span
                      className={`tabular-nums font-semibold ${
                        mem > 90 ? 'text-amber-400 font-bold' : 'text-slate-200'
                      }`}
                    >
                      {mem.toFixed(1)}%
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
                    <span>{rxMbps}M</span>
                    <span className="text-[9px] text-slate-400 font-normal ml-1">
                      (T:{fmtMbps(c.tcp_rx_bps)}/U:{fmtMbps(c.udp_rx_bps)})
                    </span>
                  </div>
                </td>

                {/* 6. Outbound (TX) */}
                <td className="py-2 px-2 whitespace-nowrap tabular-nums">
                  <div className="flex items-center gap-1 text-sky-400 font-semibold">
                    <ArrowUpRight className="h-3 w-3 text-sky-400/80" />
                    <span>{txMbps}M</span>
                    <span className="text-[9px] text-slate-400 font-normal ml-1">
                      (T:{fmtMbps(c.tcp_tx_bps)}/U:{fmtMbps(c.udp_tx_bps)})
                    </span>
                  </div>
                </td>

                {/* 7. Conns / Procs */}
                <td className="py-2 px-2 whitespace-nowrap tabular-nums text-slate-300">
                  <span className="font-semibold">{c.conn_count || 0}</span>
                  <span className="text-slate-400 text-[10px]"> conn</span>
                  <span className="text-slate-600 mx-1">·</span>
                  <span className="text-slate-400 text-[10px]">{sec.process_count || 0} proc</span>
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
                        title={`UDP 靶向限速生效中: ${c.alerts?.udp_throttle_rate_mbps ?? sec.udp_throttle?.rate_mbps ?? 10}Mbps`}
                      >
                        <Gauge className="h-2.5 w-2.5 text-rose-400" />
                        <span>限速 {c.alerts?.udp_throttle_rate_mbps ?? sec.udp_throttle?.rate_mbps ?? 10}M</span>
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

                    {!c.alerts?.hy2_detected && !sec.hy2_protocol?.detected && !c.alerts?.traffic_imbalance && (
                      <span className="text-[10px] text-slate-600">—</span>
                    )}
                  </div>
                </td>

                {/* 9. Security Diagnostics */}
                <td className="py-2 px-2 whitespace-nowrap">
                  {risk.hasRisk ? (
                    <div className="flex items-center gap-1 max-w-[200px]">
                      {risk.isCritical ? (
                        <span className="inline-flex items-center gap-1 rounded bg-rose-950/70 border border-rose-500/40 px-1.5 py-0.2 text-[10px] font-bold text-rose-300 truncate">
                          <AlertTriangle className="h-2.5 w-2.5 text-rose-400 shrink-0" />
                          <span className="truncate">{risk.reasons[0]}</span>
                          {risk.reasons.length > 1 && <span>+{risk.reasons.length - 1}</span>}
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 rounded bg-amber-950/70 border border-amber-500/40 px-1.5 py-0.2 text-[10px] font-bold text-amber-300 truncate">
                          <AlertCircle className="h-2.5 w-2.5 text-amber-400 shrink-0" />
                          <span className="truncate">{risk.reasons[0]}</span>
                        </span>
                      )}
                    </div>
                  ) : (
                    <span className="text-[10px] text-emerald-400/80">正常</span>
                  )}
                </td>

                {/* 10. Actions */}
                <td
                  className="py-2 pr-3 pl-2 text-right whitespace-nowrap"
                  onClick={(e) => e.stopPropagation()}
                >
                  <div className="flex items-center justify-end gap-1.5">
                    {risk.hasRisk && onQuickDisposition && (
                      <button
                        type="button"
                        disabled={isSubmitting}
                        onClick={() => onQuickDisposition(identity, 'deny')}
                        className="flex items-center gap-1 rounded px-2 py-0.5 text-[10px] font-semibold bg-rose-950/80 text-rose-300 border border-rose-500/40 hover:bg-rose-900 transition-colors focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-rose-400 disabled:opacity-50"
                        title="定向处置违规进程或服务"
                      >
                        <Ban className="h-2.5 w-2.5 text-rose-400" />
                        <span>处置</span>
                      </button>
                    )}

                    <button
                      type="button"
                      onClick={() => onSelect(identity)}
                      className="flex items-center gap-1 rounded px-2 py-0.5 text-[10px] font-medium bg-slate-800 text-sky-300 border border-slate-700 hover:bg-slate-750 hover:text-sky-200 transition-colors focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-sky-400"
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
