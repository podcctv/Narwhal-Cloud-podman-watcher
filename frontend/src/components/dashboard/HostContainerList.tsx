import React, { useState } from 'react';
import {
  ChevronDown,
  Server,
  Box,
  Cpu,
  HardDrive,
  Activity,
  ArrowDownLeft,
  ArrowUpRight,
  ShieldAlert,
  AlertTriangle,
  AlertCircle,
  Layers,
  Sparkles,
} from 'lucide-react';
import { ContainerItem, ContainerIdentity, SecurityAlert } from '../../api/types';
import { StatusBadge } from '../common/StatusBadge';
import { fmtBytes, fmtMbps } from '../../api/client';

interface HostContainerListProps {
  containers: ContainerItem[];
  serverVersion: string;
  activeAlerts?: SecurityAlert[];
  onSelectContainer: (id: ContainerIdentity) => void;
}

export interface ContainerRiskInfo {
  hasRisk: boolean;
  isCritical: boolean;
  isWarning: boolean;
  reasons: string[];
  sortWeight: number;
}

export function evaluateContainerRisk(
  container: ContainerItem,
  activeAlerts: SecurityAlert[] = []
): ContainerRiskInfo {
  const reasons: string[] = [];
  let sortWeight = 0;

  // 1. Check matching active security alerts from backend
  const matchingAlerts = activeAlerts.filter(
    (a) =>
      a.host_id === container.host_id &&
      a.container_name === container.container_name &&
      (!a.project || !container.project || a.project === container.project) &&
      a.status === 'active'
  );

  for (const alert of matchingAlerts) {
    if (alert.severity === 'critical') {
      reasons.push(alert.title || alert.message || '严重安全威胁');
      sortWeight += 1000;
    } else {
      reasons.push(alert.title || alert.message || '安全预警');
      sortWeight += 500;
    }
  }

  const sec = container.security || {};

  // 2. Check SOCKS proxy risks
  if (sec.socks_proxy?.detected) {
    if (sec.socks_proxy.auth_mode === 'no_auth') {
      reasons.push('检测到开放无认证 SOCKS 代理');
      sortWeight += 900;
    } else if (sec.socks_proxy.auth_mode === 'weak_password') {
      reasons.push('检测到弱口令 SOCKS 代理');
      sortWeight += 800;
    } else {
      reasons.push('运行 SOCKS 代理服务');
      sortWeight += 250;
    }
  }

  // 3. Check panel pairing
  if (sec.panel_pairing?.detected) {
    if (!sec.panel_pairing.approved) {
      reasons.push('未授权面板对接活动');
      sortWeight += 850;
    } else {
      reasons.push('已配置面板对接');
      sortWeight += 150;
    }
  }

  // 4. Inbound IP anomaly
  const inIps = Number(sec.inbound_unique_ips || 0);
  const inThresh = Number(sec.inbound_unique_ip_threshold || 10);
  if (inIps > inThresh) {
    if (inIps >= inThresh * 2) {
      reasons.push(`入站 IP 来源异常密集 (${inIps} / ${inThresh})`);
      sortWeight += 750;
    } else {
      reasons.push(`入站来源 IP 去重超标 (${inIps} / ${inThresh})`);
      sortWeight += 400;
    }
  }

  // 5. Suspicious processes / miners
  if (sec.suspicious_processes && sec.suspicious_processes.length > 0) {
    reasons.push(`检测到 ${sec.suspicious_processes.length} 个可疑/挖矿进程`);
    sortWeight += 950;
  }

  // 6. Resource overloads
  if (container.alerts?.conn || (container.conn_count || 0) > 1000) {
    reasons.push(`并发连接超限 (${container.conn_count || 0})`);
    sortWeight += 350;
  }
  if (container.alerts?.cpu || (container.cpu_percent || 0) > 90) {
    reasons.push(`CPU 负载极高 (${(container.cpu_percent || 0).toFixed(1)}%)`);
    sortWeight += 300;
  }
  if (container.alerts?.memory || (container.mem_percent || 0) > 90) {
    reasons.push(`内存占用超限 (${(container.mem_percent || 0).toFixed(1)}%)`);
    sortWeight += 300;
  }

  // 7. Stale / offline
  if (container.alerts?.stale) {
    reasons.push('容器状态失联或已停止上报');
    sortWeight += 150;
  }

  const hasRisk = sortWeight > 0;
  const isCritical = sortWeight >= 600;
  const isWarning = hasRisk && !isCritical;

  return {
    hasRisk,
    isCritical,
    isWarning,
    reasons: Array.from(new Set(reasons)),
    sortWeight,
  };
}

export const HostContainerList: React.FC<HostContainerListProps> = ({
  containers,
  serverVersion,
  activeAlerts = [],
  onSelectContainer,
}) => {
  // Group by host_id
  const hostMap: Record<string, ContainerItem[]> = {};
  containers.forEach((c) => {
    if (!hostMap[c.host_id]) hostMap[c.host_id] = [];
    hostMap[c.host_id].push(c);
  });

  // Sort hosts: hosts with higher risk come first
  const hostIds = Object.keys(hostMap).sort((a, b) => {
    const maxA = Math.max(0, ...hostMap[a].map((c) => evaluateContainerRisk(c, activeAlerts).sortWeight));
    const maxB = Math.max(0, ...hostMap[b].map((c) => evaluateContainerRisk(c, activeAlerts).sortWeight));
    if (maxA !== maxB) {
      return maxB - maxA;
    }
    return a.localeCompare(b);
  });

  // All hosts collapsed by default as requested
  const [expandedHosts, setExpandedHosts] = useState<Record<string, boolean>>({});

  const toggleHost = (hostId: string) => {
    setExpandedHosts((prev) => ({ ...prev, [hostId]: !prev[hostId] }));
  };

  const expandAll = () => {
    const next: Record<string, boolean> = {};
    hostIds.forEach((h) => (next[h] = true));
    setExpandedHosts(next);
  };

  const collapseAll = () => {
    setExpandedHosts({});
  };

  if (hostIds.length === 0) {
    return (
      <section className="rounded-2xl border border-dashed border-slate-800 p-12 text-center">
        <Server className="mx-auto h-10 w-10 text-slate-600 mb-3" />
        <h3 className="text-sm font-semibold text-slate-300">暂无已注册的主机与容器</h3>
        <p className="mt-1 text-xs text-slate-500">
          请检查客户端守护进程是否已启动并成功上报指标至 `/api/v1/report`。
        </p>
      </section>
    );
  }

  return (
    <section className="space-y-4" aria-label="主机与容器拓扑列表">
      <div className="flex items-center justify-between px-1">
        <div className="flex items-center gap-2">
          <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">服务器与容器</span>
          <span className="text-xs text-slate-500">({hostIds.length} 台主机)</span>
        </div>
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={expandAll}
            className="text-[11px] font-medium text-slate-400 hover:text-sky-300 transition-colors px-2 py-0.5 rounded border border-slate-800 hover:border-slate-700 bg-slate-900/60"
          >
            全部展开
          </button>
          <button
            type="button"
            onClick={collapseAll}
            className="text-[11px] font-medium text-slate-400 hover:text-sky-300 transition-colors px-2 py-0.5 rounded border border-slate-800 hover:border-slate-700 bg-slate-900/60"
          >
            全部折叠
          </button>
        </div>
      </div>

      {hostIds.map((hostId) => {
        const hostContainers = hostMap[hostId];
        const isExpanded = Boolean(expandedHosts[hostId]);

        // Aggregate statistics for host banner
        const totalRunning = hostContainers.filter((c) => !c.alerts?.stale).length;
        const hostRiskyContainers = hostContainers.filter(
          (c) => evaluateContainerRisk(c, activeAlerts).hasRisk
        );
        const hostRiskyCount = hostRiskyContainers.length;

        // Sort containers: risky containers ranked first!
        const sortedContainers = [...hostContainers].sort((a, b) => {
          const riskA = evaluateContainerRisk(a, activeAlerts);
          const riskB = evaluateContainerRisk(b, activeAlerts);
          if (riskA.sortWeight !== riskB.sortWeight) {
            return riskB.sortWeight - riskA.sortWeight;
          }
          return a.container_name.localeCompare(b.container_name);
        });

        const agentVersion = hostContainers[0]?.agent_version || 'unknown';
        const isVersionMatch =
          agentVersion !== 'unknown' &&
          agentVersion !== 'dev' &&
          agentVersion === serverVersion;

        return (
          <div
            key={hostId}
            className={`rounded-2xl border transition-colors shadow-sm overflow-hidden ${
              hostRiskyCount > 0
                ? 'border-rose-900/60 bg-slate-900/80 shadow-[0_0_15px_rgba(244,63,94,0.08)]'
                : 'border-slate-800 bg-slate-900/60'
            }`}
          >
            {/* Host Accordion Bar */}
            <div
              onClick={() => toggleHost(hostId)}
              className="flex items-center justify-between p-4 cursor-pointer hover:bg-slate-800/40 select-none transition-colors border-b border-transparent data-[expanded=true]:border-slate-800"
              data-expanded={isExpanded}
            >
              <div className="flex items-center gap-3">
                <div
                  className={`rounded-xl p-2 border transition-colors ${
                    hostRiskyCount > 0
                      ? 'bg-rose-950/80 text-rose-400 border-rose-500/40'
                      : 'bg-sky-950/80 text-sky-400 border-sky-500/30'
                  }`}
                >
                  <Server className="h-4 w-4" />
                </div>
                <div>
                  <div className="flex items-center gap-2">
                    <span className="font-bold text-sm text-slate-100 font-mono">
                      {hostId}
                    </span>
                    {/* Version Badge */}
                    <span
                      className={`rounded-full border px-2 py-0.2 text-[10px] font-mono font-medium ${
                        isVersionMatch
                          ? 'border-emerald-500/30 bg-emerald-950/50 text-emerald-400'
                          : agentVersion === 'unknown' || agentVersion === 'dev'
                          ? 'border-amber-500/30 bg-amber-950/50 text-amber-400'
                          : 'border-rose-500/30 bg-rose-950/50 text-rose-400'
                      }`}
                    >
                      Agent v{agentVersion}
                    </span>
                  </div>
                  <span className="text-xs text-slate-400">
                    共 {hostContainers.length} 个容器 · {totalRunning} 个在线
                  </span>
                </div>
              </div>

              {/* Badges & Chevron */}
              <div className="flex items-center gap-3">
                {hostRiskyCount > 0 && (
                  <span className="rounded-full border border-rose-500/50 bg-rose-950/70 px-2.5 py-0.5 text-xs font-bold text-rose-300 flex items-center gap-1.5 shadow-[0_0_12px_rgba(244,63,94,0.25)] animate-pulse">
                    <ShieldAlert className="h-3.5 w-3.5 text-rose-400" />
                    <span>{hostRiskyCount} 个异常容器</span>
                  </span>
                )}
                <ChevronDown
                  className={`h-4 w-4 text-slate-400 transition-transform duration-200 ${
                    isExpanded ? 'rotate-180' : ''
                  }`}
                />
              </div>
            </div>

            {/* Container Grid */}
            {isExpanded && (
              <div className="p-4 grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3.5 bg-slate-950/40">
                {sortedContainers.map((c) => {
                  const risk = evaluateContainerRisk(c, activeAlerts);
                  const isStale = c.alerts?.stale;
                  const cpu = c.cpu_percent || 0;
                  const mem = c.mem_percent || 0;
                  const rxMbps = fmtMbps(c.net_rx_bps);
                  const txMbps = fmtMbps(c.net_tx_bps);
                  const memUsed = fmtBytes(c.mem_bytes);
                  const memLimit = fmtBytes(c.mem_limit_bytes);
                  const sec = c.security || {};

                  // Dye container card based on risk level
                  let cardStyle =
                    'border-slate-800 bg-slate-900/80 hover:border-sky-500/50 shadow-sm';
                  if (risk.isCritical) {
                    cardStyle =
                      'border-rose-500/70 bg-gradient-to-b from-rose-950/40 via-slate-900/90 to-slate-900/95 shadow-[0_0_20px_rgba(244,63,94,0.18)] hover:border-rose-400 hover:shadow-[0_0_25px_rgba(244,63,94,0.28)]';
                  } else if (risk.isWarning) {
                    cardStyle =
                      'border-amber-500/50 bg-gradient-to-b from-amber-950/30 via-slate-900/90 to-slate-900/95 shadow-[0_0_15px_rgba(245,158,11,0.12)] hover:border-amber-400';
                  }

                  return (
                    <div
                      key={`${c.host_id}-${c.runtime}-${c.project || ''}-${c.container_name}`}
                      className={`group relative rounded-xl border p-4 transition-all flex flex-col justify-between ${cardStyle}`}
                    >
                      {/* Container Top Meta */}
                      <div>
                        <div className="flex items-start justify-between gap-2 mb-2">
                          <div className="min-w-0">
                            <div className="flex items-center gap-1.5">
                              <Box
                                className={`h-4 w-4 shrink-0 ${
                                  risk.isCritical
                                    ? 'text-rose-400'
                                    : risk.isWarning
                                    ? 'text-amber-400'
                                    : 'text-sky-400'
                                }`}
                              />
                              <h4
                                className={`font-bold text-sm truncate transition-colors ${
                                  risk.isCritical
                                    ? 'text-rose-200 group-hover:text-rose-100'
                                    : 'text-slate-100 group-hover:text-sky-300'
                                }`}
                                title={c.container_name}
                              >
                                {c.container_name}
                              </h4>
                            </div>
                            <span className="text-[11px] text-slate-400 font-mono">
                              {c.project ? `${c.runtime}/${c.project}` : c.runtime}
                            </span>
                          </div>

                          <div className="flex items-center gap-1.5 shrink-0">
                            {risk.isCritical && (
                              <span className="rounded-full bg-rose-500/20 border border-rose-500/50 px-2 py-0.5 text-[10px] font-bold text-rose-300 flex items-center gap-1 shadow-sm">
                                <AlertTriangle className="h-3 w-3 text-rose-400 animate-pulse" />
                                <span>异常风险</span>
                              </span>
                            )}
                            {risk.isWarning && (
                              <span className="rounded-full bg-amber-500/20 border border-amber-500/40 px-2 py-0.5 text-[10px] font-bold text-amber-300 flex items-center gap-1 shadow-sm">
                                <AlertCircle className="h-3 w-3 text-amber-400" />
                                <span>运行预警</span>
                              </span>
                            )}
                            <StatusBadge
                              status={isStale ? 'stale' : 'healthy'}
                              size="sm"
                              pulse={!isStale}
                            />
                          </div>
                        </div>

                        {/* Resource Meters */}
                        <div className="space-y-2 mt-3 text-xs">
                          {/* CPU Metric */}
                          <div>
                            <div className="flex justify-between font-mono text-slate-300 mb-1">
                              <span className="flex items-center gap-1 text-slate-400">
                                <Cpu className="h-3 w-3" /> CPU
                              </span>
                              <span
                                className={`tabular-nums font-bold ${
                                  cpu > 80 ? 'text-rose-400' : 'text-slate-200'
                                }`}
                              >
                                {cpu.toFixed(1)}%
                              </span>
                            </div>
                            <div className="h-1.5 w-full rounded-full bg-slate-800 overflow-hidden">
                              <div
                                className={`h-full transition-all duration-500 ${
                                  cpu > 80 ? 'bg-rose-500' : 'bg-sky-500'
                                }`}
                                style={{ width: `${Math.min(100, Math.max(0, cpu))}%` }}
                              />
                            </div>
                          </div>

                          {/* Memory Metric */}
                          <div>
                            <div className="flex justify-between font-mono text-slate-300 mb-1">
                              <span className="flex items-center gap-1 text-slate-400">
                                <HardDrive className="h-3 w-3" /> 内存
                              </span>
                              <span
                                className={`tabular-nums font-bold ${
                                  mem > 85 ? 'text-rose-400' : 'text-slate-200'
                                }`}
                              >
                                {mem.toFixed(1)}% ({memUsed} / {memLimit})
                              </span>
                            </div>
                            <div className="h-1.5 w-full rounded-full bg-slate-800 overflow-hidden">
                              <div
                                className={`h-full transition-all duration-500 ${
                                  mem > 85 ? 'bg-rose-500' : 'bg-emerald-500'
                                }`}
                                style={{ width: `${Math.min(100, Math.max(0, mem))}%` }}
                              />
                            </div>
                          </div>

                          {/* Traffic & Conns Grid */}
                          <div className="grid grid-cols-2 gap-2 pt-1 font-mono text-[11px]">
                            <div className="rounded-lg bg-slate-950/60 p-2 border border-slate-800/80">
                              <span className="text-slate-500 flex items-center gap-1">
                                <Activity className="h-3 w-3 text-sky-400" /> 带宽
                              </span>
                              <div className="mt-1 flex items-center justify-between text-slate-300 tabular-nums font-semibold">
                                <span className="flex items-center text-emerald-400">
                                  <ArrowDownLeft className="h-3 w-3 mr-0.5" />
                                  {rxMbps}M
                                </span>
                                <span className="flex items-center text-sky-400">
                                  <ArrowUpRight className="h-3 w-3 mr-0.5" />
                                  {txMbps}M
                                </span>
                              </div>
                            </div>

                            <div className="rounded-lg bg-slate-950/60 p-2 border border-slate-800/80">
                              <span className="text-slate-500 flex items-center gap-1">
                                <Layers className="h-3 w-3 text-amber-400" /> 连接 / 进程
                              </span>
                              <div className="mt-1 flex items-center justify-between text-slate-300 tabular-nums font-semibold">
                                <span>{c.conn_count || 0} conn</span>
                                <span>{sec.process_count || 0} proc</span>
                              </div>
                            </div>
                          </div>

                          {/* Risk Reasons Banner (Dye & Highlighted for easy inspection) */}
                          {risk.hasRisk && risk.reasons.length > 0 && (
                            <div
                              className={`mt-2.5 rounded-lg border p-2 text-xs space-y-1 ${
                                risk.isCritical
                                  ? 'border-rose-500/50 bg-rose-950/60 text-rose-200 shadow-sm'
                                  : 'border-amber-500/40 bg-amber-950/50 text-amber-200'
                              }`}
                            >
                              <div
                                className={`flex items-center gap-1.5 font-bold ${
                                  risk.isCritical ? 'text-rose-300' : 'text-amber-300'
                                }`}
                              >
                                {risk.isCritical ? (
                                  <AlertTriangle className="h-3.5 w-3.5 text-rose-400 shrink-0 animate-pulse" />
                                ) : (
                                  <AlertCircle className="h-3.5 w-3.5 text-amber-400 shrink-0" />
                                )}
                                <span>异常风险待排查 ({risk.reasons.length} 项)</span>
                              </div>
                              <ul className="space-y-0.5 text-[11px] pl-1">
                                {risk.reasons.map((reason, idx) => (
                                  <li key={idx} className="flex items-start gap-1">
                                    <span
                                      className={`font-bold ${
                                        risk.isCritical ? 'text-rose-400' : 'text-amber-400'
                                      }`}
                                    >
                                      •
                                    </span>
                                    <span className="leading-tight">{reason}</span>
                                  </li>
                                ))}
                              </ul>
                            </div>
                          )}
                        </div>
                      </div>

                      {/* Inspect Button */}
                      <div className="mt-4 pt-3 border-t border-slate-800/80 flex items-center justify-between">
                        <span className="text-[10px] text-slate-500 font-mono">
                          {c.timestamp_iso_utc8?.split(' ')[1] || ''}
                        </span>
                        <button
                          type="button"
                          onClick={() =>
                            onSelectContainer({
                              host_id: c.host_id,
                              runtime: c.runtime,
                              project: c.project,
                              container_name: c.container_name,
                            })
                          }
                          className={`flex items-center gap-1.5 rounded-lg border px-3 py-1.5 text-xs font-semibold transition-all shadow-sm ${
                            risk.isCritical
                              ? 'border-rose-500/60 bg-rose-950/70 text-rose-200 hover:border-rose-400 hover:bg-rose-900/80 hover:text-white'
                              : 'border-slate-700 bg-slate-800 text-sky-400 hover:border-sky-500 hover:text-sky-300 hover:bg-slate-750'
                          }`}
                        >
                          <Sparkles className="h-3.5 w-3.5" />
                          <span>{risk.hasRisk ? '立即排查' : '深度排查'}</span>
                        </button>
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        );
      })}
    </section>
  );
};
