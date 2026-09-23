import React, { useState, useEffect, useMemo } from 'react';
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
  Ban,
  Check,
  Radio,
  ArrowUpDown,
  FilterX,
} from 'lucide-react';
import { ContainerItem, ContainerIdentity, SecurityAlert } from '../../api/types';
import { StatusBadge } from '../common/StatusBadge';
import { ConfirmDialog } from '../common/ConfirmDialog';
import { api, fmtBytes, fmtMbps } from '../../api/client';
import { DashboardToolbar, ViewMode, FilterState } from './DashboardToolbar';
import { ContainerCardCompact } from './ContainerCardCompact';
import { ContainerTableView } from './ContainerTableView';

interface HostContainerListProps {
  containers: ContainerItem[];
  serverVersion: string;
  activeAlerts?: SecurityAlert[];
  onSelectContainer: (id: ContainerIdentity) => void;
  onToast?: (type: 'success' | 'error' | 'info', message: string) => void;
  onRefresh?: () => void;
}

export interface ContainerRiskInfo {
  hasRisk: boolean;
  canRemediate: boolean;
  actionableAlert: SecurityAlert | null;
  isCritical: boolean;
  isWarning: boolean;
  reasons: string[];
  sortWeight: number;
}

export function evaluateContainerRisk(
  container: ContainerItem,
  activeAlerts: SecurityAlert[] = []
): ContainerRiskInfo {
  if (container.alerts?.stale) {
    return {
      hasRisk: false,
      canRemediate: false,
      actionableAlert: null,
      isCritical: false,
      isWarning: false,
      reasons: [],
      sortWeight: 0,
    };
  }
  const reasons: string[] = [];
  let sortWeight = 0;

  // 1. Check matching active security alerts from backend
  const matchingAlerts = activeAlerts.filter(
    (a) =>
      a.host_id === container.host_id &&
      a.runtime === container.runtime &&
      a.container_name === container.container_name &&
      (a.project || '') === (container.project || '') &&
      a.status === 'active'
  );

  const isActionable = (alert: SecurityAlert) => {
    if (alert.runtime !== 'incus' && alert.runtime !== 'podman') return false;
    const details = alert.details || {};
    if (alert.type === 'unauthorized_panel_pairing') {
      return (details.process_patterns || []).length > 0 || (details.config_files || []).length > 0;
    }
    if (alert.type === 'socks_weak_auth') {
      return ['no_auth', 'weak_password'].includes(details.socks_auth_mode) && (details.socks_processes || []).length > 0;
    }
    if (alert.type === 'malicious_process') {
      return (details.malicious_processes || []).some((item: any) => item?.process === 'xmrig');
    }
    return false;
  };
  const actionableAlert = matchingAlerts.find(isActionable) || null;

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

  // 2. SOCKS proxy risks
  if (sec.socks_proxy?.detected) {
    if (sec.socks_proxy.auth_mode === 'weak_password') {
      reasons.push('SOCKS 代理弱密码隐患');
      sortWeight += 850;
    } else if (sec.socks_proxy.auth_mode === 'no_auth') {
      reasons.push('SOCKS 代理开放且无认证');
      sortWeight += 900;
    }
  }

  // 3. Panel pairing
  if (sec.panel_pairing?.detected && !sec.panel_pairing.approved) {
    reasons.push('未授权面板对接活动');
    sortWeight += 800;
  }

  // 4. Inbound IP flood anomaly
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

  // 6. Extreme connection flood
  if (container.alerts?.conn || (container.conn_count || 0) > 1500) {
    reasons.push(`并发连接异常泛洪 (${container.conn_count || 0})`);
    sortWeight += 450;
  }

  // 7. Traffic Imbalance
  if (container.alerts?.traffic_imbalance) {
    const ratio = container.alerts.traffic_imbalance_ratio || 10;
    const dir = container.alerts.traffic_imbalance_direction === 'outbound_heavy' ? '出栈严重偏高' : '入栈严重偏高';
    reasons.push(`网络流量严重不均衡 (${dir}, ${ratio}x)`);
    sortWeight += ratio >= 25 ? 700 : 450;
  }

  // 8. Hysteria 2 High Concurrency Observation
  if (container.alerts?.hy2_detected && (container.alerts?.hy2_concurrency || 0) >= 50) {
    reasons.push(`高并发 Hysteria 2 协议 (UDP并发: ${container.alerts.hy2_concurrency})`);
    sortWeight += (container.alerts.hy2_concurrency || 0) >= 200 ? 650 : 350;
  }

  const hasRisk = sortWeight > 0;
  const isCritical = sortWeight >= 600;
  const isWarning = hasRisk && !isCritical;

  return {
    hasRisk,
    canRemediate: Boolean(actionableAlert),
    actionableAlert,
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
  onToast,
  onRefresh,
}) => {
  // View mode state with localStorage persistence
  const [viewMode, setViewMode] = useState<ViewMode>(() => {
    const saved = localStorage.getItem('narwhal_view_mode');
    if (saved === 'table' || saved === 'detailed' || saved === 'grid') {
      return saved;
    }
    return 'grid';
  });

  const handleViewModeChange = (mode: ViewMode) => {
    setViewMode(mode);
    localStorage.setItem('narwhal_view_mode', mode);
  };

  // State filtering & search query
  const [filterState, setFilterState] = useState<FilterState>('all');
  const [searchQuery, setSearchQuery] = useState('');

  const [submittingKey, setSubmittingKey] = useState<string | null>(null);
  const [pendingDisposition, setPendingDisposition] = useState<{
    target: ContainerIdentity;
    decision: 'deny' | 'allow_silent';
  } | null>(null);

  const handleContainerDisposition = async (
    target: ContainerIdentity,
    decision: 'deny' | 'allow_silent'
  ) => {
    const key = `${target.host_id}-${target.runtime}-${target.project || ''}-${target.container_name}`;
    setSubmittingKey(key);
    try {
      const res = await api.dispositionContainer(target, decision);
      onToast?.(
        'success',
        decision === 'deny'
          ? (res.queued ? '处置指令已下发节点执行' : '安全处置已处理')
          : '已成功添加放行策略'
      );
      onRefresh?.();
    } catch (err: any) {
      onToast?.('error', `操作失败：${err.message || err}`);
    } finally {
      setSubmittingKey(null);
    }
  };

  // Group by host_id
  const liveContainers = useMemo(
    () => containers.filter((c) => !c.alerts?.stale),
    [containers]
  );

  // Global counts for filter pills
  const counts = useMemo(() => {
    let risk = 0;
    let hy2 = 0;
    let imbalance = 0;
    let healthy = 0;

    liveContainers.forEach((c) => {
      const r = evaluateContainerRisk(c, activeAlerts);
      if (r.hasRisk) risk++;
      if (c.alerts?.hy2_detected || c.security?.hy2_protocol?.detected) hy2++;
      if (c.alerts?.traffic_imbalance) imbalance++;
      if (!r.hasRisk) healthy++;
    });

    return {
      all: liveContainers.length,
      risk,
      hy2,
      imbalance,
      healthy,
    };
  }, [liveContainers, activeAlerts]);

  const hostMap = useMemo(() => {
    const map: Record<string, ContainerItem[]> = {};
    liveContainers.forEach((c) => {
      if (!map[c.host_id]) map[c.host_id] = [];
      map[c.host_id].push(c);
    });
    return map;
  }, [liveContainers]);

  // Sort hosts: hosts with higher risk come first
  const hostIds = useMemo(() => {
    return Object.keys(hostMap).sort((a, b) => {
      const maxA = Math.max(0, ...hostMap[a].map((c) => evaluateContainerRisk(c, activeAlerts).sortWeight));
      const maxB = Math.max(0, ...hostMap[b].map((c) => evaluateContainerRisk(c, activeAlerts).sortWeight));
      if (maxA !== maxB) {
        return maxB - maxA;
      }
      return a.localeCompare(b);
    });
  }, [hostMap, activeAlerts]);

  // Host accordion state: default expanded so users immediately see content
  const [expandedHosts, setExpandedHosts] = useState<Record<string, boolean>>(() => {
    const init: Record<string, boolean> = {};
    Object.keys(hostMap).forEach((h) => (init[h] = true));
    return init;
  });

  // Keep expandedHosts in sync with new hosts
  useEffect(() => {
    setExpandedHosts((prev) => {
      let changed = false;
      const next = { ...prev };
      hostIds.forEach((h) => {
        if (next[h] === undefined) {
          next[h] = true;
          changed = true;
        }
      });
      return changed ? next : prev;
    });
  }, [hostIds]);

  const toggleHost = (hostId: string) => {
    setExpandedHosts((prev) => ({ ...prev, [hostId]: !prev[hostId] }));
  };

  const allExpanded = hostIds.length > 0 && hostIds.every((h) => expandedHosts[h]);

  const handleToggleAll = () => {
    if (allExpanded) {
      setExpandedHosts({});
    } else {
      const next: Record<string, boolean> = {};
      hostIds.forEach((h) => (next[h] = true));
      setExpandedHosts(next);
    }
  };

  const pendingCopy = pendingDisposition?.decision === 'deny'
    ? { title: '确认定向处置？', description: `将仅处理 ${pendingDisposition.target.container_name} 中已识别的违规进程、服务或配置，不会停止容器。`, confirmLabel: '确认处置', tone: 'danger' as const }
    : { title: '确认放行策略？', description: pendingDisposition ? `${pendingDisposition.target.container_name} 的当前风险将被持续放行且不再提醒；可从告警历史撤销。` : '', confirmLabel: '确认放行', tone: 'primary' as const };

  if (hostIds.length === 0) {
    return (
      <section className="rounded-2xl border border-dashed border-slate-800 p-12 text-center bg-slate-950/40">
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
      {/* Master Control & Density Toolbar */}
      <DashboardToolbar
        viewMode={viewMode}
        onViewModeChange={handleViewModeChange}
        filterState={filterState}
        onFilterStateChange={setFilterState}
        searchQuery={searchQuery}
        onSearchChange={setSearchQuery}
        totalHosts={hostIds.length}
        totalContainers={liveContainers.length}
        counts={counts}
        allExpanded={allExpanded}
        onToggleAllHosts={handleToggleAll}
      />

      {/* Host Accordion List */}
      <div className="space-y-3">
        {hostIds.map((hostId) => {
          const hostContainers = hostMap[hostId] || [];
          const isExpanded = Boolean(expandedHosts[hostId]);

          // Host aggregated metrics
          const totalContainersOnHost = hostContainers.length;
          const hostRiskyContainers = hostContainers.filter(
            (c) => evaluateContainerRisk(c, activeAlerts).hasRisk
          );
          const hostRiskyCount = hostRiskyContainers.length;

          // Aggregated host bandwidth
          const sumRx = hostContainers.reduce((acc, c) => acc + (c.net_rx_bps || 0), 0);
          const sumTx = hostContainers.reduce((acc, c) => acc + (c.net_tx_bps || 0), 0);
          const sumRxMbps = fmtMbps(sumRx);
          const sumTxMbps = fmtMbps(sumTx);

          // Aggregated host CPU average
          const avgCpu = (
            hostContainers.reduce((acc, c) => acc + (c.cpu_percent || 0), 0) /
            (totalContainersOnHost || 1)
          ).toFixed(1);

          // Filter containers according to filterState and searchQuery
          const filteredContainers = hostContainers.filter((c) => {
            // Search query filter
            if (searchQuery.trim()) {
              const q = searchQuery.toLowerCase();
              const matchName = c.container_name.toLowerCase().includes(q);
              const matchHost = c.host_id.toLowerCase().includes(q);
              const matchRuntime = c.runtime.toLowerCase().includes(q);
              const matchProject = (c.project || '').toLowerCase().includes(q);
              if (!matchName && !matchHost && !matchRuntime && !matchProject) {
                return false;
              }
            }

            // State filter
            const risk = evaluateContainerRisk(c, activeAlerts);
            switch (filterState) {
              case 'risk':
                return risk.hasRisk;
              case 'hy2':
                return Boolean(c.alerts?.hy2_detected || c.security?.hy2_protocol?.detected);
              case 'imbalance':
                return Boolean(c.alerts?.traffic_imbalance);
              case 'healthy':
                return !risk.hasRisk;
              case 'all':
              default:
                return true;
            }
          });

          // Sort filtered containers: risky first
          filteredContainers.sort((a, b) => {
            const riskA = evaluateContainerRisk(a, activeAlerts);
            const riskB = evaluateContainerRisk(b, activeAlerts);
            if (riskA.sortWeight !== riskB.sortWeight) {
              return riskB.sortWeight - riskA.sortWeight;
            }
            return a.container_name.localeCompare(b.container_name);
          });

          // If search query is active and this host has 0 matches, hide the entire host card
          if (searchQuery.trim() && filteredContainers.length === 0) {
            return null;
          }

          const agentVersion = hostContainers[0]?.agent_version || 'unknown';
          const isVersionMatch =
            agentVersion !== 'unknown' &&
            agentVersion !== 'dev' &&
            agentVersion === serverVersion;

          // Status indicator color for host card left border
          let hostStatusAccent = 'border-l-emerald-500';
          if (hostRiskyCount > 0) {
            hostStatusAccent = 'border-l-rose-500 shadow-[0_0_15px_rgba(244,63,94,0.06)]';
          }

          return (
            <div
              key={hostId}
              className={`relative rounded-xl border border-l-4 transition-all overflow-hidden ${hostStatusAccent} ${
                hostRiskyCount > 0
                  ? 'border-slate-800 bg-slate-900/95'
                  : 'border-slate-800 bg-slate-900/80 hover:border-slate-700/90'
              }`}
            >
              {/* Host Accordion Master Bar */}
              <button
                type="button"
                onClick={() => toggleHost(hostId)}
                aria-expanded={isExpanded}
                aria-controls={`host-containers-${hostId}`}
                className="flex w-full flex-col gap-2 p-3 text-left transition-colors hover:bg-slate-800/40 focus:outline-none focus:ring-2 focus:ring-inset focus:ring-sky-400 sm:flex-row sm:items-center sm:justify-between data-[expanded=true]:border-b data-[expanded=true]:border-slate-800/80"
                data-expanded={isExpanded}
              >
                {/* Left: Host Identification & Node Specs */}
                <div className="flex items-center gap-2.5 min-w-0">
                  <div
                    className={`rounded-lg p-1.5 border transition-colors shrink-0 ${
                      hostRiskyCount > 0
                        ? 'bg-rose-950/80 text-rose-400 border-rose-500/40'
                        : 'bg-sky-950/80 text-sky-400 border-sky-500/30'
                    }`}
                  >
                    <Server className="h-4 w-4" />
                  </div>

                  <div className="min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="font-bold text-sm text-slate-100 font-mono tracking-tight">
                        {hostId}
                      </span>
                      {/* Version Badge */}
                      <span
                        className={`rounded-full border px-1.5 py-0.2 text-[9px] font-mono font-medium ${
                          isVersionMatch
                            ? 'border-emerald-500/30 bg-emerald-950/50 text-emerald-400'
                            : agentVersion === 'unknown' || agentVersion === 'dev'
                            ? 'border-amber-500/30 bg-amber-950/50 text-amber-400'
                            : 'border-rose-500/30 bg-rose-950/50 text-rose-400'
                        }`}
                      >
                        v{agentVersion}
                      </span>
                    </div>
                    <div className="flex items-center gap-2 text-xs text-slate-400 mt-0.5">
                      <span>
                        共 <span className="font-semibold text-slate-200 font-mono">{totalContainersOnHost}</span> 台容器
                      </span>
                      {filteredContainers.length !== totalContainersOnHost && (
                        <span className="text-sky-400 font-mono text-[11px]">
                          (筛选命中: {filteredContainers.length})
                        </span>
                      )}
                    </div>
                  </div>
                </div>

                {/* Right: Aggregate Telemetry & Badges */}
                <div className="flex items-center justify-between sm:justify-end gap-3 shrink-0 pt-1 sm:pt-0 border-t border-slate-800/40 sm:border-t-0">
                  {/* Host Aggregate Throughput */}
                  <div className="flex items-center gap-2 text-[11px] font-mono bg-slate-950/60 rounded-lg px-2 py-1 border border-slate-800">
                    <span className="flex items-center text-emerald-400 font-semibold" title={`母鸡总聚合入栈: ${sumRxMbps} Mbps`}>
                      <ArrowDownLeft className="h-3 w-3 mr-0.5" />
                      {sumRxMbps}M
                    </span>
                    <span className="text-slate-600">/</span>
                    <span className="flex items-center text-sky-400 font-semibold" title={`母鸡总聚合出栈: ${sumTxMbps} Mbps`}>
                      <ArrowUpRight className="h-3 w-3 mr-0.5" />
                      {sumTxMbps}M
                    </span>
                    <span className="text-slate-600">·</span>
                    <span className="text-slate-400" title="容器平均 CPU 占用">
                      均 {avgCpu}%
                    </span>
                  </div>

                  {/* Risky container badge */}
                  {hostRiskyCount > 0 && (
                    <span className="rounded-full border border-rose-500/50 bg-rose-950/80 px-2 py-0.5 text-xs font-bold text-rose-300 flex items-center gap-1 shadow-sm animate-pulse">
                      <ShieldAlert className="h-3 w-3 text-rose-400" />
                      <span>{hostRiskyCount} 异常</span>
                    </span>
                  )}

                  {/* Expand / Collapse Chevron */}
                  <ChevronDown
                    className={`h-4 w-4 text-slate-400 transition-transform duration-200 ${
                      isExpanded ? 'rotate-180' : ''
                    }`}
                  />
                </div>
              </button>

              {/* Sub-container Canvas Area */}
              {isExpanded && (
                <div id={`host-containers-${hostId}`} className="bg-slate-950/70 p-3">
                  {filteredContainers.length === 0 ? (
                    <div className="flex items-center justify-center gap-2 py-6 text-xs text-slate-500 border border-dashed border-slate-800/80 rounded-xl">
                      <FilterX className="h-4 w-4 text-slate-600" />
                      <span>当前筛选与搜索条件下暂无匹配容器</span>
                    </div>
                  ) : viewMode === 'grid' ? (
                    /* 1. Pro Grid Mode: High-density 4~5 cols */
                    <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-4 2xl:grid-cols-5 gap-2.5">
                      {filteredContainers.map((c) => {
                        const risk = evaluateContainerRisk(c, activeAlerts);
                        const key = `${c.host_id}-${c.runtime}-${c.project || ''}-${c.container_name}`;
                        return (
                          <ContainerCardCompact
                            key={key}
                            container={c}
                            risk={risk}
                            onSelect={onSelectContainer}
                            onQuickDisposition={(target, decision) =>
                              setPendingDisposition({ target, decision })
                            }
                            isSubmitting={submittingKey === key}
                          />
                        );
                      })}
                    </div>
                  ) : viewMode === 'table' ? (
                    /* 2. Data Table Mode: Enterprise ultra-dense rows */
                    <ContainerTableView
                      containers={filteredContainers}
                      activeAlerts={activeAlerts}
                      onSelect={onSelectContainer}
                      onQuickDisposition={(target, decision) =>
                        setPendingDisposition({ target, decision })
                      }
                      isSubmitting={Boolean(submittingKey)}
                    />
                  ) : (
                    /* 3. Detailed Cards Mode: Polished layout with fixed slots */
                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3.5">
                      {filteredContainers.map((c) => {
                        const risk = evaluateContainerRisk(c, activeAlerts);
                        const isStale = Boolean(c.alerts?.stale);
                        const cpu = c.cpu_percent || 0;
                        const mem = c.mem_percent || 0;
                        const rxMbps = fmtMbps(c.net_rx_bps);
                        const txMbps = fmtMbps(c.net_tx_bps);
                        const memUsed = fmtBytes(c.mem_bytes);
                        const memLimit = fmtBytes(c.mem_limit_bytes);
                        const sec = c.security || {};
                        const key = `${c.host_id}-${c.runtime}-${c.project || ''}-${c.container_name}`;

                        let cardStyle =
                          'border-slate-800 bg-slate-900/90 hover:border-sky-500/50 shadow-sm';
                        if (risk.isCritical) {
                          cardStyle =
                            'border-rose-500/70 bg-gradient-to-b from-rose-950/30 via-slate-900/90 to-slate-900/95 shadow-[0_0_15px_rgba(244,63,94,0.12)] hover:border-rose-400';
                        } else if (risk.isWarning) {
                          cardStyle =
                            'border-amber-500/50 bg-gradient-to-b from-amber-950/20 via-slate-900/90 to-slate-900/95 shadow-[0_0_12px_rgba(245,158,11,0.08)] hover:border-amber-400';
                        }

                        return (
                          <div
                            key={key}
                            className={`group relative rounded-xl border p-3.5 transition-all flex flex-col justify-between ${cardStyle}`}
                          >
                            {/* Card Content Top */}
                            <div>
                              {/* Title & Badges */}
                              <div className="flex items-start justify-between gap-2 mb-2.5">
                                <div className="min-w-0 flex-1">
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
                                      className={`font-bold font-mono text-xs truncate transition-colors ${
                                        risk.isCritical
                                          ? 'text-rose-200 group-hover:text-rose-100'
                                          : 'text-slate-100 group-hover:text-sky-300'
                                      }`}
                                      title={c.container_name}
                                    >
                                      {c.container_name}
                                    </h4>
                                  </div>
                                  <span className="text-[10px] text-slate-400 font-mono mt-0.5 block">
                                    {c.project ? `${c.runtime}/${c.project}` : c.runtime}
                                  </span>
                                </div>

                                <div className="flex items-center gap-1 shrink-0">
                                  {(c.alerts?.hy2_detected || sec.hy2_protocol?.detected) && (
                                    <span
                                      className="rounded-full bg-violet-500/20 border border-violet-500/40 px-1.5 py-0.2 text-[9px] font-bold text-violet-300 flex items-center gap-1 shadow-sm font-mono"
                                      title="检测到 Hysteria 2 协议"
                                    >
                                      <Radio className="h-2.5 w-2.5 text-violet-400" />
                                      <span>HY2</span>
                                    </span>
                                  )}
                                  {risk.isCritical && (
                                    <span className="rounded-full bg-rose-500/20 border border-rose-500/50 px-1.5 py-0.2 text-[9px] font-bold text-rose-300 flex items-center gap-1 shadow-sm">
                                      <AlertTriangle className="h-2.5 w-2.5 text-rose-400 animate-pulse" />
                                      <span>异常</span>
                                    </span>
                                  )}
                                  {risk.isWarning && (
                                    <span className="rounded-full bg-amber-500/20 border border-amber-500/40 px-1.5 py-0.2 text-[9px] font-bold text-amber-300 flex items-center gap-1 shadow-sm">
                                      <AlertCircle className="h-2.5 w-2.5 text-amber-400" />
                                      <span>预警</span>
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
                              <div className="space-y-2 mt-2 text-xs">
                                {/* CPU */}
                                <div>
                                  <div className="flex justify-between font-mono text-slate-300 mb-0.5 text-[11px]">
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
                                      className={`h-full transition-all duration-300 ${
                                        cpu > 80 ? 'bg-rose-500' : 'bg-sky-500'
                                      }`}
                                      style={{ width: `${Math.min(100, Math.max(0, cpu))}%` }}
                                    />
                                  </div>
                                </div>

                                {/* Memory */}
                                <div>
                                  <div className="flex justify-between font-mono text-slate-300 mb-0.5 text-[11px]">
                                    <span className="flex items-center gap-1 text-slate-400">
                                      <HardDrive className="h-3 w-3" /> 内存
                                    </span>
                                    <span
                                      className={`tabular-nums font-bold ${
                                        mem > 90 ? 'text-amber-400' : 'text-slate-200'
                                      }`}
                                    >
                                      {mem.toFixed(1)}% ({memUsed} / {memLimit})
                                    </span>
                                  </div>
                                  <div className="h-1.5 w-full rounded-full bg-slate-800 overflow-hidden">
                                    <div
                                      className={`h-full transition-all duration-300 ${
                                        mem > 90 ? 'bg-amber-500' : 'bg-emerald-500'
                                      }`}
                                      style={{ width: `${Math.min(100, Math.max(0, mem))}%` }}
                                    />
                                  </div>
                                </div>

                                {/* Bandwidth & Conns Block */}
                                <div className="grid grid-cols-2 gap-2 pt-1 font-mono text-[11px]">
                                  <div className="rounded-lg bg-slate-950/70 p-2 border border-slate-800/80">
                                    <div className="flex items-center justify-between text-slate-500 text-[10px]">
                                      <span className="flex items-center gap-1">
                                        <Activity className="h-2.5 w-2.5 text-sky-400" /> 带宽
                                      </span>
                                      {c.alerts?.traffic_imbalance && (
                                        <span
                                          className="text-[9px] font-bold text-amber-300 bg-amber-500/10 px-1 py-0.2 rounded border border-amber-500/30 flex items-center gap-0.5"
                                          title={`出入流量失衡: ${c.alerts.traffic_imbalance_ratio}x`}
                                        >
                                          <ArrowUpDown className="h-2.5 w-2.5 text-amber-400" />
                                          <span>{c.alerts.traffic_imbalance_ratio}x</span>
                                        </span>
                                      )}
                                    </div>
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
                                    <div className="mt-1 flex items-center justify-between text-[9px] text-slate-400 border-t border-slate-800/60 pt-1">
                                      <span title={`TCP: ↓ ${fmtMbps(c.tcp_rx_bps)}M / ↑ ${fmtMbps(c.tcp_tx_bps)}M`}>
                                        <span className="text-blue-400">T:</span> {fmtMbps(c.tcp_rx_bps)}/{fmtMbps(c.tcp_tx_bps)}M
                                      </span>
                                      <span title={`UDP: ↓ ${fmtMbps(c.udp_rx_bps)}M / ↑ ${fmtMbps(c.udp_tx_bps)}M`}>
                                        <span className="text-violet-400">U:</span> {fmtMbps(c.udp_rx_bps)}/{fmtMbps(c.udp_tx_bps)}M
                                      </span>
                                    </div>
                                  </div>

                                  <div className="rounded-lg bg-slate-950/70 p-2 border border-slate-800/80">
                                    <span className="text-slate-500 flex items-center gap-1 text-[10px]">
                                      <Layers className="h-2.5 w-2.5 text-amber-400" /> 连接/进程
                                    </span>
                                    <div className="mt-1 flex items-center justify-between text-slate-300 tabular-nums font-semibold">
                                      <span>{c.conn_count || 0} conn</span>
                                      <span>{sec.process_count || 0} proc</span>
                                    </div>
                                    <div className="mt-2 text-[9px] text-slate-400 font-mono text-right">
                                      更新: {c.timestamp_iso_utc8?.split(' ')[1] || '实时'}
                                    </div>
                                  </div>
                                </div>

                                {/* Risk Banner (Clean single line with preview) */}
                                {risk.hasRisk && risk.reasons.length > 0 && (
                                  <div
                                    className={`mt-2 rounded-lg border p-1.5 text-xs flex items-center justify-between gap-1.5 ${
                                      risk.isCritical
                                        ? 'border-rose-500/50 bg-rose-950/60 text-rose-200'
                                        : 'border-amber-500/40 bg-amber-950/50 text-amber-200'
                                    }`}
                                  >
                                    <div className="flex items-center gap-1 min-w-0 flex-1">
                                      {risk.isCritical ? (
                                        <AlertTriangle className="h-3 w-3 text-rose-400 shrink-0" />
                                      ) : (
                                        <AlertCircle className="h-3 w-3 text-amber-400 shrink-0" />
                                      )}
                                      <span className="text-[11px] truncate font-medium">
                                        {risk.reasons[0]}
                                      </span>
                                    </div>
                                    {risk.reasons.length > 1 && (
                                      <span className="rounded bg-black/40 px-1 text-[9px] font-mono shrink-0">
                                        +{risk.reasons.length - 1}
                                      </span>
                                    )}
                                  </div>
                                )}
                              </div>
                            </div>

                            {/* Actions Footer */}
                            <div className="mt-3 pt-2.5 border-t border-slate-800/80 flex items-center justify-end gap-1.5">
                        {risk.canRemediate ? (
                          <div className="flex items-center gap-1.5 flex-wrap justify-end">
                            <button
                              type="button"
                              disabled={submittingKey === `${c.host_id}-${c.runtime}-${c.project || ''}-${c.container_name}`}
                              onClick={(e) => {
                                e.stopPropagation();
                                setPendingDisposition({
                                  target: { host_id: c.host_id, runtime: c.runtime, project: c.project, container_name: c.container_name, alert_id: risk.actionableAlert?.id },
                                  decision: 'deny',
                                });
                              }}
                              className="flex items-center gap-1 rounded-lg border border-rose-500/50 bg-rose-950/80 px-2.5 py-1.5 text-xs font-semibold text-rose-200 hover:bg-rose-900/90 transition-all focus:outline-none focus:ring-2 focus:ring-rose-400 disabled:opacity-50 shadow-sm"
                              title="定向处置违规进程或停止非合规服务"
                            >
                              <Ban className="h-3 w-3" />
                              <span>
                                {submittingKey === `${c.host_id}-${c.runtime}-${c.project || ''}-${c.container_name}`
                                  ? '处理中...'
                                  : '定向处置'}
                              </span>
                            </button>

                            <button
                              type="button"
                              disabled={submittingKey === `${c.host_id}-${c.runtime}-${c.project || ''}-${c.container_name}`}
                              onClick={(e) => {
                                e.stopPropagation();
                                setPendingDisposition({
                                  target: { host_id: c.host_id, runtime: c.runtime, project: c.project, container_name: c.container_name, alert_id: risk.actionableAlert?.id },
                                  decision: 'allow_silent',
                                });
                              }}
                              className="flex items-center gap-1 rounded-lg border border-slate-700 bg-slate-800/90 px-2 py-1.5 text-xs font-medium text-slate-300 hover:bg-slate-750 transition-all focus:outline-none focus:ring-2 focus:ring-sky-400 disabled:opacity-50"
                              title="添加放行策略不再告警"
                            >
                              <Check className="h-3 w-3 text-emerald-400" />
                              <span>放行</span>
                            </button>

                            <button
                              type="button"
                              onClick={() =>
                                onSelectContainer({
                                  host_id: c.host_id,
                                  runtime: c.runtime,
                                  project: c.project,
                                  container_name: c.container_name,
                                  alert_id: risk.actionableAlert?.id,
                                })
                              }
                              className="flex items-center gap-1 rounded-lg border border-slate-700 bg-slate-800/80 px-2.5 py-1.5 text-xs font-medium text-sky-400 hover:text-sky-300 transition-all focus:outline-none focus:ring-2 focus:ring-sky-400"
                              title="查看容器详细指标与诊断"
                            >
                              <Sparkles className="h-3 w-3" />
                              <span>排查</span>
                            </button>
                          </div>
                        ) : (
                          <button
                            type="button"
                            onClick={() =>
                              onSelectContainer({
                                host_id: c.host_id,
                                runtime: c.runtime,
                                project: c.project,
                                container_name: c.container_name,
                                alert_id: risk.actionableAlert?.id,
                              })
                            }
                            className="flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-800 text-sky-400 px-3 py-1.5 text-xs font-semibold hover:border-sky-500 hover:text-sky-300 hover:bg-slate-750 transition-all focus:outline-none focus:ring-2 focus:ring-sky-400 shadow-sm"
                          >
                            <Sparkles className="h-3.5 w-3.5" />
                            <span>深度排查</span>
                          </button>
                        )}
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  )}
                </div>
              )}
            </div>
          );
        })}
      </div>

      {/* Global Confirmation Dialog */}
      <ConfirmDialog
        open={Boolean(pendingDisposition)}
        {...pendingCopy}
        isSubmitting={
          pendingDisposition
            ? submittingKey ===
              `${pendingDisposition.target.host_id}-${pendingDisposition.target.runtime}-${
                pendingDisposition.target.project || ''
              }-${pendingDisposition.target.container_name}`
            : false
        }
        onCancel={() => setPendingDisposition(null)}
        onConfirm={async () => {
          if (!pendingDisposition) return;
          const disposition = pendingDisposition;
          await handleContainerDisposition(disposition.target, disposition.decision);
          setPendingDisposition(null);
        }}
      />
    </section>
  );
};
