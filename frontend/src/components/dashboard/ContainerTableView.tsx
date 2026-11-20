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
  Zap,
  Activity,
  Cpu as CpuIcon,
  HardDrive,
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
      return <ArrowUpDown className="h-3 w-3 opacity-35 group-hover:opacity-80" aria-hidden="true" />;
    }
    return sortOrder === 'asc' ? (
      <ArrowUp className="h-3 w-3 text-[#087bff]" aria-hidden="true" />
    ) : (
      <ArrowDown className="h-3 w-3 text-[#087bff]" aria-hidden="true" />
    );
  };

  const renderSortHeader = (field: SortField, label: string) => (
    <th scope="col" aria-sort={sortField === field ? (sortOrder === 'asc' ? 'ascending' : 'descending') : 'none'}>
      <button
        type="button"
        onClick={() => handleSort(field)}
        aria-label={`按${label}排序`}
        className="group flex w-full items-center gap-1 px-2 py-2.5 text-left font-semibold text-[#31485e] hover:text-[#087bff] focus-visible:outline-hidden focus-visible:ring-1 focus-visible:ring-inset focus-visible:ring-[#087bff]"
      >
        <span>{label}</span>
        {renderSortIndicator(field)}
      </button>
    </th>
  );

  return (
    <div className="space-y-4">
      {/* Responsive Light-Ice Bento Card Stream for Mobile / Tablet */}
      <div className="block space-y-3 md:hidden">
        {sortedContainers.map((c) => {
          const risk = evaluateContainerRisk(c, activeAlerts);
          const isStale = Boolean(c.alerts?.stale);
          const hasResourceAlert = !isStale && hasContainerResourceAlert(c);
          const hasResourceGuardFailure = !isStale && hasContainerResourceGuardFailure(c);
          const hasProtocolGuardNeedsReview = !isStale && hasContainerProtocolGuardNeedsReview(c);
          const cpu = typeof c.cpu_percent === 'number' && Number.isFinite(c.cpu_percent) ? c.cpu_percent : null;
          const mem = typeof c.mem_percent === 'number' && Number.isFinite(c.mem_percent) ? c.mem_percent : null;
          const memUsed = typeof c.mem_bytes === 'number' && Number.isFinite(c.mem_bytes) ? fmtBytes(c.mem_bytes) : '—';
          const rxMbps = typeof c.net_rx_bps === 'number' && Number.isFinite(c.net_rx_bps) ? fmtMbps(c.net_rx_bps) : null;
          const txMbps = typeof c.net_tx_bps === 'number' && Number.isFinite(c.net_tx_bps) ? fmtMbps(c.net_tx_bps) : null;
          const sec = c.security || {};

          const identity: ContainerIdentity = {
            host_id: c.host_id,
            runtime: c.runtime,
            project: c.project,
            container_name: c.container_name,
            alert_id: risk.actionableAlert?.id,
          };

          const glowClass = risk.isCritical || hasResourceGuardFailure
            ? 'border-[#f5a3b3] bg-white'
            : risk.isWarning || hasProtocolGuardNeedsReview || hasResourceAlert
            ? 'border-[#f7d58b] bg-white'
            : 'border-[#cedae7] bg-white hover:border-[#087bff]';

          return (
            <div
              key={`card-${c.host_id}-${c.runtime}-${c.project || ''}-${c.container_name}`}
              onClick={() => onSelect(identity)}
              className={`rn2-card cursor-pointer space-y-3 p-3.5 transition-colors ${glowClass}`}
            >
              {/* Header */}
              <div className="flex items-center justify-between">
                <div className="flex min-w-0 items-center gap-2">
                  <span
                    className={`h-2.5 w-2.5 shrink-0 rounded-full ${
                      risk.isCritical || hasResourceGuardFailure
                        ? 'bg-[#dc2626]'
                        : risk.isWarning || hasProtocolGuardNeedsReview
                        ? 'bg-[#d97706]'
                        : 'bg-[#147468]'
                    }`}
                  />
                  <div className="min-w-0">
                    <div className="flex items-center gap-1.5">
                      <span className="truncate text-sm font-bold text-[#0b1636]">{c.container_name}</span>
                      <span className="rounded-md border border-[#cedae7] bg-[#f4f8fd] px-1.5 py-0.5 font-mono text-[10px] text-[#4a607a]">
                        {c.runtime}
                      </span>
                    </div>
                    {c.user_email && (
                      <div className="truncate font-mono text-[11px] text-[#0657b8]" title={c.user_email}>
                        {c.user_email}
                      </div>
                    )}
                  </div>
                </div>

                <div className="flex shrink-0 items-center gap-1.5" onClick={(e) => e.stopPropagation()}>
                  {risk.canRemediate && onQuickDisposition && (
                    <button
                      type="button"
                      disabled={isSubmitting}
                      onClick={() => onQuickDisposition(identity, 'deny')}
                      className="rounded-lg border border-[#f9b8c4] bg-[#ffeef1] px-2 py-1 text-[11px] font-bold text-[#b41835] hover:bg-[#ffe4e6]"
                    >
                      处置
                    </button>
                  )}
                  <button
                    type="button"
                    onClick={() => onSelect(identity)}
                    className="rounded-lg border border-[#a9d1ff] bg-[#e8f3ff] px-2.5 py-1 text-[11px] font-semibold text-[#0657b8] hover:border-[#087bff] hover:bg-[#d7eaff]"
                  >
                    排查
                  </button>
                </div>
              </div>

              {/* Spec Metrics 4-Grid */}
              <div className="grid grid-cols-2 gap-2 font-mono text-xs">
                <div className="rounded-lg border border-[#d2dfec] bg-[#f4f8fd] p-2.5">
                  <div className="flex items-center gap-1 font-sans text-[10px] text-[#697b9c]">
                    <CpuIcon className="h-3 w-3 text-[#087bff]" aria-hidden="true" />
                    <span>CPU 使用率</span>
                  </div>
                  <div className="mt-1 text-sm font-bold text-[#0b1636] tabular-nums">
                    {cpu !== null ? `${cpu.toFixed(1)}%` : '—'}
                  </div>
                </div>

                <div className="rounded-lg border border-[#d2dfec] bg-[#f4f8fd] p-2.5">
                  <div className="flex items-center gap-1 font-sans text-[10px] text-[#697b9c]">
                    <HardDrive className="h-3 w-3 text-[#147468]" aria-hidden="true" />
                    <span>内存占用</span>
                  </div>
                  <div className="mt-1 truncate text-sm font-bold text-[#0b1636] tabular-nums">
                    {memUsed} {mem !== null ? `(${mem.toFixed(0)}%)` : ''}
                  </div>
                </div>

                <div className="rounded-lg border border-[#d2dfec] bg-[#f4f8fd] p-2.5">
                  <div className="flex items-center gap-1 font-sans text-[10px] text-[#697b9c]">
                    <ArrowDownLeft className="h-3 w-3 text-[#147468]" aria-hidden="true" />
                    <span>网络 RX / TX</span>
                  </div>
                  <div className="mt-1 truncate text-xs font-bold text-[#0b1636] tabular-nums">
                    ↓{rxMbps ? `${rxMbps}M` : '0'} · ↑{txMbps ? `${txMbps}M` : '0'}
                  </div>
                </div>

                <div className="rounded-lg border border-[#d2dfec] bg-[#f4f8fd] p-2.5">
                  <div className="flex items-center gap-1 font-sans text-[10px] text-[#697b9c]">
                    <Activity className="h-3 w-3 text-[#ff6b00]" aria-hidden="true" />
                    <span>连接 / 进程</span>
                  </div>
                  <div className="mt-1 text-xs font-bold text-[#0b1636] tabular-nums">
                    {c.conn_count ?? 0} conn · {sec.process_count ?? 0} proc
                  </div>
                </div>
              </div>

              <div className="pt-1">
                <ContainerStateBadges container={c} activeAlerts={activeAlerts} maxVisible={4} />
              </div>
            </div>
          );
        })}
      </div>

      {/* Desktop Light-Ice Table */}
      <div
        tabIndex={0}
        role="region"
        aria-label="容器状态数据表格"
        className="rn2-table-wrap hidden md:block"
      >
        <table className="w-full border-collapse text-left text-xs">
          <thead>
            <tr className="border-b border-[#cedae7] bg-[#f4f8fd] font-mono text-[11px] font-semibold text-[#31485e]">
              <th scope="col" className="w-8 py-2.5 pl-3 pr-2">状态</th>
              {renderSortHeader('name', '容器名称 / 运行时')}
              {renderSortHeader('cpu', 'CPU')}
              {renderSortHeader('mem', '内存 (Used / Limit)')}
              {renderSortHeader('rx', '入栈 (RX)')}
              {renderSortHeader('tx', '出栈 (TX)')}
              {renderSortHeader('conns', '连接 / 进程')}
              <th scope="col" className="px-2 py-2.5">协议与特征</th>
              {renderSortHeader('risk', '安全诊断')}
              <th scope="col" className="py-2.5 pl-2 pr-3 text-right">操作</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[#eaf0f7] font-mono">
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

              let rowBg = 'hover:bg-[#f8fbff] transition-colors';
              if (risk.isCritical || hasResourceGuardFailure) {
                rowBg = 'bg-[#ffeef1]/50 hover:bg-[#ffeef1]/80 transition-colors';
              } else if (risk.isWarning || hasResourceAlert || hasProtocolGuardNeedsReview) {
                rowBg = 'bg-[#fef6e4]/60 hover:bg-[#fef6e4]/90 transition-colors';
              }

              return (
                <tr
                  key={`${c.host_id}-${c.runtime}-${c.project || ''}-${c.container_name}`}
                  onClick={() => onSelect(identity)}
                  className={`group cursor-pointer ${rowBg}`}
                >
                  {/* 1. Status Dot */}
                  <td className="whitespace-nowrap py-2.5 pl-3 pr-2">
                    <span
                      className={`inline-block h-2.5 w-2.5 rounded-full ${
                        risk.isCritical || hasResourceGuardFailure
                          ? 'bg-[#dc2626]'
                          : risk.isWarning || hasProtocolGuardNeedsReview
                          ? 'bg-[#d97706]'
                          : isStale
                          ? 'bg-[#94a3b8]'
                          : hasResourceAlert
                          ? 'bg-[#d97706]'
                          : hasProtectionOrProtocol
                          ? 'bg-[#087bff]'
                          : 'bg-[#147468]'
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
                  <td className="whitespace-nowrap px-2 py-2.5">
                    <div className="flex items-center gap-1.5">
                      <button
                        type="button"
                        onClick={(event) => {
                          event.stopPropagation();
                          onSelect(identity);
                        }}
                        aria-label={`打开容器 ${c.container_name} 详情`}
                        className={`max-w-[180px] truncate rounded-sm text-left text-xs font-bold focus-visible:outline-hidden focus-visible:ring-1 focus-visible:ring-[#087bff] sm:max-w-[240px] ${
                          risk.isCritical
                            ? 'text-[#b41835] hover:underline'
                            : 'text-[#0b1636] group-hover:text-[#087bff]'
                        }`}
                        title={c.container_name}
                      >
                        {c.container_name}
                      </button>
                      <span className="rounded-sm border border-[#d2dfec] bg-[#f4f8fd] px-1 py-0.5 text-[9px] text-[#4a607a]">
                        {c.runtime}
                      </span>
                    </div>
                    {c.user_email && (
                      <div className="max-w-[180px] truncate text-[10px] text-[#0657b8] sm:max-w-[240px]" title={c.user_email}>
                        {c.user_email}
                      </div>
                    )}
                  </td>

                  {/* 3. CPU */}
                  <td className="whitespace-nowrap px-2 py-2.5">
                    <div className="flex items-center gap-2">
                      <span
                        className={`w-10 font-semibold tabular-nums ${
                          cpu !== null && cpu > 80 ? 'font-bold text-[#b41835]' : 'text-[#0b1636]'
                        }`}
                      >
                        {cpu === null ? '—' : `${cpu.toFixed(1)}%`}
                      </span>
                      <div className="hidden h-1.5 w-12 overflow-hidden rounded-full bg-[#e2ecf6] sm:block">
                        <div
                          className={`h-full ${cpu === null ? 'bg-[#cbd7e6]' : cpu > 80 ? 'bg-[#dc2626]' : 'bg-[#087bff]'}`}
                          style={{ width: `${Math.min(100, Math.max(0, cpu ?? 0))}%` }}
                        />
                      </div>
                    </div>
                  </td>

                  {/* 4. Memory */}
                  <td className="whitespace-nowrap px-2 py-2.5">
                    <div className="flex items-center gap-2">
                      <span
                        className={`font-semibold tabular-nums ${
                          mem !== null && mem > 90 ? 'font-bold text-[#9a5b00]' : 'text-[#0b1636]'
                        }`}
                      >
                        {mem === null ? '—' : `${mem.toFixed(1)}%`}
                      </span>
                      <span className="text-[10px] text-[#697b9c] tabular-nums">
                        ({memUsed} / {memLimit})
                      </span>
                    </div>
                  </td>

                  {/* 5. Inbound (RX) */}
                  <td className="whitespace-nowrap px-2 py-2.5 tabular-nums">
                    <div className="flex items-center gap-1 font-bold text-[#147468]">
                      <ArrowDownLeft className="h-3 w-3" aria-hidden="true" />
                      <span>{rxMbps === null ? '—' : `${rxMbps}M`}</span>
                      <span className="ml-1 text-[9px] font-normal text-[#697b9c]">
                        (T:{c.tcp_rx_bps == null ? '—' : fmtMbps(c.tcp_rx_bps)}/U:{c.udp_rx_bps == null ? '—' : fmtMbps(c.udp_rx_bps)})
                      </span>
                    </div>
                  </td>

                  {/* 6. Outbound (TX) */}
                  <td className="whitespace-nowrap px-2 py-2.5 tabular-nums">
                    <div className="flex items-center gap-1 font-bold text-[#087bff]">
                      <ArrowUpRight className="h-3 w-3" aria-hidden="true" />
                      <span>{txMbps === null ? '—' : `${txMbps}M`}</span>
                      <span className="ml-1 text-[9px] font-normal text-[#697b9c]">
                        (T:{c.tcp_tx_bps == null ? '—' : fmtMbps(c.tcp_tx_bps)}/U:{c.udp_tx_bps == null ? '—' : fmtMbps(c.udp_tx_bps)})
                      </span>
                    </div>
                  </td>

                  {/* 7. Conns / Procs */}
                  <td className="whitespace-nowrap px-2 py-2 text-[#31485e] tabular-nums">
                    <span className="font-bold text-[#0b1636]">{c.conn_count ?? '—'}</span>
                    <span className="text-[10px] text-[#697b9c]"> conn</span>
                    <span className="mx-1 text-[#cbd7e6]">·</span>
                    <span className="text-[10px] text-[#697b9c]">{sec.process_count ?? '—'} proc</span>
                  </td>

                  {/* 8. Protocol & Badges */}
                  <td className="whitespace-nowrap px-2 py-2.5">
                    <div className="flex items-center gap-1">
                      {sec.microburst?.detected && (
                        <span
                          className="inline-flex items-center gap-0.5 rounded-full border border-[#f7d58b] bg-[#fef6e4] px-1.5 py-0.5 text-[9px] font-bold text-[#9a5b00]"
                          title={`微突发流量: ${sec.microburst.tx_pps} PPS (${sec.microburst.flood_type})`}
                        >
                          <Zap className="h-2.5 w-2.5" aria-hidden="true" />
                          <span>{sec.microburst.tx_pps} PPS</span>
                        </span>
                      )}
                      {(c.alerts?.hy2_detected || sec.hy2_protocol?.detected) && (
                        <span
                          className="inline-flex items-center gap-0.5 rounded-full border border-violet-300 bg-violet-50 px-1.5 py-0.5 text-[9px] font-bold text-violet-800"
                          title="Hysteria 2 协议活跃"
                        >
                          <Radio className="h-2.5 w-2.5" aria-hidden="true" />
                          <span>HY2</span>
                        </span>
                      )}

                      {(c.alerts?.udp_throttled || sec.udp_throttle?.throttled) && (
                        <span
                          className="inline-flex items-center gap-0.5 rounded-full border border-[#f9b8c4] bg-[#ffeef1] px-1.5 py-0.5 text-[9px] font-bold text-[#b41835]"
                          title={`UDP 靶向限速生效中: ${udpThrottleRate == null ? '速率未知' : `${udpThrottleRate} Mbps`}`}
                        >
                          <Gauge className="h-2.5 w-2.5" aria-hidden="true" />
                          <span>{udpThrottleRate == null ? 'UDP 限速' : `限速 ${udpThrottleRate}M`}</span>
                        </span>
                      )}

                      {c.alerts?.traffic_imbalance && (
                        <span
                          className="inline-flex items-center gap-0.5 rounded-full border border-[#f7d58b] bg-[#fef6e4] px-1.5 py-0.5 text-[9px] font-bold text-[#9a5b00]"
                          title={`出入流量失衡 ${c.alerts.traffic_imbalance_ratio}x`}
                        >
                          <ArrowUpDown className="h-2.5 w-2.5" aria-hidden="true" />
                          <span>{c.alerts.traffic_imbalance_ratio}x</span>
                        </span>
                      )}
                    </div>
                    <ContainerStateBadges container={c} activeAlerts={activeAlerts} maxVisible={5} className="mt-1" />
                  </td>

                  {/* 9. Security Diagnostics */}
                  <td className="whitespace-nowrap px-2 py-2.5">
                    {risk.hasRisk ? (
                      <div className="flex max-w-[240px] flex-wrap items-center gap-1" title={risk.reasons.join(' · ')}>
                        {risk.isCritical ? (
                          <span className="inline-flex items-center gap-1 rounded-sm border border-[#f9b8c4] bg-[#ffeef1] px-1.5 py-0.5 text-[10px] font-bold text-[#b41835]">
                            <AlertTriangle className="h-2.5 w-2.5 shrink-0" aria-hidden="true" />
                            <span>{risk.reasons.length} 项</span>
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1 rounded-sm border border-[#f7d58b] bg-[#fef6e4] px-1.5 py-0.5 text-[10px] font-bold text-[#9a5b00]">
                            <AlertCircle className="h-2.5 w-2.5 shrink-0" aria-hidden="true" />
                            <span>{risk.reasons.length} 项</span>
                          </span>
                        )}
                        {risk.reasons.slice(0, 2).map((reason, index) => (
                          <span key={`${index}-${reason}`} className="max-w-[190px] truncate rounded-sm border border-[#cedae7] bg-[#f4f8fd] px-1.5 py-0.5 text-[10px] text-[#31485e]" title={reason}>
                            {reason}
                          </span>
                        ))}
                      </div>
                    ) : (
                      <span className="text-[10px] text-[#697b9c]">暂无活动风险告警</span>
                    )}
                  </td>

                  {/* 10. Actions */}
                  <td
                    className="whitespace-nowrap py-2.5 pl-2 pr-3 text-right"
                    onClick={(e) => e.stopPropagation()}
                  >
                    <div className="flex items-center justify-end gap-1.5">
                      {risk.canRemediate && onQuickDisposition && (
                        <button
                          type="button"
                          disabled={isSubmitting}
                          onClick={() => onQuickDisposition(identity, 'deny')}
                          className="flex items-center gap-1 rounded-md border border-[#f9b8c4] bg-[#ffeef1] px-2 py-1 text-[10px] font-bold text-[#b41835] hover:bg-[#ffe4e6] disabled:opacity-50"
                          title="定向处置违规进程或服务"
                        >
                          <Ban className="h-2.5 w-2.5" aria-hidden="true" />
                          <span>处置</span>
                        </button>
                      )}

                      <button
                        type="button"
                        onClick={() => onSelect(identity)}
                        className="flex items-center gap-1 rounded-md border border-[#a9d1ff] bg-[#e8f3ff] px-2 py-1 text-[10px] font-semibold text-[#0657b8] hover:border-[#087bff] hover:bg-[#d7eaff]"
                        title="打开深度排查抽屉"
                      >
                        <Sparkles className="h-2.5 w-2.5 text-[#087bff]" aria-hidden="true" />
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
    </div>
  );
};
