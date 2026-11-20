import React from 'react';
import { Server, Box, AlertTriangle, Clock3, ArrowUpRight } from 'lucide-react';

interface KpiGridProps {
  onlineHosts: number;
  totalContainers: number;
  activeAlerts: number;
  hiddenStaleSnapshots: number;
  onFilterAlerts?: () => void;
}

export const KpiGrid: React.FC<KpiGridProps> = ({
  onlineHosts,
  totalContainers,
  activeAlerts,
  hiddenStaleSnapshots,
  onFilterAlerts,
}) => {
  return (
    <section aria-label="运行概览指标" className="mb-6 grid grid-cols-2 gap-3 sm:grid-cols-4 sm:gap-4">
      {/* KPI 1: 在线主机 */}
      <div className="rn2-card overflow-hidden transition-colors hover:border-[#087bff]">
        <div className="rn2-card-head px-3.5 py-2.5">
          <div className="min-w-0">
            <span className="rn2-eyebrow block text-[10px]">NODES ONLINE</span>
            <span className="block text-xs font-semibold text-white">在线主机</span>
          </div>
          <div className="rounded-lg border border-[#54c7ff]/40 bg-[#087bff]/20 p-1.5 text-[#54c7ff]">
            <Server className="h-4 w-4" aria-hidden="true" />
          </div>
        </div>
        <div className="flex items-baseline justify-between gap-2 bg-[#f4f8fd] px-3.5 py-3">
          <span className="font-mono text-2xl font-extrabold tracking-tight text-[#0b1636] tabular-nums sm:text-3xl">
            {onlineHosts}
          </span>
          <span className="rn2-pill rn2-pill-sm rn2-pill-blue font-mono">
            Nodes
          </span>
        </div>
      </div>

      {/* KPI 2: 活跃容器 */}
      <div className="rn2-card overflow-hidden transition-colors hover:border-[#147468]">
        <div className="rn2-card-head px-3.5 py-2.5">
          <div className="min-w-0">
            <span className="rn2-eyebrow block text-[10px] text-emerald-300">ACTIVE INSTANCES</span>
            <span className="block text-xs font-semibold text-white">活跃容器</span>
          </div>
          <div className="rounded-lg border border-emerald-400/40 bg-emerald-500/20 p-1.5 text-emerald-300">
            <Box className="h-4 w-4" aria-hidden="true" />
          </div>
        </div>
        <div className="flex items-baseline justify-between gap-2 bg-[#f4f8fd] px-3.5 py-3">
          <span className="font-mono text-2xl font-extrabold tracking-tight text-[#0b1636] tabular-nums sm:text-3xl">
            {totalContainers}
          </span>
          <span className="rn2-pill rn2-pill-sm rn2-pill-teal font-mono">
            Containers
          </span>
        </div>
      </div>

      {/* KPI 3: 活动告警 */}
      <div
        role={onFilterAlerts ? 'button' : undefined}
        tabIndex={onFilterAlerts ? 0 : undefined}
        onClick={onFilterAlerts}
        onKeyDown={(e) => {
          if (onFilterAlerts && (e.key === 'Enter' || e.key === ' ')) {
            e.preventDefault();
            onFilterAlerts();
          }
        }}
        className={`rn2-card cursor-pointer overflow-hidden transition-colors focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-[#087bff] ${
          activeAlerts > 0
            ? 'border-[#ff6b00] shadow-[0_0_0_1px_rgba(255,107,0,0.22),0_6px_18px_rgba(255,107,0,0.12)]'
            : 'hover:border-[#087bff]'
        }`}
      >
        <div
          className="rn2-card-head px-3.5 py-2.5"
          style={
            activeAlerts > 0
              ? { background: 'linear-gradient(125deg, #4b1f08, #1f172b 58%, #0c1c30)' }
              : undefined
          }
        >
          <div className="min-w-0">
            <span className={`rn2-eyebrow block text-[10px] ${activeAlerts > 0 ? 'text-[#ffb37c]' : 'text-[#54c7ff]'}`}>
              SECURITY ALERTS
            </span>
            <span className="block text-xs font-semibold text-white">活动安全告警</span>
          </div>
          <div
            className={`rounded-lg border p-1.5 ${
              activeAlerts > 0
                ? 'border-[#ff8100]/55 bg-[#ff6b00]/25 text-[#ffb37c]'
                : 'border-[#54c7ff]/30 bg-[#087bff]/15 text-[#9ad8ff]'
            }`}
          >
            <AlertTriangle className="h-4 w-4" aria-hidden="true" />
          </div>
        </div>
        <div className={`flex items-baseline justify-between gap-2 px-3.5 py-3 ${activeAlerts > 0 ? 'bg-[#fff3e8]' : 'bg-[#f4f8fd]'}`}>
          <div className="flex items-baseline gap-2">
            <span
              className={`font-mono text-2xl font-extrabold tracking-tight tabular-nums sm:text-3xl ${
                activeAlerts > 0 ? 'text-[#c2410c]' : 'text-[#0b1636]'
              }`}
            >
              {activeAlerts}
            </span>
            <span className="text-[10px] font-semibold uppercase tracking-wider text-[#697b9c]">Active</span>
          </div>
          {activeAlerts > 0 && (
            <span className="rn2-pill rn2-pill-sm rn2-pill-orange inline-flex items-center gap-0.5">
              查看 <ArrowUpRight className="h-3 w-3" aria-hidden="true" />
            </span>
          )}
        </div>
      </div>

      {/* KPI 4: hidden stale snapshots */}
      <div className="rn2-card overflow-hidden transition-colors hover:border-[#087bff]">
        <div className="rn2-card-head px-3.5 py-2.5">
          <div className="min-w-0">
            <span className="rn2-eyebrow block text-[10px] text-[#9ad8ff]">STALE SNAPSHOTS</span>
            <span className="block text-xs font-semibold text-white">已隐藏旧快照</span>
          </div>
          <div className="rounded-lg border border-[#54c7ff]/30 bg-[#087bff]/15 p-1.5 text-[#9ad8ff]">
            <Clock3 className="h-4 w-4" aria-hidden="true" />
          </div>
        </div>
        <div className="flex items-baseline justify-between gap-2 bg-[#f4f8fd] px-3.5 py-3">
          <span
            className={`font-mono text-2xl font-extrabold tracking-tight tabular-nums sm:text-3xl ${
              hiddenStaleSnapshots > 0 ? 'text-[#9a5b00]' : 'text-[#0b1636]'
            }`}
          >
            {hiddenStaleSnapshots}
          </span>
          <span className="text-[11px] font-medium text-[#697b9c]">保留在历史数据</span>
        </div>
      </div>
    </section>
  );
};
