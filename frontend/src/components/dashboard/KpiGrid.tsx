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
      <div className="relative overflow-hidden rounded-xl border border-[#087bff]/35 bg-[#041e3c]/95 shadow-[0_8px_24px_-6px_rgba(2,10,24,0.7)] transition-colors hover:border-[#087bff]/70">
        <div className="flex items-center justify-between gap-2 border-b border-sky-400/15 bg-linear-to-r from-[#031d3d] to-[#072647] px-3.5 py-2">
          <div className="min-w-0">
            <span className="block text-[10px] font-bold uppercase tracking-wider text-[#00b6ec]">NODES ONLINE</span>
            <span className="block text-xs font-semibold text-slate-200">在线主机</span>
          </div>
          <div className="rounded-lg border border-[#087bff]/40 bg-[#087bff]/15 p-1.5 text-[#00b6ec]">
            <Server className="h-4 w-4" />
          </div>
        </div>
        <div className="flex items-baseline justify-between gap-2 bg-[#02182f]/70 px-3.5 py-3">
          <span className="font-mono text-2xl font-extrabold tracking-tight text-white tabular-nums sm:text-3xl">
            {onlineHosts}
          </span>
          <span className="rounded border border-sky-400/20 bg-[#031d3d] px-1.5 py-0.5 font-mono text-[10px] font-semibold uppercase tracking-wider text-sky-300">
            Nodes
          </span>
        </div>
      </div>

      {/* KPI 2: 监控容器 */}
      <div className="relative overflow-hidden rounded-xl border border-emerald-400/30 bg-[#041e3c]/95 shadow-[0_8px_24px_-6px_rgba(2,10,24,0.7)] transition-colors hover:border-emerald-400/65">
        <div className="flex items-center justify-between gap-2 border-b border-sky-400/15 bg-linear-to-r from-[#031d3d] to-[#072647] px-3.5 py-2">
          <div className="min-w-0">
            <span className="block text-[10px] font-bold uppercase tracking-wider text-emerald-400">ACTIVE INSTANCES</span>
            <span className="block text-xs font-semibold text-slate-200">活跃容器</span>
          </div>
          <div className="rounded-lg border border-emerald-400/35 bg-emerald-500/15 p-1.5 text-emerald-400">
            <Box className="h-4 w-4" />
          </div>
        </div>
        <div className="flex items-baseline justify-between gap-2 bg-[#02182f]/70 px-3.5 py-3">
          <span className="font-mono text-2xl font-extrabold tracking-tight text-white tabular-nums sm:text-3xl">
            {totalContainers}
          </span>
          <span className="rounded border border-emerald-400/20 bg-[#031d3d] px-1.5 py-0.5 font-mono text-[10px] font-semibold uppercase tracking-wider text-emerald-300">
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
        className={`relative cursor-pointer overflow-hidden rounded-xl border shadow-[0_8px_24px_-6px_rgba(2,10,24,0.7)] transition-colors focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-[#00b6ec] ${
          activeAlerts > 0
            ? 'border-[#ff7900]/60 bg-linear-to-b from-[#2b1406]/85 to-[#041e3c]/95 hover:border-[#ff7900]'
            : 'border-sky-400/25 bg-[#041e3c]/95 hover:border-[#087bff]/60'
        }`}
      >
        <div
          className={`flex items-center justify-between gap-2 border-b px-3.5 py-2 ${
            activeAlerts > 0
              ? 'border-[#ff7900]/25 bg-linear-to-r from-[#291305] to-[#1a1523]'
              : 'border-sky-400/15 bg-linear-to-r from-[#031d3d] to-[#072647]'
          }`}
        >
          <div className="min-w-0">
            <span className={`block text-[10px] font-bold uppercase tracking-wider ${activeAlerts > 0 ? 'text-[#ff7900]' : 'text-slate-400'}`}>
              SECURITY ALERTS
            </span>
            <span className={`block text-xs font-semibold ${activeAlerts > 0 ? 'text-amber-100' : 'text-slate-200'}`}>
              活动安全告警
            </span>
          </div>
          <div
            className={`rounded-lg border p-1.5 ${
              activeAlerts > 0
                ? 'border-[#ff7900]/45 bg-[#ff7900]/15 text-[#ff7900]'
                : 'border-sky-400/20 bg-[#02182f] text-slate-400'
            }`}
          >
            <AlertTriangle className="h-4 w-4" />
          </div>
        </div>
        <div className="flex items-baseline justify-between gap-2 bg-[#02182f]/70 px-3.5 py-3">
          <div className="flex items-baseline gap-2">
            <span
              className={`font-mono text-2xl font-extrabold tracking-tight tabular-nums sm:text-3xl ${
                activeAlerts > 0 ? 'text-[#ff7900]' : 'text-white'
              }`}
            >
              {activeAlerts}
            </span>
            <span className="text-[10px] font-semibold uppercase tracking-wider text-slate-400">Active</span>
          </div>
          {activeAlerts > 0 && (
            <span className="flex items-center gap-0.5 rounded border border-[#ff7900]/40 bg-[#ff7900]/15 px-1.5 py-0.5 text-[11px] font-semibold text-amber-200">
              查看 <ArrowUpRight className="h-3.5 w-3.5" />
            </span>
          )}
        </div>
      </div>

      {/* KPI 4: hidden stale snapshots */}
      <div className="relative overflow-hidden rounded-xl border border-sky-400/25 bg-[#041e3c]/95 shadow-[0_8px_24px_-6px_rgba(2,10,24,0.7)] transition-colors hover:border-[#087bff]/60">
        <div className="flex items-center justify-between gap-2 border-b border-sky-400/15 bg-linear-to-r from-[#031d3d] to-[#072647] px-3.5 py-2">
          <div className="min-w-0">
            <span className="block text-[10px] font-bold uppercase tracking-wider text-sky-300/80">STALE SNAPSHOTS</span>
            <span className="block text-xs font-semibold text-slate-200">已隐藏旧快照</span>
          </div>
          <div className="rounded-lg border border-sky-400/20 bg-[#02182f] p-1.5 text-slate-300">
            <Clock3 className="h-4 w-4" />
          </div>
        </div>
        <div className="flex items-baseline justify-between gap-2 bg-[#02182f]/70 px-3.5 py-3">
          <span
            className={`font-mono text-2xl font-extrabold tracking-tight tabular-nums sm:text-3xl ${
              hiddenStaleSnapshots > 0 ? 'text-amber-400' : 'text-white'
            }`}
          >
            {hiddenStaleSnapshots}
          </span>
          <span className="text-[11px] font-medium text-slate-400">保留在历史数据</span>
        </div>
      </div>
    </section>
  );
};
