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
      <div className="ui-surface-card relative overflow-hidden p-4 transition-colors hover:border-slate-600/90">
        <div className="flex items-center justify-between gap-2">
          <span className="text-xs font-medium text-slate-300">在线主机</span>
          <div className="rounded-xl border border-sky-500/25 bg-sky-950/60 p-2 text-sky-400">
            <Server className="h-4 w-4" />
          </div>
        </div>
        <div className="mt-2.5 flex items-baseline gap-2">
          <span className="font-mono text-2xl font-extrabold tracking-tight text-slate-100 tabular-nums sm:text-3xl">
            {onlineHosts}
          </span>
          <span className="text-xs font-medium text-slate-400">Nodes</span>
        </div>
      </div>

      {/* KPI 2: 监控容器 */}
      <div className="ui-surface-card relative overflow-hidden p-4 transition-colors hover:border-slate-600/90">
        <div className="flex items-center justify-between gap-2">
          <span className="text-xs font-medium text-slate-300">活跃容器</span>
          <div className="rounded-xl border border-emerald-500/25 bg-emerald-950/60 p-2 text-emerald-400">
            <Box className="h-4 w-4" />
          </div>
        </div>
        <div className="mt-2.5 flex items-baseline gap-2">
          <span className="font-mono text-2xl font-extrabold tracking-tight text-slate-100 tabular-nums sm:text-3xl">
            {totalContainers}
          </span>
          <span className="text-xs font-medium text-slate-400">Containers</span>
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
        className={`relative cursor-pointer overflow-hidden rounded-2xl border p-4 shadow-xs transition-all focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-sky-400 ${activeAlerts > 0
          ? 'border-rose-500/45 bg-linear-to-b from-rose-950/35 to-slate-900/90 hover:border-rose-400/80 hover:shadow-glow-rose'
          : 'ui-surface-card hover:border-slate-600/90'
          }`}
      >
        <div className="flex items-center justify-between gap-2">
          <span className={`text-xs font-medium ${activeAlerts > 0 ? 'text-rose-200' : 'text-slate-300'}`}>
            活动安全告警
          </span>
          <div
            className={`rounded-xl border p-2 ${activeAlerts > 0
              ? 'border-rose-500/35 bg-rose-950/80 text-rose-400'
              : 'border-slate-700/60 bg-slate-800/80 text-slate-400'
              }`}
          >
            <AlertTriangle className="h-4 w-4" />
          </div>
        </div>
        <div className="mt-2.5 flex items-baseline justify-between gap-2">
          <div className="flex items-baseline gap-2">
            <span
              className={`font-mono text-2xl font-extrabold tracking-tight tabular-nums sm:text-3xl ${activeAlerts > 0 ? 'text-rose-400' : 'text-slate-100'
                }`}
            >
              {activeAlerts}
            </span>
            <span className="text-xs font-medium text-slate-400">Active</span>
          </div>
          {activeAlerts > 0 && (
            <span className="flex items-center gap-0.5 text-xs font-semibold text-rose-300">
              查看 <ArrowUpRight className="h-3.5 w-3.5" />
            </span>
          )}
        </div>
      </div>

      {/* KPI 4: hidden stale snapshots */}
      <div className="ui-surface-card relative overflow-hidden p-4 transition-colors hover:border-slate-600/90">
        <div className="flex items-center justify-between gap-2">
          <span className="text-xs font-medium text-slate-300">已隐藏旧快照</span>
          <div className="rounded-xl border border-slate-700/60 bg-slate-800/80 p-2 text-slate-400">
            <Clock3 className="h-4 w-4" />
          </div>
        </div>
        <div className="mt-2.5 flex items-baseline gap-2">
          <span
            className={`font-mono text-2xl font-extrabold tracking-tight tabular-nums sm:text-3xl ${hiddenStaleSnapshots > 0 ? 'text-amber-400' : 'text-slate-100'
              }`}
          >
            {hiddenStaleSnapshots}
          </span>
          <span className="text-xs font-medium text-slate-400">保留在历史数据</span>
        </div>
      </div>
    </section>
  );
};
