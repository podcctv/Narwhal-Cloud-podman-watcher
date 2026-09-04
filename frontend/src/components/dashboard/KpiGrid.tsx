import React from 'react';
import { Server, Box, AlertTriangle, PowerOff, ArrowUpRight } from 'lucide-react';

interface KpiGridProps {
  onlineHosts: number;
  totalContainers: number;
  activeAlerts: number;
  staleContainers: number;
  onFilterAlerts?: () => void;
}

export const KpiGrid: React.FC<KpiGridProps> = ({
  onlineHosts,
  totalContainers,
  activeAlerts,
  staleContainers,
  onFilterAlerts,
}) => {
  return (
    <section aria-label="运行概览指标" className="mb-6 grid grid-cols-2 gap-3 sm:grid-cols-4 sm:gap-4">
      {/* KPI 1: 在线主机 */}
      <div className="relative overflow-hidden rounded-2xl border border-slate-800 bg-slate-900/60 p-4 shadow-sm hover:border-slate-700 transition-colors">
        <div className="flex items-center justify-between">
          <span className="text-xs font-medium text-slate-400">在线主机</span>
          <div className="rounded-lg bg-sky-950/60 p-2 text-sky-400 border border-sky-500/20">
            <Server className="h-4 w-4" />
          </div>
        </div>
        <div className="mt-2 flex items-baseline gap-2">
          <span className="font-mono text-2xl font-extrabold tracking-tight text-slate-100 tabular-nums">
            {onlineHosts}
          </span>
          <span className="text-xs text-slate-500">Nodes</span>
        </div>
      </div>

      {/* KPI 2: 监控容器 */}
      <div className="relative overflow-hidden rounded-2xl border border-slate-800 bg-slate-900/60 p-4 shadow-sm hover:border-slate-700 transition-colors">
        <div className="flex items-center justify-between">
          <span className="text-xs font-medium text-slate-400">活跃容器</span>
          <div className="rounded-lg bg-emerald-950/60 p-2 text-emerald-400 border border-emerald-500/20">
            <Box className="h-4 w-4" />
          </div>
        </div>
        <div className="mt-2 flex items-baseline gap-2">
          <span className="font-mono text-2xl font-extrabold tracking-tight text-slate-100 tabular-nums">
            {totalContainers}
          </span>
          <span className="text-xs text-slate-500">Containers</span>
        </div>
      </div>

      {/* KPI 3: 活动告警 */}
      <div
        onClick={onFilterAlerts}
        className={`relative overflow-hidden rounded-2xl border p-4 shadow-sm transition-all cursor-pointer ${
          activeAlerts > 0
            ? 'border-rose-500/40 bg-rose-950/20 hover:border-rose-500/70 hover:shadow-glow-rose'
            : 'border-slate-800 bg-slate-900/60 hover:border-slate-700'
        }`}
      >
        <div className="flex items-center justify-between">
          <span className={`text-xs font-medium ${activeAlerts > 0 ? 'text-rose-300' : 'text-slate-400'}`}>
            活动安全告警
          </span>
          <div
            className={`rounded-lg p-2 border ${
              activeAlerts > 0
                ? 'bg-rose-950/80 text-rose-400 border-rose-500/30'
                : 'bg-slate-800/80 text-slate-400 border-slate-700/50'
            }`}
          >
            <AlertTriangle className="h-4 w-4" />
          </div>
        </div>
        <div className="mt-2 flex items-baseline justify-between">
          <div className="flex items-baseline gap-2">
            <span
              className={`font-mono text-2xl font-extrabold tracking-tight tabular-nums ${
                activeAlerts > 0 ? 'text-rose-400' : 'text-slate-100'
              }`}
            >
              {activeAlerts}
            </span>
            <span className="text-xs text-slate-500">Active</span>
          </div>
          {activeAlerts > 0 && (
            <span className="flex items-center gap-0.5 text-xs text-rose-400 font-medium">
              查看 <ArrowUpRight className="h-3 w-3" />
            </span>
          )}
        </div>
      </div>

      {/* KPI 4: 离线/过期 */}
      <div className="relative overflow-hidden rounded-2xl border border-slate-800 bg-slate-900/60 p-4 shadow-sm hover:border-slate-700 transition-colors">
        <div className="flex items-center justify-between">
          <span className="text-xs font-medium text-slate-400">离线或过期容器</span>
          <div className="rounded-lg bg-slate-800/80 p-2 text-slate-400 border border-slate-700/50">
            <PowerOff className="h-4 w-4" />
          </div>
        </div>
        <div className="mt-2 flex items-baseline gap-2">
          <span
            className={`font-mono text-2xl font-extrabold tracking-tight tabular-nums ${
              staleContainers > 0 ? 'text-amber-400' : 'text-slate-100'
            }`}
          >
            {staleContainers}
          </span>
          <span className="text-xs text-slate-500">Offline/Stale</span>
        </div>
      </div>
    </section>
  );
};
