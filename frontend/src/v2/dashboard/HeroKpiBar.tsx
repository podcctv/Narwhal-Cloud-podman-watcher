import React from 'react';
import {
  AlertTriangle,
  ArrowUpRight,
  Box,
  Clock3,
  HardDrive,
  History,
  LayoutGrid,
  Rocket,
  Server,
  ShieldAlert,
  ShieldCheck,
  SlidersHorizontal,
  Activity,
  type LucideIcon,
} from 'lucide-react';

export type QuickOpsTarget = 'cleanup' | 'firewall' | 'policy' | 'upgrades' | 'alerts';
export type WorkspaceFocus = 'all' | 'fleet' | 'telemetry' | 'alerts';

export interface HeroKpiBarProps {
  onlineHosts: number;
  totalContainers: number;
  activeAlerts: number;
  hiddenStaleSnapshots: number;
  lastRefreshTime?: string;
  workspaceFocus: WorkspaceFocus;
  onWorkspaceFocusChange: (focus: WorkspaceFocus) => void;
  onFilterAlerts?: () => void;
  onQuickOps?: (target: QuickOpsTarget, hostId?: string) => void;
  telemetryHostCount?: number;
}

const QUICK_OPS_SHORTCUTS: Array<{
  target: QuickOpsTarget;
  label: string;
  icon: LucideIcon;
  tone: 'indigo' | 'emerald' | 'slate';
}> = [
  { target: 'cleanup', label: '存储与磁盘清理', icon: HardDrive, tone: 'slate' },
  { target: 'firewall', label: '母机防火墙', icon: ShieldCheck, tone: 'slate' },
  { target: 'policy', label: '动态安全策略', icon: SlidersHorizontal, tone: 'slate' },
  { target: 'upgrades', label: '节点批量升级', icon: Rocket, tone: 'indigo' },
  { target: 'alerts', label: '告警历史', icon: History, tone: 'emerald' },
];

export const HeroKpiBar: React.FC<HeroKpiBarProps> = ({
  onlineHosts,
  totalContainers,
  activeAlerts,
  hiddenStaleSnapshots,
  lastRefreshTime,
  workspaceFocus,
  onWorkspaceFocusChange,
  onFilterAlerts,
  onQuickOps,
  telemetryHostCount = 0,
}) => {
  const focusTabs: Array<{
    id: WorkspaceFocus;
    label: string;
    icon: LucideIcon;
    count?: number;
  }> = [
    { id: 'all', label: '全部视图', icon: LayoutGrid },
    { id: 'fleet', label: '宿主机与容器', icon: Server, count: onlineHosts },
    { id: 'telemetry', label: '安全遥测', icon: Activity, count: telemetryHostCount },
    { id: 'alerts', label: '告警与隔离', icon: ShieldAlert, count: activeAlerts },
  ];

  return (
    <div className="mb-6 space-y-4">
      {/* Clean Light SaaS Top Overview Header */}
      <section aria-label="运行概览指标" className="space-y-4">
        <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              <span className="inline-flex items-center gap-1.5 rounded-full border border-[#c7d2fe] bg-[#eef2ff] px-2.5 py-0.5 font-mono text-[10px] font-bold tracking-wider uppercase text-[#4f46e5]">
                <span className="h-1.5 w-1.5 rounded-full bg-[#10b981]" aria-hidden="true" />
                FLEET WORKBENCH
              </span>
              {lastRefreshTime && (
                <span className="rounded-md border border-[#e2e8f0] bg-white px-2 py-0.5 font-mono text-[11px] font-medium text-[#64748b] tabular-nums">
                  同步 {lastRefreshTime}
                </span>
              )}
            </div>
            <h2 className="mt-1.5 text-lg font-bold tracking-tight text-[#0f172a] sm:text-xl">
              集群健康概览与快捷处置
            </h2>
          </div>

          {onQuickOps && (
            <div className="flex flex-wrap items-center gap-1.5" role="group" aria-label="快速运维入口">
              {QUICK_OPS_SHORTCUTS.map(({ target, label, icon: Icon, tone }) => (
                <button
                  key={target}
                  type="button"
                  onClick={() => onQuickOps(target)}
                  className={`inline-flex min-h-9 items-center gap-1.5 rounded-lg border px-3 py-1.5 text-xs font-semibold transition-colors ${
                    tone === 'indigo'
                      ? 'border-[#4f46e5] bg-[#4f46e5] text-white shadow-xs hover:bg-[#4338ca]'
                      : tone === 'emerald'
                        ? 'border-[#a7f3d0] bg-[#ecfdf5] text-[#059669] hover:bg-[#d1fae5]'
                        : 'border-[#e2e8f0] bg-white text-[#334155] shadow-2xs hover:border-[#c7d2fe] hover:bg-[#eef2ff] hover:text-[#4f46e5]'
                  }`}
                >
                  <Icon
                    className={`h-3.5 w-3.5 shrink-0 ${
                      tone === 'indigo' ? 'text-white' : tone === 'emerald' ? 'text-[#059669]' : 'text-[#4f46e5]'
                    }`}
                    aria-hidden={true}
                  />
                  <span>{label}</span>
                </button>
              ))}
            </div>
          )}
        </div>

        {/* 4 Clean White SaaS KPI Cards */}
        <div className="grid grid-cols-2 gap-3.5 lg:grid-cols-4">
          {/* KPI 1: 在线主机 */}
          <div className="rn2-card min-w-0 p-4 transition-shadow hover:shadow-md">
            <div className="flex items-start justify-between gap-2">
              <div className="min-w-0">
                <span className="block truncate text-xs font-semibold text-[#64748b]">在线主机</span>
                <span className="mt-0.5 block font-mono text-[10px] font-bold uppercase tracking-wider text-[#94a3b8]">
                  NODES ONLINE
                </span>
              </div>
              <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-xl border border-[#c7d2fe] bg-[#eef2ff] text-[#4f46e5]">
                <Server className="h-4 w-4" aria-hidden="true" />
              </div>
            </div>
            <div className="mt-3.5 flex items-baseline justify-between gap-2">
              <span className="font-mono text-2xl font-extrabold tracking-tight text-[#0f172a] tabular-nums sm:text-3xl">
                {onlineHosts}
              </span>
              <span className="rounded-full border border-[#c7d2fe] bg-[#eef2ff] px-2 py-0.5 font-mono text-[10px] font-bold uppercase tracking-wider text-[#4338ca]">
                HOSTS
              </span>
            </div>
          </div>

          {/* KPI 2: 活跃容器 */}
          <div className="rn2-card min-w-0 p-4 transition-shadow hover:shadow-md">
            <div className="flex items-start justify-between gap-2">
              <div className="min-w-0">
                <span className="block truncate text-xs font-semibold text-[#64748b]">活跃容器</span>
                <span className="mt-0.5 block font-mono text-[10px] font-bold uppercase tracking-wider text-[#94a3b8]">
                  ACTIVE INSTANCES
                </span>
              </div>
              <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-xl border border-[#a7f3d0] bg-[#ecfdf5] text-[#059669]">
                <Box className="h-4 w-4" aria-hidden="true" />
              </div>
            </div>
            <div className="mt-3.5 flex items-baseline justify-between gap-2">
              <span className="font-mono text-2xl font-extrabold tracking-tight text-[#0f172a] tabular-nums sm:text-3xl">
                {totalContainers}
              </span>
              <span className="inline-flex items-center gap-1 rounded-full border border-[#a7f3d0] bg-[#ecfdf5] px-2 py-0.5 font-mono text-[10px] font-bold uppercase tracking-wider text-[#059669]">
                <span className="h-1.5 w-1.5 rounded-full bg-[#10b981]" aria-hidden="true" />
                LIVE
              </span>
            </div>
          </div>

          {/* KPI 3: 活动安全告警 */}
          <button
            type="button"
            onClick={onFilterAlerts}
            disabled={!onFilterAlerts}
            className={`rn2-card min-w-0 p-4 text-left transition-all hover:shadow-md ${
              activeAlerts > 0
                ? 'border-[#fecdd3] bg-[#fffafb] hover:border-[#fb7185]'
                : 'hover:border-[#c7d2fe]'
            }`}
          >
            <div className="flex items-start justify-between gap-2">
              <div className="min-w-0">
                <span className={`block truncate text-xs font-semibold ${activeAlerts > 0 ? 'text-[#be123c]' : 'text-[#64748b]'}`}>
                  活动安全告警
                </span>
                <span className="mt-0.5 block font-mono text-[10px] font-bold uppercase tracking-wider text-[#94a3b8]">
                  SECURITY ALERTS
                </span>
              </div>
              <div
                className={`flex h-9 w-9 shrink-0 items-center justify-center rounded-xl border ${
                  activeAlerts > 0
                    ? 'border-[#fecdd3] bg-[#ffe4e6] text-[#be123c]'
                    : 'border-[#e2e8f0] bg-[#f8fafc] text-[#64748b]'
                }`}
              >
                <AlertTriangle className="h-4 w-4" aria-hidden="true" />
              </div>
            </div>
            <div className="mt-3.5 flex items-baseline justify-between gap-2">
              <span
                className={`font-mono text-2xl font-extrabold tracking-tight tabular-nums sm:text-3xl ${
                  activeAlerts > 0 ? 'text-[#be123c]' : 'text-[#0f172a]'
                }`}
              >
                {activeAlerts}
              </span>
              {activeAlerts > 0 ? (
                <span className="inline-flex items-center gap-0.5 rounded-full border border-[#fecdd3] bg-[#ffe4e6] px-2 py-0.5 text-[11px] font-bold text-[#be123c]">
                  查看 <ArrowUpRight className="h-3 w-3" aria-hidden="true" />
                </span>
              ) : (
                <span className="rounded-full border border-[#a7f3d0] bg-[#ecfdf5] px-2 py-0.5 font-mono text-[10px] font-bold uppercase tracking-wider text-[#059669]">
                  CLEAR
                </span>
              )}
            </div>
          </button>

          {/* KPI 4: 已隐藏旧快照 */}
          <div className="rn2-card min-w-0 p-4 transition-shadow hover:shadow-md">
            <div className="flex items-start justify-between gap-2">
              <div className="min-w-0">
                <span className="block truncate text-xs font-semibold text-[#64748b]">已隐藏旧快照</span>
                <span className="mt-0.5 block font-mono text-[10px] font-bold uppercase tracking-wider text-[#94a3b8]">
                  STALE SNAPSHOTS
                </span>
              </div>
              <div
                className={`flex h-9 w-9 shrink-0 items-center justify-center rounded-xl border ${
                  hiddenStaleSnapshots > 0
                    ? 'border-amber-200 bg-amber-50 text-amber-600'
                    : 'border-[#e2e8f0] bg-[#f8fafc] text-[#64748b]'
                }`}
              >
                <Clock3 className="h-4 w-4" aria-hidden="true" />
              </div>
            </div>
            <div className="mt-3.5 flex items-baseline justify-between gap-2">
              <span
                className={`font-mono text-2xl font-extrabold tracking-tight tabular-nums sm:text-3xl ${
                  hiddenStaleSnapshots > 0 ? 'text-amber-600' : 'text-[#0f172a]'
                }`}
              >
                {hiddenStaleSnapshots}
              </span>
              <span className="truncate text-[11px] font-medium text-[#64748b]">保留在历史数据</span>
            </div>
          </div>
        </div>
      </section>

      {/* Clean SaaS Workspace Focus Switcher */}
      <div
        className="rn2-card flex flex-wrap items-center justify-between gap-2 px-3.5 py-2.5"
        role="group"
        aria-label="工作区焦点切换"
      >
        <div className="flex items-center gap-2">
          <span className="font-mono text-[11px] font-bold tracking-wider uppercase text-[#4f46e5]">
            WORKSPACE FOCUS
          </span>
          <span className="hidden text-xs text-[#64748b] sm:inline">按关注域筛选看板模块</span>
        </div>

        <div className="flex flex-wrap items-center gap-1.5">
          {focusTabs.map(({ id, label, icon: Icon, count }) => {
            const active = workspaceFocus === id;
            return (
              <button
                key={id}
                type="button"
                aria-pressed={active}
                onClick={() => onWorkspaceFocusChange(id)}
                className={`inline-flex min-h-9 items-center gap-1.5 rounded-lg border px-3 py-1.5 text-xs font-semibold transition-colors ${
                  active
                    ? 'border-[#4f46e5] bg-[#4f46e5] text-white shadow-xs'
                    : 'border-[#e2e8f0] bg-[#f8fafc] text-[#475569] hover:border-[#c7d2fe] hover:bg-[#eef2ff] hover:text-[#4f46e5]'
                }`}
              >
                <Icon className="h-3.5 w-3.5 shrink-0" aria-hidden={true} />
                <span>{label}</span>
                {typeof count === 'number' && (
                  <span
                    className={`rounded-full px-1.5 py-0.5 font-mono text-[10px] leading-none tabular-nums ${
                      active
                        ? 'bg-white/20 text-white'
                        : id === 'alerts' && count > 0
                          ? 'border border-[#fecdd3] bg-[#ffe4e6] text-[#be123c]'
                          : 'border border-[#e2e8f0] bg-white text-[#475569]'
                    }`}
                  >
                    {count}
                  </span>
                )}
              </button>
            );
          })}
        </div>
      </div>
    </div>
  );
};
