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
  tone: 'cyan' | 'orange' | 'blue';
}> = [
  { target: 'cleanup', label: '存储与磁盘清理', icon: HardDrive, tone: 'cyan' },
  { target: 'firewall', label: '母机防火墙', icon: ShieldCheck, tone: 'blue' },
  { target: 'policy', label: '动态安全策略', icon: SlidersHorizontal, tone: 'blue' },
  { target: 'upgrades', label: '节点批量升级', icon: Rocket, tone: 'orange' },
  { target: 'alerts', label: '告警历史', icon: History, tone: 'cyan' },
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
    <div className="mb-6 space-y-3">
      {/* Midnight Hero Strip */}
      <section
        aria-label="运行概览指标"
        className="rn2-hero overflow-hidden rounded-2xl border border-[#54c7ff]/25 p-4 shadow-[0_14px_34px_rgba(2,24,47,0.22)] sm:p-5"
      >
        <div className="flex flex-col gap-3 border-b border-white/10 pb-4 lg:flex-row lg:items-center lg:justify-between">
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              <span className="rn2-eyebrow inline-flex items-center gap-1.5 text-[#54c7ff]">
                <span className="h-1.5 w-1.5 rounded-full bg-[#00b6ec]" aria-hidden="true" />
                INFRASTRUCTURE OVERVIEW · 2.0
              </span>
              {lastRefreshTime && (
                <span className="rounded-md border border-[#54c7ff]/30 bg-[#02182f]/75 px-2 py-0.5 font-mono text-[11px] font-semibold text-[#cde8ff] tabular-nums">
                  同步 {lastRefreshTime}
                </span>
              )}
            </div>
            <h2 className="mt-1 text-base font-extrabold tracking-tight text-white sm:text-lg">
              集群实时监控与快速处置
            </h2>
          </div>

          {onQuickOps && (
            <div className="flex flex-wrap items-center gap-1.5" role="group" aria-label="快速运维入口">
              {QUICK_OPS_SHORTCUTS.map(({ target, label, icon: Icon, tone }) => (
                <button
                  key={target}
                  type="button"
                  onClick={() => onQuickOps(target)}
                  className={`inline-flex min-h-9 items-center gap-1.5 rounded-lg border px-2.5 py-1.5 text-xs font-semibold transition-colors ${
                    tone === 'orange'
                      ? 'border-[#ff8100]/65 bg-[#ff6b00]/20 text-[#ffd7b8] hover:border-[#ff8100] hover:bg-[#ff6b00] hover:text-white'
                      : 'border-[#54c7ff]/30 bg-[#02182f]/75 text-[#e6f4ff] hover:border-[#54c7ff] hover:bg-[#087bff]/30 hover:text-white'
                  }`}
                >
                  <Icon className="h-3.5 w-3.5 shrink-0 text-[#54c7ff]" aria-hidden={true} />
                  <span>{label}</span>
                </button>
              ))}
            </div>
          )}
        </div>

        {/* 4 .bf-time-unit-inspired KPI Cards */}
        <div className="mt-4 grid grid-cols-2 gap-3 lg:grid-cols-4">
          {/* KPI 1: 在线主机 */}
          <div className="min-w-0 rounded-xl border border-[#54c7ff]/25 bg-[#02182f]/75 p-3.5 shadow-[inset_0_1px_0_rgba(84,199,255,0.14)]">
            <div className="flex items-center justify-between gap-2">
              <div className="min-w-0">
                <span className="block truncate font-mono text-[10px] font-bold uppercase tracking-[0.14em] text-[#54c7ff]">
                  NODES ONLINE
                </span>
                <span className="mt-0.5 block text-xs font-semibold text-[#e6f4ff]">在线主机</span>
              </div>
              <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg border border-[#54c7ff]/35 bg-[#087bff]/20 text-[#54c7ff]">
                <Server className="h-4 w-4" aria-hidden="true" />
              </div>
            </div>
            <div className="mt-3 flex items-baseline justify-between gap-2">
              <span className="font-mono text-2xl font-extrabold tracking-tight text-white tabular-nums sm:text-3xl">
                {onlineHosts}
              </span>
              <span className="rounded border border-[#54c7ff]/25 bg-[#031d3d] px-1.5 py-0.5 font-mono text-[10px] font-bold uppercase tracking-wider text-[#9ad8ff]">
                NODES
              </span>
            </div>
          </div>

          {/* KPI 2: 活跃容器 */}
          <div className="min-w-0 rounded-xl border border-emerald-400/30 bg-[#02182f]/75 p-3.5 shadow-[inset_0_1px_0_rgba(52,211,153,0.14)]">
            <div className="flex items-center justify-between gap-2">
              <div className="min-w-0">
                <span className="block truncate font-mono text-[10px] font-bold uppercase tracking-[0.14em] text-emerald-300">
                  ACTIVE INSTANCES
                </span>
                <span className="mt-0.5 block text-xs font-semibold text-[#e6f4ff]">活跃容器</span>
              </div>
              <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg border border-emerald-400/35 bg-emerald-500/20 text-emerald-300">
                <Box className="h-4 w-4" aria-hidden="true" />
              </div>
            </div>
            <div className="mt-3 flex items-baseline justify-between gap-2">
              <span className="font-mono text-2xl font-extrabold tracking-tight text-white tabular-nums sm:text-3xl">
                {totalContainers}
              </span>
              <span className="rounded border border-emerald-400/25 bg-[#031d3d] px-1.5 py-0.5 font-mono text-[10px] font-bold uppercase tracking-wider text-emerald-200">
                LIVE
              </span>
            </div>
          </div>

          {/* KPI 3: 活动安全告警 */}
          <button
            type="button"
            onClick={onFilterAlerts}
            disabled={!onFilterAlerts}
            className={`min-w-0 rounded-xl border p-3.5 text-left transition-colors ${
              activeAlerts > 0
                ? 'border-[#ff8100]/75 bg-[linear-gradient(155deg,rgba(255,107,0,0.22),rgba(2,24,47,0.88))] shadow-[0_6px_18px_-4px_rgba(255,107,0,0.35)] hover:border-[#ff8100]'
                : 'border-[#54c7ff]/25 bg-[#02182f]/75 shadow-[inset_0_1px_0_rgba(84,199,255,0.14)] hover:border-[#54c7ff]/60'
            }`}
          >
            <div className="flex items-center justify-between gap-2">
              <div className="min-w-0">
                <span
                  className={`block truncate font-mono text-[10px] font-bold uppercase tracking-[0.14em] ${
                    activeAlerts > 0 ? 'text-[#ffb37c]' : 'text-[#9ad8ff]'
                  }`}
                >
                  SECURITY ALERTS
                </span>
                <span className="mt-0.5 block text-xs font-semibold text-[#e6f4ff]">活动安全告警</span>
              </div>
              <div
                className={`flex h-8 w-8 shrink-0 items-center justify-center rounded-lg border ${
                  activeAlerts > 0
                    ? 'border-[#ff8100]/65 bg-[#ff6b00]/25 text-[#ffb37c]'
                    : 'border-[#54c7ff]/30 bg-[#031d3d] text-[#9ad8ff]'
                }`}
              >
                <AlertTriangle className="h-4 w-4" aria-hidden="true" />
              </div>
            </div>
            <div className="mt-3 flex items-baseline justify-between gap-2">
              <span
                className={`font-mono text-2xl font-extrabold tracking-tight tabular-nums sm:text-3xl ${
                  activeAlerts > 0 ? 'text-[#ff9c52]' : 'text-white'
                }`}
              >
                {activeAlerts}
              </span>
              {activeAlerts > 0 ? (
                <span className="inline-flex items-center gap-0.5 rounded border border-[#ff8100]/60 bg-[#ff6b00]/25 px-1.5 py-0.5 text-[11px] font-bold text-[#ffe4cf]">
                  查看 <ArrowUpRight className="h-3 w-3" aria-hidden="true" />
                </span>
              ) : (
                <span className="font-mono text-[10px] font-semibold uppercase tracking-wider text-[#9ad8ff]">
                  CLEAR
                </span>
              )}
            </div>
          </button>

          {/* KPI 4: 已隐藏旧快照 */}
          <div className="min-w-0 rounded-xl border border-[#54c7ff]/25 bg-[#02182f]/75 p-3.5 shadow-[inset_0_1px_0_rgba(84,199,255,0.14)]">
            <div className="flex items-center justify-between gap-2">
              <div className="min-w-0">
                <span
                  className={`block truncate font-mono text-[10px] font-bold uppercase tracking-[0.14em] ${
                    hiddenStaleSnapshots > 0 ? 'text-amber-300' : 'text-[#9ad8ff]'
                  }`}
                >
                  STALE SNAPSHOTS
                </span>
                <span className="mt-0.5 block text-xs font-semibold text-[#e6f4ff]">已隐藏旧快照</span>
              </div>
              <div
                className={`flex h-8 w-8 shrink-0 items-center justify-center rounded-lg border ${
                  hiddenStaleSnapshots > 0
                    ? 'border-amber-400/45 bg-amber-500/20 text-amber-300'
                    : 'border-[#54c7ff]/30 bg-[#031d3d] text-[#9ad8ff]'
                }`}
              >
                <Clock3 className="h-4 w-4" aria-hidden="true" />
              </div>
            </div>
            <div className="mt-3 flex items-baseline justify-between gap-2">
              <span
                className={`font-mono text-2xl font-extrabold tracking-tight tabular-nums sm:text-3xl ${
                  hiddenStaleSnapshots > 0 ? 'text-amber-300' : 'text-white'
                }`}
              >
                {hiddenStaleSnapshots}
              </span>
              <span className="truncate text-[11px] font-medium text-[#a9c1dc]">保留在历史数据</span>
            </div>
          </div>
        </div>
      </section>

      {/* Light-Ice Workspace Focus Switcher */}
      <div
        className="rn2-card flex flex-wrap items-center justify-between gap-2 px-3 py-2.5"
        role="group"
        aria-label="工作区焦点切换"
      >
        <div className="flex items-center gap-2">
          <span className="rn2-eyebrow text-[#087bff]">WORKSPACE FOCUS</span>
          <span className="hidden text-xs text-[#697b9c] sm:inline">按关注域筛选看板模块</span>
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
                    ? 'border-[#0867d6] bg-[#087bff] text-white shadow-xs'
                    : 'border-[#d2dfec] bg-[#f4f8fd] text-[#31485e] hover:border-[#087bff] hover:bg-[#e8f3ff] hover:text-[#08458c]'
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
                          ? 'bg-[#fff3e8] text-[#b84800] border border-[#ffc899]'
                          : 'bg-white text-[#4a607a] border border-[#cedae7]'
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
