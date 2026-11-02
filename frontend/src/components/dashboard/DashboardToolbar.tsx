import React from 'react';
import {
  Search,
  LayoutGrid,
  Table as TableIcon,
  Layers,
  AlertTriangle,
  Radio,
  ArrowUpDown,
  CheckCircle2,
  ShieldCheck,
  Clock3,
  ChevronsUpDown,
  ChevronsDownUp,
  X,
} from 'lucide-react';

export type ViewMode = 'grid' | 'table' | 'detailed';
export type FilterState = 'all' | 'risk' | 'protection' | 'protocol' | 'hy2' | 'imbalance' | 'stale' | 'healthy';

interface DashboardToolbarProps {
  viewMode: ViewMode;
  onViewModeChange: (mode: ViewMode) => void;
  filterState: FilterState;
  onFilterStateChange: (filter: FilterState) => void;
  searchQuery: string;
  onSearchChange: (query: string) => void;
  totalHosts: number;
  totalContainers: number;
  counts: {
    all: number;
    risk: number;
    protection: number;
    protocol: number;
    hy2: number;
    imbalance: number;
    stale: number;
    healthy: number;
  };
  allExpanded: boolean;
  onToggleAllHosts: () => void;
}

export const DashboardToolbar: React.FC<DashboardToolbarProps> = ({
  viewMode,
  onViewModeChange,
  filterState,
  onFilterStateChange,
  searchQuery,
  onSearchChange,
  totalHosts,
  totalContainers,
  counts,
  allExpanded,
  onToggleAllHosts,
}) => {
  return (
    <div className="mb-4 space-y-2.5">
      {/* Primary Toolbar Bar */}
      <div className="ui-toolbar-bar flex flex-col gap-3 p-3 lg:flex-row lg:items-center lg:justify-between">
        {/* Left: Search & Filter Chips */}
        <div className="flex min-w-0 flex-1 flex-wrap items-center gap-2">
          {/* Quick Search Input */}
          <div className="relative min-w-[210px] flex-1 sm:max-w-xs">
            <Search className="pointer-events-none absolute top-1/2 left-3 h-3.5 w-3.5 -translate-y-1/2 text-slate-400" />
            <input
              type="search"
              name="container-search"
              aria-label="搜索容器、主机、运行时、邮箱或备注"
              value={searchQuery}
              onChange={(e) => onSearchChange(e.target.value)}
              placeholder="搜索容器名 / 主机 / 运行时…"
              className="ui-input-sm w-full pr-7 pl-8"
            />
            {searchQuery && (
              <button
                type="button"
                onClick={() => onSearchChange('')}
                aria-label="清空搜索"
                className="absolute top-1/2 right-2 -translate-y-1/2 rounded p-0.5 text-slate-400 hover:text-slate-200 focus-visible:outline-hidden focus-visible:ring-1 focus-visible:ring-sky-400"
                title="清空搜索"
              >
                <X className="h-3.5 w-3.5" />
              </button>
            )}
          </div>

          {/* Filter Chips */}
          <div className="flex flex-wrap items-center gap-1.5">
            {/* All */}
            <button
              type="button"
              aria-pressed={filterState === 'all'}
              onClick={() => onFilterStateChange('all')}
              className={`flex h-9 items-center gap-1.5 rounded-lg border px-2.5 text-xs font-semibold transition-colors focus-visible:outline-hidden focus-visible:ring-1 focus-visible:ring-sky-400 ${
                filterState === 'all'
                  ? 'border-sky-500/50 bg-sky-500/20 text-sky-200 shadow-xs'
                  : 'border-slate-800 bg-slate-950/60 text-slate-400 hover:bg-slate-800/70 hover:text-slate-200'
              }`}
            >
              <span>全部</span>
              <span className="rounded-full bg-slate-800 px-1.5 py-0.5 font-mono text-[10px] text-slate-300 tabular-nums">
                {counts.all}
              </span>
            </button>

            {/* Resource signals and automatic protections */}
            <button
              type="button"
              aria-pressed={filterState === 'protection'}
              onClick={() => onFilterStateChange('protection')}
              className={`flex h-9 items-center gap-1.5 rounded-lg border px-2.5 text-xs font-semibold transition-colors focus-visible:outline-hidden focus-visible:ring-1 focus-visible:ring-sky-400 ${
                filterState === 'protection'
                  ? 'border-sky-500/50 bg-sky-500/20 text-sky-200 shadow-xs'
                  : 'border-slate-800 bg-slate-950/60 text-slate-400 hover:bg-slate-800/70 hover:text-sky-200'
              }`}
            >
              <ShieldCheck className="h-3.5 w-3.5" />
              <span>资源与保护</span>
              <span className="rounded-full bg-slate-800 px-1.5 py-0.5 font-mono text-[10px] tabular-nums">{counts.protection}</span>
            </button>

            {/* VMess / Trojan protocol guard */}
            <button
              type="button"
              aria-pressed={filterState === 'protocol'}
              onClick={() => onFilterStateChange('protocol')}
              className={`flex h-9 items-center gap-1.5 rounded-lg border px-2.5 text-xs font-semibold transition-colors focus-visible:outline-hidden focus-visible:ring-1 focus-visible:ring-violet-400 ${
                filterState === 'protocol'
                  ? 'border-violet-500/50 bg-violet-500/20 text-violet-200 shadow-xs'
                  : 'border-slate-800 bg-slate-950/60 text-slate-400 hover:bg-slate-800/70 hover:text-violet-200'
              }`}
            >
              <ShieldCheck className="h-3.5 w-3.5" />
              <span>协议阻断</span>
              <span className="rounded-full bg-slate-800 px-1.5 py-0.5 font-mono text-[10px] tabular-nums">{counts.protocol}</span>
            </button>

            {/* Risk */}
            <button
              type="button"
              aria-pressed={filterState === 'risk'}
              onClick={() => onFilterStateChange('risk')}
              className={`flex h-9 items-center gap-1.5 rounded-lg border px-2.5 text-xs font-semibold transition-colors focus-visible:outline-hidden focus-visible:ring-1 focus-visible:ring-rose-400 ${
                filterState === 'risk'
                  ? 'border-rose-500/50 bg-rose-500/20 text-rose-200 shadow-xs shadow-rose-950/50'
                  : 'border-slate-800 bg-slate-950/60 text-slate-400 hover:bg-slate-800/70 hover:text-rose-300'
              }`}
            >
              <AlertTriangle className={`h-3.5 w-3.5 ${counts.risk > 0 ? 'text-rose-400' : 'text-slate-500'}`} />
              <span>异常风险</span>
              <span
                className={`rounded-full px-1.5 py-0.5 font-mono text-[10px] tabular-nums ${
                  counts.risk > 0 ? 'bg-rose-900/60 font-bold text-rose-300' : 'bg-slate-800 text-slate-400'
                }`}
              >
                {counts.risk}
              </span>
            </button>

            {/* Stale telemetry */}
            <button
              type="button"
              aria-pressed={filterState === 'stale'}
              onClick={() => onFilterStateChange('stale')}
              className={`flex h-9 items-center gap-1.5 rounded-lg border px-2.5 text-xs font-semibold transition-colors focus-visible:outline-hidden focus-visible:ring-1 focus-visible:ring-amber-400 ${
                filterState === 'stale'
                  ? 'border-amber-500/50 bg-amber-500/20 text-amber-200 shadow-xs'
                  : 'border-slate-800 bg-slate-950/60 text-slate-400 hover:bg-slate-800/70 hover:text-amber-200'
              }`}
            >
              <Clock3 className="h-3.5 w-3.5" />
              <span>离线主机 / 旧快照</span>
              <span className="rounded-full bg-slate-800 px-1.5 py-0.5 font-mono text-[10px] tabular-nums">{counts.stale}</span>
            </button>

            {/* HY2 */}
            <button
              type="button"
              aria-pressed={filterState === 'hy2'}
              onClick={() => onFilterStateChange('hy2')}
              className={`flex h-9 items-center gap-1.5 rounded-lg border px-2.5 text-xs font-semibold transition-colors focus-visible:outline-hidden focus-visible:ring-1 focus-visible:ring-violet-400 ${
                filterState === 'hy2'
                  ? 'border-violet-500/50 bg-violet-500/20 text-violet-200 shadow-xs shadow-violet-950/50'
                  : 'border-slate-800 bg-slate-950/60 text-slate-400 hover:bg-slate-800/70 hover:text-violet-300'
              }`}
            >
              <Radio className={`h-3.5 w-3.5 ${counts.hy2 > 0 ? 'text-violet-400' : 'text-slate-500'}`} />
              <span>HY2 代理</span>
              <span
                className={`rounded-full px-1.5 py-0.5 font-mono text-[10px] tabular-nums ${
                  counts.hy2 > 0 ? 'bg-violet-900/60 font-bold text-violet-300' : 'bg-slate-800 text-slate-400'
                }`}
              >
                {counts.hy2}
              </span>
            </button>

            {/* Imbalance */}
            <button
              type="button"
              aria-pressed={filterState === 'imbalance'}
              onClick={() => onFilterStateChange('imbalance')}
              className={`flex h-9 items-center gap-1.5 rounded-lg border px-2.5 text-xs font-semibold transition-colors focus-visible:outline-hidden focus-visible:ring-1 focus-visible:ring-amber-400 ${
                filterState === 'imbalance'
                  ? 'border-amber-500/50 bg-amber-500/20 text-amber-200 shadow-xs shadow-amber-950/50'
                  : 'border-slate-800 bg-slate-950/60 text-slate-400 hover:bg-slate-800/70 hover:text-amber-300'
              }`}
            >
              <ArrowUpDown className={`h-3.5 w-3.5 ${counts.imbalance > 0 ? 'text-amber-400' : 'text-slate-500'}`} />
              <span>流量失衡</span>
              <span
                className={`rounded-full px-1.5 py-0.5 font-mono text-[10px] tabular-nums ${
                  counts.imbalance > 0 ? 'bg-amber-900/60 font-bold text-amber-300' : 'bg-slate-800 text-slate-400'
                }`}
              >
                {counts.imbalance}
              </span>
            </button>

            {/* Healthy */}
            <button
              type="button"
              aria-pressed={filterState === 'healthy'}
              onClick={() => onFilterStateChange('healthy')}
              className={`flex h-9 items-center gap-1.5 rounded-lg border px-2.5 text-xs font-semibold transition-colors focus-visible:outline-hidden focus-visible:ring-1 focus-visible:ring-emerald-400 ${
                filterState === 'healthy'
                  ? 'border-emerald-500/50 bg-emerald-500/20 text-emerald-200 shadow-xs'
                  : 'border-slate-800 bg-slate-950/60 text-slate-400 hover:bg-slate-800/70 hover:text-emerald-300'
              }`}
            >
              <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400" />
              <span>正常</span>
              <span className="rounded-full bg-slate-800 px-1.5 py-0.5 font-mono text-[10px] text-slate-300 tabular-nums">
                {counts.healthy}
              </span>
            </button>
          </div>
        </div>

        {/* Right: View Mode Switcher & Global Accordion Toggle */}
        <div className="flex flex-wrap items-center justify-between gap-2 border-t border-slate-800/80 pt-2.5 sm:justify-end lg:border-t-0 lg:pt-0">
          {/* Host stats pill */}
          <div className="hidden items-center gap-2 font-mono text-xs text-slate-400 sm:flex">
            <span className="font-semibold text-slate-200 tabular-nums">{totalHosts}</span>
            <span className="text-slate-500">母鸡</span>
            <span className="text-slate-600">·</span>
            <span className="font-semibold text-slate-200 tabular-nums">{totalContainers}</span>
            <span className="text-slate-500">小鸡</span>
          </div>

          {/* Expand / Collapse All Toggle */}
          <button
            type="button"
            onClick={onToggleAllHosts}
            className="flex h-9 items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-950/80 px-3 text-xs font-medium text-slate-200 transition-colors hover:border-slate-600 hover:bg-slate-800 hover:text-sky-300 focus-visible:outline-hidden focus-visible:ring-1 focus-visible:ring-sky-400"
            title={allExpanded ? '折叠本页母鸡' : '展开本页母鸡'}
          >
            {allExpanded ? (
              <>
                <ChevronsDownUp className="h-3.5 w-3.5 text-slate-400" />
                <span>折叠本页</span>
              </>
            ) : (
              <>
                <ChevronsUpDown className="h-3.5 w-3.5 text-slate-400" />
                <span>展开本页</span>
              </>
            )}
          </button>

          {/* View Mode Segmented Control */}
          <div className="flex items-center rounded-lg border border-slate-700 bg-slate-950/90 p-0.5" role="group" aria-label="视图模式">
            <button
              type="button"
              aria-pressed={viewMode === 'grid'}
              onClick={() => onViewModeChange('grid')}
              className={`flex h-8 items-center gap-1 rounded-md px-2.5 text-xs font-medium transition-colors focus-visible:outline-hidden focus-visible:ring-1 focus-visible:ring-sky-400 ${
                viewMode === 'grid'
                  ? 'bg-sky-400 font-bold text-slate-950 shadow-xs'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
              title="高密网格 (Pro Grid · 紧凑卡片)"
            >
              <LayoutGrid className="h-3.5 w-3.5" />
              <span className="hidden md:inline">高密网格</span>
            </button>

            <button
              type="button"
              aria-pressed={viewMode === 'table'}
              onClick={() => onViewModeChange('table')}
              className={`flex h-8 items-center gap-1 rounded-md px-2.5 text-xs font-medium transition-colors focus-visible:outline-hidden focus-visible:ring-1 focus-visible:ring-sky-400 ${
                viewMode === 'table'
                  ? 'bg-sky-400 font-bold text-slate-950 shadow-xs'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
              title="数据表格 (Data Table · 超高密度列表)"
            >
              <TableIcon className="h-3.5 w-3.5" />
              <span className="hidden md:inline">数据表格</span>
            </button>

            <button
              type="button"
              aria-pressed={viewMode === 'detailed'}
              onClick={() => onViewModeChange('detailed')}
              className={`flex h-8 items-center gap-1 rounded-md px-2.5 text-xs font-medium transition-colors focus-visible:outline-hidden focus-visible:ring-1 focus-visible:ring-sky-400 ${
                viewMode === 'detailed'
                  ? 'bg-sky-400 font-bold text-slate-950 shadow-xs'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
              title="拓扑卡片 (Detailed · 宽体卡片)"
            >
              <Layers className="h-3.5 w-3.5" />
              <span className="hidden md:inline">详细卡片</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
