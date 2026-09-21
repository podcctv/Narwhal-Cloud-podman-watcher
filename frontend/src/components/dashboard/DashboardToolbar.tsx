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
  ChevronsUpDown,
  ChevronsDownUp,
  X,
} from 'lucide-react';

export type ViewMode = 'grid' | 'table' | 'detailed';
export type FilterState = 'all' | 'risk' | 'hy2' | 'imbalance' | 'healthy';

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
    hy2: number;
    imbalance: number;
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
      <div className="flex flex-col gap-2.5 rounded-xl border border-slate-800 bg-slate-900/90 p-2.5 shadow-sm backdrop-blur-md lg:flex-row lg:items-center lg:justify-between">
        {/* Left: Search & Filter Chips */}
        <div className="flex flex-1 flex-wrap items-center gap-2 min-w-0">
          {/* Quick Search Input */}
          <div className="relative min-w-[200px] flex-1 sm:max-w-xs">
            <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-slate-500" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => onSearchChange(e.target.value)}
              placeholder="搜索容器名 / 主机 / 运行时..."
              className="h-8 w-full rounded-lg border border-slate-750 bg-slate-950/80 pl-8 pr-7 text-xs text-slate-200 placeholder-slate-500 transition-colors focus:border-sky-500 focus:outline-none focus:ring-1 focus:ring-sky-500"
            />
            {searchQuery && (
              <button
                type="button"
                onClick={() => onSearchChange('')}
                className="absolute right-2 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-200 focus:outline-none"
                title="清空搜索"
              >
                <X className="h-3.5 w-3.5" />
              </button>
            )}
          </div>

          {/* Filter Chips */}
          <div className="flex flex-wrap items-center gap-1">
            {/* All */}
            <button
              type="button"
              onClick={() => onFilterStateChange('all')}
              className={`flex h-8 items-center gap-1.5 rounded-lg px-2.5 text-xs font-semibold transition-colors focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-sky-400 ${
                filterState === 'all'
                  ? 'bg-sky-500/20 text-sky-300 border border-sky-500/40 shadow-sm'
                  : 'bg-slate-950/50 text-slate-400 border border-slate-800 hover:text-slate-200 hover:bg-slate-800/60'
              }`}
            >
              <span>全部</span>
              <span className="rounded-full bg-slate-800 px-1.5 py-0.2 font-mono text-[10px] text-slate-300 tabular-nums">
                {counts.all}
              </span>
            </button>

            {/* Risk */}
            <button
              type="button"
              onClick={() => onFilterStateChange('risk')}
              className={`flex h-8 items-center gap-1.5 rounded-lg px-2.5 text-xs font-semibold transition-colors focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-rose-400 ${
                filterState === 'risk'
                  ? 'bg-rose-500/20 text-rose-300 border border-rose-500/50 shadow-sm shadow-rose-950/50'
                  : 'bg-slate-950/50 text-slate-400 border border-slate-800 hover:text-rose-300 hover:bg-slate-800/60'
              }`}
            >
              <AlertTriangle className={`h-3 w-3 ${counts.risk > 0 ? 'text-rose-400' : 'text-slate-500'}`} />
              <span>异常风险</span>
              <span
                className={`rounded-full px-1.5 py-0.2 font-mono text-[10px] tabular-nums ${
                  counts.risk > 0 ? 'bg-rose-900/60 text-rose-300 font-bold' : 'bg-slate-800 text-slate-400'
                }`}
              >
                {counts.risk}
              </span>
            </button>

            {/* HY2 */}
            <button
              type="button"
              onClick={() => onFilterStateChange('hy2')}
              className={`flex h-8 items-center gap-1.5 rounded-lg px-2.5 text-xs font-semibold transition-colors focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-violet-400 ${
                filterState === 'hy2'
                  ? 'bg-violet-500/20 text-violet-300 border border-violet-500/50 shadow-sm shadow-violet-950/50'
                  : 'bg-slate-950/50 text-slate-400 border border-slate-800 hover:text-violet-300 hover:bg-slate-800/60'
              }`}
            >
              <Radio className={`h-3 w-3 ${counts.hy2 > 0 ? 'text-violet-400' : 'text-slate-500'}`} />
              <span>HY2 代理</span>
              <span
                className={`rounded-full px-1.5 py-0.2 font-mono text-[10px] tabular-nums ${
                  counts.hy2 > 0 ? 'bg-violet-900/60 text-violet-300 font-bold' : 'bg-slate-800 text-slate-400'
                }`}
              >
                {counts.hy2}
              </span>
            </button>

            {/* Imbalance */}
            <button
              type="button"
              onClick={() => onFilterStateChange('imbalance')}
              className={`flex h-8 items-center gap-1.5 rounded-lg px-2.5 text-xs font-semibold transition-colors focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-amber-400 ${
                filterState === 'imbalance'
                  ? 'bg-amber-500/20 text-amber-300 border border-amber-500/50 shadow-sm shadow-amber-950/50'
                  : 'bg-slate-950/50 text-slate-400 border border-slate-800 hover:text-amber-300 hover:bg-slate-800/60'
              }`}
            >
              <ArrowUpDown className={`h-3 w-3 ${counts.imbalance > 0 ? 'text-amber-400' : 'text-slate-500'}`} />
              <span>流量失衡</span>
              <span
                className={`rounded-full px-1.5 py-0.2 font-mono text-[10px] tabular-nums ${
                  counts.imbalance > 0 ? 'bg-amber-900/60 text-amber-300 font-bold' : 'bg-slate-800 text-slate-400'
                }`}
              >
                {counts.imbalance}
              </span>
            </button>

            {/* Healthy */}
            <button
              type="button"
              onClick={() => onFilterStateChange('healthy')}
              className={`flex h-8 items-center gap-1.5 rounded-lg px-2.5 text-xs font-semibold transition-colors focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-emerald-400 ${
                filterState === 'healthy'
                  ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/50 shadow-sm'
                  : 'bg-slate-950/50 text-slate-400 border border-slate-800 hover:text-emerald-300 hover:bg-slate-800/60'
              }`}
            >
              <CheckCircle2 className="h-3 w-3 text-emerald-400" />
              <span>正常</span>
              <span className="rounded-full bg-slate-800 px-1.5 py-0.2 font-mono text-[10px] text-slate-300 tabular-nums">
                {counts.healthy}
              </span>
            </button>
          </div>
        </div>

        {/* Right: View Mode Switcher & Global Accordion Toggle */}
        <div className="flex items-center justify-between gap-2 sm:justify-end border-t border-slate-800/80 pt-2 lg:border-t-0 lg:pt-0">
          {/* Host stats pill */}
          <div className="hidden sm:flex items-center gap-2 text-xs text-slate-400 font-mono">
            <span className="tabular-nums font-semibold text-slate-200">{totalHosts}</span>
            <span className="text-slate-500">母鸡</span>
            <span className="text-slate-600">·</span>
            <span className="tabular-nums font-semibold text-slate-200">{totalContainers}</span>
            <span className="text-slate-500">小鸡</span>
          </div>

          {/* Expand / Collapse All Toggle */}
          <button
            type="button"
            onClick={onToggleAllHosts}
            className="flex h-8 items-center gap-1 rounded-lg border border-slate-750 bg-slate-950/70 px-2.5 text-xs font-medium text-slate-300 transition-colors hover:border-slate-600 hover:text-sky-300 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-sky-400"
            title={allExpanded ? '折叠所有母鸡' : '展开所有母鸡'}
          >
            {allExpanded ? (
              <>
                <ChevronsDownUp className="h-3.5 w-3.5 text-slate-400" />
                <span className="hidden xs:inline">全部折叠</span>
              </>
            ) : (
              <>
                <ChevronsUpDown className="h-3.5 w-3.5 text-slate-400" />
                <span className="hidden xs:inline">全部展开</span>
              </>
            )}
          </button>

          {/* View Mode Segmented Control */}
          <div className="flex items-center rounded-lg border border-slate-750 bg-slate-950/80 p-0.5" role="group" aria-label="视图模式">
            <button
              type="button"
              onClick={() => onViewModeChange('grid')}
              className={`flex h-7 items-center gap-1 rounded-md px-2 text-xs font-medium transition-colors focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-sky-400 ${
                viewMode === 'grid'
                  ? 'bg-sky-500 text-slate-950 font-bold shadow-sm'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
              title="高密网格 (Pro Grid · 紧凑卡片)"
            >
              <LayoutGrid className="h-3.5 w-3.5" />
              <span className="hidden md:inline">高密网格</span>
            </button>

            <button
              type="button"
              onClick={() => onViewModeChange('table')}
              className={`flex h-7 items-center gap-1 rounded-md px-2 text-xs font-medium transition-colors focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-sky-400 ${
                viewMode === 'table'
                  ? 'bg-sky-500 text-slate-950 font-bold shadow-sm'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
              title="数据表格 (Data Table · 超高密度列表)"
            >
              <TableIcon className="h-3.5 w-3.5" />
              <span className="hidden md:inline">数据表格</span>
            </button>

            <button
              type="button"
              onClick={() => onViewModeChange('detailed')}
              className={`flex h-7 items-center gap-1 rounded-md px-2 text-xs font-medium transition-colors focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-sky-400 ${
                viewMode === 'detailed'
                  ? 'bg-sky-500 text-slate-950 font-bold shadow-sm'
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
