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
      {/* Primary Light-Ice Toolbar Bar */}
      <div className="rn2-card flex flex-col gap-3 p-3 lg:flex-row lg:items-center lg:justify-between">
        {/* Left: Search & Filter Chips */}
        <div className="flex min-w-0 flex-1 flex-wrap items-center gap-2">
          {/* Quick Search Input */}
          <div className="relative min-w-[210px] flex-1 sm:max-w-xs">
            <Search className="pointer-events-none absolute top-1/2 left-3 h-3.5 w-3.5 -translate-y-1/2 text-[#087bff]" aria-hidden="true" />
            <input
              type="search"
              name="container-search"
              aria-label="搜索容器、主机、运行时、邮箱或备注"
              value={searchQuery}
              onChange={(e) => onSearchChange(e.target.value)}
              placeholder="搜索容器名 / 主机 / 运行时…"
              className="rn2-input-sm w-full bg-[#f4f8fd] pl-8 pr-7 text-xs text-[#0b1636] placeholder:text-[#697b9c] focus:bg-white"
            />
            {searchQuery && (
              <button
                type="button"
                onClick={() => onSearchChange('')}
                aria-label="清空搜索"
                className="absolute right-2 top-1/2 -translate-y-1/2 rounded p-0.5 text-[#697b9c] hover:text-[#0b1636] focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-[#087bff]"
                title="清空搜索"
              >
                <X className="h-3.5 w-3.5" aria-hidden="true" />
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
              className={`flex h-9 items-center gap-1.5 rounded-lg border px-2.5 text-xs font-semibold transition-colors ${
                filterState === 'all'
                  ? 'border-[#087bff] bg-[#e8f3ff] text-[#0657b8] shadow-xs'
                  : 'border-[#d2dfec] bg-[#f4f8fd] text-[#31485e] hover:border-[#087bff]/60 hover:bg-[#e8f3ff]/60 hover:text-[#08458c]'
              }`}
            >
              <span>全部</span>
              <span className="rounded-full border border-[#cedae7] bg-white px-1.5 py-0.5 font-mono text-[10px] leading-none text-[#31485e] tabular-nums">
                {counts.all}
              </span>
            </button>

            {/* Resource signals and automatic protections */}
            <button
              type="button"
              aria-pressed={filterState === 'protection'}
              onClick={() => onFilterStateChange('protection')}
              className={`flex h-9 items-center gap-1.5 rounded-lg border px-2.5 text-xs font-semibold transition-colors ${
                filterState === 'protection'
                  ? 'border-[#087bff] bg-[#e8f3ff] text-[#0657b8] shadow-xs'
                  : 'border-[#d2dfec] bg-[#f4f8fd] text-[#31485e] hover:border-[#087bff]/60 hover:bg-[#e8f3ff]/60 hover:text-[#0657b8]'
              }`}
            >
              <ShieldCheck className="h-3.5 w-3.5 text-[#087bff]" aria-hidden="true" />
              <span>资源与保护</span>
              <span className="rounded-full border border-[#cedae7] bg-white px-1.5 py-0.5 font-mono text-[10px] leading-none text-[#31485e] tabular-nums">
                {counts.protection}
              </span>
            </button>

            {/* VMess / Trojan protocol guard */}
            <button
              type="button"
              aria-pressed={filterState === 'protocol'}
              onClick={() => onFilterStateChange('protocol')}
              className={`flex h-9 items-center gap-1.5 rounded-lg border px-2.5 text-xs font-semibold transition-colors ${
                filterState === 'protocol'
                  ? 'border-violet-500 bg-violet-50 text-violet-800 shadow-xs'
                  : 'border-[#d2dfec] bg-[#f4f8fd] text-[#31485e] hover:border-violet-400 hover:bg-violet-50/70 hover:text-violet-800'
              }`}
            >
              <ShieldCheck className="h-3.5 w-3.5 text-violet-600" aria-hidden="true" />
              <span>协议阻断</span>
              <span className="rounded-full border border-[#cedae7] bg-white px-1.5 py-0.5 font-mono text-[10px] leading-none text-[#31485e] tabular-nums">
                {counts.protocol}
              </span>
            </button>

            {/* Risk */}
            <button
              type="button"
              aria-pressed={filterState === 'risk'}
              onClick={() => onFilterStateChange('risk')}
              className={`flex h-9 items-center gap-1.5 rounded-lg border px-2.5 text-xs font-semibold transition-colors ${
                filterState === 'risk'
                  ? 'border-[#dc2626] bg-[#ffeef1] text-[#b41835] shadow-xs'
                  : 'border-[#d2dfec] bg-[#f4f8fd] text-[#31485e] hover:border-[#f43f5e] hover:bg-[#ffeef1]/70 hover:text-[#b41835]'
              }`}
            >
              <AlertTriangle className={`h-3.5 w-3.5 ${counts.risk > 0 ? 'text-[#dc2626]' : 'text-[#697b9c]'}`} aria-hidden="true" />
              <span>异常风险</span>
              <span
                className={`rounded-full px-1.5 py-0.5 font-mono text-[10px] leading-none tabular-nums ${
                  counts.risk > 0
                    ? 'border border-[#f9b8c4] bg-[#ffeef1] font-bold text-[#b41835]'
                    : 'border border-[#cedae7] bg-white text-[#4a607a]'
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
              className={`flex h-9 items-center gap-1.5 rounded-lg border px-2.5 text-xs font-semibold transition-colors ${
                filterState === 'stale'
                  ? 'border-[#d97706] bg-[#fef6e4] text-[#9a5b00] shadow-xs'
                  : 'border-[#d2dfec] bg-[#f4f8fd] text-[#31485e] hover:border-[#f59e0b] hover:bg-[#fef6e4]/70 hover:text-[#9a5b00]'
              }`}
            >
              <Clock3 className="h-3.5 w-3.5 text-[#b45309]" aria-hidden="true" />
              <span>数据过期</span>
              <span className="rounded-full border border-[#cedae7] bg-white px-1.5 py-0.5 font-mono text-[10px] leading-none text-[#31485e] tabular-nums">
                {counts.stale}
              </span>
            </button>

            {/* HY2 */}
            <button
              type="button"
              aria-pressed={filterState === 'hy2'}
              onClick={() => onFilterStateChange('hy2')}
              className={`flex h-9 items-center gap-1.5 rounded-lg border px-2.5 text-xs font-semibold transition-colors ${
                filterState === 'hy2'
                  ? 'border-violet-500 bg-violet-50 text-violet-800 shadow-xs'
                  : 'border-[#d2dfec] bg-[#f4f8fd] text-[#31485e] hover:border-violet-400 hover:bg-violet-50/70 hover:text-violet-800'
              }`}
            >
              <Radio className={`h-3.5 w-3.5 ${counts.hy2 > 0 ? 'text-violet-600' : 'text-[#697b9c]'}`} aria-hidden="true" />
              <span>HY2 代理</span>
              <span
                className={`rounded-full px-1.5 py-0.5 font-mono text-[10px] leading-none tabular-nums ${
                  counts.hy2 > 0
                    ? 'border border-violet-300 bg-violet-100 font-bold text-violet-800'
                    : 'border border-[#cedae7] bg-white text-[#4a607a]'
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
              className={`flex h-9 items-center gap-1.5 rounded-lg border px-2.5 text-xs font-semibold transition-colors ${
                filterState === 'imbalance'
                  ? 'border-[#ff6b00] bg-[#fff3e8] text-[#b84800] shadow-xs'
                  : 'border-[#d2dfec] bg-[#f4f8fd] text-[#31485e] hover:border-[#ff6b00] hover:bg-[#fff3e8]/70 hover:text-[#b84800]'
              }`}
            >
              <ArrowUpDown className={`h-3.5 w-3.5 ${counts.imbalance > 0 ? 'text-[#ff6b00]' : 'text-[#697b9c]'}`} aria-hidden="true" />
              <span>流量失衡</span>
              <span
                className={`rounded-full px-1.5 py-0.5 font-mono text-[10px] leading-none tabular-nums ${
                  counts.imbalance > 0
                    ? 'border border-[#ffc899] bg-[#fff3e8] font-bold text-[#b84800]'
                    : 'border border-[#cedae7] bg-white text-[#4a607a]'
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
              className={`flex h-9 items-center gap-1.5 rounded-lg border px-2.5 text-xs font-semibold transition-colors ${
                filterState === 'healthy'
                  ? 'border-[#147468] bg-[#e6f7f4] text-[#147468] shadow-xs'
                  : 'border-[#d2dfec] bg-[#f4f8fd] text-[#31485e] hover:border-[#147468] hover:bg-[#e6f7f4]/70 hover:text-[#147468]'
              }`}
            >
              <CheckCircle2 className="h-3.5 w-3.5 text-[#147468]" aria-hidden="true" />
              <span>正常</span>
              <span className="rounded-full border border-[#cedae7] bg-white px-1.5 py-0.5 font-mono text-[10px] leading-none text-[#31485e] tabular-nums">
                {counts.healthy}
              </span>
            </button>
          </div>
        </div>

        {/* Right: View Mode Switcher & Global Accordion Toggle */}
        <div className="flex flex-wrap items-center justify-between gap-2 border-t border-[#dce5ef] pt-2.5 sm:justify-end lg:border-t-0 lg:pt-0">
          {/* Host stats pill */}
          <div className="hidden items-center gap-2 font-mono text-xs text-[#697b9c] sm:flex">
            <span className="font-bold text-[#0b1636] tabular-nums">{totalHosts}</span>
            <span>母鸡</span>
            <span>·</span>
            <span className="font-bold text-[#0b1636] tabular-nums">{totalContainers}</span>
            <span>小鸡</span>
          </div>

          {/* Expand / Collapse All Toggle */}
          <button
            type="button"
            onClick={onToggleAllHosts}
            className="flex h-9 items-center gap-1.5 rounded-lg border border-[#cedae7] bg-white px-3 text-xs font-semibold text-[#0b1636] transition-colors hover:border-[#087bff] hover:bg-[#f4f8fd] hover:text-[#08458c]"
            title={allExpanded ? '折叠本页母鸡' : '展开本页母鸡'}
          >
            {allExpanded ? (
              <>
                <ChevronsDownUp className="h-3.5 w-3.5 text-[#087bff]" aria-hidden="true" />
                <span>折叠本页</span>
              </>
            ) : (
              <>
                <ChevronsUpDown className="h-3.5 w-3.5 text-[#087bff]" aria-hidden="true" />
                <span>展开本页</span>
              </>
            )}
          </button>

          {/* View Mode Segmented Control */}
          <div className="flex items-center rounded-lg border border-[#cedae7] bg-[#f4f8fd] p-0.5" role="group" aria-label="视图模式">
            <button
              type="button"
              aria-pressed={viewMode === 'grid'}
              onClick={() => onViewModeChange('grid')}
              className={`flex h-8 items-center gap-1 rounded-md px-2.5 text-xs font-medium transition-colors ${
                viewMode === 'grid'
                  ? 'bg-[#087bff] font-bold text-white shadow-xs'
                  : 'text-[#4a607a] hover:text-[#0b1636]'
              }`}
              title="高密网格 (Pro Grid · 紧凑卡片)"
            >
              <LayoutGrid className="h-3.5 w-3.5" aria-hidden="true" />
              <span className="hidden md:inline">高密网格</span>
            </button>

            <button
              type="button"
              aria-pressed={viewMode === 'table'}
              onClick={() => onViewModeChange('table')}
              className={`flex h-8 items-center gap-1 rounded-md px-2.5 text-xs font-medium transition-colors ${
                viewMode === 'table'
                  ? 'bg-[#087bff] font-bold text-white shadow-xs'
                  : 'text-[#4a607a] hover:text-[#0b1636]'
              }`}
              title="数据表格 (Data Table · 超高密度列表)"
            >
              <TableIcon className="h-3.5 w-3.5" aria-hidden="true" />
              <span className="hidden md:inline">数据表格</span>
            </button>

            <button
              type="button"
              aria-pressed={viewMode === 'detailed'}
              onClick={() => onViewModeChange('detailed')}
              className={`flex h-8 items-center gap-1 rounded-md px-2.5 text-xs font-medium transition-colors ${
                viewMode === 'detailed'
                  ? 'bg-[#087bff] font-bold text-white shadow-xs'
                  : 'text-[#4a607a] hover:text-[#0b1636]'
              }`}
              title="拓扑卡片 (Detailed · 宽体卡片)"
            >
              <Layers className="h-3.5 w-3.5" aria-hidden="true" />
              <span className="hidden md:inline">详细卡片</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
