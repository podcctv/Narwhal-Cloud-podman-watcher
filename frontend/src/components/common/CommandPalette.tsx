import React, { useState, useEffect, useRef } from 'react';
import { Search, Server, Box, AlertTriangle, BarChart3, X, ArrowRight } from 'lucide-react';
import { ContainerItem, ContainerIdentity } from '../../api/types';

interface CommandPaletteProps {
  isOpen: boolean;
  onClose: () => void;
  containers: ContainerItem[];
  onSelectContainer: (id: ContainerIdentity) => void;
  onSelectTab: (tab: 'dashboard' | 'alerts' | 'stats') => void;
}

export const CommandPalette: React.FC<CommandPaletteProps> = ({
  isOpen,
  onClose,
  containers,
  onSelectContainer,
  onSelectTab,
}) => {
  const [query, setQuery] = useState('');
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (isOpen) {
      setTimeout(() => inputRef.current?.focus(), 50);
      setQuery('');
    }
  }, [isOpen]);

  if (!isOpen) return null;

  const q = query.trim().toLowerCase();

  const filteredContainers = containers.filter((c) => {
    if (!q) return true;
    return (
      c.container_name.toLowerCase().includes(q) ||
      c.host_id.toLowerCase().includes(q) ||
      (c.project && c.project.toLowerCase().includes(q)) ||
      c.runtime.toLowerCase().includes(q)
    );
  }).slice(0, 15);


  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center pt-20 px-4 bg-slate-950/80 backdrop-blur-sm animate-in fade-in duration-150">
      <div className="relative w-full max-w-2xl rounded-2xl border border-slate-700 bg-slate-900 shadow-2xl overflow-hidden">
        {/* Search Header */}
        <div className="flex items-center gap-3 border-b border-slate-800 px-4 py-3">
          <Search className="h-5 w-5 text-slate-400 shrink-0" />
          <input
            ref={inputRef}
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="搜索节点、容器名称、运行时或快捷指令... (Esc 退出)"
            className="flex-1 bg-transparent text-sm text-slate-100 placeholder-slate-500 focus:outline-none"
          />
          <button
            type="button"
            onClick={onClose}
            className="rounded p-1 text-slate-400 hover:bg-slate-800 hover:text-slate-200"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        {/* Results List */}
        <div className="max-h-96 overflow-y-auto p-2">
          {/* Quick Navigation Commands */}
          {!q && (
            <div className="mb-2">
              <div className="px-3 py-1 text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
                快捷功能
              </div>
              <button
                type="button"
                onClick={() => {
                  onSelectTab('dashboard');
                  onClose();
                }}
                className="flex w-full items-center justify-between rounded-lg px-3 py-2 text-sm text-slate-200 hover:bg-slate-800/80 transition-colors"
              >
                <div className="flex items-center gap-2.5">
                  <Server className="h-4 w-4 text-sky-400" />
                  <span>总览看板 (Overview)</span>
                </div>
                <ArrowRight className="h-3.5 w-3.5 text-slate-500" />
              </button>
              <button
                type="button"
                onClick={() => {
                  onSelectTab('alerts');
                  onClose();
                }}
                className="flex w-full items-center justify-between rounded-lg px-3 py-2 text-sm text-slate-200 hover:bg-slate-800/80 transition-colors"
              >
                <div className="flex items-center gap-2.5">
                  <AlertTriangle className="h-4 w-4 text-amber-400" />
                  <span>安全告警历史 (Security Alerts)</span>
                </div>
                <ArrowRight className="h-3.5 w-3.5 text-slate-500" />
              </button>
              <button
                type="button"
                onClick={() => {
                  onSelectTab('stats');
                  onClose();
                }}
                className="flex w-full items-center justify-between rounded-lg px-3 py-2 text-sm text-slate-200 hover:bg-slate-800/80 transition-colors"
              >
                <div className="flex items-center gap-2.5">
                  <BarChart3 className="h-4 w-4 text-emerald-400" />
                  <span>统计分析与排行榜 (Telemetry & Stats)</span>
                </div>
                <ArrowRight className="h-3.5 w-3.5 text-slate-500" />
              </button>
            </div>
          )}

          {/* Containers Section */}
          <div className="mb-2">
            <div className="px-3 py-1 text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
              容器 ({filteredContainers.length})
            </div>
            {filteredContainers.length === 0 ? (
              <div className="px-3 py-4 text-center text-xs text-slate-500">
                未找到匹配的容器
              </div>
            ) : (
              filteredContainers.map((c) => (
                <button
                  key={`${c.host_id}-${c.runtime}-${c.project || ''}-${c.container_name}`}
                  type="button"
                  onClick={() => {
                    onSelectContainer({
                      host_id: c.host_id,
                      runtime: c.runtime,
                      project: c.project,
                      container_name: c.container_name,
                    });
                    onClose();
                  }}
                  className="flex w-full items-center justify-between rounded-lg px-3 py-2 text-sm text-slate-200 hover:bg-slate-800/80 transition-colors group"
                >
                  <div className="flex items-center gap-2.5 min-w-0">
                    <Box className="h-4 w-4 text-sky-400 shrink-0" />
                    <span className="font-medium truncate">{c.container_name}</span>
                    <span className="text-xs text-slate-500 truncate">
                      {c.host_id} · {c.project ? `${c.runtime}/${c.project}` : c.runtime}
                    </span>
                  </div>
                  <div className="flex items-center gap-2 text-xs text-slate-400 shrink-0">
                    <span className="font-mono tabular-nums">
                      CPU {(c.cpu_percent || 0).toFixed(1)}%
                    </span>
                    <ArrowRight className="h-3.5 w-3.5 text-slate-600 group-hover:text-slate-300 transition-colors" />
                  </div>
                </button>
              ))
            )}
          </div>
        </div>

        {/* Footer */}
        <div className="flex items-center justify-between border-t border-slate-800 bg-slate-950/60 px-4 py-2 text-[11px] text-slate-500">
          <span>
            按 <kbd className="rounded bg-slate-800 px-1 py-0.5 text-slate-400">↑</kbd>{' '}
            <kbd className="rounded bg-slate-800 px-1 py-0.5 text-slate-400">↓</kbd> 导航，
            <kbd className="rounded bg-slate-800 px-1 py-0.5 text-slate-400">Enter</kbd> 查看
          </span>
          <span>
            快捷键：<kbd className="rounded bg-slate-800 px-1 py-0.5 text-slate-400">Ctrl+K</kbd>
          </span>
        </div>
      </div>
    </div>
  );
};
