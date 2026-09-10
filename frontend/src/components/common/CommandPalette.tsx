import React, { useState, useEffect, useRef } from 'react';
import { Search, Server, Box, AlertTriangle, BarChart3, Bell, X, ArrowRight } from 'lucide-react';
import { ContainerItem, ContainerIdentity } from '../../api/types';

interface CommandPaletteProps {
  isOpen: boolean;
  onClose: () => void;
  containers: ContainerItem[];
  onSelectContainer: (id: ContainerIdentity) => void;
  onSelectTab: (tab: 'dashboard' | 'alerts' | 'stats' | 'notifications') => void;
}

export const CommandPalette: React.FC<CommandPaletteProps> = ({
  isOpen,
  onClose,
  containers,
  onSelectContainer,
  onSelectTab,
}) => {
  const [query, setQuery] = useState('');
  const [activeIndex, setActiveIndex] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (isOpen) {
      setTimeout(() => inputRef.current?.focus(), 50);
      setQuery('');
      setActiveIndex(0);
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

  const quickActions = !q ? [
    { id: 'dashboard', label: '总览看板', hint: 'Overview', icon: Server, color: 'text-sky-400', run: () => onSelectTab('dashboard') },
    { id: 'alerts', label: '安全告警历史', hint: 'Security Alerts', icon: AlertTriangle, color: 'text-amber-400', run: () => onSelectTab('alerts') },
    { id: 'stats', label: '统计分析与排行榜', hint: 'Telemetry & Stats', icon: BarChart3, color: 'text-emerald-400', run: () => onSelectTab('stats') },
    { id: 'notifications', label: '推送设置', hint: 'Notifications', icon: Bell, color: 'text-sky-300', run: () => onSelectTab('notifications') },
  ] : [];
  const resultCount = quickActions.length + filteredContainers.length;

  useEffect(() => {
    setActiveIndex(0);
  }, [query]);

  const activate = (index: number) => {
    if (index < quickActions.length) {
      quickActions[index].run();
      onClose();
      return;
    }
    const container = filteredContainers[index - quickActions.length];
    if (!container) return;
    onSelectContainer({ host_id: container.host_id, runtime: container.runtime, project: container.project, container_name: container.container_name });
    onClose();
  };

  const onInputKeyDown = (event: React.KeyboardEvent<HTMLInputElement>) => {
    if (!resultCount) return;
    if (event.key === 'ArrowDown') {
      event.preventDefault();
      setActiveIndex((value) => (value + 1) % resultCount);
    } else if (event.key === 'ArrowUp') {
      event.preventDefault();
      setActiveIndex((value) => (value - 1 + resultCount) % resultCount);
    } else if (event.key === 'Enter') {
      event.preventDefault();
      activate(activeIndex);
    }
  };


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
            onKeyDown={onInputKeyDown}
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
              {quickActions.map((action, index) => {
                const Icon = action.icon;
                return <button key={action.id} type="button" onMouseEnter={() => setActiveIndex(index)} onClick={() => activate(index)} className={`flex w-full items-center justify-between rounded-lg px-3 py-2 text-sm text-slate-200 transition-colors ${activeIndex === index ? 'bg-slate-800/90' : 'hover:bg-slate-800/80'}`}>
                  <div className="flex items-center gap-2.5"><Icon className={`h-4 w-4 ${action.color}`} /><span>{action.label} <span className="text-slate-500">({action.hint})</span></span></div><ArrowRight className="h-3.5 w-3.5 text-slate-500" />
                </button>;
              })}
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
              filteredContainers.map((c, index) => (
                <button
                  key={`${c.host_id}-${c.runtime}-${c.project || ''}-${c.container_name}`}
                  type="button"
                  onMouseEnter={() => setActiveIndex(quickActions.length + index)}
                  onClick={() => activate(quickActions.length + index)}
                  className={`group flex w-full items-center justify-between rounded-lg px-3 py-2 text-sm text-slate-200 transition-colors ${activeIndex === quickActions.length + index ? 'bg-slate-800/90' : 'hover:bg-slate-800/80'}`}
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
