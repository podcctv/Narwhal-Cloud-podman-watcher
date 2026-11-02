import React, { useState, useEffect, useRef } from 'react';
import { Search, Server, Box, AlertTriangle, BarChart3, Settings, X, ArrowRight, ShieldCheck, Users, BriefcaseBusiness, Wrench } from 'lucide-react';
import { ContainerItem, ContainerIdentity } from '../../api/types';

interface CommandPaletteProps {
  isOpen: boolean;
  onClose: () => void;
  containers: ContainerItem[];
  onSelectContainer: (id: ContainerIdentity) => void;
  onSelectTab: (tab: 'dashboard' | 'alerts' | 'investigation' | 'stats' | 'settings' | 'notifications' | 'operations' | 'commerce' | 'firewall') => void;
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

  useEffect(() => {
    setActiveIndex(0);
  }, [query]);

  if (!isOpen) return null;

  const q = query.trim().toLowerCase();

  const filteredContainers = containers.filter((c) => {
    if (!q) return true;
    return (
      c.container_name.toLowerCase().includes(q) ||
      c.host_id.toLowerCase().includes(q) ||
      (c.user_email || '').toLowerCase().includes(q) ||
      (c.user_note || '').toLowerCase().includes(q) ||
      (c.project && c.project.toLowerCase().includes(q)) ||
      c.runtime.toLowerCase().includes(q)
    );
  }).slice(0, 15);

  const quickActions = !q ? [
    { id: 'dashboard', label: '总览看板', hint: 'Overview', icon: Server, color: 'text-sky-400', run: () => onSelectTab('dashboard') },
    { id: 'alerts', label: '安全告警历史', hint: 'Security Alerts', icon: AlertTriangle, color: 'text-amber-400', run: () => onSelectTab('alerts') },
    { id: 'investigation', label: '用户与容器排查', hint: 'User Investigation', icon: Users, color: 'text-sky-300', run: () => onSelectTab('investigation') },
    { id: 'stats', label: '统计分析与排行榜', hint: 'Telemetry & Stats', icon: BarChart3, color: 'text-emerald-400', run: () => onSelectTab('stats') },
    { id: 'commerce', label: '经营分析与账本', hint: 'Commerce & Ledger', icon: BriefcaseBusiness, color: 'text-violet-300', run: () => onSelectTab('commerce') },
    { id: 'operations', label: '运维中心', hint: 'Operations', icon: Wrench, color: 'text-sky-300', run: () => onSelectTab('operations') },
    { id: 'firewall', label: '母机防火墙策略', hint: 'Host Firewall', icon: ShieldCheck, color: 'text-rose-300', run: () => onSelectTab('firewall') },
    { id: 'settings', label: '系统设置与推送配置', hint: 'Settings & Push', icon: Settings, color: 'text-slate-300', run: () => onSelectTab('settings') },
  ] : [];
  const resultCount = quickActions.length + filteredContainers.length;

  const activate = (index: number) => {
    if (index < quickActions.length) {
      quickActions[index].run();
      onClose();
      return;
    }
    const container = filteredContainers[index - quickActions.length];
    if (!container) return;
    onSelectContainer({ host_id: container.host_id, runtime: container.runtime, project: container.project, container_name: container.container_name, container_id: container.container_id });
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
    <div
      role="dialog"
      aria-modal="true"
      aria-label="全局检索"
      className="fixed inset-0 z-50 flex items-start justify-center bg-slate-950/80 px-3 pt-12 backdrop-blur-xs sm:px-4 sm:pt-20 animate-in fade-in duration-150"
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div className="relative w-full max-w-2xl overflow-hidden rounded-2xl border border-slate-700/90 bg-slate-900 shadow-2xl">
        {/* Search Header */}
        <div className="flex items-center gap-3 border-b border-slate-800 bg-slate-950/50 px-4 py-3.5">
          <Search className="h-5 w-5 shrink-0 text-sky-400" />
          <input
            ref={inputRef}
            type="text"
            aria-label="搜索节点、容器或用户邮箱"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={onInputKeyDown}
            placeholder="搜索节点、容器名称、用户邮箱、运行时或快捷指令... (Esc 退出)"
            className="min-w-0 flex-1 bg-transparent text-sm text-slate-100 placeholder-slate-500 focus:outline-hidden"
          />
          <button
            type="button"
            onClick={onClose}
            aria-label="关闭全局检索"
            className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg border border-slate-800 bg-slate-900 text-slate-400 transition-colors hover:border-slate-700 hover:bg-slate-800 hover:text-slate-200"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        {/* Results List */}
        <div className="max-h-[68dvh] overflow-y-auto p-2 sm:max-h-96">
          {/* Quick Navigation Commands */}
          {!q && (
            <div className="mb-2">
              <div className="px-3 py-1.5 text-[11px] font-semibold tracking-wider text-slate-400 uppercase">
                快捷功能导航
              </div>
              <div className="grid grid-cols-1 gap-0.5 sm:grid-cols-2">
                {quickActions.map((action, index) => {
                  const Icon = action.icon;
                  return (
                    <button
                      key={action.id}
                      type="button"
                      onMouseEnter={() => setActiveIndex(index)}
                      onClick={() => activate(index)}
                      className={`flex min-h-10 w-full items-center justify-between rounded-xl px-3 py-2 text-left text-sm text-slate-200 transition-colors ${
                        activeIndex === index
                          ? 'bg-sky-500/15 text-sky-100 ring-1 ring-sky-500/40'
                          : 'hover:bg-slate-800/80'
                      }`}
                    >
                      <div className="flex min-w-0 items-center gap-2.5">
                        <Icon className={`h-4 w-4 shrink-0 ${action.color}`} />
                        <span className="truncate font-medium">
                          {action.label}{' '}
                          <span className="text-xs font-normal text-slate-500">({action.hint})</span>
                        </span>
                      </div>
                      <ArrowRight className="h-3.5 w-3.5 shrink-0 text-slate-500" />
                    </button>
                  );
                })}
              </div>
            </div>
          )}

          {/* Containers Section */}
          <div className="mb-1">
            <div className="px-3 py-1.5 text-[11px] font-semibold tracking-wider text-slate-400 uppercase">
              在线容器 ({filteredContainers.length})
            </div>
            {filteredContainers.length === 0 ? (
              <div className="px-3 py-6 text-center text-xs text-slate-400">
                未找到匹配的容器
              </div>
            ) : (
              filteredContainers.map((c, index) => (
                <button
                  key={`${c.host_id}-${c.runtime}-${c.project || ''}-${c.container_name}`}
                  type="button"
                  onMouseEnter={() => setActiveIndex(quickActions.length + index)}
                  onClick={() => activate(quickActions.length + index)}
                  className={`group flex min-h-10 w-full items-center justify-between gap-2 rounded-xl px-3 py-2 text-left text-sm text-slate-200 transition-colors ${
                    activeIndex === quickActions.length + index
                      ? 'bg-sky-500/15 text-sky-100 ring-1 ring-sky-500/40'
                      : 'hover:bg-slate-800/80'
                  }`}
                >
                  <div className="flex min-w-0 items-center gap-2.5">
                    <Box className="h-4 w-4 shrink-0 text-sky-400" />
                    <span className="truncate font-medium">{c.container_name}</span>
                    <span className="truncate text-xs text-slate-400">
                      {c.user_email ? `${c.user_email} · ` : ''}
                      {c.user_note ? `${c.user_note} · ` : ''}
                      {c.host_id} · {c.project ? `${c.runtime}/${c.project}` : c.runtime}
                    </span>
                  </div>
                  <div className="flex shrink-0 items-center gap-2 text-xs text-slate-400">
                    <span className="font-mono tabular-nums">
                      CPU {(c.cpu_percent || 0).toFixed(1)}%
                    </span>
                    <ArrowRight className="h-3.5 w-3.5 text-slate-500 transition-colors group-hover:text-slate-200" />
                  </div>
                </button>
              ))
            )}
          </div>
        </div>

        {/* Footer */}
        <div className="flex flex-wrap items-center justify-between gap-2 border-t border-slate-800 bg-slate-950/70 px-4 py-2.5 text-[11px] text-slate-400">
          <span>
            按 <kbd className="rounded border border-slate-700 bg-slate-800 px-1.5 py-0.5 font-mono text-[10px] text-slate-300">↑</kbd>{' '}
            <kbd className="rounded border border-slate-700 bg-slate-800 px-1.5 py-0.5 font-mono text-[10px] text-slate-300">↓</kbd> 导航，
            <kbd className="rounded border border-slate-700 bg-slate-800 px-1.5 py-0.5 font-mono text-[10px] text-slate-300">Enter</kbd> 查看
          </span>
          <span>
            快捷键：<kbd className="rounded border border-slate-700 bg-slate-800 px-1.5 py-0.5 font-mono text-[10px] text-slate-300">Ctrl+K</kbd>
          </span>
        </div>
      </div>
    </div>
  );
};
