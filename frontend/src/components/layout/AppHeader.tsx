import React from 'react';
import { ShieldAlert, BarChart3, LayoutDashboard, Search, Bell } from 'lucide-react';
import { CountdownTimer } from '../common/CountdownTimer';

interface AppHeaderProps {
  activeTab: 'dashboard' | 'alerts' | 'stats' | 'notifications';
  onSelectTab: (tab: 'dashboard' | 'alerts' | 'stats' | 'notifications') => void;
  serverVersion: string;
  activeAlertCount: number;
  countdown: number;
  isPaused: boolean;
  onTogglePause: () => void;
  onRefreshNow: () => void;
  isRefreshing: boolean;
  lastRefreshTime?: string;
  onOpenSearch: () => void;
}

export const AppHeader: React.FC<AppHeaderProps> = ({
  activeTab,
  onSelectTab,
  serverVersion,
  activeAlertCount,
  countdown,
  isPaused,
  onTogglePause,
  onRefreshNow,
  isRefreshing,
  lastRefreshTime,
  onOpenSearch,
}) => {
  return (
    <header className="sticky top-0 z-30 mb-6 border-b border-slate-800/80 bg-slate-950/80 backdrop-blur-xl">
      <div className="mx-auto flex max-w-7xl flex-col gap-3 px-4 py-3 sm:px-6 xl:flex-row xl:items-center xl:justify-between">
        {/* Brand & Title */}
        <div className="flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-xl border border-sky-500/40 bg-sky-950/60 shadow-inner">
            <span className="font-mono text-base font-extrabold text-sky-400">NW</span>
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-lg font-bold tracking-tight text-slate-100">
                Narwhal Monitor
              </h1>
              <span className="rounded-full border border-slate-700 bg-slate-800/80 px-2 py-0.5 font-mono text-[11px] text-slate-300">
                v{serverVersion || 'dev'}
              </span>
            </div>
            <p className="text-xs text-slate-400">
              云原生容器与主机安全监控中心
            </p>
          </div>
        </div>

        {/* Navigation Tabs */}
        <nav aria-label="主导航" className="grid w-full grid-cols-2 gap-1 rounded-xl border border-slate-800 bg-slate-900/80 p-1 sm:flex sm:w-auto sm:items-center">
          <button
            type="button"
            onClick={() => onSelectTab('dashboard')}
            aria-current={activeTab === 'dashboard' ? 'page' : undefined}
            className={`min-h-11 justify-center flex items-center gap-2 rounded-lg px-3 py-1.5 text-xs font-semibold transition-colors ${
              activeTab === 'dashboard'
                ? 'bg-sky-500 text-slate-950 shadow-sm'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <LayoutDashboard className="h-3.5 w-3.5" />
            <span>总览看板</span>
          </button>
          <button type="button" onClick={() => onSelectTab('notifications')} aria-current={activeTab === 'notifications' ? 'page' : undefined} className={`min-h-11 justify-center flex items-center gap-2 rounded-lg px-3 py-1.5 text-xs font-semibold transition-colors ${activeTab === 'notifications' ? 'bg-sky-500 text-slate-950 shadow-sm' : 'text-slate-400 hover:text-slate-200'}`}>
            <Bell className="h-3.5 w-3.5" /><span>推送设置</span>
          </button>

          <button
            type="button"
            onClick={() => onSelectTab('alerts')}
            aria-current={activeTab === 'alerts' ? 'page' : undefined}
            className={`relative min-h-11 justify-center flex items-center gap-2 rounded-lg px-3 py-1.5 text-xs font-semibold transition-colors ${
              activeTab === 'alerts'
                ? 'bg-sky-500 text-slate-950 shadow-sm'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <ShieldAlert className="h-3.5 w-3.5" />
            <span>安全告警</span>
            {activeAlertCount > 0 && (
              <span
                className={`ml-0.5 rounded-full px-1.5 py-0.2 text-[10px] font-bold ${
                  activeTab === 'alerts'
                    ? 'bg-rose-600 text-white'
                    : 'bg-rose-500/20 text-rose-400 border border-rose-500/40'
                }`}
              >
                {activeAlertCount}
              </span>
            )}
          </button>

          <button
            type="button"
            onClick={() => onSelectTab('stats')}
            aria-current={activeTab === 'stats' ? 'page' : undefined}
            className={`min-h-11 justify-center flex items-center gap-2 rounded-lg px-3 py-1.5 text-xs font-semibold transition-colors ${
              activeTab === 'stats'
                ? 'bg-sky-500 text-slate-950 shadow-sm'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <BarChart3 className="h-3.5 w-3.5" />
            <span>数据统计</span>
          </button>
        </nav>

        {/* Search & Timer Tools */}
        <div className="flex items-center justify-between gap-2.5 xl:justify-end">
          {/* Global Search Button */}
          <button
            type="button"
            onClick={onOpenSearch}
            className="min-h-11 flex flex-1 items-center gap-2 rounded-lg border border-slate-800 bg-slate-900/90 px-3 py-1.5 text-xs text-slate-400 transition-colors hover:border-slate-700 hover:text-slate-200 focus:outline-none focus:ring-2 focus:ring-sky-400 xl:flex-none"
          >
            <Search className="h-3.5 w-3.5" />
            <span className="hidden md:inline">全局检索...</span>
            <kbd className="hidden md:inline rounded border border-slate-700 bg-slate-800 px-1 py-0.2 font-mono text-[10px] text-slate-400">
              Ctrl+K
            </kbd>
          </button>

          {/* Real-time Countdown Timer */}
          <CountdownTimer
            countdown={countdown}
            totalSeconds={10}
            isPaused={isPaused}
            onTogglePause={onTogglePause}
            onRefreshNow={onRefreshNow}
            isRefreshing={isRefreshing}
            lastRefreshTime={lastRefreshTime}
          />
        </div>
      </div>
    </header>
  );
};
