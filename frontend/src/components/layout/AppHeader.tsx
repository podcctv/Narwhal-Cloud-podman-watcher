import React from 'react';
import { ShieldAlert, BarChart3, LayoutDashboard, Search, Settings, Users, LogOut } from 'lucide-react';
import { CountdownTimer } from '../common/CountdownTimer';

interface AppHeaderProps {
  activeTab: 'dashboard' | 'alerts' | 'investigation' | 'stats' | 'settings' | 'notifications' | 'operations';
  onSelectTab: (tab: 'dashboard' | 'alerts' | 'investigation' | 'stats' | 'settings' | 'notifications' | 'operations') => void;
  serverVersion: string;
  activeAlertCount: number;
  countdown: number;
  totalSeconds?: number;
  isPaused: boolean;
  onTogglePause: () => void;
  onRefreshNow: () => void;
  isRefreshing: boolean;
  lastRefreshTime?: string;
  onOpenSearch: () => void;
  onLogout: () => void;
  isLoggingOut: boolean;
}

export const AppHeader: React.FC<AppHeaderProps> = ({
  activeTab,
  onSelectTab,
  serverVersion,
  activeAlertCount,
  countdown,
  totalSeconds = 10,
  isPaused,
  onTogglePause,
  onRefreshNow,
  isRefreshing,
  lastRefreshTime,
  onOpenSearch,
  onLogout,
  isLoggingOut,
}) => {
  return (
    <header className="top-0 z-30 mb-6 border-b border-slate-800/80 bg-slate-950/80 backdrop-blur-xl lg:sticky">
      <div className="mx-auto flex max-w-[1536px] flex-col gap-3 px-4 py-3 sm:px-6 xl:flex-row xl:flex-wrap xl:items-center xl:justify-between 2xl:flex-nowrap">
        {/* Brand & Title */}
        <div className="flex shrink-0 items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-xl border border-sky-500/40 bg-sky-950/60 shadow-inner">
            <span className="font-mono text-base font-extrabold text-sky-400">NW</span>
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="whitespace-nowrap text-lg font-bold tracking-tight text-slate-100">
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
        <nav aria-label="主导航" className="grid w-full grid-cols-2 gap-1 rounded-xl border border-slate-800 bg-slate-900/80 p-1 sm:flex sm:w-auto sm:flex-wrap sm:items-center [&>button]:whitespace-nowrap">
          <button
            type="button"
            onClick={() => onSelectTab('dashboard')}
            aria-current={activeTab === 'dashboard' ? 'page' : undefined}
            className={`min-h-11 justify-center flex items-center gap-2 rounded-lg px-3 py-1.5 text-xs font-semibold transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-sky-400 ${
              activeTab === 'dashboard'
                ? 'bg-sky-500 text-slate-950 shadow-sm'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <LayoutDashboard className="h-3.5 w-3.5" />
            <span>总览看板</span>
          </button>
          <button
            type="button"
            onClick={() => onSelectTab('settings')}
            aria-current={activeTab === 'settings' || activeTab === 'notifications' ? 'page' : undefined}
            className={`min-h-11 justify-center flex items-center gap-2 rounded-lg px-3 py-1.5 text-xs font-semibold transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-sky-400 ${
              activeTab === 'settings' || activeTab === 'notifications'
                ? 'bg-sky-500 text-slate-950 shadow-sm'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Settings className="h-3.5 w-3.5" />
            <span>系统设置</span>
          </button>

          <button
            type="button"
            onClick={() => onSelectTab('alerts')}
            aria-current={activeTab === 'alerts' ? 'page' : undefined}
            className={`relative min-h-11 justify-center flex items-center gap-2 rounded-lg px-3 py-1.5 text-xs font-semibold transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-sky-400 ${
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
            className={`min-h-11 justify-center flex items-center gap-2 rounded-lg px-3 py-1.5 text-xs font-semibold transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-sky-400 ${
              activeTab === 'stats'
                ? 'bg-sky-500 text-slate-950 shadow-sm'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <BarChart3 className="h-3.5 w-3.5" />
            <span>数据统计</span>
          </button>
          <button type="button" onClick={() => onSelectTab('investigation')} aria-current={activeTab === 'investigation' ? 'page' : undefined} className={`min-h-11 flex items-center justify-center gap-2 rounded-lg px-3 py-1.5 text-xs font-semibold ${activeTab === 'investigation' ? 'bg-sky-500 text-slate-950' : 'text-slate-400 hover:text-slate-200'}`}><Users className="h-3.5 w-3.5" /><span>用户排查</span></button>
        </nav>
        <button type="button" onClick={() => onSelectTab('operations')} aria-current={activeTab === 'operations' ? 'page' : undefined} className={`min-h-11 rounded-lg border px-3 py-2 text-xs font-semibold ${activeTab === 'operations' ? 'border-sky-400 bg-sky-500 text-slate-950' : 'border-slate-700 text-slate-300 hover:border-sky-500'}`}>运维中心</button>

        {/* Search & Timer Tools */}
        <div className="flex items-center justify-between gap-2.5 xl:justify-end">
          {/* Global Search Button */}
          <button
            type="button"
            onClick={onOpenSearch}
            aria-label="打开全局检索"
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
            totalSeconds={totalSeconds}
            isPaused={isPaused}
            onTogglePause={onTogglePause}
            onRefreshNow={onRefreshNow}
            isRefreshing={isRefreshing}
            lastRefreshTime={lastRefreshTime}
          />
          <button type="button" onClick={onLogout} disabled={isLoggingOut} className="flex min-h-11 shrink-0 items-center gap-2 rounded-lg border border-slate-700 px-3 text-xs font-medium text-slate-300 transition-colors hover:border-sky-400 hover:text-slate-100 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-sky-400 disabled:opacity-60"><LogOut aria-hidden="true" className="h-4 w-4" /><span>{isLoggingOut ? '正在退出' : '退出登录'}</span></button>
        </div>
      </div>
    </header>
  );
};
