import React from 'react';
import {
  BarChart3,
  BriefcaseBusiness,
  ChevronRight,
  Globe2,
  LayoutDashboard,
  LogOut,
  Search,
  Settings,
  ShieldAlert,
  ShieldCheck,
  Users,
  Wrench,
} from 'lucide-react';
import { CountdownTimer } from '../../components/common/CountdownTimer';
import './console-shell.css';

export type ConsoleTab =
  | 'dashboard'
  | 'alerts'
  | 'investigation'
  | 'stats'
  | 'settings'
  | 'notifications'
  | 'operations'
  | 'commerce'
  | 'firewall';

export interface ConsoleShellProps {
  activeTab: ConsoleTab;
  onSelectTab: (tab: ConsoleTab) => void;
  serverVersion: string;
  activeAlertCount: number;
  alertCountState: 'unknown' | 'current' | 'stale';
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
  subLabel?: string;
}

const NAVIGATION = [
  { tab: 'dashboard', label: '总览看板', group: 'monitor', icon: LayoutDashboard },
  { tab: 'alerts', label: '安全告警', group: 'monitor', icon: ShieldAlert },
  { tab: 'investigation', label: '用户排查', group: 'monitor', icon: Users },
  { tab: 'stats', label: '数据统计', group: 'monitor', icon: BarChart3 },
  { tab: 'commerce', label: '经营分析', group: 'ops', icon: BriefcaseBusiness },
  { tab: 'operations', label: '运维中心', group: 'ops', icon: Wrench },
  { tab: 'firewall', label: '母机防火墙', group: 'ops', icon: ShieldCheck },
  { tab: 'settings', label: '系统设置', group: 'ops', icon: Settings },
] as const;

const TAB_BREADCRUMBS: Record<ConsoleTab, { section: string; title: string; subtitle: string }> = {
  dashboard: { section: 'Overview', title: '总览看板', subtitle: 'Fleet Health & Telemetry' },
  alerts: { section: 'Security', title: '安全告警', subtitle: 'Active Incidents & Audit' },
  investigation: { section: 'Security', title: '用户排查', subtitle: 'Tenant & Lifetime Forensics' },
  stats: { section: 'Analytics', title: '数据统计', subtitle: 'Top Resource Consumers' },
  commerce: { section: 'Business', title: '经营分析', subtitle: 'Revenue & Profitability' },
  operations: { section: 'Operations', title: '运维中心', subtitle: '14-in-1 Fleet Workbench' },
  firewall: { section: 'Network', title: '母机防火墙', subtitle: 'RFW & Protocol Policies' },
  settings: { section: 'Platform', title: '系统设置', subtitle: 'Policies & Integrations' },
  notifications: { section: 'Platform', title: '系统设置', subtitle: 'Buyer Notification Audit' },
};

export interface ConsoleSidebarProps {
  activeTab: ConsoleTab;
  onSelectTab: (tab: ConsoleTab) => void;
  serverVersion: string;
  activeAlertCount: number;
  alertCountState: 'unknown' | 'current' | 'stale';
}

export const ConsoleSidebar: React.FC<ConsoleSidebarProps> = ({
  activeTab,
  onSelectTab,
  serverVersion,
  activeAlertCount,
  alertCountState,
}) => (
  <aside className="saas-sidebar" aria-label="主侧边栏">
    <div className="saas-sidebar-brand">
      <div className="saas-brand-mark" aria-hidden="true">
        NW
      </div>
      <div className="saas-brand-copy">
        <div className="saas-brand-title">
          <span>Narwhal Monitor</span>
          <span className="saas-version-badge">v{serverVersion || 'dev'}</span>
        </div>
        <p>Cloud Container Workbench</p>
      </div>
    </div>

    <nav aria-label="主导航" className="app-primary-nav">
      {NAVIGATION.map(({ tab, label, group, icon: Icon }, idx) => {
        const selected =
          activeTab === tab ||
          (tab === 'settings' && activeTab === 'notifications');
        const showAlertCount =
          tab === 'alerts' &&
          (activeAlertCount > 0 || alertCountState === 'unknown');
        const isFirstOps = group === 'ops' && NAVIGATION[idx - 1]?.group !== 'ops';

        return (
          <React.Fragment key={tab}>
            {idx === 0 && (
              <div className="saas-nav-group-label" aria-hidden="true">
                监控与安全
              </div>
            )}
            {isFirstOps && (
              <div className="saas-nav-group-label" aria-hidden="true">
                平台与运维
              </div>
            )}
            <button
              type="button"
              onClick={() => onSelectTab(tab)}
              aria-current={selected ? 'page' : undefined}
            >
              <Icon aria-hidden="true" size={17} />
              <span>{label}</span>
              {showAlertCount && (
                <span
                  className={`app-alert-count${
                    alertCountState === 'unknown'
                      ? ' app-alert-count-unknown'
                      : alertCountState === 'stale'
                        ? ' app-alert-count-stale'
                        : ''
                  }`}
                  aria-label={
                    alertCountState === 'unknown'
                      ? '活动告警数量未知'
                      : `${alertCountState === 'stale' ? '上次成功采样：' : ''}${activeAlertCount} 项活动告警`
                  }
                >
                  {alertCountState === 'unknown'
                    ? '?'
                    : activeAlertCount > 99
                      ? '99+'
                      : activeAlertCount}
                </span>
              )}
            </button>
          </React.Fragment>
        );
      })}

      <div className="saas-nav-group-label" aria-hidden="true">
        外部探测
      </div>
      <a href="/tcping" className="app-tcp-link" aria-label="全国 TCP 测试">
        <Globe2 aria-hidden="true" size={17} />
        <span className="app-nav-full">全国 TCP 测试</span>
        <span className="app-nav-short">TCP 测速</span>
      </a>
    </nav>

    <div className="saas-sidebar-footer" aria-hidden="true">
      <div className="saas-status-dot" />
      <div className="min-w-0">
        <p className="truncate text-xs font-semibold text-[#0f172a]">控制面运行中</p>
        <p className="truncate text-[11px] text-[#64748b]">Light SaaS · 2.0 Workbench</p>
      </div>
    </div>
  </aside>
);

export const ConsoleShell: React.FC<ConsoleShellProps> = (props) => {
  const crumb = TAB_BREADCRUMBS[props.activeTab] || TAB_BREADCRUMBS.dashboard;

  return (
    <header className="app-header">
      <div className="app-header-inner">
        <div className="app-header-top">
          <div className="app-brand">
            <div className="app-brand-mark lg:hidden" aria-hidden="true">
              NW
            </div>
            <div className="app-brand-copy">
              <div className="app-brand-title">
                <span className="hidden items-center gap-1.5 text-xs font-semibold text-[#64748b] lg:inline-flex">
                  <span>{crumb.section}</span>
                  <ChevronRight className="h-3.5 w-3.5 text-[#94a3b8]" aria-hidden="true" />
                </span>
                <h1>{crumb.title}</h1>
                <span className="lg:hidden">v{props.serverVersion || 'dev'}</span>
              </div>
              <p className="hidden sm:block">{props.subLabel || crumb.subtitle}</p>
            </div>
          </div>

          <div className="app-header-tools" role="group" aria-label="看板工具">
            <button
              type="button"
              onClick={props.onOpenSearch}
              aria-label="打开全局检索"
              className="app-search"
            >
              <Search aria-hidden="true" size={16} />
              <span>全局检索</span>
              <kbd>Ctrl+K</kbd>
            </button>
            <CountdownTimer
              countdown={props.countdown}
              totalSeconds={props.totalSeconds}
              isPaused={props.isPaused}
              onTogglePause={props.onTogglePause}
              onRefreshNow={props.onRefreshNow}
              isRefreshing={props.isRefreshing}
              lastRefreshTime={props.lastRefreshTime}
            />
            <button
              type="button"
              onClick={props.onLogout}
              disabled={props.isLoggingOut}
              className="app-logout"
              aria-label={props.isLoggingOut ? '正在退出' : '退出登录'}
              title="退出登录"
            >
              <LogOut aria-hidden="true" size={16} />
              <span>{props.isLoggingOut ? '正在退出' : '退出登录'}</span>
            </button>
          </div>
        </div>
      </div>
    </header>
  );
};
