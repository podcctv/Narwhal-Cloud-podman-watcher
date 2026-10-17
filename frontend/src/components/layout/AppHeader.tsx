import React from 'react';
import { ShieldAlert, BarChart3, LayoutDashboard, Search, Settings, Users, LogOut, BriefcaseBusiness, Wrench, Globe2, ShieldCheck } from 'lucide-react';
import { CountdownTimer } from '../common/CountdownTimer';
import './app-header.css';

type Tab = 'dashboard' | 'alerts' | 'investigation' | 'stats' | 'settings' | 'notifications' | 'operations' | 'commerce' | 'firewall';
interface AppHeaderProps {
  activeTab: Tab; onSelectTab: (tab: Tab) => void; serverVersion: string;
  activeAlertCount: number; countdown: number; totalSeconds?: number; isPaused: boolean;
  onTogglePause: () => void; onRefreshNow: () => void; isRefreshing: boolean;
  lastRefreshTime?: string; onOpenSearch: () => void; onLogout: () => void; isLoggingOut: boolean;
}
const navigation = [
  { tab: 'dashboard', label: '总览看板', icon: LayoutDashboard },
  { tab: 'alerts', label: '安全告警', icon: ShieldAlert },
  { tab: 'investigation', label: '用户排查', icon: Users },
  { tab: 'stats', label: '数据统计', icon: BarChart3 },
  { tab: 'commerce', label: '经营分析', icon: BriefcaseBusiness },
  { tab: 'operations', label: '运维中心', icon: Wrench },
  { tab: 'firewall', label: '母机防火墙', icon: ShieldCheck },
  { tab: 'settings', label: '系统设置', icon: Settings },
] as const;

export const AppHeader: React.FC<AppHeaderProps> = (props) => (
  <header className="app-header">
    <div className="app-header-inner">
      <div className="app-header-top">
        <div className="app-brand">
          <div className="app-brand-mark" aria-hidden="true">NW</div>
          <div className="app-brand-copy">
            <div className="app-brand-title"><h1>Narwhal Monitor</h1><span>v{props.serverVersion || 'dev'}</span></div>
            <p>云原生容器与主机安全监控中心</p>
          </div>
        </div>
        <div className="app-header-tools" role="group" aria-label="看板工具">
          <button type="button" onClick={props.onOpenSearch} aria-label="打开全局检索" className="app-search">
            <Search aria-hidden="true" size={16}/><span>全局检索</span><kbd>Ctrl+K</kbd>
          </button>
          <CountdownTimer countdown={props.countdown} totalSeconds={props.totalSeconds} isPaused={props.isPaused}
            onTogglePause={props.onTogglePause} onRefreshNow={props.onRefreshNow} isRefreshing={props.isRefreshing} lastRefreshTime={props.lastRefreshTime}/>
          <button type="button" onClick={props.onLogout} disabled={props.isLoggingOut} className="app-logout" aria-label={props.isLoggingOut ? '正在退出' : '退出登录'} title="退出登录">
            <LogOut aria-hidden="true" size={16}/><span>{props.isLoggingOut ? '正在退出' : '退出登录'}</span>
          </button>
        </div>
      </div>
      <nav aria-label="主导航" className="app-primary-nav">
        {navigation.map(({tab,label,icon:Icon})=>{
          const selected=props.activeTab===tab || (tab==='settings' && props.activeTab==='notifications');
          return <button type="button" key={tab} onClick={()=>props.onSelectTab(tab)} aria-current={selected?'page':undefined}>
            <Icon aria-hidden="true" size={16}/><span>{label}</span>
            {tab==='alerts' && props.activeAlertCount>0 && <span className="app-alert-count" aria-label={`${props.activeAlertCount} 项活动告警`}>{props.activeAlertCount>99?'99+':props.activeAlertCount}</span>}
          </button>;
        })}
        <a href="/tcping" className="app-tcp-link" aria-label="全国 TCP 测试"><Globe2 aria-hidden="true" size={16}/><span className="app-nav-full">全国 TCP 测试</span><span className="app-nav-short">TCP 测速</span></a>
      </nav>
    </div>
  </header>
);
