import React, { lazy, Suspense, useState, useEffect, useCallback } from 'react';
import { AlertTriangle, LoaderCircle, RotateCw } from 'lucide-react';
import {
  ContainerItem,
  SecurityAlert,
  SecurityStatusItem,
  ContainerIdentity,
} from './api/types';
import { api, request } from './api/client';
import { AppHeader } from './components/layout/AppHeader';
import { KpiGrid } from './components/dashboard/KpiGrid';
import { SecurityAlertSection } from './components/dashboard/SecurityAlertSection';
import { QuarantinePanel } from './components/dashboard/QuarantinePanel';
import { TelemetrySection } from './components/dashboard/TelemetrySection';
import { HostContainerList } from './components/dashboard/HostContainerList';
import { CommandPalette } from './components/common/CommandPalette';
import { ToastContainer, ToastMessage } from './components/common/Toast';
import { ErrorBoundary } from './components/common/ErrorBoundary';
import { isCurrentContainerInventoryItem } from './utils/containerFreshness';

const ContainerDrawer = lazy(() => import('./components/container/ContainerDrawer').then(module => ({ default: module.ContainerDrawer })));
const AlertHistoryView = lazy(() => import('./components/alerts/AlertHistoryView').then(module => ({ default: module.AlertHistoryView })));
const UserInvestigationView = lazy(() => import('./components/alerts/UserInvestigationView').then(module => ({ default: module.UserInvestigationView })));
const StatsAnalyticsView = lazy(() => import('./components/stats/StatsAnalyticsView').then(module => ({ default: module.StatsAnalyticsView })));
const SettingsView = lazy(() => import('./components/settings/SettingsView').then(module => ({ default: module.SettingsView })));
const OperationsView = lazy(() => import('./components/operations/OperationsView').then(module => ({ default: module.OperationsView })));
const CommerceView = lazy(() => import('./components/commerce/CommerceView').then(module => ({ default: module.CommerceView })));
const FirewallView = lazy(() => import('./components/firewall/FirewallView').then(module => ({ default: module.FirewallView })));

export const Dashboard: React.FC = () => {
  const [isLoggingOut, setIsLoggingOut] = useState(false);
  // Navigation tabs
  const [activeTab, setActiveTab] = useState<'dashboard' | 'alerts' | 'investigation' | 'stats' | 'settings' | 'notifications' | 'operations' | 'commerce' | 'firewall'>('dashboard');

  // Selected container for slide-over drawer
  const [selectedContainer, setSelectedContainer] = useState<ContainerIdentity | null>(null);

  // Global search modal
  const [isSearchOpen, setIsSearchOpen] = useState(false);

  // Toast notifications
  const [toasts, setToasts] = useState<ToastMessage[]>([]);

  const addToast = useCallback((type: 'success' | 'error' | 'info', message: string) => {
    const id = `${Date.now()}-${Math.random()}`;
    setToasts((prev) => [...prev, { id, type, message }]);
    setTimeout(() => {
      setToasts((prev) => prev.filter((t) => t.id !== id));
    }, 4500);
  }, []);

  const dismissToast = useCallback((id: string) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  }, []);

  const logout = async () => {
    setIsLoggingOut(true);
    try {
      await request('/api/v1/auth/logout', { method: 'POST' });
      window.location.replace('/login');
    } catch {
      addToast('error', '退出登录未成功，请重试');
      setIsLoggingOut(false);
    }
  };

  // Polling data
  const [containers, setContainers] = useState<ContainerItem[]>([]);
  const [hiddenStaleSnapshotCount, setHiddenStaleSnapshotCount] = useState(0);
  const [activeAlerts, setActiveAlerts] = useState<SecurityAlert[]>([]);
  const [securityStatus, setSecurityStatus] = useState<SecurityStatusItem[]>([]);
  const [serverVersion, setServerVersion] = useState<string>('dev');
  const [lastRefreshTime, setLastRefreshTime] = useState<string>('');
  const [hasLoadedData, setHasLoadedData] = useState(false);
  const [dataFetchError, setDataFetchError] = useState<string | null>(null);

  // Polling controls
  const POLL_INTERVAL = 10;
  const HIDDEN_POLL_INTERVAL = 60;
  const [isDocumentHidden, setIsDocumentHidden] = useState(() => document.hidden);
  const effectivePollInterval = isDocumentHidden ? HIDDEN_POLL_INTERVAL : POLL_INTERVAL;
  const [countdown, setCountdown] = useState(POLL_INTERVAL);
  const [isPaused, setIsPaused] = useState(false);
  const [isRefreshing, setIsRefreshing] = useState(false);

  const isFetchingRef = React.useRef(false);

  const fetchAllData = useCallback(async () => {
    if (isFetchingRef.current) return;
    isFetchingRef.current = true;
    setIsRefreshing(true);
    try {
      const [latestRes, alertsRes, secStatusRes] = await Promise.all([
        // Retained snapshots support host-level freshness summaries. Only
        // current-inventory items are shown as containers below.
        api.getLatest(true),
        api.getActiveAlerts(),
        api.getSecurityStatus(),
      ]);

      const containerSnapshots = latestRes.items || [];
      const currentContainers = containerSnapshots.filter(isCurrentContainerInventoryItem);
      setContainers(containerSnapshots);
      setHiddenStaleSnapshotCount(containerSnapshots.length - currentContainers.length);
      setServerVersion(latestRes.server_version || 'dev');
      const alertItems = alertsRes.items || alertsRes.alerts || [];
      const liveSecurityStatus = secStatusRes.items || [];
      const securityByHost = new Map(liveSecurityStatus.map((item) => [item.host_id, item]));
      // A host-level alert is live only while the host heartbeat is fresh. A
      // container alert also needs an exact runtime/project/container match;
      // this prevents a stale alert or same-name container in another runtime
      // from becoming an actionable risk card.
      setActiveAlerts(alertItems.filter((alert) => {
        if (!alert.container_name) {
          const host = securityByHost.get(alert.host_id);
          return Boolean(host && !host.stale);
        }
        return currentContainers.some((container) => {
          const sameContainer = container.host_id === alert.host_id &&
            container.runtime === alert.runtime &&
            (container.project || '') === (alert.project || '') &&
            container.container_name === alert.container_name;
          if (!(sameContainer && !container.alerts?.stale && !container.alerts?.host_stale)) return false;
          const alertInstance = String(alert.details?.instance_id || '').toLowerCase();
          const currentInstance = String(container.container_instance_id || '').toLowerCase();
          if (alert.type === 'prohibited_activity' && alertInstance && currentInstance) {
            const sameInstance = alert.runtime === 'podman'
              ? alertInstance.length >= 12 && currentInstance.length >= 12 &&
                (alertInstance.startsWith(currentInstance) || currentInstance.startsWith(alertInstance))
              : alertInstance === currentInstance;
            if (!sameInstance) return false;
          }
          return true;
        });
      }));
      setSecurityStatus(liveSecurityStatus);
      setHasLoadedData(true);
      setDataFetchError(null);

      const now = new Date();
      setLastRefreshTime(
        `${now.getHours().toString().padStart(2, '0')}:${now
          .getMinutes()
          .toString()
          .padStart(2, '0')}:${now.getSeconds().toString().padStart(2, '0')}`
      );
    } catch (err: any) {
      const message = err?.message || String(err);
      setDataFetchError(message);
      addToast('error', `数据获取失败：${message}`);
    } finally {
      isFetchingRef.current = false;
      setIsRefreshing(false);
      setCountdown(document.hidden ? HIDDEN_POLL_INTERVAL : POLL_INTERVAL);
    }
  }, [addToast]);

  const openAlertContainer = useCallback((identity: ContainerIdentity) => {
    const target = containers.find((container) =>
      isCurrentContainerInventoryItem(container) &&
      container.host_id === identity.host_id &&
      container.runtime === identity.runtime &&
      (container.project || '') === (identity.project || '') &&
      container.container_name === identity.container_name
    );
    if (!target) {
      addToast('info', '该容器当前没有在线采样数据，请从告警详情核对主机状态');
      return;
    }
    setActiveTab('dashboard');
    setSelectedContainer({
      host_id: target.host_id,
      runtime: target.runtime,
      project: target.project || '',
      container_name: target.container_name,
      container_id: target.container_id,
    });
  }, [addToast, containers]);

  useEffect(() => {
    if (!selectedContainer) return;
    const selectionIsCurrent = containers.some((container) =>
      isCurrentContainerInventoryItem(container) &&
      container.host_id === selectedContainer.host_id &&
      container.runtime === selectedContainer.runtime &&
      (container.project || '') === (selectedContainer.project || '') &&
      container.container_name === selectedContainer.container_name
    );
    if (!selectionIsCurrent) setSelectedContainer(null);
  }, [containers, selectedContainer]);

  useEffect(() => {
    const onVisibilityChange = () => {
      const hidden = document.hidden;
      setIsDocumentHidden(hidden);
      setCountdown(hidden ? HIDDEN_POLL_INTERVAL : POLL_INTERVAL);
    };
    document.addEventListener('visibilitychange', onVisibilityChange);
    return () => document.removeEventListener('visibilitychange', onVisibilityChange);
  }, []);

  // Initial load
  useEffect(() => {
    fetchAllData();
  }, [fetchAllData]);

  // Real-time countdown interval (pure state updater without side effects)
  useEffect(() => {
    if (isPaused) return;

    const timer = setInterval(() => {
      setCountdown((prev) => {
        if (prev <= 1) {
          return 0;
        }
        return prev - 1;
      });
    }, 1000);

    return () => clearInterval(timer);
  }, [isPaused]);

  // When countdown expires, trigger refresh
  useEffect(() => {
    if (!isPaused && countdown === 0) {
      fetchAllData();
    }
  }, [countdown, isPaused, fetchAllData]);

  // Keyboard shortcut listener (Ctrl+K, Escape)
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        setIsSearchOpen((prev) => !prev);
      } else if (e.key === 'Escape') {
        if (isSearchOpen) {
          setIsSearchOpen(false);
        } else if (selectedContainer) {
          setSelectedContainer(null);
        }
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isSearchOpen, selectedContainer]);

  // KPI computations
  const currentContainers = containers.filter(isCurrentContainerInventoryItem);
  const staleSnapshots = containers.filter((container) => !isCurrentContainerInventoryItem(container));
  const onlineHostsCount = new Set([
    ...currentContainers.map((container) => container.host_id),
    ...securityStatus.filter((host) => !host.stale).map((host) => host.host_id),
  ]).size;
  const totalContainersCount = currentContainers.length;
  const activeAlertsCount = activeAlerts.length;

  return (
    <div className="min-h-screen bg-dark text-slate-100 flex flex-col selection:bg-sky-500/30">
      {/* Top Application Header */}
      <AppHeader
        onLogout={logout}
        isLoggingOut={isLoggingOut}
        activeTab={activeTab}
        onSelectTab={setActiveTab}
        serverVersion={serverVersion}
        activeAlertCount={activeAlertsCount}
        alertCountState={!hasLoadedData ? 'unknown' : dataFetchError ? 'stale' : 'current'}
        countdown={countdown}
        totalSeconds={effectivePollInterval}
        isPaused={isPaused}
        onTogglePause={() => setIsPaused((prev) => !prev)}
        onRefreshNow={fetchAllData}
        isRefreshing={isRefreshing}
        lastRefreshTime={lastRefreshTime}
        onOpenSearch={() => setIsSearchOpen(true)}
      />

      {/* Main Body */}
      <main className="mx-auto w-full max-w-[1536px] flex-1 px-3.5 sm:px-6 pb-16">
        {activeTab === 'dashboard' && hasLoadedData && dataFetchError && (
          <section role="alert" aria-live="assertive" className="mb-5 flex flex-col gap-3 rounded-xl border border-amber-500/40 bg-amber-950/30 p-4 sm:flex-row sm:items-center sm:justify-between">
            <div className="flex min-w-0 items-start gap-3">
              <AlertTriangle className="mt-0.5 h-5 w-5 shrink-0 text-amber-300" aria-hidden="true" />
              <div className="min-w-0">
                <h2 className="text-sm font-semibold text-amber-100">自动刷新失败，当前显示上次成功采样</h2>
                <p className="mt-1 text-xs text-amber-200">上次成功更新：<span className="font-mono tabular-nums">{lastRefreshTime || '未知'}</span> · {dataFetchError}</p>
              </div>
            </div>
            <button type="button" onClick={() => void fetchAllData()} disabled={isRefreshing} className="inline-flex min-h-11 shrink-0 items-center justify-center gap-2 rounded-lg border border-amber-400/50 px-3 text-sm font-medium text-amber-100 transition-colors hover:bg-amber-900/40 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-amber-300 disabled:cursor-wait disabled:opacity-60">
              <RotateCw className={`h-4 w-4 ${isRefreshing ? 'animate-spin motion-reduce:animate-none' : ''}`} aria-hidden="true" />
              {isRefreshing ? '正在重试…' : '立即重试'}
            </button>
          </section>
        )}
        {activeTab === 'dashboard' && !hasLoadedData && (
          <section role={dataFetchError ? 'alert' : 'status'} aria-live={dataFetchError ? 'assertive' : 'polite'} className="my-8 flex min-h-48 flex-col items-start justify-center gap-4 rounded-2xl border border-slate-700 bg-slate-900/70 p-6 sm:flex-row sm:items-center sm:justify-between sm:p-8">
            <div className="flex min-w-0 items-start gap-4">
              {dataFetchError
                ? <AlertTriangle className="mt-0.5 h-6 w-6 shrink-0 text-amber-300" aria-hidden="true" />
                : <LoaderCircle className="mt-0.5 h-6 w-6 shrink-0 animate-spin text-sky-300 motion-reduce:animate-none" aria-hidden="true" />}
              <div className="min-w-0">
                <h2 className="text-base font-semibold text-slate-100">{dataFetchError ? '实时监控状态尚未确认' : '正在读取运行状态'}</h2>
                <p className="mt-2 max-w-2xl text-sm leading-6 text-slate-300">{dataFetchError ? '尚未取得成功采样，主机、容器和告警数量未知。请勿将空列表视为系统健康。' : '正在获取主机、容器、告警与安全遥测数据。'}</p>
                {dataFetchError && <p className="mt-2 break-words text-xs text-amber-200">读取失败：{dataFetchError} · {isRefreshing ? '正在重试…' : `将在 ${countdown} 秒后自动重试`}</p>}
              </div>
            </div>
            {dataFetchError && <button type="button" onClick={() => void fetchAllData()} disabled={isRefreshing} className="inline-flex min-h-11 shrink-0 items-center justify-center gap-2 rounded-lg border border-slate-600 bg-slate-800 px-4 text-sm font-medium text-slate-100 transition-colors hover:bg-slate-700 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-sky-300 disabled:cursor-wait disabled:opacity-60"><RotateCw className={`h-4 w-4 ${isRefreshing ? 'animate-spin motion-reduce:animate-none' : ''}`} aria-hidden="true" />{isRefreshing ? '正在重试…' : '立即重试'}</button>}
          </section>
        )}
        <ErrorBoundary fallbackTitle="主界面视图加载异常">
          <Suspense fallback={<div className="flex min-h-40 items-center justify-center text-sm text-slate-400" role="status">正在载入此页面…</div>}>
          {activeTab === 'dashboard' && hasLoadedData && (
            <>
              {/* KPI Cards Grid */}
              <KpiGrid
                onlineHosts={onlineHostsCount}
                totalContainers={totalContainersCount}
                activeAlerts={activeAlertsCount}
                hiddenStaleSnapshots={hiddenStaleSnapshotCount}
                onFilterAlerts={() => setActiveTab('alerts')}
              />

              {/* Active Security Alerts Banner */}
              <QuarantinePanel onToast={addToast} />
              <SecurityAlertSection
                alerts={activeAlerts}
                onRefresh={fetchAllData}
                onViewAllHistory={() => setActiveTab('alerts')}
                onToast={addToast}
                onSelectContainer={openAlertContainer}
              />

              {/* Host Security Telemetry */}
              <TelemetrySection telemetry={securityStatus} onToast={addToast} onRefresh={fetchAllData} />

              {/* Host Topologies and Container Cards */}
              <HostContainerList
                containers={containers}
                staleSnapshots={staleSnapshots}
                serverVersion={serverVersion}
                activeAlerts={activeAlerts}
                onSelectContainer={setSelectedContainer}
                onToast={addToast}
                onRefresh={fetchAllData}
              />
            </>
          )}

          {activeTab === 'alerts' && (
            <AlertHistoryView
              onToast={addToast}
              onBackToDashboard={() => setActiveTab('dashboard')}
            />
          )}

          {activeTab === 'investigation' && <UserInvestigationView />}
          {activeTab === 'commerce' && <CommerceView />}
          {activeTab === 'firewall' && <FirewallView containers={currentContainers} telemetry={securityStatus} onToast={addToast} />}

          {activeTab === 'stats' && (
            <StatsAnalyticsView
              onSelectContainer={setSelectedContainer}
              onToast={addToast}
              onBackToDashboard={() => setActiveTab('dashboard')}
            />
          )}
          {(activeTab === 'settings' || activeTab === 'notifications') && <SettingsView onToast={addToast} />}
          {activeTab === 'operations' && <OperationsView onToast={addToast} isPaused={isPaused} />}
          </Suspense>
        </ErrorBoundary>
      </main>

      {/* Slide-over Container Drawer */}
      {selectedContainer && <Suspense fallback={null}><ContainerDrawer
        identity={selectedContainer}
        activeAlerts={activeAlerts}
        onClose={() => setSelectedContainer(null)}
        serverVersion={serverVersion}
        onToast={addToast}
        onRefresh={fetchAllData}
      /></Suspense>}

      {/* Command Palette (Ctrl+K) */}
      <CommandPalette
        isOpen={isSearchOpen}
        onClose={() => setIsSearchOpen(false)}
        containers={currentContainers}
        onSelectContainer={setSelectedContainer}
        onSelectTab={setActiveTab}
      />

      {/* Toast Feedbacks */}
      <ToastContainer toasts={toasts} onDismiss={dismissToast} />
    </div>
  );
};
