import React, { useState, useEffect, useCallback } from 'react';
import {
  ContainerItem,
  SecurityAlert,
  SecurityStatusItem,
  ContainerIdentity,
} from './api/types';
import { api } from './api/client';
import { AppHeader } from './components/layout/AppHeader';
import { KpiGrid } from './components/dashboard/KpiGrid';
import { SecurityAlertSection } from './components/dashboard/SecurityAlertSection';
import { TelemetrySection } from './components/dashboard/TelemetrySection';
import { HostContainerList } from './components/dashboard/HostContainerList';
import { ContainerDrawer } from './components/container/ContainerDrawer';
import { AlertHistoryView } from './components/alerts/AlertHistoryView';
import { StatsAnalyticsView } from './components/stats/StatsAnalyticsView';
import { CommandPalette } from './components/common/CommandPalette';
import { ToastContainer, ToastMessage } from './components/common/Toast';
import { ErrorBoundary } from './components/common/ErrorBoundary';
import { SettingsView } from './components/settings/SettingsView';

export const App: React.FC = () => {
  // Navigation tabs
  const [activeTab, setActiveTab] = useState<'dashboard' | 'alerts' | 'stats' | 'settings' | 'notifications'>('dashboard');

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

  // Polling data
  const [containers, setContainers] = useState<ContainerItem[]>([]);
  const [activeAlerts, setActiveAlerts] = useState<SecurityAlert[]>([]);
  const [securityStatus, setSecurityStatus] = useState<SecurityStatusItem[]>([]);
  const [serverVersion, setServerVersion] = useState<string>('dev');
  const [lastRefreshTime, setLastRefreshTime] = useState<string>('');

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
        // The dashboard is a live operations view. Stale samples are retained
        // server-side for history/detail diagnostics, not shown as live risk.
        api.getLatest(false),
        api.getActiveAlerts(),
        api.getSecurityStatus(),
      ]);

      const liveContainers = latestRes.items || [];
      setContainers(liveContainers);
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
        return liveContainers.some((container) =>
          container.host_id === alert.host_id &&
          container.runtime === alert.runtime &&
          (container.project || '') === (alert.project || '') &&
          container.container_name === alert.container_name &&
          !container.alerts?.stale
        );
      }));
      setSecurityStatus(liveSecurityStatus);

      const now = new Date();
      setLastRefreshTime(
        `${now.getHours().toString().padStart(2, '0')}:${now
          .getMinutes()
          .toString()
          .padStart(2, '0')}:${now.getSeconds().toString().padStart(2, '0')}`
      );
      setCountdown(isDocumentHidden ? HIDDEN_POLL_INTERVAL : POLL_INTERVAL);
    } catch (err: any) {
      addToast('error', `数据获取失败：${err.message || err}`);
    } finally {
      isFetchingRef.current = false;
      setIsRefreshing(false);
    }
  }, [addToast, isDocumentHidden]);

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
  const onlineHostsCount = new Set(containers.map((c) => c.host_id)).size;
  const totalContainersCount = containers.length;
  const activeAlertsCount = activeAlerts.length;
  const staleContainersCount = containers.filter((c) => c.alerts?.stale).length;

  return (
    <div className="min-h-screen bg-dark text-slate-100 flex flex-col selection:bg-sky-500/30">
      {/* Top Application Header */}
      <AppHeader
        activeTab={activeTab}
        onSelectTab={setActiveTab}
        serverVersion={serverVersion}
        activeAlertCount={activeAlertsCount}
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
      <main className="mx-auto w-full max-w-7xl flex-1 px-4 sm:px-6 pb-16">
        <ErrorBoundary fallbackTitle="主界面视图加载异常">
          {activeTab === 'dashboard' && (
            <>
              {/* KPI Cards Grid */}
              <KpiGrid
                onlineHosts={onlineHostsCount}
                totalContainers={totalContainersCount}
                activeAlerts={activeAlertsCount}
                staleContainers={staleContainersCount}
                onFilterAlerts={() => setActiveTab('alerts')}
              />

              {/* Active Security Alerts Banner */}
              <SecurityAlertSection
                alerts={activeAlerts}
                onRefresh={fetchAllData}
                onViewAllHistory={() => setActiveTab('alerts')}
                onToast={addToast}
              />

              {/* Host Security Telemetry */}
              <TelemetrySection telemetry={securityStatus} onToast={addToast} onRefresh={fetchAllData} />

              {/* Host Topologies and Container Cards */}
              <HostContainerList
                containers={containers}
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

          {activeTab === 'stats' && (
            <StatsAnalyticsView
              onSelectContainer={setSelectedContainer}
              onToast={addToast}
              onBackToDashboard={() => setActiveTab('dashboard')}
            />
          )}
          {(activeTab === 'settings' || activeTab === 'notifications') && <SettingsView onToast={addToast} />}
        </ErrorBoundary>
      </main>

      {/* Slide-over Container Drawer */}
      <ContainerDrawer
        identity={selectedContainer}
        activeAlerts={activeAlerts}
        onClose={() => setSelectedContainer(null)}
        serverVersion={serverVersion}
        onToast={addToast}
      />

      {/* Command Palette (Ctrl+K) */}
      <CommandPalette
        isOpen={isSearchOpen}
        onClose={() => setIsSearchOpen(false)}
        containers={containers}
        onSelectContainer={setSelectedContainer}
        onSelectTab={setActiveTab}
      />

      {/* Toast Feedbacks */}
      <ToastContainer toasts={toasts} onDismiss={dismissToast} />
    </div>
  );
};
