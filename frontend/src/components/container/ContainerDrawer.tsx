import React, { useEffect, useState } from 'react';
import {
  X,
  Box,
  Activity,
  Cpu,
  HardDrive,
  Network,
  Shield,
  AlertTriangle,
  Ban,
  Check,
  CheckCircle2,
} from 'lucide-react';
import { ContainerItem, ContainerIdentity, HistoryPoint, DiagnosticData } from '../../api/types';
import { api, fmtBytes, fmtNumber } from '../../api/client';
import { StatusBadge } from '../common/StatusBadge';
import { ResourceChart } from './ResourceChart';
import { NetworkChart } from './NetworkChart';
import { DiagnosticPanel } from './DiagnosticPanel';

interface ContainerDrawerProps {
  identity: ContainerIdentity | null;
  onClose: () => void;
  serverVersion: string;
  onToast: (type: 'success' | 'error' | 'info', message: string) => void;
}

export const ContainerDrawer: React.FC<ContainerDrawerProps> = ({
  identity,
  onClose,
  serverVersion,
  onToast,
}) => {
  const [container, setContainer] = useState<ContainerItem | null>(null);
  const [history, setHistory] = useState<HistoryPoint[]>([]);
  const [diagnostic, setDiagnostic] = useState<DiagnosticData | null>(null);
  const [isDrawerActionLoading, setIsDrawerActionLoading] = useState(false);

  const handleDrawerDisposition = async (
    decision: 'deny' | 'allow_silent' | 'resolve'
  ) => {
    if (!identity) return;
    setIsDrawerActionLoading(true);
    try {
      const res = await api.dispositionContainer(identity, decision);
      onToast(
        'success',
        decision === 'deny'
          ? (res.queued ? '处置指令已下发节点执行' : '安全处置已更新')
          : decision === 'resolve'
          ? '风险已标记为已解决'
          : '已成功添加放行策略'
      );
      const latestData = await api.getLatest(true);
      const found = latestData.items.find(
        (c) =>
          c.host_id === identity.host_id &&
          c.runtime === identity.runtime &&
          (c.project || '') === (identity.project || '') &&
          c.container_name === identity.container_name
      );
      setContainer(found || null);
    } catch (err: any) {
      onToast('error', `操作失败：${err.message || err}`);
    } finally {
      setIsDrawerActionLoading(false);
    }
  };

  useEffect(() => {
    if (!identity) {
      setContainer(null);
      setHistory([]);
      setDiagnostic(null);
      return;
    }

    let isMounted = true;

    const loadData = async () => {
      try {
        const [latestData, histData, diagData] = await Promise.all([
          api.getLatest(true),
          api.getContainerHistory(identity, 1440),
          api.getContainerDiagnostic(identity),
        ]);

        if (!isMounted) return;

        const found = latestData.items.find(
          (c) =>
            c.host_id === identity.host_id &&
            c.runtime === identity.runtime &&
            (c.project || '') === (identity.project || '') &&
            c.container_name === identity.container_name
        );

        setContainer(found || null);
        setHistory(histData.items || []);
        setDiagnostic(diagData);
      } catch (err: any) {
        if (isMounted) {
          onToast('error', `加载容器指标失败：${err.message || err}`);
        }
      }
    };

    loadData();

    // Refresh every 15s when drawer is open
    const interval = setInterval(loadData, 15000);
    return () => {
      isMounted = false;
      clearInterval(interval);
    };
  }, [identity]);

  if (!identity) return null;

  const sec = container?.security || {};
  const inIps = sec.inbound_unique_ips || 0;
  const inThresh = sec.inbound_unique_ip_threshold || 10;
  const inIpAlert = inIps > inThresh;

  const agentVersion = container?.agent_version || 'unknown';
  const isVersionMatch =
    agentVersion !== 'unknown' &&
    agentVersion !== 'dev' &&
    agentVersion === serverVersion;

  const socks = sec.socks_proxy;
  const pairing = sec.panel_pairing;

  return (
    <div className="fixed inset-0 z-50 overflow-hidden">
      {/* Backdrop */}
      <div
        onClick={onClose}
        className="absolute inset-0 bg-slate-950/70 backdrop-blur-sm transition-opacity animate-in fade-in duration-200"
      />

      {/* Slide-over Drawer Panel */}
      <div className="absolute inset-y-0 right-0 flex max-w-full pl-10">
        <div className="w-screen max-w-2xl transform bg-slate-900 border-l border-slate-800 shadow-2xl transition-transform animate-in slide-in-from-right duration-250 flex flex-col">
          {/* Drawer Header */}
          <div className="flex items-center justify-between border-b border-slate-800 bg-slate-950/80 px-6 py-4">
            <div className="flex items-center gap-3 min-w-0">
              <div className="rounded-xl bg-sky-950/80 p-2.5 text-sky-400 border border-sky-500/30 shrink-0">
                <Box className="h-5 w-5" />
              </div>
              <div className="min-w-0">
                <div className="flex items-center gap-2 flex-wrap">
                  <h2 className="text-base font-bold text-slate-100 truncate">
                    {identity.container_name}
                  </h2>
                  <StatusBadge
                    status={container?.alerts?.stale ? 'stale' : 'healthy'}
                    size="sm"
                    pulse={!container?.alerts?.stale}
                  />
                  <span
                    className={`rounded-full border px-2 py-0.2 text-[10px] font-mono font-medium ${
                      isVersionMatch
                        ? 'border-emerald-500/30 bg-emerald-950/50 text-emerald-400'
                        : 'border-amber-500/30 bg-amber-950/50 text-amber-400'
                    }`}
                  >
                    Agent v{agentVersion}
                  </span>
                </div>
                <div className="flex items-center gap-2 text-xs text-slate-400 mt-0.5">
                  <span className="font-mono">{identity.host_id}</span>
                  <span>•</span>
                  <span>
                    {identity.project ? `${identity.runtime}/${identity.project}` : identity.runtime}
                  </span>
                </div>
              </div>
            </div>

            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={onClose}
                className="rounded-lg p-2 text-slate-400 hover:bg-slate-800 hover:text-slate-100 transition-colors"
                title="关闭抽屉 (Esc)"
              >
                <X className="h-5 w-5" />
              </button>
            </div>
          </div>

          {/* Drawer Scrollable Body */}
          <div className="flex-1 overflow-y-auto p-6 space-y-6">
            {/* Quick KPI Cards Grid */}
            <div className="grid grid-cols-3 gap-3 font-mono text-xs">
              <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-3">
                <span className="text-slate-400 flex items-center gap-1 text-[11px] mb-1">
                  <Cpu className="h-3.5 w-3.5 text-sky-400" /> CPU 占用
                </span>
                <span className="text-lg font-bold text-slate-100 tabular-nums">
                  {fmtNumber(container?.cpu_percent)}%
                </span>
              </div>

              <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-3">
                <span className="text-slate-400 flex items-center gap-1 text-[11px] mb-1">
                  <HardDrive className="h-3.5 w-3.5 text-emerald-400" /> 内存使用
                </span>
                <span className="text-lg font-bold text-slate-100 tabular-nums">
                  {fmtNumber(container?.mem_percent)}%
                </span>
                <span className="text-[10px] text-slate-500 block truncate">
                  {fmtBytes(container?.mem_bytes)} / {fmtBytes(container?.mem_limit_bytes)}
                </span>
              </div>

              <div
                className={`rounded-xl border p-3 ${
                  inIpAlert
                    ? 'border-rose-500/40 bg-rose-950/30 text-rose-300'
                    : 'border-slate-800 bg-slate-950/60'
                }`}
              >
                <span className="text-slate-400 flex items-center gap-1 text-[11px] mb-1">
                  <Network className="h-3.5 w-3.5 text-amber-400" /> 入站去重 IP
                </span>
                <span className={`text-lg font-bold tabular-nums ${inIpAlert ? 'text-rose-400' : 'text-slate-100'}`}>
                  {inIps}
                </span>
                <span className="text-[10px] text-slate-500 block">
                  阈值：{inThresh} IPs
                </span>
              </div>
            </div>

            {/* Visual Charts: CPU & Memory */}
            <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-4">
              <h3 className="text-xs font-bold text-slate-200 mb-2 flex items-center gap-2">
                <Activity className="h-4 w-4 text-sky-400" />
                <span>CPU 与内存历史趋势 (24h)</span>
              </h3>
              <ResourceChart history={history} />
            </div>

            {/* Visual Charts: Network Bandwidth */}
            <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-4">
              <h3 className="text-xs font-bold text-slate-200 mb-2 flex items-center gap-2">
                <Network className="h-4 w-4 text-emerald-400" />
                <span>实时吞吐速率趋势 (RX & TX)</span>
              </h3>
              <NetworkChart history={history} />
            </div>

            {/* Security Checks & Surface Risk */}
            <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-4 space-y-3">
              <h3 className="text-xs font-bold text-slate-200 flex items-center gap-2">
                <Shield className="h-4 w-4 text-amber-400" />
                <span>安全合规与暴露面排查</span>
              </h3>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
                {/* SOCKS Check */}
                <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-3">
                  <span className="text-slate-400 block text-[11px]">SOCKS 代理服务</span>
                  <div className="mt-1 font-semibold">
                    {socks?.detected ? (
                      <span className="text-amber-400">
                        已检测 · {socks.auth_mode === 'no_auth' ? '无认证 (高危)' : socks.auth_mode}
                        {socks.public_exposure && ' · 公网暴露'}
                      </span>
                    ) : (
                      <span className="text-emerald-400">未发现可疑 SOCKS 代理</span>
                    )}
                  </div>
                </div>

                {/* Panel Pairing */}
                <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-3">
                  <span className="text-slate-400 block text-[11px]">第三方控制面板对接</span>
                  <div className="mt-1 font-semibold">
                    {pairing?.detected ? (
                      <span className={pairing.approved ? 'text-emerald-400' : 'text-rose-400'}>
                        {pairing.approved ? '已放行对接' : '检测到未授权面板特征'}
                      </span>
                    ) : (
                      <span className="text-emerald-400">未发现异常对接</span>
                    )}
                  </div>
                </div>
              </div>

              {/* If Risk is detected in SOCKS or Panel, show Quick Disposition Controls */}
              {((socks?.detected && (socks.auth_mode === 'no_auth' || socks.auth_mode === 'weak_password')) ||
                (pairing?.detected && !pairing.approved)) && (
                <div className="rounded-xl border border-rose-500/50 bg-rose-950/40 p-3.5 space-y-2.5">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2 text-rose-300 font-bold text-xs">
                      <AlertTriangle className="h-4 w-4 text-rose-400 animate-pulse" />
                      <span>检测到非合规安全风险需处置</span>
                    </div>
                  </div>
                  <p className="text-[11px] text-slate-300">
                    {socks?.detected && socks.auth_mode === 'no_auth'
                      ? '当前容器正在运行开放且无认证的 SOCKS 代理服务，极易被利用为跳板。'
                      : pairing?.detected && !pairing.approved
                      ? '当前容器检测到未经放行的第三方机场节点对接活动与内部特征。'
                      : '检测到运行风险，建议定向处置或加入安全白名单。'}
                  </p>
                  <div className="flex items-center gap-2 pt-1 flex-wrap">
                    <button
                      type="button"
                      disabled={isDrawerActionLoading}
                      onClick={() => handleDrawerDisposition('deny')}
                      className="flex items-center gap-1.5 rounded-lg border border-rose-500/60 bg-rose-950/90 px-3 py-1.5 text-xs font-semibold text-rose-200 hover:bg-rose-900 transition-all disabled:opacity-50 shadow-sm"
                    >
                      <Ban className="h-3.5 w-3.5" />
                      <span>{isDrawerActionLoading ? '处理中...' : '定向处置违规服务'}</span>
                    </button>
                    <button
                      type="button"
                      disabled={isDrawerActionLoading}
                      onClick={() => handleDrawerDisposition('allow_silent')}
                      className="flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-800/90 px-3 py-1.5 text-xs font-medium text-slate-300 hover:bg-slate-750 transition-all disabled:opacity-50"
                    >
                      <Check className="h-3.5 w-3.5 text-emerald-400" />
                      <span>放行此策略</span>
                    </button>
                    <button
                      type="button"
                      disabled={isDrawerActionLoading}
                      onClick={() => handleDrawerDisposition('resolve')}
                      className="flex items-center gap-1.5 rounded-lg border border-emerald-500/40 bg-emerald-950/40 px-3 py-1.5 text-xs font-medium text-emerald-300 hover:bg-emerald-900/60 transition-all disabled:opacity-50"
                    >
                      <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400" />
                      <span>标记已解决</span>
                    </button>
                  </div>
                </div>
              )}

              {/* Listening Ports & Exposure */}
              <div className="font-mono text-xs space-y-1 text-slate-300 pt-1">
                <div className="flex justify-between py-1 border-t border-slate-800/80">
                  <span className="text-slate-500">监听端口</span>
                  <span className="truncate max-w-xs">
                    {(sec.listening_ports || []).join(', ') || '无对外开放端口'}
                  </span>
                </div>
                <div className="flex justify-between py-1 border-t border-slate-800/80">
                  <span className="text-slate-500">NAT 暴露映射</span>
                  <span className="truncate max-w-xs">
                    {(sec.network_exposure || [])
                      .map((x) => `${x.listen} → ${x.target}`)
                      .join(', ') || '内部隔离'}
                  </span>
                </div>
                <div className="flex justify-between py-1 border-t border-slate-800/80">
                  <span className="text-slate-500">最高 CPU 进程</span>
                  <span className="text-sky-300 truncate max-w-xs" title={container?.top_cpu_process_command}>
                    {container?.top_cpu_process_command
                      ? `PID ${container.top_cpu_process_pid} (${fmtNumber(container.top_cpu_process_cpu_percent)}%) · ${container.top_cpu_process_command}`
                      : '无显著负载进程'}
                  </span>
                </div>
              </div>
            </div>

            {/* On-Demand Diagnostic Panel */}
            <DiagnosticPanel
              identity={identity}
              diagnostic={diagnostic}
              onRefresh={() => {
                api.getContainerDiagnostic(identity).then(setDiagnostic);
              }}
              onToast={onToast}
            />
          </div>
        </div>
      </div>
    </div>
  );
};
