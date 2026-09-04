import React, { useState } from 'react';
import { Sparkles, Terminal, Globe, AlertCircle, CheckCircle2, Clock } from 'lucide-react';
import { DiagnosticData, ContainerIdentity } from '../../api/types';
import { api, fmtBytes, fmtMbps, fmtNumber } from '../../api/client';

interface DiagnosticPanelProps {
  identity: ContainerIdentity;
  diagnostic: DiagnosticData | null;
  onRefresh: () => void;
  onToast: (type: 'success' | 'error' | 'info', message: string) => void;
}

export const DiagnosticPanel: React.FC<DiagnosticPanelProps> = ({
  identity,
  diagnostic,
  onRefresh,
  onToast,
}) => {
  const [submitting, setSubmitting] = useState(false);

  const action = diagnostic?.action;
  const sample = diagnostic?.sample;
  const isQueuedOrDispatched =
    action && (action.status === 'queued' || action.status === 'dispatched');

  const handleRequest = async () => {
    if (submitting) return;
    setSubmitting(true);
    try {
      await api.requestContainerDiagnostic(identity);
      onToast('success', '已触发一次性深度采样请求');
      onRefresh();
    } catch (err: any) {
      onToast('error', `请求失败：${err.message || err}`);
    } finally {
      setSubmitting(false);
    }
  };

  const isSupportedRuntime = ['incus', 'podman'].includes(identity.runtime);

  return (
    <div className="rounded-xl border border-sky-500/30 bg-gradient-to-br from-slate-900 via-slate-900/90 to-sky-950/30 p-4 shadow-sm">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-slate-800">
        <div>
          <div className="flex items-center gap-2">
            <Sparkles className="h-4 w-4 text-sky-400" />
            <h3 className="text-sm font-bold text-slate-100">按需深度快照分析</h3>
          </div>
          <p className="text-xs text-slate-400 mt-0.5">
            仅在下一周期对容器做一次有界快照（不持续抓包、不全盘扫描）；完成后自动恢复普通采集。
          </p>
        </div>

        <button
          type="button"
          disabled={submitting || isQueuedOrDispatched || !isSupportedRuntime}
          onClick={handleRequest}
          className="flex items-center gap-1.5 rounded-lg border border-sky-500/50 bg-sky-600 px-3 py-1.5 text-xs font-semibold text-white hover:bg-sky-500 transition-all disabled:opacity-50 shadow-sm shrink-0"
        >
          <Sparkles className="h-3.5 w-3.5" />
          <span>
            {submitting
              ? '提交中...'
              : isQueuedOrDispatched
              ? '等待上报中'
              : '请求深度上报'}
          </span>
        </button>
      </div>

      {/* State Status Banner */}
      <div className="my-3">
        {!isSupportedRuntime ? (
          <div className="rounded-lg border border-amber-500/30 bg-amber-950/40 p-2.5 text-xs text-amber-300">
            Docker 默认仅提醒，当前节点不支持深度快照采集。
          </div>
        ) : action?.status === 'queued' ? (
          <div className="flex items-center gap-2 rounded-lg border border-sky-500/30 bg-sky-950/40 p-2.5 text-xs text-sky-300">
            <Clock className="h-4 w-4 animate-spin text-sky-400" />
            <span>任务 #{action.id} 已排队，等待节点守护进程领取（通常 10 秒内）...</span>
          </div>
        ) : action?.status === 'dispatched' ? (
          <div className="flex items-center gap-2 rounded-lg border border-sky-500/30 bg-sky-950/40 p-2.5 text-xs text-sky-300">
            <Clock className="h-4 w-4 animate-spin text-sky-400" />
            <span>任务 #{action.id} 已由节点领取，正在等待指标返回...</span>
          </div>
        ) : action?.status === 'succeeded' ? (
          <div className="flex items-center gap-2 rounded-lg border border-emerald-500/30 bg-emerald-950/40 p-2.5 text-xs text-emerald-300">
            <CheckCircle2 className="h-4 w-4 text-emerald-400" />
            <span>深度采样完成 · {action.updated_at_utc8 || '最新'}</span>
          </div>
        ) : action?.status === 'failed' ? (
          <div className="flex items-center gap-2 rounded-lg border border-rose-500/30 bg-rose-950/40 p-2.5 text-xs text-rose-300">
            <AlertCircle className="h-4 w-4 text-rose-400" />
            <span>采样失败：{action.result_message || '节点未返回报告'}</span>
          </div>
        ) : (
          <div className="text-xs text-slate-500">尚未请求深度上报快照。</div>
        )}
      </div>

      {/* Snapshot Data View */}
      {sample && (
        <div className="space-y-4 pt-2">
          {/* Rate Summary Cards */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 font-mono text-xs">
            <div className="rounded-lg border border-slate-800 bg-slate-950/60 p-2">
              <span className="text-slate-500 block text-[10px]">瞬时 RX 带宽</span>
              <span className="text-emerald-400 font-bold text-sm">
                {fmtMbps(sample.network_rates?.rx_bps)} Mbps
              </span>
            </div>
            <div className="rounded-lg border border-slate-800 bg-slate-950/60 p-2">
              <span className="text-slate-500 block text-[10px]">瞬时 TX 带宽</span>
              <span className="text-sky-400 font-bold text-sm">
                {fmtMbps(sample.network_rates?.tx_bps)} Mbps
              </span>
            </div>
            <div className="rounded-lg border border-slate-800 bg-slate-950/60 p-2">
              <span className="text-slate-500 block text-[10px]">连接 IP 数</span>
              <span className="text-slate-200 font-bold text-sm">
                {sample.unique_connection_ips || 0} IPs
              </span>
            </div>
            <div className="rounded-lg border border-slate-800 bg-slate-950/60 p-2">
              <span className="text-slate-500 block text-[10px]">进程数量</span>
              <span className="text-slate-200 font-bold text-sm">
                {sample.process_count || 0} Procs
              </span>
            </div>
          </div>

          {/* Detailed Processes Table */}
          {sample.processes?.items && sample.processes.items.length > 0 && (
            <div>
              <h4 className="text-xs font-bold text-slate-200 mb-2 flex items-center gap-1.5">
                <Terminal className="h-3.5 w-3.5 text-sky-400" />
                <span>快照进程列表 ({sample.processes.items.length})</span>
              </h4>
              <div className="max-h-48 overflow-y-auto rounded-lg border border-slate-800 bg-slate-950/60 divide-y divide-slate-800/60 font-mono text-xs">
                {sample.processes.items.map((p, idx) => (
                  <div key={idx} className="p-2.5 hover:bg-slate-900/60 transition-colors">
                    <div className="flex items-center justify-between text-slate-200 font-semibold">
                      <span>{p.process || 'unknown'} · PID {p.pid}</span>
                      <span className="text-sky-400">
                        CPU {fmtNumber(p.cpu_percent)}% · RSS {fmtBytes(p.rss_bytes)}
                      </span>
                    </div>
                    <div className="text-[11px] text-slate-400 truncate mt-1">
                      {p.command || '-'}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Connection IPs Breakdown */}
          {sample.connection_ips && sample.connection_ips.length > 0 && (
            <div>
              <h4 className="text-xs font-bold text-slate-200 mb-2 flex items-center gap-1.5">
                <Globe className="h-3.5 w-3.5 text-emerald-400" />
                <span>远端连接 IP 排查 ({sample.connection_ips.length})</span>
              </h4>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 max-h-40 overflow-y-auto font-mono text-xs">
                {sample.connection_ips.map((ip, idx) => (
                  <div key={idx} className="rounded-lg border border-slate-800 bg-slate-950/60 p-2">
                    <div className="flex items-center justify-between font-bold text-slate-200">
                      <span>{ip.ip}</span>
                      <span className="text-slate-400">{ip.connections} conns</span>
                    </div>
                    <div className="text-[11px] text-slate-500 mt-0.5 truncate">
                      归属：{ip.processes?.join(', ') || 'unknown'}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
