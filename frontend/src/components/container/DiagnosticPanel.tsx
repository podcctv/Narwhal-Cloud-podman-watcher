import React, { useState } from 'react';
import { Sparkles, Terminal, Globe, AlertCircle, CheckCircle2, Clock } from 'lucide-react';
import { DiagnosticData, ContainerIdentity } from '../../api/types';
import { api, fmtBytes, fmtMbps, fmtNumber } from '../../api/client';

interface DiagnosticPanelProps {
  identity: ContainerIdentity;
  diagnostic: DiagnosticData | null;
  isStale?: boolean;
  onRefresh: () => void;
  onToast: (type: 'success' | 'error' | 'info', message: string) => void;
}

export const DiagnosticPanel: React.FC<DiagnosticPanelProps> = ({
  identity,
  diagnostic,
  isStale = false,
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
  const inboundIps = sample?.inbound_ips || (sample?.connection_ips || []).filter((ip) => Number(ip.inbound || 0) > 0);
  const outboundIps = sample?.outbound_ips || (sample?.connection_ips || []).filter((ip) => Number(ip.outbound || 0) > 0);

  const renderIpGroup = (title: string, description: string, ips: typeof inboundIps, direction: 'inbound' | 'outbound') => (
    <div>
      <h4 className="text-xs font-bold text-slate-200 mb-1 flex items-center gap-1.5">
        <Globe className={`h-3.5 w-3.5 ${direction === 'inbound' ? 'text-emerald-400' : 'text-sky-400'}`} />
        <span>{title} ({ips.length})</span>
      </h4>
      <p className="mb-2 text-[11px] text-slate-500">{description}</p>
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 max-h-52 overflow-y-auto font-mono text-xs">
        {ips.map((ip, idx) => (
          <div key={`${direction}-${ip.ip}-${idx}`} className="rounded-lg border border-slate-800 bg-slate-950/60 p-2">
            <div className="flex items-center justify-between gap-2 font-bold text-slate-200">
              <span className="break-all">{ip.ip}</span>
              <span className="shrink-0 text-slate-400">{direction === 'inbound' ? ip.inbound : ip.outbound} conns</span>
            </div>
            <div className="mt-1 text-[11px] text-slate-400">
              {[ip.country || 'UN', ip.region, ip.city].filter(Boolean).join(' · ')}
            </div>
            <div className="mt-0.5 break-words text-[11px] text-slate-500">
              运营商：{ip.isp || '暂未识别'}{ip.asn ? ` · AS${ip.asn}` : ''}
            </div>
            <div className="mt-0.5 break-words text-[11px] text-slate-500">
              关联进程：{ip.processes?.join('、') || 'unknown'}
            </div>
          </div>
        ))}
        {ips.length === 0 && <div className="text-[11px] text-slate-500">采样瞬间未发现可见的公网 IP。</div>}
      </div>
    </div>
  );

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
          disabled={submitting || isQueuedOrDispatched || !isSupportedRuntime || isStale}
          onClick={handleRequest}
          className="flex items-center gap-1.5 rounded-lg border border-sky-500/50 bg-sky-600 px-3 py-1.5 text-xs font-semibold text-white hover:bg-sky-500 transition-all disabled:opacity-50 shadow-sm shrink-0"
        >
          <Sparkles className="h-3.5 w-3.5" />
          <span>
            {submitting
              ? '提交中...'
              : isQueuedOrDispatched
              ? '等待上报中'
              : isStale
              ? '采样已过期'
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
        ) : isStale ? (
          <div className="flex items-center gap-2 rounded-lg border border-amber-500/30 bg-amber-950/40 p-2.5 text-xs text-amber-300">
            <AlertCircle className="h-4 w-4 shrink-0 text-amber-400" />
            <span>该容器的监控采样已过期，无法向 Agent 下发任务。请确认容器仍在运行并恢复监控后重试。</span>
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

          {renderIpGroup('接入容器的公网客户端', '通过监听端口或宿主机 NAT / Incus Proxy 还原的真实来源。', inboundIps, 'inbound')}
          {renderIpGroup('容器主动访问的公网目标', '由容器内进程主动建立的公网连接；已排除网桥、代理和其他私网地址。', outboundIps, 'outbound')}
        </div>
      )}
    </div>
  );
};
