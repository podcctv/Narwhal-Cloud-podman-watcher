import React, { useCallback, useEffect, useState } from 'react';
import { Clock3, LoaderCircle, RefreshCw, ShieldAlert } from 'lucide-react';
import { ContainerIdentity, ConnectionEvidenceResponse } from '../../api/types';
import { api } from '../../api/client';

const classificationLabel: Record<string, string> = {
  repeated_established_listener_transport: '重复连接到服务端口',
  repeated_uncompleted_multiport_probe: '重复未完成的多端口探测线索',
  mixed_repeated_listener_transport_and_probe_clues: '同时有服务连接与探测线索',
  mixed_single_sample_clues: '单次采样存在混合线索',
  insufficient_evidence: '证据不足',
};

const processNames = (items: unknown[]) => items.slice(0, 5).map((item) => {
  if (typeof item === 'string') return item;
  if (item && typeof item === 'object') {
    const row = item as Record<string, unknown>;
    const process = String(row.process || row.name || '未知进程');
    const pid = Number(row.pid || 0);
    return pid > 0 ? `${process} (PID ${pid})` : process;
  }
  return '';
}).filter(Boolean).join(', ');

export const ConnectionEvidenceTimeline: React.FC<{ identity: ContainerIdentity }> = ({ identity }) => {
  const [data, setData] = useState<ConnectionEvidenceResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const load = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      setData(await api.getConnectionEvidence(identity, 1440));
    } catch (err: any) {
      setError(err?.message || '读取连接证据失败');
    } finally {
      setLoading(false);
    }
  }, [identity.host_id, identity.runtime, identity.project, identity.container_name]);

  useEffect(() => { void load(); }, [load]);

  const assessments = data?.source_assessment?.assessments || [];
  const timeline = data?.timeline || [];

  return <section className="rounded-xl border border-sky-900/60 bg-slate-950/50 p-4" aria-label="连接来源证据时间线">
    <div className="flex flex-wrap items-center justify-between gap-2">
      <div className="flex items-center gap-2">
        <ShieldAlert className="h-4 w-4 text-sky-300" aria-hidden="true" />
        <h3 className="text-xs font-bold text-slate-100">连接来源证据 · 最近 24 小时</h3>
        {data && <span className="text-[10px] text-slate-500">{data.sample_count} 个采样</span>}
      </div>
      <button type="button" onClick={() => void load()} disabled={loading} className="inline-flex min-h-8 items-center gap-1.5 rounded-md border border-slate-700 bg-slate-900 px-2.5 text-[10px] text-slate-300 hover:bg-slate-800 disabled:opacity-50">
        {loading ? <LoaderCircle className="h-3 w-3 animate-spin" aria-hidden="true" /> : <RefreshCw className="h-3 w-3" aria-hidden="true" />}刷新证据
      </button>
    </div>
    {error ? <p className="mt-3 rounded-md border border-rose-900/50 bg-rose-950/20 p-2.5 text-xs text-rose-200">{error}</p>
      : !data && loading ? <p className="mt-3 flex items-center gap-2 text-xs text-slate-400"><LoaderCircle className="h-3.5 w-3.5 animate-spin" aria-hidden="true" />正在读取历史采样…</p>
      : data && <>
        <p className="mt-2 text-[10px] leading-4 text-slate-500">{data.interpretation}</p>
        <div className="mt-3 space-y-2">
          {assessments.length ? assessments.map((item: Record<string, any>) => <div key={item.ip} className="rounded-lg border border-slate-800 bg-slate-900/70 p-3">
            <div className="flex flex-wrap items-center gap-2">
              <code className="text-xs text-sky-200">{item.ip}</code>
              <span className={`rounded-full border px-2 py-0.5 text-[10px] ${item.classification === 'repeated_uncompleted_multiport_probe' ? 'border-amber-800 bg-amber-950/40 text-amber-200' : item.classification === 'repeated_established_listener_transport' ? 'border-emerald-800 bg-emerald-950/40 text-emerald-200' : 'border-slate-700 bg-slate-950 text-slate-300'}`}>
                {classificationLabel[item.classification] || '证据不足'}
              </span>
              <span className="text-[10px] text-slate-500">{item.sample_count || 0} 次采样 · 身份未确认</span>
            </div>
            <p className="mt-1 text-[10px] leading-4 text-slate-400">服务端口：{(item.service_ports || []).join(', ') || '无'} · 未监听端口：{(item.non_listener_ports || []).join(', ') || '无'} · 已建立连接峰值 {item.max_established_flows || 0} · 未完成连接峰值 {item.max_incomplete_flows || 0}</p>
          </div>) : <p className="rounded-lg border border-slate-800 bg-slate-900/70 p-3 text-[11px] text-slate-400">当前窗口没有足够的 conntrack 历史样本，不能判断来源行为。</p>}
        </div>
        <details className="mt-3 rounded-lg border border-slate-800 bg-slate-900/50 p-3">
          <summary className="cursor-pointer select-none text-[11px] font-medium text-slate-300">展开原始采样时间线（{timeline.length} 条）</summary>
          <div className="mt-2 max-h-80 space-y-2 overflow-auto pr-1">
            {[...timeline].reverse().slice(0, 20).map((sample) => <article key={sample.ts} className="rounded-md border border-slate-800 bg-slate-950/70 p-2.5">
              <div className="flex flex-wrap items-center gap-2 text-[10px] text-slate-400"><Clock3 className="h-3 w-3" aria-hidden="true" />{new Date(sample.ts * 1000).toLocaleString()} · 连接 {sample.connection_count} · 本机发起 {sample.process_attribution.confirmed_local} · 外部发起 {sample.process_attribution.confirmed_remote} · 方向未知 {sample.process_attribution.unknown_direction}</div>
              <div className="mt-1 text-[10px] text-slate-500">进程归属 {sample.process_attribution.attributed}/{sample.process_attribution.captured} · conntrack {sample.process_attribution.conntrack_available ? '可用' : '不可用'} · 日志请求 {sample.access_log.requests ?? '未采集'}</div>
              {sample.ips.length > 0 && <div className="mt-2 space-y-1">{sample.ips.map((entry) => <div key={entry.ip} className="break-words text-[10px] text-slate-300"><code>{entry.ip}</code> · {entry.inbound} 条入站连接 · {processNames(entry.processes) || '未关联到本机进程'} · {classificationLabel[entry.assessment?.classification] || '证据不足'} · AbuseIPDB {entry.abuseipdb?.status === 'checked' ? `缓存分 ${entry.abuseipdb?.abuse_confidence_score ?? '未知'}` : '无缓存结果'}</div>)}</div>}
            </article>)}
          </div>
        </details>
      </>}
  </section>;
};
