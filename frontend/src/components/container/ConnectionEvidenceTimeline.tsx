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
  const attributionUnavailable = (sample: ConnectionEvidenceResponse['timeline'][number]) => {
    const attribution = sample.process_attribution;
    return attribution.status === 'unavailable'
      || (sample.connection_count > 0 && (attribution.captured === null || attribution.captured === 0));
  };
  const socketEvidenceSamples = timeline.filter((sample) => !attributionUnavailable(sample)
    && ['available', 'partial'].includes(sample.process_attribution.status)).length;
  const conntrackSamples = timeline.filter((sample) => !attributionUnavailable(sample)
    && sample.process_attribution.conntrack_available === true).length;

  return (
    <section className="rn2-card min-w-0 overflow-hidden bg-white" aria-label="连接来源证据时间线">
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-[#cedae7] bg-[#f4f8fd] px-4 py-3">
        <div className="flex flex-wrap items-center gap-2">
          <ShieldAlert className="h-4 w-4 text-[#087bff]" aria-hidden="true" />
          <h3 className="text-xs font-extrabold text-[#0e233c]">连接来源证据 · 最近 24 小时</h3>
          {data && (
            <span className="rounded-full border border-[#cedae7] bg-white px-2 py-0.5 text-[10px] font-semibold text-[#4a607a] tabular-nums">
              {data.sample_count} 条上报
            </span>
          )}
        </div>
        <button
          type="button"
          onClick={() => void load()}
          disabled={loading}
          className="inline-flex min-h-9 items-center gap-1.5 rounded-lg border border-[#cedae7] bg-white px-2.5 text-[11px] font-semibold text-[#0e233c] transition-colors hover:border-[#087bff] hover:bg-[#e8f3ff] hover:text-[#0657b8] disabled:opacity-50"
        >
          {loading ? <LoaderCircle className="h-3 w-3 animate-spin" aria-hidden="true" /> : <RefreshCw className="h-3 w-3" aria-hidden="true" />}
          刷新证据
        </button>
      </div>

      <div className="p-4">
        {error ? (
          <p className="rounded-lg border border-[#f1b4bf] bg-[#ffeef1] p-2.5 text-xs font-medium text-[#b41835]">
            {error}
          </p>
        ) : !data && loading ? (
          <p className="flex items-center gap-2 text-xs text-[#4a607a]">
            <LoaderCircle className="h-3.5 w-3.5 animate-spin text-[#087bff]" aria-hidden="true" />
            正在读取历史采样…
          </p>
        ) : data && (
          <>
            <p className="text-[11px] leading-4 text-[#4a607a]">{data.interpretation}</p>
            <div className="mt-3 space-y-2">
              {assessments.length ? assessments.map((item: Record<string, any>) => (
                <div key={item.ip} className="min-w-0 rounded-xl border border-[#d2dfec] bg-[#f4f8fd] p-3">
                  <div className="flex flex-wrap items-center gap-2">
                    <code className="min-w-0 break-all font-mono text-xs font-bold text-[#0e233c]">{item.ip}</code>
                    <span
                      className={`rounded-full border px-2 py-0.5 text-[10px] font-bold ${
                        item.classification === 'repeated_uncompleted_multiport_probe'
                          ? 'border-[#e8bf70] bg-[#fef6e4] text-[#9a5b00]'
                          : item.classification === 'repeated_established_listener_transport'
                            ? 'border-[#b4e4dc] bg-[#e6f7f4] text-[#147468]'
                            : 'border-[#cedae7] bg-white text-[#31485e]'
                      }`}
                    >
                      {classificationLabel[item.classification] || '证据不足'}
                    </span>
                    <span className="text-[10px] font-medium text-[#4a607a]">
                      {item.sample_count || 0} 次采样 · 身份未确认
                    </span>
                  </div>
                  <p className="mt-1.5 text-[11px] leading-4 text-[#31485e]">
                    服务端口：{(item.service_ports || []).join(', ') || '无'} · 未监听端口：{(item.non_listener_ports || []).join(', ') || '无'} · 已建立连接峰值 {item.max_established_flows || 0} · 未完成连接峰值 {item.max_incomplete_flows || 0}
                  </p>
                </div>
              )) : (
                <p className="rounded-xl border border-[#d2dfec] bg-[#f4f8fd] p-3 text-[11px] leading-5 text-[#31485e]">
                  {timeline.length === 0
                    ? '当前窗口没有历史采样，暂时不能判断来源行为。'
                    : socketEvidenceSamples > 0
                      ? `已取得 ${socketEvidenceSamples} 个逐连接样本，但只有 ${conntrackSamples} 个样本具备 conntrack 证据；不足以区分持续业务连接和外部探测。`
                      : '有基础连接数记录，但没有逐连接归属证据。旧版 Agent 未上报该字段，不能把缺失数据解释成“本机/外部发起为 0”；升级 Agent 后的新样本会补充证据。'}
                </p>
              )}
            </div>

            <details className="mt-3 rounded-xl border border-[#cedae7] bg-[#f4f8fd] p-3">
              <summary className="cursor-pointer select-none text-[11px] font-bold text-[#0e233c]">
                展开原始采样时间线（{timeline.length} 条）
              </summary>
              <div className="mt-2.5 max-h-80 space-y-2 overflow-auto pr-1">
                {[...timeline].reverse().slice(0, 20).map((sample) => (
                  <article key={sample.ts} className="min-w-0 rounded-lg border border-[#d2dfec] bg-white p-2.5">
                    <div className="flex flex-wrap items-center gap-2 text-[10px] font-semibold text-[#31485e]">
                      <Clock3 className="h-3 w-3 text-[#087bff]" aria-hidden="true" />
                      {new Date(sample.ts * 1000).toLocaleString()} · 连接 {sample.connection_count} ·{' '}
                      {attributionUnavailable(sample)
                        ? sample.connection_count > 0
                          ? '连接总数非零，但逐连接来源/PID 快照未采集'
                          : '来源与进程归属未采集'
                        : sample.process_attribution.status === 'no_connections'
                          ? '未观察到连接'
                          : sample.process_attribution.status === 'unavailable'
                            ? sample.process_attribution.reason === 'high_connection_count_socket_snapshot_empty'
                              ? '连接数非零，但逐连接来源/PID 快照为空'
                              : '来源与进程归属未采集'
                            : `本机发起 已确认 ${sample.process_attribution.confirmed_local ?? 0} / 推定 ${sample.process_attribution.probable_local ?? 0} · 外部发起 已确认 ${sample.process_attribution.confirmed_remote ?? 0} / 推定 ${sample.process_attribution.probable_remote ?? 0} · 方向未知 ${sample.process_attribution.unknown_direction ?? 0}`}
                    </div>
                    <div className="mt-1 text-[10px] text-[#4a607a]">
                      {attributionUnavailable(sample)
                        ? '逐连接样本、PID 归属和发起方向均未知，不能按 0 条判断'
                        : sample.process_attribution.captured === null
                          ? '没有逐连接样本'
                          : `逐连接样本 ${sample.process_attribution.captured} 条 · 进程归属 ${sample.process_attribution.attributed ?? 0} 条`}
                      {' · '}conntrack{' '}
                      {sample.process_attribution.conntrack_available === true
                        ? `可用${sample.process_attribution.conntrack_confirmed !== null ? `，五元组确认 ${sample.process_attribution.conntrack_confirmed} 条` : ''}`
                        : sample.process_attribution.conntrack_available === false
                          ? '不可用'
                          : '状态未上报'}
                      {sample.process_attribution.status === 'partial' ? ' · 采样不完整' : ''}
                      {' · '}日志请求 {sample.access_log.requests ?? '未采集'}
                    </div>
                    {sample.ips.length > 0 && (
                      <div className="mt-2 space-y-1 border-t border-[#e1ebf4] pt-1.5">
                        {sample.ips.map((entry) => (
                          <div key={entry.ip} className="min-w-0 break-words text-[10px] text-[#0b1636]">
                            <code className="break-all font-mono font-bold text-[#0657b8]">{entry.ip}</code> · {entry.inbound} 条入站连接 · 发起方向{' '}
                            {entry.origin_confidence === 'confirmed'
                              ? '已确认'
                              : entry.origin_confidence === 'probable'
                                ? '推定'
                                : '未知'}{' '}
                            · {processNames(entry.processes) || '未关联到本机进程'} ·{' '}
                            {classificationLabel[entry.assessment?.classification] || '证据不足'} · AbuseIPDB{' '}
                            {entry.abuseipdb?.status === 'checked'
                              ? `缓存分 ${entry.abuseipdb?.abuse_confidence_score ?? '未知'}`
                              : '无缓存结果'}
                          </div>
                        ))}
                      </div>
                    )}
                  </article>
                ))}
              </div>
            </details>
          </>
        )}
      </div>
    </section>
  );
};
