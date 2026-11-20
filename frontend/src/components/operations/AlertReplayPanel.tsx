import { useEffect, useMemo, useState } from 'react';
import { History, Search, ShieldCheck } from 'lucide-react';
import { request } from '../../api/client';
import { SpecCard } from '../../v2/components/Primitives';

type Data = Record<string, any>;
type Props = {
  inventory: Data[];
  initialReplays: Data[];
  onToast: (type: 'success' | 'error' | 'info', message: string) => void;
};

const categoryLabels: Record<string, string> = {
  likely_external_scan: '疑似外部扫描线索',
  legitimate_business: '疑似正常业务',
  false_positive: '误报',
  confirmed_abuse: '人工确认滥用',
  insufficient_evidence: '证据不足',
};
const classificationLabels: Record<string, string> = {
  repeated_established_listener_transport: '多次连接到容器监听服务',
  repeated_uncompleted_multiport_probe: '重复出现未完成的多端口探测线索',
  mixed_repeated_listener_transport_and_probe_clues: '监听连接与探测线索同时出现',
  mixed_single_sample_clues: '单次采样包含混合线索',
  insufficient_evidence: '证据不足',
};
const identity = (item: Data) => JSON.stringify([item.host_id, item.runtime, item.project || '', item.container_name]);
const date = (ts?: number) =>
  ts ? new Date(ts * 1000).toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai', hour12: false }) : '未知时间';

export function AlertReplayPanel({ inventory, initialReplays, onToast }: Props) {
  const options = useMemo(
    () => inventory.filter((item) => ['incus', 'podman', 'runman'].includes(item.runtime)),
    [inventory]
  );
  const [selected, setSelected] = useState('');
  const [minutes, setMinutes] = useState(60);
  const [replays, setReplays] = useState<Data[]>(initialReplays);
  const [active, setActive] = useState<Data | null>(initialReplays[0] || null);
  const [feedback, setFeedback] = useState<Record<string, { category: string; note: string }>>({});
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    setReplays(initialReplays);
    setActive((current) => current || initialReplays[0] || null);
  }, [initialReplays]);

  useEffect(() => {
    if (!selected && options.length) setSelected(identity(options[0]));
    if (selected && !options.some((item) => identity(item) === selected)) {
      setSelected(options.length ? identity(options[0]) : '');
    }
  }, [options, selected]);

  const selectedItem = options.find((item) => identity(item) === selected);
  const runReplay = async () => {
    if (!selectedItem || busy) return;
    setBusy(true);
    try {
      const result = await request<Data>('/api/v1/ops/alerts/replay', {
        method: 'POST',
        body: JSON.stringify({
          host_id: selectedItem.host_id,
          runtime: selectedItem.runtime,
          project: selectedItem.project || '',
          container_name: selectedItem.container_name,
          minutes,
        }),
      });
      setActive(result);
      setReplays((items) => [result, ...items.filter((item) => item.id !== result.id)].slice(0, 50));
      setFeedback({});
      onToast('success', '已完成历史采样回放；结果不会触发自动封禁');
    } catch (error) {
      onToast('error', error instanceof Error ? error.message : String(error));
    } finally {
      setBusy(false);
    }
  };

  const saveFeedback = async (replay: Data, sourceIp: string) => {
    const value = feedback[`${replay.id}:${sourceIp}`] || { category: 'insufficient_evidence', note: '' };
    setBusy(true);
    try {
      const result = await request<Data>(`/api/v1/ops/alerts/replays/${replay.id}/feedback`, {
        method: 'POST',
        body: JSON.stringify({ source_ip: sourceIp, category: value.category, note: value.note }),
      });
      setActive((current) =>
        current && current.id === replay.id ? { ...current, feedback: [result, ...(current.feedback || [])] } : current
      );
      setReplays((items) =>
        items.map((item) => (item.id === replay.id ? { ...item, feedback: [result, ...(item.feedback || [])] } : item))
      );
      onToast('success', '已保存人工判断；系统不会据此自动封禁');
    } catch (error) {
      onToast('error', error instanceof Error ? error.message : String(error));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="space-y-4 tabular-nums">
      <SpecCard
        eyebrow="CONNTRACK REPLAY · READ-ONLY"
        title={
          <span className="inline-flex items-center gap-2">
            <Search className="h-4 w-4 text-[#54c7ff]" aria-hidden="true" />
            <span>历史连接回放</span>
          </span>
        }
        bodyClassName="p-4 sm:p-5"
      >
        <p className="mb-4 text-xs leading-5 text-[#31485e]">
          按主机和容器重放已保存的 conntrack 来源采样，识别重复监听连接或多端口探测线索。连接特征不能证明用户身份或攻击意图；人工反馈只作审计记录，不改变保护、封禁或通知策略。
        </p>
        <div className="grid gap-3 sm:grid-cols-[minmax(0,1fr)_9.5rem_auto]">
          <label className="text-xs font-semibold text-[#31485e]">
            主机 / 容器 / 备注邮箱
            <select className="rn2-select mt-1.5" value={selected} onChange={(event) => setSelected(event.target.value)}>
              {!options.length && <option value="">暂无 Incus / Podman / Runman 服务清单</option>}
              {options.map((item) => (
                <option key={identity(item)} value={identity(item)}>
                  {item.host_id} / {item.runtime}
                  {item.project ? `/${item.project}` : ''} / {item.container_name}
                  {item.owner?.user_email ? ` · ${item.owner.user_email}` : ''}
                </option>
              ))}
            </select>
          </label>
          <label className="text-xs font-semibold text-[#31485e]">
            回放时间窗
            <select className="rn2-select mt-1.5" value={minutes} onChange={(event) => setMinutes(Number(event.target.value))}>
              {[15, 30, 60].map((value) => (
                <option key={value} value={value}>
                  {value} 分钟
                </option>
              ))}
            </select>
          </label>
          <button
            type="button"
            className="rn2-btn rn2-btn-orange self-end"
            disabled={!selectedItem || busy}
            onClick={() => void runReplay()}
          >
            {busy ? '处理中…' : '回放采样'}
          </button>
        </div>
        {!options.length && (
          <p className="mt-3 rounded-xl border border-[#f7d58b] bg-[#fef6e4] px-3 py-2 text-xs font-medium text-[#9a5b00]">
            需要新版 Agent 至少完成一次完整服务清单采样。
          </p>
        )}
      </SpecCard>

      {active && (
        <SpecCard
          eyebrow="REPLAY ASSESSMENT"
          title={
            <span className="wrap-break-word">
              回放 #{active.id} · {active.host_id} / {active.runtime}
              {active.project ? `/${active.project}` : ''} / {active.container_name}
            </span>
          }
          subtitle={
            <span className="font-mono">
              {date(active.created_at)} · {active.report_count} 条样本 · SHA256 {String(active.input_digest || '').slice(0, 12)}
            </span>
          }
          bodyClassName="p-4 sm:p-5"
        >
          <div className="mb-3 flex items-start gap-2 rounded-xl border border-[#a9d1ff] bg-[#e8f3ff] p-3 text-xs leading-5 text-[#08458c]">
            <ShieldCheck className="mt-0.5 h-4 w-4 shrink-0 text-[#087bff]" aria-hidden="true" />
            <span>判定仅反映传输层证据，不代表用户违规。没有足够连续采样时会显示“证据不足”。</span>
          </div>
          <p className="mb-3 text-xs text-[#31485e]">
            采样覆盖 {active.assessment?.conntrack_sample_count || 0} 次 conntrack，状态：
            {active.assessment?.status === 'available' ? '有连续证据' : '历史不足'}；身份已确认：否。
          </p>
          {!(active.assessment?.assessments || []).length && (
            <p className="py-5 text-sm text-[#697b9c]">该时间窗没有可分类的公开来源 IP，或 Agent 未采集到有效 conntrack 证据。</p>
          )}
          <div className="space-y-3">
            {(active.assessment?.assessments || []).map((item: Data) => {
              const key = `${active.id}:${item.ip}`;
              const value = feedback[key] || { category: 'insufficient_evidence', note: '' };
              return (
                <article key={item.ip} className="min-w-0 rounded-xl border border-[#cedae7] bg-[#f4f8fd] p-3.5">
                  <div className="flex flex-wrap items-start justify-between gap-2">
                    <div className="min-w-0">
                      <strong className="font-mono text-sm font-bold text-[#08458c]">{item.ip}</strong>
                      <p className="mt-1 text-xs text-[#31485e]">
                        {classificationLabels[item.classification] || item.classification} · {item.sample_count} 次 /{' '}
                        {Math.round((item.sample_span_seconds || 0) / 60)} 分钟
                      </p>
                    </div>
                    <span className="font-mono text-xs text-[#697b9c]">
                      最多已建立 {item.max_established_flows} · 未完成 {item.max_incomplete_flows}
                    </span>
                  </div>
                  <p className="mt-2 break-all text-xs text-[#697b9c]">
                    监听端口：{(item.service_ports || []).join(', ') || '无'} · 未监听端口探测线索：
                    {(item.non_listener_ports || []).join(', ') || '无'} · 用户身份未确认
                  </p>
                  <div className="mt-3 grid gap-2 sm:grid-cols-[12rem_minmax(0,1fr)_auto]">
                    <label className="text-xs font-semibold text-[#31485e]">
                      人工分类
                      <select
                        className="rn2-select mt-1.5"
                        value={value.category}
                        onChange={(event) =>
                          setFeedback((state) => ({ ...state, [key]: { ...value, category: event.target.value } }))
                        }
                      >
                        {Object.entries(categoryLabels).map(([code, label]) => (
                          <option key={code} value={code}>
                            {label}
                          </option>
                        ))}
                      </select>
                    </label>
                    <label className="text-xs font-semibold text-[#31485e]">
                      备注
                      <textarea
                        className="rn2-input mt-1.5 min-h-11"
                        maxLength={500}
                        value={value.note}
                        onChange={(event) =>
                          setFeedback((state) => ({ ...state, [key]: { ...value, note: event.target.value } }))
                        }
                        placeholder="记录判断依据；避免写入密码、Token 等敏感信息"
                      />
                    </label>
                    <button
                      type="button"
                      className="rn2-btn rn2-btn-blue self-end"
                      disabled={busy}
                      onClick={() => void saveFeedback(active, item.ip)}
                    >
                      保存判断
                    </button>
                  </div>
                  {(active.feedback || [])
                    .filter((entry: Data) => entry.source_ip === item.ip)
                    .slice(0, 3)
                    .map((entry: Data) => (
                      <p key={entry.id} className="mt-2 text-xs text-[#697b9c]">
                        历史人工判断：{categoryLabels[entry.category] || entry.category}
                        {entry.note ? ` · ${entry.note}` : ''} · {entry.requested_by} · {date(entry.created_at)}
                      </p>
                    ))}
                </article>
              );
            })}
          </div>
        </SpecCard>
      )}

      <SpecCard
        eyebrow="REPLAY HISTORY"
        title={
          <span className="inline-flex items-center gap-2">
            <History className="h-4 w-4 text-[#54c7ff]" aria-hidden="true" />
            <span>最近回放与人工记录</span>
          </span>
        }
        bodyClassName="p-4 sm:p-5"
      >
        {!replays.length && <p className="py-4 text-sm text-[#697b9c]">暂无回放记录。</p>}
        <div className="divide-y divide-[#dce5ef]">
          {replays.slice(0, 20).map((replay) => {
            const isActive = active?.id === replay.id;
            return (
              <button
                type="button"
                key={replay.id}
                onClick={() => setActive(replay)}
                className={`flex min-h-11 w-full flex-wrap items-center justify-between gap-2 rounded-lg px-2.5 py-2.5 text-left transition-colors ${
                  isActive ? 'bg-[#e8f3ff] font-semibold text-[#0657b8]' : 'text-[#0b1636] hover:bg-[#f4f8fd]'
                }`}
              >
                <span className="min-w-0 break-all text-sm">
                  #{replay.id} · {replay.host_id} / {replay.runtime}
                  {replay.project ? `/${replay.project}` : ''} / {replay.container_name}
                </span>
                <span className="text-xs text-[#697b9c]">
                  {replay.report_count} 样本 · {(replay.feedback || []).length} 条人工反馈 · {date(replay.created_at)}
                </span>
              </button>
            );
          })}
        </div>
      </SpecCard>
    </div>
  );
}
