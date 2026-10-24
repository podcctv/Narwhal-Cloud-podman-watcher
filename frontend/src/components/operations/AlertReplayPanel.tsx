import { useEffect, useMemo, useState } from 'react';
import { Search, ShieldCheck } from 'lucide-react';
import { request } from '../../api/client';

type Data = Record<string, any>;
type Props = {
  inventory: Data[];
  initialReplays: Data[];
  onToast: (type: 'success' | 'error' | 'info', message: string) => void;
};

const field = 'w-full min-w-0 rounded-lg border border-slate-700 bg-slate-950 p-2.5 text-sm text-slate-200';
const button = 'min-h-11 rounded-lg border border-sky-500/40 bg-sky-500/10 px-3 py-2 text-sm text-sky-200 hover:bg-sky-500/20 disabled:cursor-not-allowed disabled:opacity-40';
const categoryLabels: Record<string, string> = {
  likely_external_scan: '疑似外部扫描线索', legitimate_business: '疑似正常业务', false_positive: '误报',
  confirmed_abuse: '人工确认滥用', insufficient_evidence: '证据不足',
};
const classificationLabels: Record<string, string> = {
  repeated_established_listener_transport: '多次连接到容器监听服务',
  repeated_uncompleted_multiport_probe: '重复出现未完成的多端口探测线索',
  mixed_repeated_listener_transport_and_probe_clues: '监听连接与探测线索同时出现',
  mixed_single_sample_clues: '单次采样包含混合线索', insufficient_evidence: '证据不足',
};
const identity = (item: Data) => JSON.stringify([item.host_id, item.runtime, item.project || '', item.container_name]);
const date = (ts?: number) => ts ? new Date(ts * 1000).toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai', hour12: false }) : '未知时间';

export function AlertReplayPanel({ inventory, initialReplays, onToast }: Props) {
  const options = useMemo(() => inventory.filter(item => ['incus', 'podman'].includes(item.runtime)), [inventory]);
  const [selected, setSelected] = useState('');
  const [minutes, setMinutes] = useState(60);
  const [replays, setReplays] = useState<Data[]>(initialReplays);
  const [active, setActive] = useState<Data | null>(initialReplays[0] || null);
  const [feedback, setFeedback] = useState<Record<string, { category: string; note: string }>>({});
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    setReplays(initialReplays);
    setActive(current => current || initialReplays[0] || null);
  }, [initialReplays]);
  useEffect(() => {
    if (!selected && options.length) setSelected(identity(options[0]));
    if (selected && !options.some(item => identity(item) === selected)) setSelected(options.length ? identity(options[0]) : '');
  }, [options, selected]);

  const selectedItem = options.find(item => identity(item) === selected);
  const runReplay = async () => {
    if (!selectedItem || busy) return;
    setBusy(true);
    try {
      const result = await request<Data>('/api/v1/ops/alerts/replay', {
        method: 'POST',
        body: JSON.stringify({ host_id: selectedItem.host_id, runtime: selectedItem.runtime, project: selectedItem.project || '', container_name: selectedItem.container_name, minutes }),
      });
      setActive(result);
      setReplays(items => [result, ...items.filter(item => item.id !== result.id)].slice(0, 50));
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
        method: 'POST', body: JSON.stringify({ source_ip: sourceIp, category: value.category, note: value.note }),
      });
      setActive(current => current && current.id === replay.id ? { ...current, feedback: [result, ...(current.feedback || [])] } : current);
      setReplays(items => items.map(item => item.id === replay.id ? { ...item, feedback: [result, ...(item.feedback || [])] } : item));
      onToast('success', '已保存人工判断；系统不会据此自动封禁');
    } catch (error) {
      onToast('error', error instanceof Error ? error.message : String(error));
    } finally {
      setBusy(false);
    }
  };

  return <div className="space-y-4">
    <section className="min-w-0 rounded-xl border border-slate-800 bg-slate-900/50 p-4">
      <h3 className="mb-2 flex items-center gap-2 text-sm font-semibold text-slate-200"><Search className="h-4 w-4 text-sky-300" />历史连接回放</h3>
      <p className="mb-4 text-xs leading-5 text-slate-400">按主机和容器重放已保存的 conntrack 来源采样，识别重复监听连接或多端口探测线索。连接特征不能证明用户身份或攻击意图；人工反馈只作审计记录，不改变保护、封禁或通知策略。</p>
      <div className="grid gap-3 sm:grid-cols-[minmax(0,1fr)_9rem_auto]">
        <label className="text-xs text-slate-400">主机 / 容器 / 备注邮箱
          <select className={`${field} mt-1`} value={selected} onChange={event => setSelected(event.target.value)}>
            {!options.length && <option value="">暂无 Incus / Podman 服务清单</option>}
            {options.map(item => <option key={identity(item)} value={identity(item)}>{item.host_id} / {item.runtime}{item.project ? `/${item.project}` : ''} / {item.container_name}{item.owner?.user_email ? ` · ${item.owner.user_email}` : ''}</option>)}
          </select>
        </label>
        <label className="text-xs text-slate-400">回放时间窗
          <select className={`${field} mt-1`} value={minutes} onChange={event => setMinutes(Number(event.target.value))}>
            {[15, 30, 60].map(value => <option key={value} value={value}>{value} 分钟</option>)}
          </select>
        </label>
        <button className={`${button} self-end`} disabled={!selectedItem || busy} onClick={() => void runReplay()}>{busy ? '处理中…' : '回放采样'}</button>
      </div>
      {!options.length && <p className="mt-3 text-xs text-amber-200">需要新版 Agent 至少完成一次完整服务清单采样。</p>}
    </section>

    {active && <section className="min-w-0 rounded-xl border border-slate-800 bg-slate-900/50 p-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h3 className="text-sm font-semibold text-slate-200">回放 #{active.id} · {active.host_id} / {active.runtime}{active.project ? `/${active.project}` : ''} / {active.container_name}</h3>
        <span className="text-xs text-slate-500">{date(active.created_at)} · {active.report_count} 条样本 · SHA256 {String(active.input_digest || '').slice(0, 12)}</span>
      </div>
      <div className="my-3 flex items-start gap-2 rounded-lg border border-sky-900/70 bg-sky-950/30 p-3 text-xs leading-5 text-sky-100"><ShieldCheck className="mt-0.5 h-4 w-4 shrink-0" />判定仅反映传输层证据，不代表用户违规。没有足够连续采样时会显示“证据不足”。</div>
      <p className="mb-3 text-xs text-slate-400">采样覆盖 {active.assessment?.conntrack_sample_count || 0} 次 conntrack，状态：{active.assessment?.status === 'available' ? '有连续证据' : '历史不足'}；身份已确认：否。</p>
      {!(active.assessment?.assessments || []).length && <p className="py-5 text-sm text-slate-400">该时间窗没有可分类的公开来源 IP，或 Agent 未采集到有效 conntrack 证据。</p>}
      <div className="space-y-3">{(active.assessment?.assessments || []).map((item: Data) => {
        const key = `${active.id}:${item.ip}`;
        const value = feedback[key] || { category: 'insufficient_evidence', note: '' };
        return <article key={item.ip} className="min-w-0 rounded-lg border border-slate-800 bg-slate-950/60 p-3">
          <div className="flex flex-wrap items-start justify-between gap-2">
            <div className="min-w-0"><strong className="font-mono text-sm text-sky-200">{item.ip}</strong><p className="mt-1 text-xs text-slate-300">{classificationLabels[item.classification] || item.classification} · {item.sample_count} 次 / {Math.round((item.sample_span_seconds || 0) / 60)} 分钟</p></div>
            <span className="text-xs text-slate-500">最多已建立 {item.max_established_flows} · 未完成 {item.max_incomplete_flows}</span>
          </div>
          <p className="mt-2 break-all text-xs text-slate-400">监听端口：{(item.service_ports || []).join(', ') || '无'} · 未监听端口探测线索：{(item.non_listener_ports || []).join(', ') || '无'} · 用户身份未确认</p>
          <div className="mt-3 grid gap-2 sm:grid-cols-[12rem_minmax(0,1fr)_auto]">
            <label className="text-xs text-slate-400">人工分类<select className={`${field} mt-1`} value={value.category} onChange={event => setFeedback(state => ({ ...state, [key]: { ...value, category: event.target.value } }))}>{Object.entries(categoryLabels).map(([code, label]) => <option key={code} value={code}>{label}</option>)}</select></label>
            <label className="text-xs text-slate-400">备注<textarea className={`${field} mt-1 min-h-11`} maxLength={500} value={value.note} onChange={event => setFeedback(state => ({ ...state, [key]: { ...value, note: event.target.value } }))} placeholder="记录判断依据；避免写入密码、Token 等敏感信息" /></label>
            <button className={`${button} self-end`} disabled={busy} onClick={() => void saveFeedback(active, item.ip)}>保存判断</button>
          </div>
          {(active.feedback || []).filter((entry: Data) => entry.source_ip === item.ip).slice(0, 3).map((entry: Data) => <p key={entry.id} className="mt-2 text-xs text-slate-500">历史人工判断：{categoryLabels[entry.category] || entry.category}{entry.note ? ` · ${entry.note}` : ''} · {entry.requested_by} · {date(entry.created_at)}</p>)}
        </article>;
      })}</div>
    </section>}

    <section className="min-w-0 rounded-xl border border-slate-800 bg-slate-900/50 p-4">
      <h3 className="mb-3 text-sm font-semibold text-slate-200">最近回放与人工记录</h3>
      {!replays.length && <p className="py-4 text-sm text-slate-400">暂无回放记录。</p>}
      {replays.slice(0, 20).map(replay => <button type="button" key={replay.id} onClick={() => setActive(replay)} className={`flex w-full flex-wrap items-center justify-between gap-2 border-t border-slate-800 py-3 text-left ${active?.id === replay.id ? 'text-sky-200' : 'text-slate-300'}`}>
        <span className="min-w-0 break-all text-sm">#{replay.id} · {replay.host_id} / {replay.runtime}{replay.project ? `/${replay.project}` : ''} / {replay.container_name}</span>
        <span className="text-xs text-slate-500">{replay.report_count} 样本 · {(replay.feedback || []).length} 条人工反馈 · {date(replay.created_at)}</span>
      </button>)}
    </section>
  </div>;
}
