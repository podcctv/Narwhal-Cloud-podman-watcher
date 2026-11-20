import { useCallback, useEffect, useState } from 'react';
import { BellRing, RefreshCw, Save, Send } from 'lucide-react';
import { api, request } from '../../api/client';
import { ConfirmDialog } from '../common/ConfirmDialog';
import { ToastMessage } from '../common/Toast';

type Target = {
  host_id: string;
  runtime: string;
  project: string;
  container_name: string;
  machine_id: string;
  user_id: string;
  node_name: string;
  scope: 'user' | 'machine';
  enabled: boolean | number;
  source?: string;
  verified_at?: number;
};

type RecordItem = Target & {
  id: number;
  state: string;
  status: string;
  subject: string;
  message: string;
  last_error: string;
  attempts: number;
  due_at: number;
  machine_next_at: number;
  created_at: number;
  http_status: number;
};

type SyncState = {
  status: string;
  message: string;
  verified_at?: number;
  matched?: number;
  unmatched?: number;
  manual?: number;
};

type NoticeEvent = {
  id: number;
  notice_id: string;
  channel: 'telegram' | 'banner';
  status: string;
  attempt: number;
  ts: number;
  detail: string;
  host_id: string;
  runtime: string;
  project: string;
  container_name: string;
  subject: string;
};

type Data = {
  items: RecordItem[];
  counts: Record<string, number>;
  notice_channel_counts?: { telegram?: Record<string, number>; banner?: Record<string, number> };
  notice_events?: NoticeEvent[];
  targets: Target[];
  hosts: Target[];
  mapping_sync?: SyncState;
  mapping_issues?: (Target & { reason: string })[];
};

const EMPTY: Target = {
  host_id: '',
  runtime: '',
  project: '',
  container_name: '',
  machine_id: '',
  user_id: '',
  node_name: '',
  scope: 'user',
  enabled: true,
};

const LABELS: Record<string, string> = {
  blocked: '暂缓发送',
  queued: '待发送',
  retrying: '等待重试',
  sending: '发送中',
  succeeded: '成功',
  failed: '失败',
  uncertain: '结果不确定',
  cancelled: '状态变化已取消',
  expired: '已过期',
};

const stamp = (t: number) => (t ? new Date(t * 1000).toLocaleString('zh-CN') : '—');
const identity = (t: Target) => JSON.stringify([t.host_id, t.runtime, t.project, t.container_name]);

const statusPillClass = (status: string) => {
  if (status === 'succeeded') return 'rn2-pill rn2-pill-teal';
  if (['failed', 'uncertain'].includes(status)) return 'rn2-pill rn2-pill-crimson';
  if (['blocked', 'retrying', 'queued', 'sending'].includes(status)) return 'rn2-pill rn2-pill-amber';
  return 'rn2-pill rn2-pill-slate';
};

export function BuyerNotificationsView({
  onToast,
}: {
  onToast: (type: ToastMessage['type'], message: string) => void;
}) {
  const [data, setData] = useState<Data>({ items: [], counts: {}, targets: [], hosts: [] });
  const [form, setForm] = useState<Target>(EMPTY);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [preview, setPreview] = useState<{ subject?: string; body?: string; audience?: string } | null>(null);
  const [confirmation, setConfirmation] = useState<'target' | 'test' | 'sync' | RecordItem | null>(null);

  const load = useCallback(async () => {
    try {
      setData(await request<Data>('/api/v1/buyer/records'));
      setError('');
    } catch (e: any) {
      setError(e.message);
    }
  }, []);

  useEffect(() => {
    void load();
    const timer = setInterval(() => {
      if (!document.hidden) void load();
    }, 10000);
    return () => clearInterval(timer);
  }, [load]);

  const run = async (work: () => Promise<void>) => {
    setBusy(true);
    try {
      await work();
      await load();
    } catch (e: any) {
      onToast('error', e.message);
    } finally {
      setBusy(false);
      setConfirmation(null);
    }
  };

  const save = () =>
    run(async () => {
      await request('/api/v1/buyer/targets', {
        method: 'POST',
        body: JSON.stringify({
          ...form,
          enabled: Boolean(form.enabled),
          confirm_broadcast: form.scope === 'machine',
        }),
      });
      onToast('success', '精确收件映射已保存；不会发送测试通知');
    });

  const testPayload = () => ({
    narwhal_machine_id: form.machine_id,
    narwhal_node_name: form.node_name,
    user_id: form.user_id,
    scope: form.scope,
  });

  const makePreview = () =>
    run(async () => {
      const p = await api.testPushSettings(testPayload());
      setPreview(p);
    });

  const accept = () => {
    if (confirmation === 'target') return save();
    if (confirmation === 'sync') {
      return run(async () => {
        const result = await request<SyncState>('/api/v1/buyer/sync', { method: 'POST' });
        onToast(result.status === 'ok' ? 'success' : 'error', result.message);
      });
    }
    if (confirmation === 'test') {
      return run(async () => {
        const r = await api.testPushSettings({
          ...testPayload(),
          send: true,
          confirm_audience: preview?.audience,
          confirm_broadcast: form.scope === 'machine',
        });
        onToast(r.ok ? 'success' : 'error', r.message);
        setPreview(null);
      });
    }
    if (confirmation) {
      const row = confirmation;
      return run(async () => {
        await request(`/api/v1/buyer/records/${row.id}/retry`, {
          method: 'POST',
          body: JSON.stringify({ confirm_duplicate_risk: true }),
        });
        onToast('success', '已排队；不会绕过机器冷却期');
      });
    }
  };

  const change = (value: Partial<Target>) => {
    setForm((old) => ({ ...old, ...value }));
    setPreview(null);
  };

  const choose = (t: Target) => {
    const saved = data.targets.find((s) => identity(s) === identity(t));
    setForm(
      saved
        ? { ...saved, enabled: Boolean(saved.enabled) }
        : { ...EMPTY, host_id: t.host_id, runtime: t.runtime, project: t.project, container_name: t.container_name }
    );
    setPreview(null);
  };

  return (
    <section className="rn2-card min-w-0 overflow-hidden">
      <div className="rn2-card-head">
        <div className="flex min-w-0 items-center gap-3">
          <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl border border-[#54c7ff]/40 bg-[#087bff]/25 text-[#54c7ff]">
            <BellRing className="h-5 w-5" aria-hidden="true" />
          </div>
          <div className="min-w-0">
            <span className="rn2-eyebrow block">BUYER NOTIFICATIONS · AUDIT &amp; MAPPING</span>
            <h3 className="mt-0.5 text-base font-bold text-white">买家推送记录与收件范围</h3>
            <p className="mt-0.5 text-xs text-[#b9d3ee]">
              仅服务端发送；持久队列、机器级冷却、七天投递期限、九十天记录保留。
            </p>
          </div>
        </div>

        <button
          type="button"
          onClick={() => void load()}
          className="rn2-btn rn2-btn-ghost rn2-btn-sm min-w-11"
          aria-label="刷新买家推送记录"
        >
          <RefreshCw className="h-4 w-4" aria-hidden="true" />
          <span>刷新</span>
        </button>
      </div>

      <div className="space-y-5 p-5 sm:p-6 text-[#0b1636]">
        {error && (
          <p role="alert" className="rounded-xl border border-[#f9b8c4] bg-[#ffeef1] px-4 py-3 text-sm font-medium text-[#b41835]">
            {error}
          </p>
        )}

        <div className="flex flex-col gap-3 rounded-xl border border-[#d2dfec] bg-[#f4f8fd] p-4 sm:flex-row sm:items-center sm:justify-between">
          <div className="min-w-0 space-y-1.5 text-xs text-[#31485e] wrap-break-word">
            <p className={`font-semibold ${data.mapping_sync?.status === 'error' ? 'text-[#b41835]' : 'text-[#0657b8]'}`}>
              {data.mapping_sync?.message || '尚未同步上游收件关联'}
            </p>
            <p>
              每五分钟按唯一实例 UUID 和运行时关联指定买家；不会按相似主机名猜测，也不会自动整机广播。手工映射优先。
            </p>
            {data.mapping_sync?.verified_at && (
              <p className="font-mono text-[11px] font-semibold text-[#506483] tabular-nums">
                最近核验 {stamp(data.mapping_sync.verified_at)} · 已关联 {data.mapping_sync.matched || 0} · 待核查{' '}
                {data.mapping_sync.unmatched || 0} · 手工 {data.mapping_sync.manual || 0}
              </p>
            )}
          </div>
          <button
            type="button"
            disabled={busy}
            onClick={() => setConfirmation('sync')}
            className="rn2-btn rn2-btn-blue shrink-0"
          >
            同步上游收件关联
          </button>
        </div>

        {Object.keys(data.counts).length > 0 && (
          <div className="flex flex-wrap gap-2">
            {Object.entries(data.counts).map(([status, count]) => (
              <span
                key={status}
                className="inline-flex items-center gap-2 rounded-lg border border-[#cedae7] bg-[#f4f8fd] px-3 py-1.5 text-xs font-semibold text-[#0b1636] tabular-nums"
              >
                <span className="text-[#506483]">{LABELS[status] || status}</span>
                <span className="font-mono text-sm font-bold text-[#087bff]">{count}</span>
              </span>
            ))}
          </div>
        )}

        {data.notice_channel_counts && (
          <div className="grid gap-3 md:grid-cols-2">
            {(['telegram', 'banner'] as const).map((channel) => {
              const counts = data.notice_channel_counts?.[channel] || {};
              const pending = Object.entries(counts)
                .filter(([state]) => ['queued', 'blocked', 'sending', 'retrying', 'failed', 'uncertain'].includes(state))
                .reduce((sum, [, count]) => sum + count, 0);
              return (
                <div key={channel} className="rounded-xl border border-[#dce5ef] bg-[#f4f8fd] p-3.5">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <strong className="text-sm font-bold text-[#0b1636]">
                      {channel === 'telegram' ? 'Telegram 通知' : 'SSH Banner 提醒'}
                    </strong>
                    <span className={`rn2-pill rn2-pill-sm ${pending > 0 ? 'rn2-pill-amber' : 'rn2-pill-teal'} tabular-nums`}>
                      待处理 {pending}
                    </span>
                  </div>
                  <div className="mt-2.5 flex flex-wrap gap-2">
                    {Object.entries(counts).map(([state, count]) => (
                      <span
                        key={state}
                        className="rounded-md border border-[#cedae7] bg-white px-2.5 py-1 text-xs font-medium text-[#31485e] tabular-nums"
                      >
                        {LABELS[state] || state} <b className="font-mono text-[#0b1636]">{count}</b>
                      </span>
                    ))}
                  </div>
                </div>
              );
            })}
          </div>
        )}

        {!!data.notice_events?.length && (
          <details className="rounded-xl border border-[#cedae7] bg-[#f4f8fd] p-3.5">
            <summary className="cursor-pointer text-sm font-bold text-[#0b1636]">
              最近用户通知投递事件（{data.notice_events.length}）
            </summary>
            <div className="mt-3 grid gap-2.5 md:grid-cols-2">
              {data.notice_events.map((event) => (
                <article
                  key={event.id}
                  className="min-w-0 rounded-lg border border-[#cedae7] bg-white p-3 text-xs text-[#31485e]"
                >
                  <p className="flex flex-wrap items-center justify-between gap-2">
                    <strong className="text-[#0b1636]">
                      {event.channel === 'telegram' ? 'Telegram' : 'SSH Banner'} · {LABELS[event.status] || event.status}
                    </strong>
                    <span className="font-mono text-[#506483]">第 {event.attempt} 次</span>
                  </p>
                  <p className="mt-1 break-all font-mono text-[11px] text-[#0657b8]">
                    {event.host_id} / {event.runtime} / {event.project} / {event.container_name}
                  </p>
                  <p className="mt-1 text-[#31485e]">
                    {event.subject} · <span className="font-mono tabular-nums">{stamp(event.ts)}</span>
                  </p>
                  {event.detail && <p className="mt-1 break-words text-[#506483]">{event.detail}</p>}
                </article>
              ))}
            </div>
          </details>
        )}

        <form
          onSubmit={(e) => {
            e.preventDefault();
            if (form.scope === 'machine') {
              setConfirmation('target');
            } else {
              void save();
            }
          }}
          className="grid grid-cols-1 gap-3.5 rounded-xl border border-[#dce5ef] bg-[#f4f8fd] p-4 md:grid-cols-2 xl:grid-cols-3"
        >
          <label className="text-xs font-semibold text-[#31485e]">
            精确容器身份
            <select
              required
              value={identity(form)}
              onChange={(e) => {
                const t = data.hosts.find((item) => identity(item) === e.target.value);
                if (t) choose(t);
              }}
              className="rn2-select mt-1.5"
            >
              <option value={identity(EMPTY)}>选择主机 / 运行时 / 项目 / 容器</option>
              {data.hosts.map((t) => (
                <option key={identity(t)} value={identity(t)}>
                  {t.host_id} / {t.runtime} / {t.project} / {t.container_name}
                </option>
              ))}
            </select>
          </label>

          <label className="text-xs font-semibold text-[#31485e]">
            托管机器 UUID
            <input
              required
              value={form.machine_id}
              onChange={(e) => change({ machine_id: e.target.value })}
              className="rn2-input mt-1.5 font-mono"
            />
          </label>

          <label className="text-xs font-semibold text-[#31485e]">
            通知范围
            <select
              value={form.scope}
              onChange={(e) => change({ scope: e.target.value as Target['scope'] })}
              className="rn2-select mt-1.5"
            >
              <option value="user">仅指定买家（推荐）</option>
              <option value="machine">整机全部买家（广播）</option>
            </select>
          </label>

          <label className="text-xs font-semibold text-[#31485e]">
            买家 user_id
            <input
              required={form.scope === 'user'}
              disabled={form.scope !== 'user'}
              value={form.user_id}
              onChange={(e) => change({ user_id: e.target.value })}
              className="rn2-input mt-1.5 font-mono"
            />
          </label>

          <label className="text-xs font-semibold text-[#31485e]">
            节点显示名称
            <input
              value={form.node_name}
              onChange={(e) => change({ node_name: e.target.value })}
              className="rn2-input mt-1.5"
            />
          </label>

          <label className="flex min-h-11 cursor-pointer items-center gap-2.5 self-end rounded-xl border border-[#cedae7] bg-white px-3.5 text-sm font-semibold text-[#0b1636]">
            <input
              type="checkbox"
              checked={Boolean(form.enabled)}
              onChange={(e) => change({ enabled: e.target.checked })}
              className="h-4 w-4 accent-[#087bff]"
            />
            启用此映射
          </label>

          <div className="flex flex-wrap items-center gap-2.5 md:col-span-2 xl:col-span-3">
            {form.source === 'upstream' && (
              <p className="w-full text-xs font-medium text-[#0657b8]">
                已由上游实例核验关联；手工保存将改为人工维护，不再自动覆盖。
              </p>
            )}
            <button type="submit" disabled={busy || !form.host_id} className="rn2-btn rn2-btn-orange">
              <Save className="h-4 w-4" aria-hidden="true" />
              保存映射
            </button>
            <button type="button" disabled={busy} onClick={makePreview} className="rn2-btn rn2-btn-ghost">
              预览测试（不发送）
            </button>
          </div>
        </form>

        {preview && (
          <div className="rounded-xl border border-[#f7d58b] bg-[#fef6e4] p-4 text-sm text-[#0b1636] wrap-break-word">
            <p className="font-semibold text-[#9a5b00]">{preview.audience}</p>
            <p className="mt-2 font-bold text-[#0b1636]">{preview.subject}</p>
            <p className="mt-1 whitespace-pre-wrap text-xs leading-6 text-[#31485e]">{preview.body}</p>
            <button
              type="button"
              disabled={busy}
              onClick={() => setConfirmation('test')}
              className="rn2-btn rn2-btn-orange rn2-btn-sm mt-3"
            >
              <Send className="h-3.5 w-3.5" aria-hidden="true" />
              确认范围后真实测试
            </button>
          </div>
        )}

        {data.items.length > 0 ? (
          <div tabIndex={0} role="region" aria-label="买家推送审计记录表" className="rn2-table-wrap">
            <table className="w-full min-w-[820px] text-left text-xs">
              <thead className="bg-[#edf5fc] text-[11px] font-bold uppercase tracking-wider text-[#31485e]">
                <tr>
                  <th className="px-4 py-3">状态 / 记录</th>
                  <th className="px-4 py-3">通知主题与正文</th>
                  <th className="px-4 py-3">精确容器身份</th>
                  <th className="px-4 py-3">收件范围</th>
                  <th className="px-4 py-3">时间 / 尝试 / HTTP</th>
                  <th className="px-4 py-3 text-right">操作</th>
                </tr>
              </thead>
              <tbody>
                {data.items.map((r) => (
                  <tr key={r.id} className="align-top">
                    <td className="px-4 py-3.5">
                      <span className={statusPillClass(r.status)}>{LABELS[r.status] || r.status}</span>
                      <div className="mt-1.5 font-mono text-[11px] text-[#506483]">#{r.id}</div>
                    </td>
                    <td className="max-w-xs px-4 py-3.5">
                      <strong className="block text-sm font-bold text-[#0b1636]">{r.subject}</strong>
                      {r.last_error && <p className="mt-1 font-medium text-[#b41835] wrap-break-word">{r.last_error}</p>}
                      {r.status === 'blocked' && (
                        <p className="mt-1 font-medium text-[#9a5b00] wrap-break-word">
                          {data.mapping_issues?.find((t) => identity(t) === identity(r))?.reason}
                        </p>
                      )}
                      <details className="mt-1.5">
                        <summary className="min-h-8 cursor-pointer font-semibold text-[#087bff]">查看通知内容</summary>
                        <p className="mt-1 whitespace-pre-wrap rounded-lg border border-[#dce5ef] bg-[#f4f8fd] p-2.5 text-[11px] leading-5 text-[#31485e]">
                          {r.message}
                        </p>
                      </details>
                    </td>
                    <td className="px-4 py-3.5 font-mono text-[11px] text-[#31485e] break-all">
                      {r.host_id} / {r.runtime} / {r.project} / {r.container_name}
                    </td>
                    <td className="px-4 py-3.5 text-[#31485e] wrap-break-word">
                      {r.machine_id
                        ? `${r.machine_id} / ${r.scope === 'machine' ? '整机全部买家' : r.user_id || '买家未指定'}`
                        : ['cancelled', 'expired'].includes(r.status)
                          ? '历史记录未投递，无收件快照'
                          : '待关联上游买家'}
                    </td>
                    <td className="px-4 py-3.5 font-mono text-[11px] text-[#506483] tabular-nums">
                      <div>创建 {stamp(r.created_at)}</div>
                      <div className="mt-1">
                        尝试 {r.attempts} 次 · HTTP {r.http_status || '—'}
                      </div>
                      {['queued', 'retrying', 'blocked'].includes(r.status) && (
                        <div className="mt-1 text-[#9a5b00]">
                          最早下次尝试 {stamp(Math.max(r.due_at, r.machine_next_at))}
                        </div>
                      )}
                    </td>
                    <td className="px-4 py-3.5 text-right">
                      <div className="flex flex-col items-end gap-1.5">
                        {r.status === 'blocked' && (
                          <button
                            type="button"
                            disabled={busy}
                            onClick={() => choose(r)}
                            className="rn2-btn rn2-btn-blue rn2-btn-sm"
                          >
                            检查该容器关联
                          </button>
                        )}
                        {['failed', 'uncertain', 'blocked'].includes(r.status) && r.state !== 'test' && (
                          <button
                            type="button"
                            disabled={busy}
                            onClick={() => setConfirmation(r)}
                            className="rn2-btn rn2-btn-ghost rn2-btn-sm"
                          >
                            受控补发
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <p className="rounded-xl border border-dashed border-[#cedae7] bg-[#f4f8fd] p-6 text-center text-sm text-[#506483]">
            尚无投递记录。不会补发升级前的历史恢复消息。
          </p>
        )}
      </div>

      <ConfirmDialog
        open={Boolean(confirmation)}
        title={
          confirmation === 'sync'
            ? '同步精确收件关联'
            : confirmation === 'target'
              ? '确认整机买家广播'
              : confirmation === 'test'
                ? '发送真实测试通知'
                : '确认补发风险'
        }
        description={
          confirmation === 'sync'
            ? '读取上游实例并关联唯一 UUID 对应的买家。有效的待发告警将恢复正常投递；没有匹配或有冲突的记录仍暂停。不会发送测试通知或整机广播。'
            : confirmation === 'target'
              ? `该容器事件将发送给机器 ${form.machine_id} 的全部买家。`
              : confirmation === 'test'
                ? `${preview?.audience}。将发送真实通知并占用机器冷却额度。`
                : '网络失败可能发生在上游已接收之后；补发可能重复。请先核对上游记录。'
        }
        confirmLabel="确认"
        isSubmitting={busy}
        onCancel={() => setConfirmation(null)}
        onConfirm={accept}
      />
    </section>
  );
}
