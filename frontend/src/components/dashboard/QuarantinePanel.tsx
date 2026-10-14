import React, { useCallback, useEffect, useState } from 'react';
import { LockKeyhole, UnlockKeyhole, AlertTriangle, RefreshCw } from 'lucide-react';
import { request } from '../../api/client';
import { ConfirmDialog } from '../common/ConfirmDialog';

interface Quarantine {
  alert_id: number;
  host_id: string;
  runtime: string;
  project: string;
  container_name: string;
  instance_id: string;
  status: string;
  title: string;
  message: string;
  updated_at: number;
  host_last_seen: number | null;
  release_action_status: string | null;
  details: { abuse_evidence?: Array<{ kind: string; pid: number; source_sha256?: string;
    features?: { corroborating_samples?: number; concurrency?: number } }> };
}

const labels: Record<string, string> = {
  outbound_scan: '对外扫描', authentication_bruteforce: '认证爆破',
  credential_stuffing: '撞库', identity_enumeration: '身份信息枚举',
};

export const QuarantinePanel: React.FC<{
  onToast: (type: 'success' | 'error' | 'info', message: string) => void;
}> = ({ onToast }) => {
  const [items, setItems] = useState<Quarantine[]>([]);
  const [error, setError] = useState('');
  const [selected, setSelected] = useState<Quarantine | null>(null);
  const [busy, setBusy] = useState(false);
  const [queued, setQueued] = useState<Set<number>>(new Set());

  const refresh = useCallback(async (signal?: AbortSignal) => {
    try {
      const result = await request<{ items: Quarantine[] }>('/api/v1/security/quarantines', { signal });
      setItems(result.items);
      setQueued(previous => new Set([...previous].filter(id => result.items.some(item =>
        item.alert_id === id && ['queued', 'dispatched'].includes(item.release_action_status || '')))));
      setError('');
    } catch (err: any) {
      if (err.name !== 'AbortError') setError('隔离状态暂时无法读取；不能据此认为网络已恢复。');
    }
  }, []);

  useEffect(() => {
    const controller = new AbortController();
    void refresh(controller.signal);
    const timer = window.setInterval(() => {
      if (!document.hidden) void refresh(controller.signal);
    }, 10000);
    return () => { controller.abort(); window.clearInterval(timer); };
  }, [refresh]);

  const release = async () => {
    if (!selected) return;
    setBusy(true);
    try {
      const result = await request<{ queued: boolean }>(`/api/v1/security/alerts/${selected.alert_id}/release-quarantine`, {
        method: 'POST', body: JSON.stringify({ confirmed: true }),
      });
      setQueued(previous => new Set(previous).add(selected.alert_id));
      onToast('info', result.queued ? '解除隔离指令已排队，等待节点验证恢复；不等于风险已消除。' : '已有解除隔离指令正在执行，请等待节点回执。');
      setSelected(null);
      await refresh();
    } catch (err: any) {
      onToast('error', err.status === 403 ? '仅管理员可以复核解除隔离。' : `解除隔离失败：${err.message || err}`);
    } finally {
      setBusy(false);
    }
  };

  if (!items.length && !error) return null;
  return (
    <section className="mb-6 overflow-hidden rounded-2xl border border-rose-500/40 bg-slate-900" aria-labelledby="quarantine-title">
      <div className="flex items-center justify-between gap-3 border-b border-slate-700 px-5 py-4">
        <div className="flex items-center gap-3">
          <LockKeyhole className="h-5 w-5 shrink-0 text-rose-300" aria-hidden="true" />
          <div>
            <h2 id="quarantine-title" className="text-sm font-bold text-slate-100">违规活动隔离 · 待管理员复核</h2>
            <p className="mt-1 text-xs leading-5 text-slate-300">只处理多次佐证的高置信度行为；隔离全部受管入站和出站，保留容器、磁盘和证据。</p>
          </div>
        </div>
        <button type="button" onClick={() => void refresh()} className="min-h-11 rounded-lg border border-slate-600 px-3 text-sky-300 hover:bg-slate-800 focus:outline-none focus:ring-2 focus:ring-sky-400" aria-label="刷新隔离状态">
          <RefreshCw className="h-4 w-4" />
        </button>
      </div>
      {error && <p role="alert" className="px-5 py-3 text-sm text-amber-300">{error}</p>}
      <div className="divide-y divide-slate-700">
        {items.map(item => {
          const stale = !item.host_last_seen || Date.now()/1000-item.host_last_seen > 900 || Date.now()/1000-item.updated_at > 900;
          const isolated = item.status === 'isolated' && !stale;
          const pending = queued.has(item.alert_id) || ['queued', 'dispatched'].includes(item.release_action_status || '');
          return (
            <article key={`${item.alert_id}:${item.instance_id}`} className="space-y-3 p-5">
              <div className="flex flex-wrap items-center gap-2">
                <span className={`rounded-md border px-2 py-1 text-xs font-semibold ${isolated ? 'border-rose-500/50 bg-rose-950 text-rose-200' : 'border-amber-500/50 bg-amber-950 text-amber-200'}`}>
                  {stale ? '节点或隔离采样已过期 · 当前状态待确认' : item.status === 'isolated' ? '已双向隔离' : item.status === 'release_failed' ? '解除隔离未验证成功' : '隔离未能完整验证'}
                </span>
                <span className="text-sm font-semibold text-slate-100">{item.title}</span>
              </div>
              <p className="break-all font-mono text-xs text-slate-300">{item.host_id} · {item.runtime}/{item.project || '-'} · {item.container_name}</p>
              <p className="text-sm leading-6 text-slate-200">{stale ? '以下为最近一次隔离记录，不表示当前网络状态已验证。' : item.message}</p>
              <ul className="space-y-1 rounded-lg border border-slate-700 bg-slate-950/70 p-3 text-xs leading-6 text-slate-300">
                {(item.details.abuse_evidence || []).slice(0, 5).map((proof, index) => (
                  <li key={index} className="break-all tabular-nums">
                    {labels[proof.kind] || proof.kind} · PID {proof.pid} · 连续佐证 {proof.features?.corroborating_samples || '-'} 次
                    {!!proof.features?.concurrency && ` · 并发配置 ${proof.features.concurrency}`}
                    {proof.source_sha256 && ` · 入口文件 SHA256 ${proof.source_sha256.slice(0, 12)}`}
                  </li>
                ))}
              </ul>
              <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                <p className="flex items-center gap-2 text-xs text-amber-200"><AlertTriangle className="h-4 w-4 shrink-0" aria-hidden="true" />隔离会阻断 SSH；请通过宿主机控制台排查。解除不代表风险已恢复。</p>
                <button type="button" disabled={stale || busy || pending} onClick={() => setSelected(item)} className="flex min-h-11 shrink-0 items-center justify-center gap-2 rounded-lg border border-sky-500/60 bg-sky-950 px-4 text-xs font-semibold text-sky-100 hover:bg-sky-900 focus:outline-none focus:ring-2 focus:ring-sky-400 disabled:cursor-not-allowed disabled:opacity-50">
                  <UnlockKeyhole className="h-4 w-4" aria-hidden="true" />{pending ? '等待解除隔离回执' : '管理员复核后解除隔离'}
                </button>
              </div>
            </article>
          );
        })}
      </div>
      <ConfirmDialog open={!!selected} title="确认已完成排查并解除隔离？" description="将恢复该实例隔离前的受管网络连接，可能重新开放公网服务。容器与磁盘不会删除。请先通过宿主机控制台处置违规程序；若再次命中确凿特征，会重新隔离并告警。解除操作不等于风险已复查通过。" confirmLabel="确认复核并恢复网络" tone="danger" isSubmitting={busy} onConfirm={() => void release()} onCancel={() => { if (!busy) setSelected(null); }} />
    </section>
  );
};

