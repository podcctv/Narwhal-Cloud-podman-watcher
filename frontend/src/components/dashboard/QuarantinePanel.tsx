import React, { useCallback, useEffect, useState } from 'react';
import { LockKeyhole, UnlockKeyhole, AlertTriangle, RefreshCw, Archive } from 'lucide-react';
import { api, request } from '../../api/client';
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
  host_agent_version: string | null;
  replacement_review_supported: boolean;
  release_action_status: string | null;
  replacement_action_status: string | null;
  details: { abuse_evidence?: Array<{ kind: string; pid: number; source_sha256?: string; tool?: string;
    pending_attempts?: number; vertical_ports?: number; horizontal_targets?: number;
    pending_ratio?: number; failed_ratio?: number;
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
  const [role, setRole] = useState<'unknown' | 'viewer' | 'operator' | 'admin'>('unknown');
  const [roleUnavailable, setRoleUnavailable] = useState(false);
  const [selected, setSelected] = useState<Quarantine | null>(null);
  const [selectedAction, setSelectedAction] = useState<'release' | 'replace' | null>(null);
  const [busy, setBusy] = useState(false);
  const [queuedActionByAlert, setQueuedActionByAlert] = useState<Map<number, 'release' | 'replace'>>(new Map());

  const refresh = useCallback(async (signal?: AbortSignal) => {
    try {
      const result = await request<{ items: Quarantine[] }>('/api/v1/security/quarantines', { signal });
      setItems(result.items);
      const activeStatuses = ['queued', 'dispatched', 'running'];
      setQueuedActionByAlert(previous => new Map([...previous].filter(([id, action]) => {
        const item = result.items.find(candidate => candidate.alert_id === id);
        if (!item) return false;
        const status = action === 'replace' ? item.replacement_action_status : item.release_action_status;
        return activeStatuses.includes(status || '');
      })));
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

  useEffect(() => {
    const controller = new AbortController();
    void request<{ role: string }>('/api/v1/ops/session', { signal: controller.signal })
      .then(session => {
        setRoleUnavailable(false);
        setRole(session.role === 'admin' ? 'admin' : session.role === 'operator' ? 'operator' : 'viewer');
      })
      .catch(() => { if (!controller.signal.aborted) setRoleUnavailable(true); });
    return () => controller.abort();
  }, []);

  const submitReview = async () => {
    if (!selected) return;
    setBusy(true);
    try {
      const result = selectedAction === 'replace'
        ? await api.confirmReplacedQuarantine(selected.alert_id)
        : await request<{ queued: boolean }>(`/api/v1/security/alerts/${selected.alert_id}/release-quarantine`, {
          method: 'POST', body: JSON.stringify({ confirmed: true }),
        });
      setQueuedActionByAlert(previous => new Map(previous).set(selected.alert_id, selectedAction || 'release'));
      const message = selectedAction === 'replace'
        ? '容器身份核验已排队；只有旧实例确认不存在后才会归档，不会改动新容器网络。'
        : '解除隔离指令已排队，等待节点验证恢复；不等于风险已消除。';
      onToast('info', result.queued ? message : '已有复核指令正在执行，请等待节点回执。');
      setSelected(null);
      setSelectedAction(null);
      await refresh();
    } catch (err: any) {
      const actionLabel = selectedAction === 'replace' ? '容器重装核验' : '解除隔离复核';
      onToast('error', err.status === 403 ? '仅管理员可以复核隔离事件。' : `${actionLabel}失败：${err.message || err}`);
    } finally {
      setBusy(false);
    }
  };

  if (!items.length && !error) return null;
  return (
    <section id="quarantine-review" tabIndex={-1} className="mb-6 overflow-hidden rounded-2xl border border-rose-500/40 bg-linear-to-b from-rose-950/20 via-slate-900/95 to-slate-900 shadow-lg focus:outline-hidden focus-visible:ring-2 focus-visible:ring-rose-400" aria-labelledby="quarantine-title">
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-800 bg-rose-950/20 px-4 py-3.5 sm:px-5 sm:py-4">
        <div className="flex items-center gap-3 min-w-0">
          <div className="rounded-xl border border-rose-500/35 bg-rose-500/15 p-2 text-rose-300 shrink-0">
            <LockKeyhole className="h-5 w-5" aria-hidden="true" />
          </div>
          <div className="min-w-0">
            <h2 id="quarantine-title" className="text-sm font-bold text-slate-100">违规活动隔离 · 待管理员复核</h2>
            <p className="mt-0.5 text-xs leading-5 text-slate-300">只处理多次佐证的高置信度行为；隔离全部受管入站和出站，保留容器、磁盘和证据。</p>
          </div>
        </div>
        <button type="button" onClick={() => void refresh()} className="inline-flex min-h-11 min-w-11 shrink-0 items-center justify-center rounded-xl border border-slate-700 bg-slate-900/80 px-3 text-sky-300 transition-colors hover:bg-slate-800 focus:outline-hidden focus:ring-2 focus:ring-sky-400" aria-label="刷新隔离状态">
          <RefreshCw className="h-4 w-4" />
        </button>
      </div>
      {error && <p role="alert" className="px-4 py-3 text-sm text-amber-300 sm:px-5">{error}</p>}
      <div className="divide-y divide-slate-800/90">
        {items.map(item => {
          const hostAge = item.host_last_seen ? Date.now()/1000-item.host_last_seen : Number.POSITIVE_INFINITY;
          const hostStale = hostAge < 0 || hostAge > 900;
          const recordOld = Date.now()/1000-item.updated_at > 900;
          const activeStatuses = ['queued', 'dispatched', 'running'];
          const releasePending = queuedActionByAlert.get(item.alert_id) === 'release' ||
            activeStatuses.includes(item.release_action_status || '');
          const replacementPending = queuedActionByAlert.get(item.alert_id) === 'replace' ||
            activeStatuses.includes(item.replacement_action_status || '');
          const pending = releasePending || replacementPending;
          return (
            <article key={`${item.alert_id}:${item.instance_id}`} className="space-y-3 p-5">
              <div className="flex flex-wrap items-center gap-2">
                <span className={`rounded-md border px-2 py-1 text-xs font-semibold ${item.status === 'isolated' ? 'border-rose-500/50 bg-rose-950 text-rose-200' : 'border-amber-500/50 bg-amber-950 text-amber-200'}`}>
                  {item.status === 'isolated' ? '已双向隔离' : item.status === 'release_failed' ? '解除隔离未验证成功' : '隔离未能完整验证'}
                </span>
                <span className={`rounded-md border px-2 py-1 text-xs ${hostStale ? 'border-slate-600 bg-slate-800 text-slate-300' : 'border-emerald-700 bg-emerald-950/50 text-emerald-200'}`}>
                  {hostStale ? '主机心跳过期 · 暂不可操作' : '主机在线'}
                </span>
                {recordOld && <span className="text-xs text-slate-400">隔离记录较旧 · {new Date(item.updated_at * 1000).toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai', hour12: false })}</span>}
                <span className="text-sm font-semibold text-slate-100">{item.title}</span>
              </div>
              <p className="break-all font-mono text-xs text-slate-300">{item.host_id} · {item.runtime}/{item.project || '-'} · {item.container_name}</p>
              <p className="text-sm leading-6 text-slate-200">{item.message}</p>
              <p className="break-all font-mono text-[11px] text-slate-400">隔离记录绑定的旧实例 ID：{item.instance_id}</p>
              {recordOld && !hostStale && <p className="text-xs text-sky-200">记录时间较旧不代表主机离线；操作资格按最近心跳判断，实例身份仍由节点复核。</p>}
              <ul className="space-y-1 rounded-lg border border-slate-700 bg-slate-950/70 p-3 text-xs leading-6 text-slate-300">
                {(item.details.abuse_evidence || []).slice(0, 5).map((proof, index) => (
                  <li key={index} className="break-all tabular-nums">
                    {labels[proof.kind] || proof.kind} · PID {proof.pid} · 连续佐证 {proof.features?.corroborating_samples || '-'} 次
                    {proof.tool && ` · 工具 ${proof.tool}`}
                    {!!proof.features?.concurrency && ` · 并发配置 ${proof.features.concurrency}`}
                    {!!proof.pending_attempts && ` · SYN 待连接 ${proof.pending_attempts}`}
                    {!!proof.vertical_ports && ` · 纵向端口 ${proof.vertical_ports}`}
                    {!!proof.horizontal_targets && ` · 横向目标 ${proof.horizontal_targets}`}
                    {(proof.pending_ratio != null || proof.failed_ratio != null) && ` · 待连接占比 ${Math.round((proof.pending_ratio ?? proof.failed_ratio ?? 0)*100)}%`}
                    {proof.source_sha256 && ` · 入口文件 SHA256 ${proof.source_sha256.slice(0, 12)}`}
                  </li>
                ))}
              </ul>
              <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                <p className="flex items-center gap-2 text-xs text-amber-200"><AlertTriangle className="h-4 w-4 shrink-0" aria-hidden="true" />解除隔离只恢复原实例网络；容器已重装或已删除时请走身份核验，不会改动新实例网络。</p>
                <div className="flex flex-wrap gap-2">
                  <button type="button" disabled={hostStale || busy || pending || role !== 'admin'} onClick={() => { setSelectedAction('release'); setSelected(item); }} className="flex min-h-11 shrink-0 items-center justify-center gap-2 rounded-lg border border-sky-500/60 bg-sky-950 px-4 text-xs font-semibold text-sky-100 hover:bg-sky-900 focus:outline-hidden focus:ring-2 focus:ring-sky-400 disabled:cursor-not-allowed disabled:opacity-50" title={role !== 'admin' ? '仅管理员可复核隔离事件' : undefined}>
                    <UnlockKeyhole className="h-4 w-4" aria-hidden="true" />{releasePending ? '等待网络恢复回执' : '复核并恢复原实例网络'}
                  </button>
                  <button type="button" disabled={hostStale || busy || pending || role !== 'admin' || !item.replacement_review_supported} onClick={() => { setSelectedAction('replace'); setSelected(item); }} className="flex min-h-11 shrink-0 items-center justify-center gap-2 rounded-lg border border-amber-500/60 bg-amber-950/60 px-4 text-xs font-semibold text-amber-100 hover:bg-amber-900/70 focus:outline-hidden focus:ring-2 focus:ring-amber-400 disabled:cursor-not-allowed disabled:opacity-50" title={role !== 'admin' ? '仅管理员可复核隔离事件' : !item.replacement_review_supported ? `需要 Client 1.7.188 或更新版本；当前 ${item.host_agent_version || '未知'}` : '核验当前实例 ID 与隔离记录不同，或旧容器已被删除'}>
                    <Archive className="h-4 w-4" aria-hidden="true" />{replacementPending ? '等待身份核验回执' : '容器已重装或已删除：核验并归档旧隔离'}
                  </button>
                </div>
              </div>
              {!item.replacement_review_supported && <p className="text-xs text-slate-400">节点 Client {item.host_agent_version || '版本未知'} 尚不支持重装身份核验；升级至 1.7.188 后可用。</p>}
              {role !== 'admin' && <p className="text-xs text-slate-400">{roleUnavailable ? '未能确认当前账号权限；为安全起见操作已禁用，请刷新页面或重新登录。' : role === 'unknown' ? '正在确认当前账号权限…' : '当前账号为只读/运维角色；隔离复核仅对管理员开放。'}</p>}
            </article>
          );
        })}
      </div>
      <ConfirmDialog open={!!selected} title={selectedAction === 'replace' ? '确认容器已重装或已删除并核验旧实例？' : '确认已完成排查并解除隔离？'} description={selectedAction === 'replace'
        ? '节点将核对当前容器 ID 与旧隔离 ID。若容器已被删除销毁或已分配新实例 ID，且旧实例已从运行时完全消失，将安全归档旧隔离记录并解除告警；验证失败时告警继续保留。'
        : '将恢复该实例隔离前的受管网络连接，可能重新开放公网服务。容器与磁盘不会删除。请先通过宿主机控制台处置违规程序；若再次命中确凿特征，会重新隔离并告警。解除操作不等于风险已复查通过。'} confirmLabel={selectedAction === 'replace' ? '确认核验并归档旧隔离' : '确认复核并恢复网络'} tone="danger" isSubmitting={busy} onConfirm={() => void submitReview()} onCancel={() => { if (!busy) { setSelected(null); setSelectedAction(null); } }} />
    </section>
  );
};

