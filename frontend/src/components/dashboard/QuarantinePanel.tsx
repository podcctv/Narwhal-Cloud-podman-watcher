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
  bandwidth_monetization: '挂机卖带宽 / P2P 代理节点',
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
    <section
      id="quarantine-review"
      tabIndex={-1}
      className="rn2-card mb-6 overflow-hidden border-[#f5a3b3] focus:outline-hidden focus-visible:ring-2 focus-visible:ring-[#dc2626]"
      aria-labelledby="quarantine-title"
    >
      <div
        className="rn2-card-head"
        style={{ background: 'linear-gradient(125deg, #3f1323, #1b1834 55%, #0e233c)' }}
      >
        <div className="flex min-w-0 flex-1 items-center gap-3">
          <div className="shrink-0 rounded-lg border border-rose-400/45 bg-rose-500/20 p-2 text-rose-200">
            <LockKeyhole className="h-5 w-5" aria-hidden="true" />
          </div>
          <div className="min-w-0">
            <span className="rn2-eyebrow block text-rose-200">QUARANTINE REVIEW</span>
            <h2 id="quarantine-title" className="mt-0.5 text-sm font-bold text-white sm:text-base">
              违规活动隔离 · 待管理员复核
            </h2>
            <p className="mt-0.5 text-xs leading-5 text-[#dbeafe]">
              只处理多次佐证的高置信度行为；隔离全部受管入站和出站，保留容器、磁盘和证据。
            </p>
          </div>
        </div>
        <button
          type="button"
          onClick={() => void refresh()}
          className="rn2-btn rn2-btn-ghost min-h-11 min-w-11 px-3"
          aria-label="刷新隔离状态"
        >
          <RefreshCw className="h-4 w-4" aria-hidden="true" />
        </button>
      </div>

      {error && (
        <p role="alert" className="border-b border-[#f7d58b] bg-[#fef6e4] px-4 py-3 text-sm font-medium text-[#9a5b00] sm:px-5">
          {error}
        </p>
      )}

      <div className="divide-y divide-[#dce5ef] bg-white">
        {items.map(item => {
          const hostAge = item.host_last_seen ? Date.now() / 1000 - item.host_last_seen : Number.POSITIVE_INFINITY;
          const hostStale = hostAge < 0 || hostAge > 900;
          const recordOld = Date.now() / 1000 - item.updated_at > 900;
          const activeStatuses = ['queued', 'dispatched', 'running'];
          const releasePending = queuedActionByAlert.get(item.alert_id) === 'release' ||
            activeStatuses.includes(item.release_action_status || '');
          const replacementPending = queuedActionByAlert.get(item.alert_id) === 'replace' ||
            activeStatuses.includes(item.replacement_action_status || '');
          const pending = releasePending || replacementPending;
          return (
            <article key={`${item.alert_id}:${item.instance_id}`} className="min-w-0 space-y-3 p-5">
              <div className="flex flex-wrap items-center gap-2">
                <span
                  className={`rn2-pill ${
                    item.status === 'isolated' ? 'rn2-pill-crimson' : 'rn2-pill-amber'
                  }`}
                >
                  {item.status === 'isolated'
                    ? '已双向隔离'
                    : item.status === 'release_failed'
                      ? '解除隔离未验证成功'
                      : '隔离未能完整验证'}
                </span>
                <span
                  className={`rn2-pill ${
                    hostStale ? 'rn2-pill-slate' : 'rn2-pill-teal'
                  }`}
                >
                  {hostStale ? '主机心跳过期 · 暂不可操作' : '主机在线'}
                </span>
                {recordOld && (
                  <span className="text-xs text-[#697b9c] tabular-nums">
                    隔离记录较旧 · {new Date(item.updated_at * 1000).toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai', hour12: false })}
                  </span>
                )}
                <span className="text-sm font-bold text-[#0b1636]">{item.title}</span>
              </div>

              <p className="break-all font-mono text-xs font-semibold text-[#31485e]">
                {item.host_id} · {item.runtime}/{item.project || '-'} · {item.container_name}
              </p>
              <p className="text-sm leading-6 text-[#0b1636]">{item.message}</p>
              <p className="break-all font-mono text-[11px] text-[#697b9c]">
                隔离记录绑定的旧实例 ID：{item.instance_id}
              </p>

              {recordOld && !hostStale && (
                <p className="text-xs font-medium text-[#0657b8]">
                  记录时间较旧不代表主机离线；操作资格按最近心跳判断，实例身份仍由节点复核。
                </p>
              )}

              <ul className="space-y-1 rounded-xl border border-[#dce5ef] bg-[#f4f8fd] p-3 text-xs leading-6 text-[#31485e]">
                {(item.details.abuse_evidence || []).slice(0, 5).map((proof, index) => (
                  <li key={index} className="break-all tabular-nums">
                    {labels[proof.kind] || proof.kind} · PID {proof.pid} · 连续佐证 {proof.features?.corroborating_samples || '-'} 次
                    {proof.tool && ` · 工具 ${proof.tool}`}
                    {!!proof.features?.concurrency && ` · 并发配置 ${proof.features.concurrency}`}
                    {!!proof.pending_attempts && ` · SYN 待连接 ${proof.pending_attempts}`}
                    {!!proof.vertical_ports && ` · 纵向端口 ${proof.vertical_ports}`}
                    {!!proof.horizontal_targets && ` · 横向目标 ${proof.horizontal_targets}`}
                    {(proof.pending_ratio != null || proof.failed_ratio != null) && ` · 待连接占比 ${Math.round((proof.pending_ratio ?? proof.failed_ratio ?? 0) * 100)}%`}
                    {proof.source_sha256 && ` · 入口文件 SHA256 ${proof.source_sha256.slice(0, 12)}`}
                  </li>
                ))}
              </ul>

              <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                <p className="flex items-start gap-2 text-xs text-[#9a5b00]">
                  <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-[#d97706]" aria-hidden="true" />
                  <span>解除隔离只恢复原实例网络；容器已重装或已删除时请走身份核验，不会改动新实例网络。</span>
                </p>
                <div className="flex flex-wrap gap-2">
                  <button
                    type="button"
                    disabled={hostStale || busy || pending || role !== 'admin'}
                    onClick={() => { setSelectedAction('release'); setSelected(item); }}
                    className="rn2-btn rn2-btn-blue min-h-11 shrink-0 px-4 text-xs"
                    title={role !== 'admin' ? '仅管理员可复核隔离事件' : undefined}
                  >
                    <UnlockKeyhole className="h-4 w-4 shrink-0" aria-hidden="true" />
                    <span>{releasePending ? '等待网络恢复回执' : '复核并恢复原实例网络'}</span>
                  </button>
                  <button
                    type="button"
                    disabled={hostStale || busy || pending || role !== 'admin' || !item.replacement_review_supported}
                    onClick={() => { setSelectedAction('replace'); setSelected(item); }}
                    className="inline-flex min-h-11 shrink-0 items-center justify-center gap-2 rounded-[10px] border border-[#f7d58b] bg-[#fef6e4] px-4 text-xs font-semibold text-[#9a5b00] transition-colors hover:border-[#d97706] hover:bg-[#fdecc8] disabled:cursor-not-allowed disabled:opacity-50"
                    title={
                      role !== 'admin'
                        ? '仅管理员可复核隔离事件'
                        : !item.replacement_review_supported
                          ? `需要 Client 1.7.188 或更新版本；当前 ${item.host_agent_version || '未知'}`
                          : '核验当前实例 ID 与隔离记录不同，或旧容器已被删除'
                    }
                  >
                    <Archive className="h-4 w-4 shrink-0" aria-hidden="true" />
                    <span>{replacementPending ? '等待身份核验回执' : '容器已重装或已删除：核验并归档旧隔离'}</span>
                  </button>
                </div>
              </div>

              {!item.replacement_review_supported && (
                <p className="text-xs text-[#697b9c]">
                  节点 Client {item.host_agent_version || '版本未知'} 尚不支持重装身份核验；升级至 1.7.188 后可用。
                </p>
              )}
              {role !== 'admin' && (
                <p className="text-xs text-[#697b9c]">
                  {roleUnavailable
                    ? '未能确认当前账号权限；为安全起见操作已禁用，请刷新页面或重新登录。'
                    : role === 'unknown'
                      ? '正在确认当前账号权限…'
                      : '当前账号为只读/运维角色；隔离复核仅对管理员开放。'}
                </p>
              )}
            </article>
          );
        })}
      </div>

      <ConfirmDialog
        open={!!selected}
        title={selectedAction === 'replace' ? '确认容器已重装或已删除并核验旧实例？' : '确认已完成排查并解除隔离？'}
        description={selectedAction === 'replace'
          ? '节点将核对当前容器 ID 与旧隔离 ID。若容器已被删除销毁或已分配新实例 ID，且旧实例已从运行时完全消失，将安全归档旧隔离记录并解除告警；验证失败时告警继续保留。'
          : '将恢复该实例隔离前的受管网络连接，可能重新开放公网服务。容器与磁盘不会删除。请先通过宿主机控制台处置违规程序；若再次命中确凿特征，会重新隔离并告警。解除操作不等于风险已复查通过。'}
        confirmLabel={selectedAction === 'replace' ? '确认核验并归档旧隔离' : '确认复核并恢复网络'}
        tone="danger"
        isSubmitting={busy}
        onConfirm={() => void submitReview()}
        onCancel={() => { if (!busy) { setSelected(null); setSelectedAction(null); } }}
      />
    </section>
  );
};
