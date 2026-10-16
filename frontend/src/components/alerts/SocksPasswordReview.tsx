import { useState } from 'react';
import { Ban, KeyRound } from 'lucide-react';
import { SecurityAlert } from '../../api/types';
import { api } from '../../api/client';
import { ConfirmDialog } from '../common/ConfirmDialog';

interface Profile {
  available: boolean; reason?: string; account_index?: number; length?: number;
  lowercase?: number; uppercase?: number; digits?: number; symbols?: number; other?: number;
  repeated_digits?: number; max_digit_frequency?: number; longest_identical_run?: number;
}
interface Review { pid: number; process: string; port: number; config_path?: string; action_safe: boolean; password_profiles?: Profile[] }
type Toast = (type: 'success' | 'error' | 'info', message: string) => void;

export function SocksPasswordReview({ alert, onRefresh, onToast }: { alert: SecurityAlert; onRefresh: () => void; onToast: Toast }) {
  const [confirming, setConfirming] = useState(false);
  const [busy, setBusy] = useState(false);
  if (alert.type !== 'socks_password_review') return null;
  const reviews: Review[] = Array.isArray(alert.details?.password_review) ? alert.details.password_review : [];
  const fresh = Date.now()/1000 - Number(alert.details?.review_observed_at || 0) <= 900;
  const canStop = fresh && alert.status === 'active' && ['incus', 'podman'].includes(alert.runtime) && reviews.length > 0 && reviews.every(r => r.action_safe) && Boolean(alert.details?.review_token);
  return <div className="space-y-3 rounded-xl border border-amber-500/30 bg-amber-950/20 p-3 text-xs text-slate-300">
    <div className="flex items-center gap-2 font-semibold text-amber-200"><KeyRound className="h-4 w-4" aria-hidden="true" />要求认证已确认 · 密码由管理员评估</div>
    <p>仅统计配置中的密码组成，不显示原文、用户名或哈希；未尝试使用该密码登录，字符种类多不等于密码一定安全。</p>
    {reviews.map((r, i) => <div key={`${r.pid}-${r.port}-${i}`} className="space-y-2 border-t border-amber-500/15 pt-2 min-w-0">
      <p className="break-all font-mono">{r.process} · PID {r.pid} · 端口 {r.port}{r.config_path ? ` · ${r.config_path}` : ''}</p>
      {(r.password_profiles || []).map((p, j) => <div key={j}>
        {p.available ? <>
          <div className="flex flex-wrap gap-x-4 gap-y-2 tabular-nums"><span>账号 #{p.account_index || j+1}：{p.length} 位字符</span><span>小写 {p.lowercase}</span><span>大写 {p.uppercase}</span><span>数字 {p.digits}</span><span>符号 {p.symbols}</span><span>其他/空白 {p.other}</span></div>
          <p className="mt-2 text-slate-400">重复数字 {p.repeated_digits} 个（超过首次出现的次数） · 单个数字最多出现 {p.max_digit_frequency} 次 · 最长连续同字符 {p.longest_identical_run} 位</p>
        </> : <p className="text-amber-300 break-words">无法统计：{p.reason || '未找到可统计的内联密码，不按空密码处理'}</p>}
      </div>)}
    </div>)}
    <div className="flex flex-wrap items-center gap-3">
      <button type="button" disabled={!canStop || busy} onClick={() => setConfirming(true)} className="flex min-h-11 items-center gap-2 rounded-lg border border-rose-500/40 bg-rose-950/50 px-3 text-rose-200 focus:ring-2 focus:ring-sky-400 disabled:opacity-50"><Ban className="h-4 w-4" />人工决定停止</button>
      <span className="min-w-0 flex-1 text-slate-400">{canStop ? '仅停止已核实的 SOCKS 进程，不停止容器；也可使用放行策略。' : '停止入口受保护：证据过期、版本未支持或进程含混合业务时需先核实范围。'}</span>
    </div>
    <ConfirmDialog open={confirming} title="确认人工停止该 SOCKS 服务？" description="这不是已确认的弱密码结论。节点将重新核验 PID、监听端口及配置版本；证据变化则拒绝执行。不会停止整个容器，也不建立自动弱密码拦截策略。" confirmLabel="确认人工停止" isSubmitting={busy} onCancel={() => setConfirming(false)} onConfirm={async () => {
      if (busy) return;
      setBusy(true);
      try { const result = await api.stopReviewedSocks(alert.id, alert.details.review_token); onToast('success', result.queued ? '人工停止指令已排队，等待节点复核执行' : '已有同类指令，请查看回执'); setConfirming(false); onRefresh(); }
      catch (e: any) { onToast('error', e.message || '操作失败'); }
      finally { setBusy(false); }
    }} />
  </div>;
}
