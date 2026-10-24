import { useState, useRef } from 'react';
import { Send } from 'lucide-react';
import { api } from '../../api/client';
import { ConfirmDialog } from '../common/ConfirmDialog';

const status: Record<string, string> = { ready:'确认后排队（尚未发送）', queued:'已排队', blocked:'等待配置/映射', sending:'投递中', succeeded:'上游已受理', written:'已写入登录提醒', uncertain:'结果不确定，需核对', failed:'失败', expired:'已过期', retrying:'等待重试', cancelled:'已取消' };
export function UserNoticeAction({ alertId, onToast }: { alertId: number; onToast: (type: 'success' | 'error' | 'info', message: string) => void }) {
  const [preview, setPreview] = useState<Awaited<ReturnType<typeof api.previewUserNotice>> | null>(null);
  const [loading, setLoading] = useState(false);
  const [sending, setSending] = useState(false);
  const [sent, setSent] = useState(false);
  const requestId = useRef('');
  const retry = async (noticeId: string, channel: 'telegram' | 'banner') => {
    if (sending) return;
    setSending(true);
    try {
      await api.retryUserNotice(noticeId, channel);
      setPreview(await api.previewUserNotice(alertId));
      setSent(true);
      onToast('success', `${channel === 'telegram' ? 'Telegram' : 'SSH 登录提醒'}已重新排队`);
    } catch (e: any) { onToast('error', e.message || '重试失败'); }
    finally { setSending(false); }
  };
  const open = async () => {
    if (loading) return;
    setLoading(true);
    try { setPreview(await api.previewUserNotice(alertId)); requestId.current = crypto.randomUUID().replace(/-/g, ''); setSent(false); }
    catch (e: any) { onToast('error', e.message || '通知预览失败'); }
    finally { setLoading(false); }
  };
  return <>
    <button type="button" disabled={loading} onClick={open} className="flex min-h-11 items-center gap-1.5 rounded-lg border border-sky-500/40 bg-sky-950/40 px-3 text-xs font-semibold text-sky-200 focus:ring-2 focus:ring-sky-400 disabled:opacity-50"><Send className="h-3.5 w-3.5" />{loading ? '读取通知…' : '通知用户'}</button>
    <ConfirmDialog open={Boolean(preview)} title={sent ? '通知已登记' : '预览用户安全提醒'} description={sent ? '排队不等于已送达；两条通道独立执行。重新打开本窗口可查看最近投递状态。' : '确认后同时排入用户 Telegram／买家通知 API 与容器 SSH 登录提醒。提醒保留 24 小时；不会向整台母鸡广播。'} confirmLabel={sent ? '完成' : preview?.can_submit ? '确认通知用户' : '关闭（目标不可用）'} tone="primary" isSubmitting={sending} onCancel={() => setPreview(null)} onConfirm={async () => {
      if (sent || !preview?.can_submit) { setPreview(null); return; }
      if (sending) return;
      setSending(true);
      try { await api.sendUserNotice(alertId, preview.preview_token, requestId.current); setSent(true); setPreview(await api.previewUserNotice(alertId)); onToast('success', '用户通知已登记，请分别查看投递状态'); }
      catch (e: any) { onToast('error', e.message || '登记失败；请刷新记录核对，勿重复发送'); }
      finally { setSending(false); }
    }}>
      {preview && <div className="mt-4 space-y-3 text-xs text-slate-300 wrap-break-word" aria-live="polite">
        <p>收件范围：{preview.audience}</p>
        <div className="rounded-lg border border-slate-700 bg-slate-950 p-3"><h3 className="font-semibold text-slate-100">{preview.subject}</h3><p className="mt-2 whitespace-pre-wrap leading-6">{preview.message}</p></div>
        <p>Telegram{sent ? '通道配置' : ''}：{sent && preview.telegram === 'ready' ? '可用（实际状态见最近记录）' : status[preview.telegram] || preview.telegram} · {preview.telegram_note}</p>
        <p>SSH banner：{preview.banner_note}</p>
        {preview.latest.map(n => <div key={n.id} className="space-y-2 border-t border-slate-700 pt-3">
          <p className="font-semibold">通知记录 {n.id.slice(0, 8)}</p>
          <p>Telegram：{status[n.telegram_status] || n.telegram_status} · 已尝试 {n.telegram_attempts} 次</p>
          {n.telegram_error && <p className="text-amber-300">Telegram 错误：{n.telegram_error}</p>}
          <p>SSH 登录提醒：{status[n.banner_status] || n.banner_status} · 已尝试 {n.banner_attempts} 次</p>
          {n.banner_error && <p className="text-amber-300">SSH 提醒错误：{n.banner_error}</p>}
          {n.telegram_status === 'uncertain' && <p className="text-amber-300">Telegram 结果不确定，为避免重复推送，系统不提供自动重发。</p>}
          {n.events?.length > 0 && <div className="space-y-1 border-l border-slate-700 pl-3">{n.events.map((event, index) => <p key={`${event.channel}-${event.ts}-${index}`} className="text-slate-400">{event.channel === 'telegram' ? 'Telegram' : 'SSH'} · {status[event.status] || event.status} · 第 {event.attempt} 次 · {new Date(event.ts * 1000).toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai', hour12: false })}{event.detail ? ` · ${event.detail}` : ''}</p>)}</div>}
          <div className="flex flex-wrap gap-2">
            {n.can_retry_telegram && <button type="button" className="rounded-md border border-sky-500/40 px-2 py-1 text-sky-200 disabled:opacity-50" disabled={sending} onClick={() => void retry(n.id, 'telegram')}>重试 Telegram</button>}
            {n.can_retry_banner && <button type="button" className="rounded-md border border-sky-500/40 px-2 py-1 text-sky-200 disabled:opacity-50" disabled={sending} onClick={() => void retry(n.id, 'banner')}>重试 SSH 提醒</button>}
          </div>
        </div>)}
      </div>}
    </ConfirmDialog>
  </>;
}
