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
        {preview.latest.map(n => <div key={n.id} className="border-t border-slate-700 pt-2"><p>最近记录：Telegram {status[n.telegram_status] || n.telegram_status}；SSH {status[n.banner_status] || n.banner_status}</p>{n.last_error && <p className="mt-1 text-amber-300">{n.last_error}</p>}</div>)}
      </div>}
    </ConfirmDialog>
  </>;
}
