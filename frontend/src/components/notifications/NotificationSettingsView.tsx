import React, { useCallback, useEffect, useState } from 'react';
import { Bell, Bot, Send, Trash2, Eye, EyeOff, Globe } from 'lucide-react';
import { api } from '../../api/client';
import { NotificationBot } from '../../api/types';
import { ToastMessage } from '../common/Toast';
import { ConfirmDialog } from '../common/ConfirmDialog';

export const NotificationSettingsView: React.FC<{ onToast: (type: ToastMessage['type'], message: string) => void }> = ({ onToast }) => {
  const [bots, setBots] = useState<NotificationBot[]>([]);
  const [callbackReady, setCallbackReady] = useState(true);
  const [proxyConfigured, setProxyConfigured] = useState(false);
  const [proxyScheme, setProxyScheme] = useState('');
  const [saving, setSaving] = useState(false);
  const [showToken, setShowToken] = useState(false);
  const [deleting, setDeleting] = useState<NotificationBot | null>(null);
  const [deletingId, setDeletingId] = useState<number | null>(null);
  const [form, setForm] = useState({ name: 'Telegram 告警机器人', token: '', target: '', min_severity: 'critical' });

  const load = useCallback(async () => {
    try {
      const data = await api.getNotificationBots();
      setBots(data.items);
      setCallbackReady(data.callback_ready);
      setProxyConfigured(Boolean(data.proxy_configured));
      setProxyScheme(data.proxy_scheme || '');
    } catch (err: any) {
      onToast('error', `无法读取通知配置：${err.message || err}`);
    }
  }, [onToast]);

  useEffect(() => { load(); }, [load]);

  const save = async (event: React.FormEvent) => {
    event.preventDefault();
    setSaving(true);
    try {
      const result = await api.createNotificationBot(form);
      setForm({ name: 'Telegram 告警机器人', token: '', target: '', min_severity: 'critical' });
      await load();
      onToast(
        result.callback_ready ? 'success' : 'info',
        result.callback_error
          ? `消息发送验证成功，但操作按钮回调注册失败：${result.callback_error}`
          : result.callback_ready
          ? '机器人已保存，验证消息已发送，操作回调已注册。'
          : '机器人已保存且验证消息已发送；配置 PUBLIC_BASE_URL 后才能使用消息内操作按钮。'
      );
    } catch (err: any) {
      onToast('error', err.message || '保存失败');
    } finally {
      setSaving(false);
    }
  };

  return (
    <section className="space-y-5">
      <div className="rounded-2xl border border-sky-500/25 bg-gradient-to-br from-sky-950/60 to-slate-900 p-5">
        <div className="flex items-start gap-3">
          <div className="rounded-xl border border-sky-500/30 bg-sky-500/10 p-2">
            <Bell className="h-5 w-5 text-sky-400" />
          </div>
          <div>
            <h2 className="text-lg font-bold text-slate-100">告警推送</h2>
            <p className="mt-1 text-sm text-slate-400">
              按最低严重级别推送到 Telegram。推送卡片支持动态实时刷新，并可直接在 Telegram 中忽略或标记为已处理。
            </p>
          </div>
        </div>

        <div className="mt-4 flex flex-wrap items-center gap-2 text-xs">
          <span
            className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 font-medium border ${
              proxyConfigured
                ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-300'
                : 'border-slate-700 bg-slate-800/80 text-slate-300'
            }`}
          >
            <Globe className="h-3.5 w-3.5" />
            {proxyConfigured ? `已启用出站代理（${proxyScheme.toUpperCase()}）` : '直连 Telegram API'}
          </span>
          {!proxyConfigured && (
            <span className="text-slate-400">
              （若服务器网络受限无法访问 Telegram，可在环境变量配置 <code>TELEGRAM_PROXY_URL=socks5://...</code> 或 HTTP 代理）
            </span>
          )}
        </div>

        {!callbackReady && (
          <p className="mt-4 rounded-lg border border-amber-700/60 bg-amber-950/40 p-3 text-sm text-amber-200">
            已可发送通知；要启用推送内交互按钮，请在 Server 环境配置 <code>PUBLIC_BASE_URL</code> 为公网 HTTPS 面板地址，然后点击测试以注册 Webhook 回调。未配置时将使用轮询机制接收控制台指令。
          </p>
        )}
      </div>

      <form onSubmit={save} className="grid gap-4 rounded-2xl border border-slate-800 bg-slate-900/70 p-5 md:grid-cols-2">
        <div className="md:col-span-2 flex items-center gap-2 text-sm font-semibold text-slate-200">
          <Bot className="h-4 w-4 text-sky-400" />
          添加 Telegram 机器人
        </div>
        <label className="text-sm text-slate-300">
          名称
          <input
            required
            value={form.name}
            onChange={e => setForm({ ...form, name: e.target.value })}
            className="mt-1.5 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-slate-100 outline-none focus:border-sky-500"
          />
        </label>
        <label className="text-sm text-slate-300">
          最低推送级别
          <select
            value={form.min_severity}
            onChange={e => setForm({ ...form, min_severity: e.target.value })}
            className="mt-1.5 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-slate-100 outline-none focus:border-sky-500"
          >
            <option value="critical">仅严重告警</option>
            <option value="warning">警告及以上</option>
            <option value="info">全部告警</option>
          </select>
        </label>
        <label className="text-sm text-slate-300">
          Bot Token
          <div className="relative mt-1.5">
            <input
              required
              type={showToken ? 'text' : 'password'}
              autoComplete="new-password"
              value={form.token}
              onChange={e => setForm({ ...form, token: e.target.value })}
              placeholder="123456:ABC-DEF..."
              className="min-h-11 w-full rounded-lg border border-slate-700 bg-slate-950 py-2 pl-3 pr-12 text-slate-100 outline-none focus:border-sky-500"
            />
            <button
              type="button"
              onClick={() => setShowToken(value => !value)}
              className="absolute inset-y-0 right-0 flex w-11 items-center justify-center text-slate-400 hover:text-sky-300"
              aria-label={showToken ? '隐藏 Bot Token' : '显示 Bot Token'}
            >
              {showToken ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
            </button>
          </div>
          <span className="mt-1 block text-xs text-slate-500">
            来自 @BotFather，支持带或不带 bot 前缀，系统自动规范化
          </span>
        </label>
        <label className="text-sm text-slate-300">
          推送目标（Chat ID、频道或话题）
          <input
            required
            value={form.target}
            onChange={e => setForm({ ...form, target: e.target.value })}
            placeholder="-1001234567890、@channel 或 -100xxx:topic_id"
            className="mt-1.5 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-slate-100 outline-none focus:border-sky-500"
          />
          <span className="mt-1 block text-xs text-slate-500">
            私聊请先向 Bot 发送 /start；频道填 @channel；超级群论坛话题可填 -100xxx:topic_id
          </span>
        </label>
        <div className="md:col-span-2">
          <button
            disabled={saving}
            className="inline-flex min-h-11 items-center gap-2 rounded-lg bg-sky-500 px-4 py-2 text-sm font-bold text-slate-950 disabled:opacity-60"
          >
            <Bell className="h-4 w-4" />
            {saving ? '保存中…' : '保存机器人'}
          </button>
        </div>
      </form>

      <div className="space-y-3">
        {bots.map(bot => (
          <div key={bot.id} className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-slate-800 bg-slate-900 p-4">
            <div>
              <p className="font-semibold text-slate-100">
                {bot.name} <span className="ml-2 text-xs font-normal text-slate-400">{bot.target}</span>
              </p>
              <p className="mt-1 text-xs text-slate-400">
                Telegram · {bot.min_severity === 'critical' ? '仅严重告警' : bot.min_severity === 'warning' ? '警告及以上' : '全部告警'} · Token 已脱敏
              </p>
              <p
                className={`mt-1 text-xs ${
                  bot.last_delivery_status === 'failed'
                    ? 'text-rose-400'
                    : bot.last_delivery_status === 'succeeded'
                    ? 'text-emerald-400'
                    : 'text-slate-500'
                }`}
              >
                {bot.last_delivery_status === 'failed'
                  ? `最近发送失败：${bot.last_delivery_error || '未知错误'}`
                  : bot.last_delivery_status === 'succeeded'
                  ? `最近发送成功${bot.last_sent_at_utc8 ? ` · ${bot.last_sent_at_utc8}` : ''}`
                  : '尚未发送'}
              </p>
            </div>
            <div className="flex gap-2">
              <button
                type="button"
                onClick={async () => {
                  try {
                    await api.testNotificationBot(bot.id);
                    await load();
                    onToast('success', '测试消息已发送，操作回调已重新注册。');
                  } catch (e: any) {
                    await load();
                    onToast('error', e.message);
                  }
                }}
                className="inline-flex min-h-11 items-center gap-1 rounded-lg border border-sky-700/60 px-3 py-2 text-xs font-semibold text-sky-300 hover:bg-sky-950"
              >
                <Send className="h-3.5 w-3.5" />
                测试
              </button>
              <button
                type="button"
                onClick={() => setDeleting(bot)}
                className="flex h-11 w-11 items-center justify-center rounded-lg border border-rose-800/60 text-rose-300 hover:bg-rose-950"
                aria-label={`删除机器人 ${bot.name}`}
              >
                <Trash2 className="h-4 w-4" />
              </button>
            </div>
          </div>
        ))}
        {bots.length === 0 && (
          <p className="rounded-xl border border-dashed border-slate-700 p-6 text-center text-sm text-slate-500">
            尚未配置推送机器人
          </p>
        )}
      </div>

      <ConfirmDialog
        open={Boolean(deleting)}
        title="确认删除 Telegram 机器人？"
        description={deleting ? `将删除“${deleting.name}”的推送配置，之后不会再向 ${deleting.target} 发送告警。` : ''}
        confirmLabel="确认删除"
        tone="danger"
        isSubmitting={deleting ? deletingId === deleting.id : false}
        onCancel={() => setDeleting(null)}
        onConfirm={async () => {
          if (!deleting) return;
          setDeletingId(deleting.id);
          try {
            await api.deleteNotificationBot(deleting.id);
            await load();
            onToast('success', '机器人已删除');
            setDeleting(null);
          } catch (e: any) {
            onToast('error', e.message || '删除失败');
          } finally {
            setDeletingId(null);
          }
        }}
      />
    </section>
  );
};
