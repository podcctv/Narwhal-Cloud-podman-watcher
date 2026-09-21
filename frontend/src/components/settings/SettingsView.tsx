import React, { useCallback, useEffect, useState } from 'react';
import {
  Settings,
  Cloud,
  Bot,
  Send,
  Save,
  Trash2,
  Eye,
  EyeOff,
  Globe,
  CheckCircle2,
  AlertTriangle,
  Radio,
  Server,
  KeyRound,
  BellRing,
  Info,
} from 'lucide-react';
import { api } from '../../api/client';
import { NotificationBot, PushSettingsResponse, PushSettingsPayload } from '../../api/types';
import { ToastMessage } from '../common/Toast';
import { ConfirmDialog } from '../common/ConfirmDialog';

interface SettingsViewProps {
  onToast: (type: ToastMessage['type'], message: string) => void;
}

export const SettingsView: React.FC<SettingsViewProps> = ({ onToast }) => {
  // Push & API settings state
  const [loadingPush, setLoadingPush] = useState(true);
  const [savingPush, setSavingPush] = useState(false);
  const [testingPush, setTestingPush] = useState(false);
  const [showApiKey, setShowApiKey] = useState(false);
  const [pushSettings, setPushSettings] = useState<PushSettingsResponse | null>(null);

  const [apiForm, setApiForm] = useState<PushSettingsPayload>({
    narwhal_api_url: 'https://api.fuckip.me/api/v1',
    narwhal_api_key: '',
    narwhal_machine_id: '',
    narwhal_node_name: '',
    buyer_notify_enabled: true,
  });

  // Telegram bot state
  const [bots, setBots] = useState<NotificationBot[]>([]);
  const [callbackReady, setCallbackReady] = useState(true);
  const [proxyConfigured, setProxyConfigured] = useState(false);
  const [proxyScheme, setProxyScheme] = useState('');
  const [savingBot, setSavingBot] = useState(false);
  const [showBotToken, setShowBotToken] = useState(false);
  const [deletingBot, setDeletingBot] = useState<NotificationBot | null>(null);
  const [deletingBotId, setDeletingBotId] = useState<number | null>(null);
  const [botForm, setBotForm] = useState({
    name: 'Telegram 告警机器人',
    token: '',
    target: '',
    min_severity: 'critical',
  });

  // Load push settings and Telegram bots
  const loadSettings = useCallback(async () => {
    try {
      setLoadingPush(true);
      const [pushData, botData] = await Promise.all([
        api.getPushSettings(),
        api.getNotificationBots(),
      ]);

      setPushSettings(pushData);
      setApiForm({
        narwhal_api_url: pushData.narwhal_api_url || 'https://api.fuckip.me/api/v1',
        narwhal_api_key: '',
        narwhal_machine_id: pushData.narwhal_machine_id || '',
        narwhal_node_name: pushData.narwhal_node_name || '',
        buyer_notify_enabled: Boolean(pushData.buyer_notify_enabled),
      });

      setBots(botData.items);
      setCallbackReady(botData.callback_ready);
      setProxyConfigured(Boolean(botData.proxy_configured));
      setProxyScheme(botData.proxy_scheme || '');
    } catch (err: any) {
      onToast('error', `加载设置失败：${err.message || err}`);
    } finally {
      setLoadingPush(false);
    }
  }, [onToast]);

  useEffect(() => {
    loadSettings();
  }, [loadSettings]);

  // Save Narwhal API Push settings
  const handleSavePush = async (e: React.FormEvent) => {
    e.preventDefault();
    setSavingPush(true);
    try {
      const payload: PushSettingsPayload = {
        narwhal_api_url: apiForm.narwhal_api_url?.trim(),
        narwhal_machine_id: apiForm.narwhal_machine_id?.trim(),
        narwhal_node_name: apiForm.narwhal_node_name?.trim(),
        buyer_notify_enabled: apiForm.buyer_notify_enabled,
      };
      if (apiForm.narwhal_api_key && apiForm.narwhal_api_key.trim()) {
        payload.narwhal_api_key = apiForm.narwhal_api_key.trim();
      }

      const res = await api.updatePushSettings(payload);
      onToast('success', res.message || 'Narwhal API 推送设置已保存');
      setApiForm(prev => ({ ...prev, narwhal_api_key: '' }));
      await loadSettings();
    } catch (err: any) {
      onToast('error', `保存失败：${err.message || err}`);
    } finally {
      setSavingPush(false);
    }
  };

  // Test Narwhal API Push connectivity
  const handleTestPush = async () => {
    setTestingPush(true);
    try {
      const payload: PushSettingsPayload = {
        narwhal_api_url: apiForm.narwhal_api_url?.trim(),
        narwhal_machine_id: apiForm.narwhal_machine_id?.trim(),
        narwhal_node_name: apiForm.narwhal_node_name?.trim(),
      };
      if (apiForm.narwhal_api_key && apiForm.narwhal_api_key.trim()) {
        payload.narwhal_api_key = apiForm.narwhal_api_key.trim();
      }

      const res = await api.testPushSettings(payload);
      if (res.status_code === 429) {
        onToast('info', res.message);
      } else {
        onToast('success', res.message || 'API 连通性测试成功');
      }
    } catch (err: any) {
      onToast('error', `测试失败：${err.message || err}`);
    } finally {
      setTestingPush(false);
    }
  };

  // Save Telegram bot
  const handleSaveBot = async (event: React.FormEvent) => {
    event.preventDefault();
    setSavingBot(true);
    try {
      const result = await api.createNotificationBot(botForm);
      setBotForm({
        name: 'Telegram 告警机器人',
        token: '',
        target: '',
        min_severity: 'critical',
      });
      await loadSettings();
      onToast(
        result.callback_ready ? 'success' : 'info',
        result.callback_error
          ? `消息发送验证成功，但操作回调注册失败：${result.callback_error}`
          : result.callback_ready
          ? '机器人已保存，验证消息已发送，操作回调已注册。'
          : '机器人已保存且验证消息已发送；配置 PUBLIC_BASE_URL 后才能使用消息内操作按钮。'
      );
    } catch (err: any) {
      onToast('error', err.message || '保存机器人失败');
    } finally {
      setSavingBot(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Settings Top Overview Banner */}
      <section className="rounded-2xl border border-slate-800 bg-gradient-to-br from-slate-900 via-slate-950 to-slate-900 p-5 sm:p-6 shadow-xl">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div className="flex items-start gap-3.5">
            <div className="flex h-12 w-12 shrink-0 items-center justify-center rounded-xl border border-sky-500/30 bg-sky-500/10 shadow-inner">
              <Settings className="h-6 w-6 text-sky-400" />
            </div>
            <div>
              <div className="flex items-center gap-2.5">
                <h2 className="text-xl font-bold text-slate-100 tracking-tight">系统设置</h2>
                <span className="rounded-md border border-slate-700 bg-slate-800/80 px-2 py-0.5 font-mono text-xs text-slate-300">
                  推送与 API 集成
                </span>
              </div>
              <p className="mt-1 text-xs sm:text-sm text-slate-400">
                集中管理 Narwhal 官方买家预警推送接口与 Telegram 运维告警机器人通知渠道。
              </p>
            </div>
          </div>

          {/* Status summary pills */}
          <div className="flex flex-wrap items-center gap-2 text-xs">
            <span
              className={`inline-flex items-center gap-1.5 rounded-full px-3 py-1 font-medium border ${
                pushSettings?.buyer_notify_enabled
                  ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-300'
                  : 'border-slate-700 bg-slate-800/80 text-slate-400'
              }`}
            >
              <Radio className="h-3 w-3" />
              {pushSettings?.buyer_notify_enabled ? '买家推送已启用' : '买家推送已停用'}
            </span>
            <span
              className={`inline-flex items-center gap-1.5 rounded-full px-3 py-1 font-medium border ${
                pushSettings?.narwhal_api_key_configured
                  ? 'border-sky-500/30 bg-sky-500/10 text-sky-300'
                  : 'border-amber-500/30 bg-amber-500/10 text-amber-300'
              }`}
            >
              <KeyRound className="h-3 w-3" />
              {pushSettings?.narwhal_api_key_configured ? 'API 密钥已配置' : 'API 密钥未配置'}
            </span>
            <span
              className={`inline-flex items-center gap-1.5 rounded-full px-3 py-1 font-medium border ${
                bots.length > 0
                  ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-300'
                  : 'border-slate-700 bg-slate-800/80 text-slate-400'
              }`}
            >
              <Bot className="h-3 w-3" />
              {bots.length > 0 ? `${bots.length} 个 TG 机器人` : '未配置 TG 机器人'}
            </span>
          </div>
        </div>
      </section>

      {/* Grid: Card 1 (Narwhal Cloud Buyer API) & Card 2 (Telegram Bots) */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2 items-start">
        {/* =========================================================================
            CARD A: Narwhal Cloud 买家告警推送配置
           ========================================================================= */}
        <section className="rounded-2xl border border-slate-800 bg-slate-900/80 p-5 sm:p-6 shadow-lg flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between gap-3 border-b border-slate-800/80 pb-4">
              <div className="flex items-center gap-3">
                <div className="flex h-10 w-10 items-center justify-center rounded-lg border border-sky-500/30 bg-sky-500/10">
                  <Cloud className="h-5 w-5 text-sky-400" />
                </div>
                <div>
                  <h3 className="text-base font-semibold text-slate-100">Narwhal Cloud 买家推送配置</h3>
                  <p className="text-xs text-slate-400">
                    向购买该机器容器的租户直接推送严重违规/安全预警通知
                  </p>
                </div>
              </div>

              {/* Active Toggle Switch */}
              <label className="flex items-center gap-2 cursor-pointer select-none">
                <span className="text-xs text-slate-300">
                  {apiForm.buyer_notify_enabled ? '启用推送' : '已停用'}
                </span>
                <input
                  type="checkbox"
                  checked={apiForm.buyer_notify_enabled}
                  onChange={e => setApiForm({ ...apiForm, buyer_notify_enabled: e.target.checked })}
                  className="sr-only peer"
                />
                <div className="relative w-11 h-6 bg-slate-800 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-slate-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-sky-500"></div>
              </label>
            </div>

            <form onSubmit={handleSavePush} className="mt-5 space-y-4">
              {/* API URL */}
              <div>
                <label className="block text-xs font-medium text-slate-300">
                  Narwhal API 接口基地址
                </label>
                <div className="relative mt-1.5">
                  <div className="pointer-events-none absolute inset-y-0 left-0 flex items-center pl-3 text-slate-500">
                    <Server className="h-4 w-4" />
                  </div>
                  <input
                    type="url"
                    required
                    value={apiForm.narwhal_api_url}
                    onChange={e => setApiForm({ ...apiForm, narwhal_api_url: e.target.value })}
                    placeholder="https://api.fuckip.me/api/v1"
                    className="min-h-11 w-full rounded-lg border border-slate-700 bg-slate-950 pl-10 pr-3 py-2 text-sm text-slate-100 placeholder-slate-500 outline-none focus:border-sky-500 font-mono"
                  />
                </div>
                <span className="mt-1 block text-[11px] text-slate-500">
                  推送端点为 <code>/machines/&#123;machineId&#125;/notify-buyers</code>
                </span>
              </div>

              {/* API Key */}
              <div>
                <div className="flex items-center justify-between">
                  <label className="block text-xs font-medium text-slate-300">
                    Narwhal API 密钥 (Bearer Token)
                  </label>
                  {pushSettings?.narwhal_api_key_configured && (
                    <span className="text-[11px] text-emerald-400 font-mono">
                      当前已生效：{pushSettings.narwhal_api_key_masked}
                    </span>
                  )}
                </div>
                <div className="relative mt-1.5">
                  <div className="pointer-events-none absolute inset-y-0 left-0 flex items-center pl-3 text-slate-500">
                    <KeyRound className="h-4 w-4" />
                  </div>
                  <input
                    type={showApiKey ? 'text' : 'password'}
                    autoComplete="new-password"
                    value={apiForm.narwhal_api_key}
                    onChange={e => setApiForm({ ...apiForm, narwhal_api_key: e.target.value })}
                    placeholder={
                      pushSettings?.narwhal_api_key_configured
                        ? '留空保持现有密钥，输入新密钥覆盖'
                        : '请输入 Narwhal 平台 API Key (例如 sk_...)'
                    }
                    className="min-h-11 w-full rounded-lg border border-slate-700 bg-slate-950 pl-10 pr-12 py-2 text-sm text-slate-100 placeholder-slate-500 outline-none focus:border-sky-500 font-mono"
                  />
                  <button
                    type="button"
                    onClick={() => setShowApiKey(prev => !prev)}
                    className="absolute inset-y-0 right-0 flex w-11 items-center justify-center text-slate-400 hover:text-sky-300 focus-visible:outline-none"
                    aria-label={showApiKey ? '隐藏 API Key' : '显示 API Key'}
                  >
                    {showApiKey ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                  </button>
                </div>
              </div>

              {/* Two columns: Machine ID & Node Name */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                {/* Machine ID */}
                <div>
                  <label className="block text-xs font-medium text-slate-300">
                    母鸡机器 UUID (Machine ID)
                  </label>
                  <input
                    type="text"
                    value={apiForm.narwhal_machine_id}
                    onChange={e => setApiForm({ ...apiForm, narwhal_machine_id: e.target.value })}
                    placeholder="00000000-0000-0000-0000-000000000001"
                    className="mt-1.5 min-h-11 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 placeholder-slate-500 outline-none focus:border-sky-500 font-mono"
                  />
                  <span className="mt-1 block text-[11px] text-slate-500">
                    Narwhal 控制台母鸡机器的唯一 UUID
                  </span>
                </div>

                {/* Node Name */}
                <div>
                  <label className="block text-xs font-medium text-slate-300">
                    母鸡节点展示名称
                  </label>
                  <input
                    type="text"
                    value={apiForm.narwhal_node_name}
                    onChange={e => setApiForm({ ...apiForm, narwhal_node_name: e.target.value })}
                    placeholder="如 US-LAX-01 或 宿主机名"
                    className="mt-1.5 min-h-11 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 placeholder-slate-500 outline-none focus:border-sky-500"
                  />
                  <span className="mt-1 block text-[11px] text-slate-500">
                    展示在通知标题中的节点名称
                  </span>
                </div>
              </div>

              {/* Real-time Preview Box */}
              <div className="mt-4 rounded-xl border border-slate-800/80 bg-slate-950/90 p-3.5">
                <div className="flex items-center justify-between pb-2 mb-2 border-b border-slate-800 text-[11px] text-slate-400">
                  <span className="font-semibold text-slate-300 flex items-center gap-1.5">
                    <Info className="h-3.5 w-3.5 text-sky-400" />
                    买家通知实时格式预览
                  </span>
                  <span className="text-slate-500 font-mono">24h 智能频控</span>
                </div>
                <div className="font-mono text-xs space-y-2 text-slate-300 leading-relaxed">
                  <div className="font-bold text-amber-300">
                    ⚠️【节点安全告警】{apiForm.narwhal_node_name || 'US-LAX-01'}
                  </div>
                  <div className="bg-slate-900/80 p-2.5 rounded border border-slate-800/60 whitespace-pre-line text-slate-300 text-[11px]">
                    {`🚨【容器安全告警】\n\n📦 容器 ID ：c-demo-8f3a\n⚠️ 异常问题：检测到暴露公网的无认证 / 弱口令 SOCKS5 代理 (已自动拦截)\n\n💡 处置提示：请及时登录排查。已记录日志，如有持续滥用会导致删鸡。`}
                  </div>
                </div>
              </div>

              {/* Action Buttons */}
              <div className="pt-2 flex flex-wrap items-center gap-3">
                <button
                  type="submit"
                  disabled={savingPush || loadingPush}
                  className="inline-flex min-h-11 items-center gap-2 rounded-lg bg-sky-500 px-4 py-2 text-xs sm:text-sm font-bold text-slate-950 hover:bg-sky-400 transition-colors focus:outline-none focus:ring-2 focus:ring-sky-400 disabled:opacity-60 shadow-sm"
                >
                  <Save className="h-4 w-4" />
                  {savingPush ? '保存中…' : '保存 API 配置'}
                </button>

                <button
                  type="button"
                  disabled={testingPush || loadingPush}
                  onClick={handleTestPush}
                  className="inline-flex min-h-11 items-center gap-2 rounded-lg border border-sky-600/50 bg-sky-950/40 px-4 py-2 text-xs sm:text-sm font-semibold text-sky-300 hover:bg-sky-900/60 transition-colors focus:outline-none focus:ring-2 focus:ring-sky-400 disabled:opacity-60"
                >
                  <Send className="h-3.5 w-3.5" />
                  {testingPush ? '测试中…' : '测试推送连接'}
                </button>
              </div>

              <div className="rounded-lg border border-slate-800 bg-slate-950/50 p-3 text-[11px] text-slate-400 flex items-start gap-2">
                <CheckCircle2 className="h-4 w-4 text-sky-400 shrink-0 mt-0.5" />
                <span>
                  <strong>频控机制保护：</strong>同一母鸡机器 24 小时内向买家发送一条预警通知，以避免短时间内重复骚扰用户。
                </span>
              </div>
            </form>
          </div>
        </section>

        {/* =========================================================================
            CARD B: Telegram 告警机器人配置
           ========================================================================= */}
        <section className="rounded-2xl border border-slate-800 bg-slate-900/80 p-5 sm:p-6 shadow-lg space-y-5">
          <div className="flex items-center justify-between gap-3 border-b border-slate-800/80 pb-4">
            <div className="flex items-center gap-3">
              <div className="flex h-10 w-10 items-center justify-center rounded-lg border border-sky-500/30 bg-sky-500/10">
                <Bot className="h-5 w-5 text-sky-400" />
              </div>
              <div>
                <h3 className="text-base font-semibold text-slate-100">Telegram 告警机器人</h3>
                <p className="text-xs text-slate-400">
                  推送运维告警至管理员群组，支持动态刷新与控制台操作
                </p>
              </div>
            </div>

            {/* Outbound proxy badge */}
            <span
              className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-xs font-medium border ${
                proxyConfigured
                  ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-300'
                  : 'border-slate-700 bg-slate-800/80 text-slate-300'
              }`}
            >
              <Globe className="h-3.5 w-3.5" />
              {proxyConfigured ? `代理 (${proxyScheme.toUpperCase()})` : '直连 API'}
            </span>
          </div>

          {!callbackReady && (
            <div className="rounded-lg border border-amber-700/60 bg-amber-950/40 p-3 text-xs text-amber-200 flex items-start gap-2">
              <AlertTriangle className="h-4 w-4 shrink-0 mt-0.5 text-amber-400" />
              <span>
                已可发送通知；要启用消息内交互按钮（快捷处理/忽略），请在 Server 环境变量配置 <code>PUBLIC_BASE_URL</code> 为公网 HTTPS 地址。
              </span>
            </div>
          )}

          {/* Add Telegram Bot Form */}
          <form onSubmit={handleSaveBot} className="space-y-4 rounded-xl border border-slate-800 bg-slate-950/70 p-4">
            <div className="flex items-center gap-2 text-xs font-semibold text-slate-200">
              <BellRing className="h-3.5 w-3.5 text-sky-400" />
              添加新 Telegram 机器人
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <div>
                <label className="block text-xs text-slate-300">机器人名称</label>
                <input
                  required
                  value={botForm.name}
                  onChange={e => setBotForm({ ...botForm, name: e.target.value })}
                  placeholder="如 运维告警群"
                  className="mt-1 min-h-11 w-full rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-100 outline-none focus:border-sky-500"
                />
              </div>

              <div>
                <label className="block text-xs text-slate-300">最低推送级别</label>
                <select
                  value={botForm.min_severity}
                  onChange={e => setBotForm({ ...botForm, min_severity: e.target.value })}
                  className="mt-1 min-h-11 w-full rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-100 outline-none focus:border-sky-500"
                >
                  <option value="critical">仅严重告警 (Critical)</option>
                  <option value="warning">警告及以上 (Warning+)</option>
                  <option value="info">全部告警 (All)</option>
                </select>
              </div>
            </div>

            <div>
              <label className="block text-xs text-slate-300">Bot Token</label>
              <div className="relative mt-1">
                <input
                  required
                  type={showBotToken ? 'text' : 'password'}
                  autoComplete="new-password"
                  value={botForm.token}
                  onChange={e => setBotForm({ ...botForm, token: e.target.value })}
                  placeholder="123456789:ABCdef-GHI..."
                  className="min-h-11 w-full rounded-lg border border-slate-700 bg-slate-900 py-2 pl-3 pr-12 text-sm text-slate-100 font-mono outline-none focus:border-sky-500"
                />
                <button
                  type="button"
                  onClick={() => setShowBotToken(prev => !prev)}
                  className="absolute inset-y-0 right-0 flex w-11 items-center justify-center text-slate-400 hover:text-sky-300"
                  aria-label={showBotToken ? '隐藏 Bot Token' : '显示 Bot Token'}
                >
                  {showBotToken ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                </button>
              </div>
            </div>

            <div>
              <label className="block text-xs text-slate-300">
                推送目标 (Chat ID、@频道 或 话题)
              </label>
              <input
                required
                value={botForm.target}
                onChange={e => setBotForm({ ...botForm, target: e.target.value })}
                placeholder="-1001234567890、@channel 或 -100xxx:topic_id"
                className="mt-1 min-h-11 w-full rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-100 font-mono outline-none focus:border-sky-500"
              />
              <span className="mt-1 block text-[11px] text-slate-500">
                私聊先发送 /start；频道填 @channel；群论坛话题填 -100xxx:topic_id
              </span>
            </div>

            <div>
              <button
                type="submit"
                disabled={savingBot}
                className="inline-flex min-h-11 items-center gap-2 rounded-lg bg-sky-500 px-4 py-2 text-xs sm:text-sm font-bold text-slate-950 hover:bg-sky-400 transition-colors focus:outline-none focus:ring-2 focus:ring-sky-400 disabled:opacity-60"
              >
                <Bot className="h-4 w-4" />
                {savingBot ? '保存中…' : '添加机器人并验证'}
              </button>
            </div>
          </form>

          {/* Configured Bot List */}
          <div className="space-y-3">
            <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
              已配置的 Telegram 机器人 ({bots.length})
            </h4>

            {bots.map(bot => (
              <div
                key={bot.id}
                className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-slate-800 bg-slate-950/60 p-4 transition-colors hover:border-slate-700"
              >
                <div className="space-y-1">
                  <p className="font-semibold text-sm text-slate-100 flex items-center gap-2">
                    {bot.name}
                    <span className="font-mono text-xs font-normal text-slate-400 bg-slate-800/60 px-2 py-0.5 rounded">
                      {bot.target}
                    </span>
                  </p>
                  <p className="text-xs text-slate-400">
                    级别：{bot.min_severity === 'critical' ? '仅严重告警' : bot.min_severity === 'warning' ? '警告及以上' : '全部告警'} · Token 已脱敏保护
                  </p>
                  <p
                    className={`text-xs ${
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

                <div className="flex items-center gap-2">
                  <button
                    type="button"
                    onClick={async () => {
                      try {
                        await api.testNotificationBot(bot.id);
                        await loadSettings();
                        onToast('success', '测试消息已发送，操作回调已重新注册。');
                      } catch (e: any) {
                        await loadSettings();
                        onToast('error', e.message);
                      }
                    }}
                    className="inline-flex min-h-11 items-center gap-1.5 rounded-lg border border-sky-700/60 bg-sky-950/30 px-3 py-2 text-xs font-semibold text-sky-300 hover:bg-sky-900/50 transition-colors focus:outline-none focus:ring-2 focus:ring-sky-400"
                  >
                    <Send className="h-3.5 w-3.5" />
                    测试
                  </button>

                  <button
                    type="button"
                    onClick={() => setDeletingBot(bot)}
                    className="flex h-11 w-11 items-center justify-center rounded-lg border border-rose-800/60 bg-rose-950/20 text-rose-300 hover:bg-rose-900/50 transition-colors focus:outline-none focus:ring-2 focus:ring-rose-400"
                    aria-label={`删除机器人 ${bot.name}`}
                  >
                    <Trash2 className="h-4 w-4" />
                  </button>
                </div>
              </div>
            ))}

            {bots.length === 0 && (
              <div className="rounded-xl border border-dashed border-slate-800 p-6 text-center text-xs sm:text-sm text-slate-500">
                尚未配置 Telegram 推送机器人，可使用上方表单快速添加
              </div>
            )}
          </div>
        </section>
      </div>

      {/* Delete Confirmation Dialog */}
      <ConfirmDialog
        open={Boolean(deletingBot)}
        title="确认删除 Telegram 机器人？"
        description={
          deletingBot
            ? `将删除“${deletingBot.name}”的推送配置，之后系统将不再向 ${deletingBot.target} 发送告警通知。`
            : ''
        }
        confirmLabel="确认删除"
        tone="danger"
        isSubmitting={deletingBot ? deletingBotId === deletingBot.id : false}
        onCancel={() => setDeletingBot(null)}
        onConfirm={async () => {
          if (!deletingBot) return;
          setDeletingBotId(deletingBot.id);
          try {
            await api.deleteNotificationBot(deletingBot.id);
            await loadSettings();
            onToast('success', '机器人已删除');
            setDeletingBot(null);
          } catch (e: any) {
            onToast('error', e.message || '删除失败');
          } finally {
            setDeletingBotId(null);
          }
        }}
      />
    </div>
  );
};
