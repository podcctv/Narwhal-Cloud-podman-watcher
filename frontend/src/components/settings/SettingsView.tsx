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
  ShieldCheck,
} from 'lucide-react';
import { api } from '../../api/client';
import {
  IPReputationResult,
  IPReputationSettings,
  NotificationBot,
  PushSettingsResponse,
  PushSettingsPayload,
} from '../../api/types';
import { ToastMessage } from '../common/Toast';
import { ConfirmDialog } from '../common/ConfirmDialog';
import { BuyerNotificationsView } from './BuyerNotificationsView';

interface SettingsViewProps {
  onToast: (type: ToastMessage['type'], message: string) => void;
}

export const SettingsView: React.FC<SettingsViewProps> = ({ onToast }) => {
  // Push & API settings state
  const [loadingPush, setLoadingPush] = useState(true);
  const [savingPush, setSavingPush] = useState(false);
  const [testingPush, setTestingPush] = useState(false);
  const [showApiKey, setShowApiKey] = useState(false);
  const [showAbuseKey, setShowAbuseKey] = useState(false);
  const [pushSettings, setPushSettings] = useState<PushSettingsResponse | null>(null);
  const [ipReputationConfigured, setIpReputationConfigured] = useState(false);
  const [ipReputationSettings, setIpReputationSettings] = useState<IPReputationSettings | null>(null);
  const [ipReputationKey, setIpReputationKey] = useState('');
  const [savingIpReputationKey, setSavingIpReputationKey] = useState(false);
  const [testingIpReputation, setTestingIpReputation] = useState(false);
  const [ipReputationTestResult, setIpReputationTestResult] = useState<IPReputationResult | null>(null);

  const [apiForm, setApiForm] = useState<PushSettingsPayload>({
    narwhal_api_url: 'https://api.fuckip.me/api/v1',
    narwhal_api_key: '',
    narwhal_machine_id: '',
    narwhal_node_name: '',
    buyer_notify_enabled: true,
    buyer_min_severity: 'warning',
    buyer_recovery_enabled: true,
  });

  // Telegram bot state
  const [bots, setBots] = useState<NotificationBot[]>([]);
  const [callbackReady, setCallbackReady] = useState(true);
  const [proxyConfigured, setProxyConfigured] = useState(false);
  const [proxyScheme, setProxyScheme] = useState('');
  const [savingBot, setSavingBot] = useState(false);
  const [showBotToken, setShowBotToken] = useState(false);

  // Dynamic Security Policy state
  const [secPolicy, setSecPolicy] = useState({
    sni_enforcement: true,
    block_cn_missing_sni: true,
    service_audit_enabled: true,
    auto_block_disallowed_service: false,
  });
  const [sniText, setSniText] = useState('');
  const [disallowedProtosText, setDisallowedProtosText] = useState('vmess, trojan');
  const [savingSecPolicy, setSavingSecPolicy] = useState(false);
  const [deletingBot, setDeletingBot] = useState<NotificationBot | null>(null);
  const [deletingBotId, setDeletingBotId] = useState<number | null>(null);
  const [botForm, setBotForm] = useState({
    name: 'Telegram 告警机器人',
    token: '',
    target: '',
    min_severity: 'critical',
  });

  const loadSettings = useCallback(async () => {
    try {
      setLoadingPush(true);
      const [pushData, botData, ipReputationData, secPolicyData] = await Promise.all([
        api.getPushSettings(),
        api.getNotificationBots(),
        api.getIPReputationSettings(),
        api.getSecurityPolicy().catch(() => null),
      ]);

      setPushSettings(pushData);
      setApiForm({
        narwhal_api_url: pushData.narwhal_api_url || 'https://api.fuckip.me/api/v1',
        narwhal_api_key: '',
        narwhal_machine_id: pushData.narwhal_machine_id || '',
        narwhal_node_name: pushData.narwhal_node_name || '',
        buyer_notify_enabled: Boolean(pushData.buyer_notify_enabled),
        buyer_min_severity: pushData.buyer_min_severity || 'warning',
        buyer_recovery_enabled: pushData.buyer_recovery_enabled !== false,
      });

      setBots(botData.items);
      setCallbackReady(botData.callback_ready);
      setProxyConfigured(Boolean(botData.proxy_configured));
      setProxyScheme(botData.proxy_scheme || '');
      setIpReputationConfigured(Boolean(ipReputationData.configured));
      setIpReputationSettings(ipReputationData);
      if (secPolicyData) {
        setSecPolicy({
          sni_enforcement: secPolicyData.sni_enforcement !== false,
          block_cn_missing_sni: secPolicyData.block_cn_missing_sni !== false,
          service_audit_enabled: secPolicyData.service_audit_enabled !== false,
          auto_block_disallowed_service: Boolean(secPolicyData.auto_block_disallowed_service),
        });
        setSniText((secPolicyData.sni_whitelist || []).join('\n'));
        setDisallowedProtosText((secPolicyData.disallowed_protocols || []).join(', '));
      }
    } catch (err: any) {
      onToast('error', `加载设置失败：${err.message || err}`);
    } finally {
      setLoadingPush(false);
    }
  }, [onToast]);

  useEffect(() => {
    loadSettings();
  }, [loadSettings]);

  const handleSavePush = async (e: React.FormEvent) => {
    e.preventDefault();
    setSavingPush(true);
    try {
      const payload: PushSettingsPayload = {
        narwhal_api_url: apiForm.narwhal_api_url?.trim(),
        narwhal_machine_id: apiForm.narwhal_machine_id?.trim(),
        narwhal_node_name: apiForm.narwhal_node_name?.trim(),
        buyer_notify_enabled: apiForm.buyer_notify_enabled,
        buyer_min_severity: apiForm.buyer_min_severity,
        buyer_recovery_enabled: apiForm.buyer_recovery_enabled,
      };
      if (apiForm.narwhal_api_key && apiForm.narwhal_api_key.trim()) {
        payload.narwhal_api_key = apiForm.narwhal_api_key.trim();
      }

      const res = await api.updatePushSettings(payload);
      onToast('success', res.message || 'Narwhal API 推送设置已保存');
      setApiForm((prev) => ({ ...prev, narwhal_api_key: '' }));
      await loadSettings();
    } catch (err: any) {
      onToast('error', `保存失败：${err.message || err}`);
    } finally {
      setSavingPush(false);
    }
  };

  const handleSaveSecurityPolicy = async (e: React.FormEvent) => {
    e.preventDefault();
    setSavingSecPolicy(true);
    try {
      const sni_whitelist = sniText
        .split(/[\n,]+/)
        .map((s) => s.trim().toLowerCase())
        .filter(Boolean);
      const disallowed_protocols = disallowedProtosText
        .split(/[,\n]+/)
        .map((s) => s.trim().toLowerCase())
        .filter(Boolean);
      const res = await api.saveSecurityPolicy({
        sni_enforcement: secPolicy.sni_enforcement,
        block_cn_missing_sni: secPolicy.block_cn_missing_sni,
        service_audit_enabled: secPolicy.service_audit_enabled,
        auto_block_disallowed_service: secPolicy.auto_block_disallowed_service,
        sni_whitelist,
        disallowed_protocols,
      });
      if (res?.policy) {
        setSniText((res.policy.sni_whitelist || []).join('\n'));
        setDisallowedProtosText((res.policy.disallowed_protocols || []).join(', '));
      }
      onToast('success', '动态安全策略已保存，节点将在下次心跳自动热更新生效');
    } catch (err: any) {
      onToast('error', `保存动态安全策略失败：${err.message || err}`);
    } finally {
      setSavingSecPolicy(false);
    }
  };

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

  const testSavedIpReputation = async () => {
    setTestingIpReputation(true);
    setIpReputationTestResult(null);
    try {
      const result = await api.testIPReputation();
      setIpReputationTestResult(result);
      if (result.status === 'checked') {
        onToast('success', 'AbuseIPDB API Key 验证成功');
      } else if (result.status === 'local_limit') {
        onToast('info', result.message || 'Key 已保存，但本地每日查询保护上限已触发，暂时无法验证');
      } else {
        onToast('error', `Key 已保存，但 AbuseIPDB 验证失败：${result.message || '请检查 API Key、额度或主控网络连接'}`);
      }
    } catch (err: any) {
      const result: IPReputationResult = {
        status: 'error',
        ip: '8.8.8.8',
        message: err?.message || '请求失败，请检查主控 API 状态',
      };
      setIpReputationTestResult(result);
      onToast('error', `Key 已保存，但验证请求失败：${result.message}`);
    } finally {
      try {
        const settings = await api.getIPReputationSettings();
        setIpReputationConfigured(Boolean(settings.configured));
        setIpReputationSettings(settings);
      } catch {
        // Keep the actual test result visible even if the follow-up status read fails.
      }
      setTestingIpReputation(false);
    }
  };

  const handleSaveIpReputationKey = async (event: React.FormEvent) => {
    event.preventDefault();
    if (!ipReputationKey.trim() || savingIpReputationKey) return;
    setSavingIpReputationKey(true);
    try {
      const result = await api.saveIPReputationKey(ipReputationKey.trim());
      setIpReputationKey('');
      setIpReputationConfigured(true);
      setIpReputationSettings((current) => (current ? { ...current, last_check: null } : current));
      setIpReputationTestResult(null);
      onToast('info', result.message || 'AbuseIPDB API Key 已加密保存，正在验证上游连通性');
      await testSavedIpReputation();
    } catch (err: any) {
      onToast('error', `保存 AbuseIPDB Key 失败：${err.message || err}`);
    } finally {
      setSavingIpReputationKey(false);
    }
  };

  const handleTestIpReputation = async () => {
    if (!ipReputationConfigured || testingIpReputation) return;
    await testSavedIpReputation();
  };

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

  const reputationLastCheck = ipReputationSettings?.last_check;
  const reputationStatusLabel = !ipReputationConfigured
    ? '尚未配置'
    : !reputationLastCheck
      ? '已配置 · 尚未验证'
      : reputationLastCheck.status === 'checked'
        ? '上游最近查询成功'
        : '上游最近查询失败';
  const reputationBoxClass =
    !ipReputationConfigured || (reputationLastCheck && reputationLastCheck.status !== 'checked')
      ? 'border-[#f7d58b] bg-[#fef6e4] text-[#9a5b00]'
      : reputationLastCheck
        ? 'border-[#9de2d8] bg-[#e6f7f4] text-[#147468]'
        : 'border-[#cbd7e6] bg-[#eef3f9] text-[#4a607a]';
  const reputationPillClass =
    !ipReputationConfigured || (reputationLastCheck && reputationLastCheck.status !== 'checked')
      ? 'rn2-pill rn2-pill-amber'
      : reputationLastCheck
        ? 'rn2-pill rn2-pill-teal'
        : 'rn2-pill rn2-pill-slate';
  const reputationCheckedAt = reputationLastCheck?.checked_at
    ? new Date(reputationLastCheck.checked_at * 1000).toLocaleString('zh-CN', { hour12: false })
    : '';

  return (
    <div className="space-y-6 text-[#0b1636]">
      {/* Settings Top Overview Card */}
      <section className="rn2-card overflow-hidden">
        <div className="rn2-card-head">
          <div className="flex min-w-0 items-center gap-3.5">
            <div className="flex h-11 w-11 shrink-0 items-center justify-center rounded-xl border border-[#54c7ff]/45 bg-[#087bff]/25 text-[#54c7ff]">
              <Settings className="h-5 w-5" aria-hidden="true" />
            </div>
            <div className="min-w-0">
              <span className="rn2-eyebrow block">SYSTEM CONFIGURATION · INTEGRATIONS &amp; POLICY</span>
              <div className="mt-0.5 flex flex-wrap items-center gap-2.5">
                <h2 className="text-lg font-bold tracking-tight text-white sm:text-xl">系统设置</h2>
                <span className="rounded-md border border-[#54c7ff]/40 bg-[#073365]/75 px-2 py-0.5 font-mono text-xs text-[#cde8ff]">
                  推送与 API 集成
                </span>
              </div>
              <p className="mt-0.5 text-xs text-[#b9d3ee]">
                集中管理 Narwhal 官方买家预警推送接口、AbuseIPDB 信誉库、Telegram 机器人与热下发安全策略。
              </p>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <span className={`rn2-pill ${pushSettings?.buyer_notify_enabled ? 'rn2-pill-teal' : 'rn2-pill-slate'}`}>
              <Radio className="h-3 w-3" aria-hidden="true" />
              {pushSettings?.buyer_notify_enabled ? '买家推送已启用' : '买家推送已停用'}
            </span>
            <span className={`rn2-pill ${pushSettings?.narwhal_api_key_configured ? 'rn2-pill-blue' : 'rn2-pill-amber'}`}>
              <KeyRound className="h-3 w-3" aria-hidden="true" />
              {pushSettings?.narwhal_api_key_configured ? 'API 密钥已配置' : 'API 密钥未配置'}
            </span>
            <span className={`rn2-pill ${bots.length > 0 ? 'rn2-pill-teal' : 'rn2-pill-slate'}`}>
              <Bot className="h-3 w-3" aria-hidden="true" />
              {bots.length > 0 ? `${bots.length} 个 TG 机器人` : '未配置 TG 机器人'}
            </span>
          </div>
        </div>

        <div className="rn2-spec-strip grid-cols-2 sm:grid-cols-4">
          <div className="rn2-spec-cell">
            <div className="text-[11px] font-bold uppercase tracking-wider text-[#697b9c]">买家推送状态</div>
            <div className={`mt-1 text-base font-bold ${pushSettings?.buyer_notify_enabled ? 'text-[#147468]' : 'text-[#506483]'}`}>
              {pushSettings?.buyer_notify_enabled ? '已启用' : '已停用'}
            </div>
          </div>
          <div className="rn2-spec-cell">
            <div className="text-[11px] font-bold uppercase tracking-wider text-[#697b9c]">Narwhal API 密钥</div>
            <div className={`mt-1 text-base font-bold ${pushSettings?.narwhal_api_key_configured ? 'text-[#087bff]' : 'text-[#9a5b00]'}`}>
              {pushSettings?.narwhal_api_key_configured ? '已加密配置' : '待配置'}
            </div>
          </div>
          <div className="rn2-spec-cell">
            <div className="text-[11px] font-bold uppercase tracking-wider text-[#697b9c]">Telegram 通道</div>
            <div className="mt-1 font-mono text-base font-bold text-[#0b1636] tabular-nums">
              {bots.length} 个机器人
            </div>
          </div>
          <div className="rn2-spec-cell">
            <div className="text-[11px] font-bold uppercase tracking-wider text-[#697b9c]">AbuseIPDB 信誉库</div>
            <div className={`mt-1 text-base font-bold ${ipReputationConfigured ? 'text-[#147468]' : 'text-[#9a5b00]'}`}>
              {reputationStatusLabel}
            </div>
          </div>
        </div>
      </section>

      <BuyerNotificationsView onToast={onToast} />

      {/* AbuseIPDB IP Reputation Card */}
      <section className="rn2-card overflow-hidden" aria-labelledby="ip-reputation-heading">
        <div className="rn2-card-head">
          <div className="flex min-w-0 items-center gap-3">
            <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl border border-[#54c7ff]/40 bg-[#087bff]/25 text-[#54c7ff]">
              <Globe className="h-5 w-5" aria-hidden="true" />
            </div>
            <div className="min-w-0">
              <span className="rn2-eyebrow block">ABUSEIPDB · INBOUND IP REPUTATION</span>
              <h3 id="ip-reputation-heading" className="mt-0.5 text-base font-bold text-white">
                入站 IP 信誉查询
              </h3>
            </div>
          </div>
          <span className={reputationPillClass}>{reputationStatusLabel}</span>
        </div>

        <div className="space-y-4 p-5 sm:p-6">
          <div className="flex flex-col gap-5 lg:flex-row lg:items-start lg:justify-between">
            <div className="max-w-2xl space-y-2.5">
              <p className="text-sm leading-6 text-[#31485e]">
                这不是逐条连接或全站后台扫描：打开容器诊断并取得有效深度快照后，页面自动查询入站连接数最多的前 5 个公网 IP；也可在快照中逐个补查。只向 AbuseIPDB 提交 IP，不发送主机或容器信息。
              </p>
              <p aria-live="polite" className={`rounded-xl border px-3.5 py-2.5 text-xs font-medium leading-5 ${reputationBoxClass}`}>
                {!ipReputationConfigured
                  ? '尚未保存 API Key。'
                  : !reputationLastCheck
                    ? 'Key 已保存，但还没有用当前 Key 完成上游验证；点击“测试连通性”进行一次真实查询。'
                    : reputationLastCheck.status === 'checked'
                      ? `最近一次上游查询成功${reputationCheckedAt ? ` · ${reputationCheckedAt}` : ''}。即使举报数和评分为 0，也表示 API 有正常返回。`
                      : `最近一次上游查询失败${reputationCheckedAt ? ` · ${reputationCheckedAt}` : ''}：${reputationLastCheck.message || '请检查 Key、权限、额度或主控网络。'}${reputationLastCheck.provider_status ? `（HTTP ${reputationLastCheck.provider_status}${reputationLastCheck.retry_after_seconds ? `，${reputationLastCheck.retry_after_seconds} 秒后可重试` : ''}）` : ''}`}
              </p>
              <p className="rounded-lg border border-[#f7d58b] bg-[#fef6e4] px-3 py-2 text-xs leading-5 text-[#9a5b00]">
                命中会在深度快照中提醒，≥75 分标红；信誉分不能证明本次连接恶意或归责客户，不会自动封禁来源、停容器或处罚客户。
              </p>
            </div>

            <form
              onSubmit={handleSaveIpReputationKey}
              className="flex w-full flex-col gap-3 rounded-xl border border-[#dce5ef] bg-[#f4f8fd] p-4 sm:flex-row sm:items-end lg:max-w-2xl"
            >
              <div className="min-w-0 flex-1">
                <label htmlFor="abuseipdb-key" className="block text-xs font-semibold text-[#31485e]">
                  {ipReputationConfigured ? '输入新的 AbuseIPDB API Key 以替换' : 'AbuseIPDB API Key'}
                </label>
                <div className="relative mt-1.5">
                  <input
                    id="abuseipdb-key"
                    type={showAbuseKey ? 'text' : 'password'}
                    autoComplete="new-password"
                    spellCheck={false}
                    maxLength={256}
                    value={ipReputationKey}
                    onChange={(event) => setIpReputationKey(event.target.value)}
                    placeholder={ipReputationConfigured ? '已配置的密钥不会显示' : '粘贴新签发的 API Key'}
                    className="rn2-input pr-12 font-mono"
                  />
                  <button
                    type="button"
                    onClick={() => setShowAbuseKey((prev) => !prev)}
                    aria-label={showAbuseKey ? '隐藏 AbuseIPDB API Key' : '显示 AbuseIPDB API Key'}
                    aria-pressed={showAbuseKey}
                    className="absolute inset-y-0 right-0 flex w-11 items-center justify-center text-[#506483] transition-colors hover:text-[#087bff]"
                  >
                    {showAbuseKey ? <EyeOff className="h-4 w-4" aria-hidden="true" /> : <Eye className="h-4 w-4" aria-hidden="true" />}
                  </button>
                </div>
              </div>
              <button
                type="button"
                onClick={handleTestIpReputation}
                disabled={!ipReputationConfigured || testingIpReputation || savingIpReputationKey}
                className="rn2-btn rn2-btn-ghost shrink-0"
              >
                {testingIpReputation ? '测试中…' : '测试连通性'}
              </button>
              <button
                type="submit"
                disabled={savingIpReputationKey || !ipReputationKey.trim()}
                className="rn2-btn rn2-btn-orange shrink-0"
              >
                {savingIpReputationKey ? '加密保存中…' : ipReputationConfigured ? '替换密钥' : '加密保存'}
              </button>
            </form>
          </div>

          <p className="text-xs leading-5 text-[#506483]">
            连通性测试会向 AbuseIPDB 发起一次真实查询，使用固定公网测试 IP 8.8.8.8，并计入当日额度；不会提交任何客户 IP、主机名或容器信息。
          </p>

          {ipReputationTestResult && (
            <div
              role="status"
              className={`rounded-xl border px-3.5 py-2.5 text-xs leading-5 ${
                ipReputationTestResult.status === 'checked'
                  ? 'border-[#9de2d8] bg-[#e6f7f4] text-[#147468]'
                  : ipReputationTestResult.status === 'local_limit'
                    ? 'border-[#f7d58b] bg-[#fef6e4] text-[#9a5b00]'
                    : 'border-[#f9b8c4] bg-[#ffeef1] text-[#b41835]'
              }`}
            >
              <strong>
                {ipReputationTestResult.status === 'checked'
                  ? 'API Key 与上游连通正常'
                  : ipReputationTestResult.status === 'local_limit'
                    ? '本地查询额度保护已触发，尚未完成上游验证'
                    : 'API 连通性验证失败'}
              </strong>
              {ipReputationTestResult.status === 'checked' ? (
                <span>
                  {' '}
                  · 测试 IP {ipReputationTestResult.ip} · 评分 {ipReputationTestResult.abuse_confidence_score ?? 0}/100 · 公开举报{' '}
                  {ipReputationTestResult.total_reports ?? 0} 次
                </span>
              ) : (
                <span>
                  {' '}
                  · {ipReputationTestResult.message || '请检查 API Key、额度或主控网络连接。'}
                  {ipReputationTestResult.provider_status
                    ? `（上游 HTTP ${ipReputationTestResult.provider_status}${ipReputationTestResult.retry_after_seconds ? `，建议 ${ipReputationTestResult.retry_after_seconds} 秒后重试` : ''}）`
                    : ''}
                </span>
              )}
            </div>
          )}

          <p className="border-t border-[#dce5ef] pt-3 text-xs leading-5 text-[#506483]">
            密钥加密保存在主控端数据库，不会返回前端或下发到节点；成功结果缓存 24 小时，每日最多 900 次查询以留出免费套餐余量。查询失败或额度耗尽不代表 IP 安全或恶意。
          </p>
        </div>
      </section>

      <div className="grid grid-cols-1 items-start gap-6 lg:grid-cols-2">
        {/* CARD A: Narwhal Cloud Buyer Push */}
        <section className="rn2-card overflow-hidden">
          <div className="rn2-card-head">
            <div className="flex min-w-0 items-center gap-3">
              <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl border border-[#54c7ff]/40 bg-[#087bff]/25 text-[#54c7ff]">
                <Cloud className="h-5 w-5" aria-hidden="true" />
              </div>
              <div className="min-w-0">
                <span className="rn2-eyebrow block">BUYER PUSH API</span>
                <h3 className="mt-0.5 text-base font-bold text-white">Narwhal Cloud 买家推送配置</h3>
                <p className="mt-0.5 text-xs text-[#b9d3ee]">向购买该机器容器的租户直接推送严重违规/安全预警通知</p>
              </div>
            </div>

            <label className="flex min-h-11 cursor-pointer select-none items-center gap-2">
              <span className="text-xs font-semibold text-[#e6f4ff]">
                {apiForm.buyer_notify_enabled ? '启用推送' : '已停用'}
              </span>
              <input
                type="checkbox"
                checked={apiForm.buyer_notify_enabled}
                onChange={(e) => setApiForm({ ...apiForm, buyer_notify_enabled: e.target.checked })}
                className="sr-only peer"
              />
              <div className="relative h-6 w-11 rounded-full bg-[#09203b] border border-[#54c7ff]/40 after:absolute after:left-[2px] after:top-[2px] after:h-5 after:w-5 after:rounded-full after:bg-white after:transition-all after:content-[''] peer-checked:bg-[#087bff] peer-checked:after:translate-x-full peer-focus-visible:ring-2 peer-focus-visible:ring-[#54c7ff]" />
            </label>
          </div>

          <div className="space-y-4 p-5 sm:p-6">
            <div className="flex items-start gap-2.5 rounded-xl border border-[#a9d1ff] bg-[#e8f3ff] p-3.5 text-xs text-[#0657b8]">
              <Info className="mt-0.5 h-4 w-4 shrink-0 text-[#087bff]" aria-hidden="true" />
              <div className="space-y-1">
                <p className="font-bold text-[#0b1636]">服务端统一发送，API 密钥不下发节点</p>
                <p className="text-[11px] leading-relaxed text-[#31485e]">
                  在上方记录中心登记精确的主机、运行时、项目、容器与买家 user_id。缺少映射时阻止发送，绝不猜测机器 UUID 或默认广播。预览不会请求上游；真实测试需要单独确认收件范围。
                </p>
              </div>
            </div>

            <form onSubmit={handleSavePush} className="space-y-4">
              <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                <label className="block text-xs font-semibold text-[#31485e]">
                  最低告警等级
                  <select
                    value={apiForm.buyer_min_severity || 'warning'}
                    onChange={(e) =>
                      setApiForm({ ...apiForm, buyer_min_severity: e.target.value as 'warning' | 'critical' })
                    }
                    className="rn2-select mt-1.5"
                  >
                    <option value="warning">警告及危险</option>
                    <option value="critical">仅危险</option>
                  </select>
                </label>

                <label className="flex min-h-11 cursor-pointer items-center gap-2.5 self-end rounded-xl border border-[#cedae7] bg-[#f4f8fd] px-3.5 text-xs font-semibold text-[#0b1636]">
                  <input
                    type="checkbox"
                    checked={apiForm.buyer_recovery_enabled !== false}
                    onChange={(e) => setApiForm({ ...apiForm, buyer_recovery_enabled: e.target.checked })}
                    className="h-4 w-4 accent-[#087bff]"
                  />
                  发送复查恢复通知
                </label>
              </div>

              <div>
                <label htmlFor="narwhal-api-url" className="block text-xs font-semibold text-[#31485e]">
                  Narwhal API 接口基地址
                </label>
                <div className="relative mt-1.5">
                  <div className="pointer-events-none absolute inset-y-0 left-0 flex items-center pl-3 text-[#697b9c]">
                    <Server className="h-4 w-4" aria-hidden="true" />
                  </div>
                  <input
                    id="narwhal-api-url"
                    type="url"
                    required
                    value={apiForm.narwhal_api_url}
                    onChange={(e) => setApiForm({ ...apiForm, narwhal_api_url: e.target.value })}
                    placeholder="https://api.fuckip.me/api/v1"
                    className="rn2-input pl-10 font-mono"
                  />
                </div>
                <span className="mt-1 block text-[11px] text-[#506483]">
                  推送端点为 <code className="font-mono text-[#0657b8]">/machines/&#123;machineId&#125;/notify-buyers</code>
                </span>
              </div>

              <div>
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <label htmlFor="narwhal-api-key" className="block text-xs font-semibold text-[#31485e]">
                    Narwhal API 密钥 (Bearer Token)
                  </label>
                  {pushSettings?.narwhal_api_key_configured && (
                    <span className="font-mono text-[11px] font-semibold text-[#147468]">
                      当前已生效：{pushSettings.narwhal_api_key_masked}
                    </span>
                  )}
                </div>
                <div className="relative mt-1.5">
                  <div className="pointer-events-none absolute inset-y-0 left-0 flex items-center pl-3 text-[#697b9c]">
                    <KeyRound className="h-4 w-4" aria-hidden="true" />
                  </div>
                  <input
                    id="narwhal-api-key"
                    type={showApiKey ? 'text' : 'password'}
                    autoComplete="new-password"
                    value={apiForm.narwhal_api_key}
                    onChange={(e) => setApiForm({ ...apiForm, narwhal_api_key: e.target.value })}
                    placeholder={
                      pushSettings?.narwhal_api_key_configured
                        ? '留空保持现有密钥，输入新密钥覆盖'
                        : '请输入 Narwhal 平台 API Key (例如 sk_...)'
                    }
                    className="rn2-input pl-10 pr-12 font-mono"
                  />
                  <button
                    type="button"
                    onClick={() => setShowApiKey((prev) => !prev)}
                    className="absolute inset-y-0 right-0 flex w-11 items-center justify-center text-[#506483] transition-colors hover:text-[#087bff]"
                    aria-label={showApiKey ? '隐藏 API Key' : '显示 API Key'}
                    aria-pressed={showApiKey}
                  >
                    {showApiKey ? <EyeOff className="h-4 w-4" aria-hidden="true" /> : <Eye className="h-4 w-4" aria-hidden="true" />}
                  </button>
                </div>
              </div>

              <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
                <div>
                  <label htmlFor="narwhal-machine-id" className="block text-xs font-semibold text-[#31485e]">
                    测试机器 UUID (选填 · 供测试连通性使用)
                  </label>
                  <input
                    id="narwhal-machine-id"
                    type="text"
                    value={apiForm.narwhal_machine_id}
                    onChange={(e) => setApiForm({ ...apiForm, narwhal_machine_id: e.target.value })}
                    placeholder="选填，如 00000000-0000-0000-0000-000000000001"
                    className="rn2-input mt-1.5 font-mono"
                  />
                  <span className="mt-1 block text-[11px] text-[#506483]">
                    此处仅供格式预览；实际告警使用上方登记的精确收件映射
                  </span>
                </div>

                <div>
                  <label htmlFor="narwhal-node-name" className="block text-xs font-semibold text-[#31485e]">
                    测试节点名称 (选填 · 默认取母鸡主机名)
                  </label>
                  <input
                    id="narwhal-node-name"
                    type="text"
                    value={apiForm.narwhal_node_name}
                    onChange={(e) => setApiForm({ ...apiForm, narwhal_node_name: e.target.value })}
                    placeholder="选填，如 US-LAX-01 或 宿主机名"
                    className="rn2-input mt-1.5"
                  />
                  <span className="mt-1 block text-[11px] text-[#506483]">
                    实际告警标题使用精确映射中的节点名称
                  </span>
                </div>
              </div>

              <div className="rounded-xl border border-[#cedae7] bg-[#f4f8fd] p-3.5">
                <div className="mb-2 flex items-center justify-between border-b border-[#d2dfec] pb-2 text-[11px]">
                  <span className="flex items-center gap-1.5 font-bold text-[#0b1636]">
                    <Info className="h-3.5 w-3.5 text-[#087bff]" aria-hidden="true" />
                    买家通知实时格式预览
                  </span>
                  <span className="font-mono font-semibold text-[#506483]">24h 智能频控</span>
                </div>
                <div className="space-y-2 font-mono text-xs leading-relaxed">
                  <div className="font-bold text-[#9a5b00]">
                    [已执行，待复查] {apiForm.narwhal_node_name || 'US-LAX-01'}
                  </div>
                  <div className="whitespace-pre-line rounded-lg border border-[#dce5ef] bg-white p-2.5 text-[11px] text-[#31485e]">
                    {`事件 NW-demo\n容器 incus/default/c-demo-8f3a\n状态 已执行，待复查\n问题 无认证 / 弱口令 SOCKS5 代理\n执行成功不等于复查通过，请等待新报告验证。`}
                  </div>
                </div>
              </div>

              <div className="flex flex-wrap items-center gap-3 pt-1">
                <button type="submit" disabled={savingPush || loadingPush} className="rn2-btn rn2-btn-orange">
                  <Save className="h-4 w-4" aria-hidden="true" />
                  {savingPush ? '保存中…' : '保存 API 配置'}
                </button>

                <button
                  type="button"
                  disabled={testingPush || loadingPush}
                  onClick={handleTestPush}
                  className="rn2-btn rn2-btn-blue"
                >
                  <Send className="h-3.5 w-3.5" aria-hidden="true" />
                  {testingPush ? '预览中…' : '检查通知预览（不发送）'}
                </button>
              </div>

              <div className="flex items-start gap-2 rounded-xl border border-[#dce5ef] bg-[#f4f8fd] p-3 text-[11px] text-[#31485e]">
                <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-[#147468]" aria-hidden="true" />
                <span>
                  <strong className="text-[#0b1636]">频控机制保护：</strong>
                  同一母鸡机器 24 小时内向买家发送一条预警通知，以避免短时间内重复骚扰用户。
                </span>
              </div>
            </form>
          </div>
        </section>

        {/* CARD B: Telegram Alert Bots */}
        <section className="rn2-card overflow-hidden">
          <div className="rn2-card-head">
            <div className="flex min-w-0 items-center gap-3">
              <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl border border-[#54c7ff]/40 bg-[#087bff]/25 text-[#54c7ff]">
                <Bot className="h-5 w-5" aria-hidden="true" />
              </div>
              <div className="min-w-0">
                <span className="rn2-eyebrow block">TELEGRAM BOT</span>
                <h3 className="mt-0.5 text-base font-bold text-white">Telegram 告警机器人</h3>
                <p className="mt-0.5 text-xs text-[#b9d3ee]">推送运维告警至管理员群组，支持动态刷新与控制台操作</p>
              </div>
            </div>

            <span className={`rn2-pill ${proxyConfigured ? 'rn2-pill-teal' : 'rn2-pill-slate'}`}>
              <Globe className="h-3.5 w-3.5" aria-hidden="true" />
              {proxyConfigured ? `代理 (${proxyScheme.toUpperCase()})` : '直连 API'}
            </span>
          </div>

          <div className="space-y-5 p-5 sm:p-6">
            {!callbackReady && (
              <div className="flex items-start gap-2 rounded-xl border border-[#f7d58b] bg-[#fef6e4] p-3 text-xs text-[#9a5b00]">
                <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" aria-hidden="true" />
                <span>
                  已可发送通知；要启用消息内交互按钮（快捷处理/忽略），请在 Server 环境变量配置{' '}
                  <code className="rounded bg-white px-1 py-0.5 font-mono text-[#0b1636]">PUBLIC_BASE_URL</code> 为公网 HTTPS 地址。
                </span>
              </div>
            )}

            <form
              onSubmit={handleSaveBot}
              className="space-y-4 rounded-xl border border-[#dce5ef] bg-[#f4f8fd] p-4"
            >
              <div className="flex items-center gap-2 text-xs font-bold text-[#0b1636]">
                <BellRing className="h-3.5 w-3.5 text-[#087bff]" aria-hidden="true" />
                添加新 Telegram 机器人
              </div>

              <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                <div>
                  <label htmlFor="tg-bot-name" className="block text-xs font-semibold text-[#31485e]">
                    机器人名称
                  </label>
                  <input
                    id="tg-bot-name"
                    required
                    value={botForm.name}
                    onChange={(e) => setBotForm({ ...botForm, name: e.target.value })}
                    placeholder="如 运维告警群"
                    className="rn2-input mt-1.5"
                  />
                </div>

                <div>
                  <label htmlFor="tg-bot-severity" className="block text-xs font-semibold text-[#31485e]">
                    最低推送级别
                  </label>
                  <select
                    id="tg-bot-severity"
                    value={botForm.min_severity}
                    onChange={(e) => setBotForm({ ...botForm, min_severity: e.target.value })}
                    className="rn2-select mt-1.5"
                  >
                    <option value="critical">仅严重告警 (Critical)</option>
                    <option value="warning">警告及以上 (Warning+)</option>
                    <option value="info">全部告警 (All)</option>
                  </select>
                </div>
              </div>

              <div>
                <label htmlFor="tg-bot-token" className="block text-xs font-semibold text-[#31485e]">
                  Bot Token
                </label>
                <div className="relative mt-1.5">
                  <input
                    id="tg-bot-token"
                    required
                    type={showBotToken ? 'text' : 'password'}
                    autoComplete="new-password"
                    value={botForm.token}
                    onChange={(e) => setBotForm({ ...botForm, token: e.target.value })}
                    placeholder="123456789:ABCdef-GHI..."
                    className="rn2-input pr-12 font-mono"
                  />
                  <button
                    type="button"
                    onClick={() => setShowBotToken((prev) => !prev)}
                    className="absolute inset-y-0 right-0 flex w-11 items-center justify-center text-[#506483] transition-colors hover:text-[#087bff]"
                    aria-label={showBotToken ? '隐藏 Bot Token' : '显示 Bot Token'}
                    aria-pressed={showBotToken}
                  >
                    {showBotToken ? <EyeOff className="h-4 w-4" aria-hidden="true" /> : <Eye className="h-4 w-4" aria-hidden="true" />}
                  </button>
                </div>
              </div>

              <div>
                <label htmlFor="tg-bot-target" className="block text-xs font-semibold text-[#31485e]">
                  推送目标 (Chat ID、@频道 或 话题)
                </label>
                <input
                  id="tg-bot-target"
                  required
                  value={botForm.target}
                  onChange={(e) => setBotForm({ ...botForm, target: e.target.value })}
                  placeholder="-1001234567890、@channel 或 -100xxx:topic_id"
                  className="rn2-input mt-1.5 font-mono"
                />
                <span className="mt-1 block text-[11px] text-[#506483]">
                  私聊先发送 /start；频道填 @channel；群论坛话题填 -100xxx:topic_id
                </span>
              </div>

              <div>
                <button type="submit" disabled={savingBot} className="rn2-btn rn2-btn-orange">
                  <Bot className="h-4 w-4" aria-hidden="true" />
                  {savingBot ? '保存中…' : '添加机器人并验证'}
                </button>
              </div>
            </form>

            <div className="space-y-3">
              <h4 className="text-xs font-bold uppercase tracking-wider text-[#506483]">
                已配置的 Telegram 机器人 ({bots.length})
              </h4>

              {bots.map((bot) => (
                <div
                  key={bot.id}
                  className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-[#cedae7] bg-white p-4 transition-colors hover:border-[#087bff]/50"
                >
                  <div className="min-w-0 space-y-1">
                    <p className="flex flex-wrap items-center gap-2 text-sm font-bold text-[#0b1636]">
                      <span>{bot.name}</span>
                      <span className="rounded-md border border-[#cedae7] bg-[#f4f8fd] px-2 py-0.5 font-mono text-xs font-normal text-[#31485e]">
                        {bot.target}
                      </span>
                    </p>
                    <p className="text-xs text-[#31485e]">
                      级别：{bot.min_severity === 'critical' ? '仅严重告警' : bot.min_severity === 'warning' ? '警告及以上' : '全部告警'} · Token 已脱敏保护
                    </p>
                    <p
                      className={`text-xs font-medium ${
                        bot.last_delivery_status === 'failed'
                          ? 'text-[#b41835]'
                          : bot.last_delivery_status === 'succeeded'
                            ? 'text-[#147468]'
                            : 'text-[#697b9c]'
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
                      className="rn2-btn rn2-btn-ghost rn2-btn-sm"
                    >
                      <Send className="h-3.5 w-3.5 text-[#087bff]" aria-hidden="true" />
                      测试
                    </button>

                    <button
                      type="button"
                      onClick={() => setDeletingBot(bot)}
                      className="rn2-btn rn2-btn-danger rn2-btn-sm min-w-11"
                      aria-label={`删除机器人 ${bot.name}`}
                    >
                      <Trash2 className="h-4 w-4" aria-hidden="true" />
                    </button>
                  </div>
                </div>
              ))}

              {bots.length === 0 && (
                <div className="rounded-xl border border-dashed border-[#cedae7] bg-[#f4f8fd] p-6 text-center text-xs sm:text-sm text-[#506483]">
                  尚未配置 Telegram 推送机器人，可使用上方表单快速添加
                </div>
              )}
            </div>
          </div>
        </section>

        {/* CARD C: Dynamic Security Policy Center */}
        <section className="rn2-card overflow-hidden lg:col-span-2">
          <div className="rn2-card-head">
            <div className="flex min-w-0 items-center gap-3">
              <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl border border-[#54c7ff]/40 bg-[#087bff]/25 text-[#54c7ff]">
                <ShieldCheck className="h-5 w-5" aria-hidden="true" />
              </div>
              <div className="min-w-0">
                <span className="rn2-eyebrow block">DYNAMIC SECURITY POLICY · HOT RELOAD</span>
                <h3 className="mt-0.5 text-base font-bold text-white">
                  动态安全策略中心（SNI 白名单 &amp; 服务合规）
                </h3>
                <p className="mt-0.5 text-xs text-[#b9d3ee]">
                  无需重启或重编节点 Agent，保存后随心跳实时热下发至所有在线宿主机
                </p>
              </div>
            </div>
          </div>

          <form onSubmit={handleSaveSecurityPolicy} className="space-y-4 p-5 sm:p-6">
            <div className="grid grid-cols-1 gap-3 md:grid-cols-2 lg:grid-cols-4">
              <label className="flex cursor-pointer items-start gap-2.5 rounded-xl border border-[#dce5ef] bg-[#f4f8fd] p-3.5 transition-colors hover:border-[#087bff]/60">
                <input
                  type="checkbox"
                  checked={secPolicy.sni_enforcement}
                  onChange={(e) => setSecPolicy((p) => ({ ...p, sni_enforcement: e.target.checked }))}
                  className="mt-0.5 h-4 w-4 accent-[#087bff]"
                />
                <div className="text-xs">
                  <div className="font-bold text-[#0b1636]">启用 SNI 白名单阻断</div>
                  <div className="mt-0.5 text-[#506483]">对入站 TLS 握手校验 SNI 白名单</div>
                </div>
              </label>

              <label className="flex cursor-pointer items-start gap-2.5 rounded-xl border border-[#dce5ef] bg-[#f4f8fd] p-3.5 transition-colors hover:border-[#087bff]/60">
                <input
                  type="checkbox"
                  checked={secPolicy.block_cn_missing_sni}
                  onChange={(e) => setSecPolicy((p) => ({ ...p, block_cn_missing_sni: e.target.checked }))}
                  className="mt-0.5 h-4 w-4 accent-[#087bff]"
                />
                <div className="text-xs">
                  <div className="font-bold text-[#0b1636]">阻断 CN 无 SNI 流量</div>
                  <div className="mt-0.5 text-[#506483]">拦截来自中国大陆但缺失 SNI 的 TLS/QUIC 包</div>
                </div>
              </label>

              <label className="flex cursor-pointer items-start gap-2.5 rounded-xl border border-[#dce5ef] bg-[#f4f8fd] p-3.5 transition-colors hover:border-[#087bff]/60">
                <input
                  type="checkbox"
                  checked={secPolicy.service_audit_enabled}
                  onChange={(e) => setSecPolicy((p) => ({ ...p, service_audit_enabled: e.target.checked }))}
                  className="mt-0.5 h-4 w-4 accent-[#087bff]"
                />
                <div className="text-xs">
                  <div className="font-bold text-[#0b1636]">启用容器服务配置审计</div>
                  <div className="mt-0.5 text-[#506483]">脱敏采集容器代理配置并核验违规协议/开放代理</div>
                </div>
              </label>

              <label className="flex cursor-pointer items-start gap-2.5 rounded-xl border border-[#f7d58b] bg-[#fef6e4] p-3.5 transition-colors hover:border-[#d97706]">
                <input
                  type="checkbox"
                  checked={secPolicy.auto_block_disallowed_service}
                  onChange={(e) => setSecPolicy((p) => ({ ...p, auto_block_disallowed_service: e.target.checked }))}
                  className="mt-0.5 h-4 w-4 accent-[#ff6b00]"
                />
                <div className="text-xs">
                  <div className="font-bold text-[#9a5b00]">违规服务自动限流</div>
                  <div className="mt-0.5 text-[#7c4d08]">检测到受限协议/穿透服务时自动下发 30 分钟 500 并发上限</div>
                </div>
              </label>
            </div>

            <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
              <div>
                <label htmlFor="sni-whitelist-input" className="mb-1.5 block text-xs font-semibold text-[#31485e]">
                  SNI 允许白名单域名（每行或逗号分隔，支持主域及子域）
                </label>
                <textarea
                  id="sni-whitelist-input"
                  rows={5}
                  value={sniText}
                  onChange={(e) => setSniText(e.target.value)}
                  placeholder="crates.io&#10;github.com&#10;pypi.org"
                  className="rn2-input font-mono text-xs"
                />
              </div>

              <div className="space-y-3">
                <div>
                  <label htmlFor="disallowed-protos-input" className="mb-1.5 block text-xs font-semibold text-[#31485e]">
                    受限/违规服务协议（逗号分隔）
                  </label>
                  <input
                    id="disallowed-protos-input"
                    type="text"
                    value={disallowedProtosText}
                    onChange={(e) => setDisallowedProtosText(e.target.value)}
                    placeholder="vmess, trojan"
                    className="rn2-input font-mono text-xs"
                  />
                  <p className="mt-1.5 text-[11px] text-[#506483]">
                    匹配容器内正在运行的代理入站协议时触发{' '}
                    <code className="rounded bg-[#f4f8fd] px-1 py-0.5 font-mono text-[#0657b8]">
                      service_disallowed_protocol
                    </code>{' '}
                    告警。
                  </p>
                </div>

                <div className="pt-2">
                  <button
                    type="submit"
                    disabled={savingSecPolicy || loadingPush}
                    className="rn2-btn rn2-btn-orange"
                  >
                    <Save className="h-4 w-4" aria-hidden="true" />
                    {savingSecPolicy ? '下发中…' : '保存并热下发安全策略'}
                  </button>
                </div>
              </div>
            </div>
          </form>
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
