import React, { useState, useEffect, useCallback, useMemo } from 'react';
import {
  Globe, Shield, AlertTriangle, CheckCircle2, RefreshCw,
  Zap, ArrowRight, HelpCircle, ChevronDown, ChevronUp, Copy, Check,
  Key, Clock, Sparkles
} from 'lucide-react';
import { RegionResult, ReachCheckSummary } from '../../utils/reachCheck';
import { api } from '../../api/client';
import { ReachabilityClusterSummary, ReachabilitySummaryItem, ReachabilityQuotaInfo } from '../../api/types';

interface ReachCheckPanelProps {
  initialTarget?: string;
  initialPort?: number;
  availableHosts?: Array<{ id: string; name: string; ip?: string }>;
  onBackToTcping?: () => void;
  isLoggedIn?: boolean;
}

const isIpString = (val?: string) => !!val && /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(val.trim());

function formatInspectionTime(checkedAt?: number, isoUtc8?: string): { time: string; relative: string; full: string } {
  if (!checkedAt || checkedAt <= 0) {
    return { time: '—', relative: '未巡检', full: '尚未巡检' };
  }
  const date = new Date(checkedAt * 1000);
  const timeStr = date.toLocaleTimeString('zh-CN', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });
  const fullStr = isoUtc8 || date.toLocaleString('zh-CN', { hour12: false });

  const nowSec = Math.floor(Date.now() / 1000);
  const diffSec = Math.max(0, nowSec - checkedAt);
  let relativeStr = '刚刚';
  if (diffSec < 60) {
    relativeStr = `${diffSec}秒前`;
  } else if (diffSec < 3600) {
    relativeStr = `${Math.floor(diffSec / 60)}分钟前`;
  } else if (diffSec < 86400) {
    relativeStr = `${Math.floor(diffSec / 3600)}小时前`;
  } else {
    relativeStr = `${Math.floor(diffSec / 86400)}天前`;
  }
  return { time: timeStr, relative: relativeStr, full: fullStr };
}

const latencyBadgeColor = (ms: number) => {
  if (ms <= 60) return 'border-emerald-500/40 bg-emerald-950/40 text-emerald-300';
  if (ms <= 150) return 'border-sky-500/40 bg-sky-950/40 text-sky-300';
  if (ms <= 260) return 'border-amber-500/40 bg-amber-950/40 text-amber-300';
  return 'border-rose-500/40 bg-rose-950/40 text-rose-300';
};

export const ReachCheckPanel: React.FC<ReachCheckPanelProps> = ({
  availableHosts = [],
  onBackToTcping,
  isLoggedIn,
}) => {
  const [authed, setAuthed] = useState<boolean>(isLoggedIn ?? false);

  useEffect(() => {
    if (isLoggedIn !== undefined) {
      setAuthed(isLoggedIn);
      return;
    }
    let alive = true;
    api.getAuthStatus().then(s => {
      if (alive) setAuthed(!!s?.authenticated);
    }).catch(() => {
      if (alive) setAuthed(false);
    });
    return () => { alive = false; };
  }, [isLoggedIn]);

  // Cluster data & quota
  const [clusterData, setClusterData] = useState<ReachabilityClusterSummary | null>(null);
  const [quota, setQuota] = useState<ReachabilityQuotaInfo | null>(null);
  const [loadingCluster, setLoadingCluster] = useState(false);
  const [triggeringCluster, setTriggeringCluster] = useState(false);
  const [triggeringHostId, setTriggeringHostId] = useState<string | null>(null);
  const [triggerMessage, setTriggerMessage] = useState<string>('');

  // API Key modal
  const [showKeyModal, setShowKeyModal] = useState(false);
  const [apiKeyInput, setApiKeyInput] = useState('');
  const [savingKey, setSavingKey] = useState(false);
  const [keyFeedback, setKeyFeedback] = useState<string>('');

  // Expandable in-place host detail state
  const [expandedHostId, setExpandedHostId] = useState<string | null>(null);
  const [activeStackTab, setActiveStackTab] = useState<'v4' | 'v6'>('v4');
  const [summary, setSummary] = useState<ReachCheckSummary | null>(null);
  const [liveResults, setLiveResults] = useState<RegionResult[]>([]);
  const [copied, setCopied] = useState(false);
  const [showAdvice, setShowAdvice] = useState(true);
  const [filterGroup, setFilterGroup] = useState<'all' | 'cn' | 'apac' | 'emea' | 'am'>('all');

  const fetchClusterSummary = useCallback(async () => {
    setLoadingCluster(true);
    try {
      const data: ReachabilityClusterSummary = await api.getReachabilitySummary();
      setClusterData(data);
      if (data.quota) {
        setQuota(data.quota);
      }
    } catch (err: any) {
      console.warn('Failed to load reachability cluster summary', err);
    } finally {
      setLoadingCluster(false);
    }
  }, []);

  useEffect(() => {
    fetchClusterSummary();
    const timer = setInterval(fetchClusterSummary, 60000);
    return () => clearInterval(timer);
  }, [fetchClusterSummary]);

  // Trigger whole-cluster scheduled cycle
  const handleTriggerCluster = async () => {
    if (!authed) {
      setTriggerMessage('需管理员登录后触发巡检');
      return;
    }
    setTriggeringCluster(true);
    setTriggerMessage('');
    try {
      const res: any = await api.triggerReachabilityCheck();
      setTriggerMessage(res?.message || '全集群巡检已触发，正在后台平滑时序调度...');
      setTimeout(() => {
        fetchClusterSummary();
        setTriggerMessage('');
      }, 5000);
    } catch (err: any) {
      setTriggerMessage(`触发失败：${err.message || err}`);
    } finally {
      setTriggeringCluster(false);
    }
  };

  // Trigger single host immediate reach check
  const handleTriggerHost = async (hostId: string) => {
    if (!authed) {
      setTriggerMessage('需管理员登录后触发检测');
      return;
    }
    setTriggeringHostId(hostId);
    setTriggerMessage('');
    try {
      const res: any = await api.triggerReachabilityCheck(hostId);
      if (res?.item) {
        setClusterData(prev => {
          if (!prev) return prev;
          const items = prev.items.map(it => it.host_id === hostId ? res.item : it);
          return { ...prev, items };
        });
        if (expandedHostId === hostId) {
          handleSelectClusterItem(res.item, activeStackTab);
        }
      } else {
        await fetchClusterSummary();
      }
      setTriggerMessage(res?.message || `主机 ${hostId} 检测已完成`);
      setTimeout(() => setTriggerMessage(''), 4000);
    } catch (err: any) {
      setTriggerMessage(`检测失败：${err.message || err}`);
      setTimeout(() => setTriggerMessage(''), 4000);
    } finally {
      setTriggeringHostId(null);
    }
  };

  const handleSelectClusterItem = useCallback((item: ReachabilitySummaryItem, stack: 'v4' | 'v6' = 'v4') => {
    setActiveStackTab(stack);

    const isV6 = stack === 'v6';
    const targetIp = isV6 ? (item.target_v6 || '') : (item.target || '');
    const displayTarget = authed ? (targetIp || item.host_id) : (item.host_id || '已脱敏目标');
    const portNum = isV6 ? (item.port_v6 || item.port || 0) : (item.port || 0);
    const protoStr = isV6 ? (item.protocol_v6 || item.protocol || 'TCP') : (item.protocol || 'TCP');
    const verdictStr = isV6 ? (item.verdict_v6 || item.verdict || 'ok') : (item.verdict || 'ok');
    const verdictLabelStr = isV6 ? (item.verdict_label_v6 || item.verdict_label || '可达性检测完毕') : (item.verdict_label || '可达性检测完毕');
    const verdictDescStr = isV6 ? (item.verdict_desc_v6 || item.verdict_desc || '') : (item.verdict_desc || '');
    const resList = isV6 ? (item.results_v6 && item.results_v6.length > 0 ? item.results_v6 : item.results || []) : (item.results || []);
    const statsObj = isV6 ? (item.stats_v6 || item.stats) : item.stats;

    setLiveResults(resList);
    const isOk = verdictStr === 'ok';
    const isPing = protoStr.toUpperCase() === 'PING' || portNum <= 0;

    setSummary({
      target: displayTarget,
      port: portNum,
      protocol: (protoStr as any) || (isPing ? 'PING' : 'TCP'),
      verdict: (verdictStr as any) || 'ok',
      verdictLabel: verdictLabelStr,
      verdictDescription: verdictDescStr,
      advice: [
        isOk
          ? `${isV6 ? 'IPv6 ' : ''}当前${isPing ? 'ICMP Ping' : '开放端口'}从已测核心区域及中国三大运营商均可顺畅建立连接。`
          : `检测到部分区域或运营商可能存在${isV6 ? ' IPv6 ' : ''}握手丢包或超时，请根据下方探针时延与状态排查。`
      ],
      results: resList,
      stats: {
        total: statsObj?.total || resList.length || 18,
        success: statsObj?.success ?? statsObj?.ok ?? resList.filter((r: any) => r.status === 'ok').length,
        failed: statsObj?.failed ?? ((statsObj?.total || resList.length) - (statsObj?.success ?? statsObj?.ok ?? resList.filter((r: any) => r.status === 'ok').length)),
        cnSuccess: statsObj?.cn_success ?? resList.filter((r: any) => r.region?.group === 'cn' && r.status === 'ok').length,
        cnTotal: statsObj?.cn_total ?? (resList.filter((r: any) => r.region?.group === 'cn').length || 3),
        cnAverageMs: statsObj?.cnAverageMs ?? (statsObj as any)?.cn_avg_ms ?? null,
        globalAverageMs: statsObj?.globalAverageMs ?? (statsObj as any)?.global_avg_ms ?? null,
        minLatencyMs: statsObj?.min_ms ?? null,
        maxLatencyMs: statsObj?.max_ms ?? null,
      },
      checkedAt: (isV6 ? (item.checked_at_v6 || item.checked_at) : (item.checked_at || Math.floor(Date.now() / 1000))) * 1000,
    });
  }, [authed]);

  const toggleExpandHost = (item: ReachabilitySummaryItem) => {
    if (expandedHostId === item.host_id) {
      setExpandedHostId(null);
    } else {
      setExpandedHostId(item.host_id);
      handleSelectClusterItem(item, 'v4');
    }
  };

  const handleSaveApiKey = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    setSavingKey(true);
    setKeyFeedback('');
    try {
      const trimmed = apiKeyInput.trim();
      const res = await api.saveReachabilitySettings({ globalping_api_key: trimmed });
      if (typeof window !== 'undefined') {
        if (trimmed) {
          localStorage.setItem('narwhal_globalping_key', trimmed);
        } else {
          localStorage.removeItem('narwhal_globalping_key');
        }
      }
      if (res.quota) setQuota(res.quota);
      setKeyFeedback(res.message || '配置已成功保存！');
      setTimeout(() => {
        setShowKeyModal(false);
        setKeyFeedback('');
        fetchClusterSummary();
      }, 1200);
    } catch (err: any) {
      setKeyFeedback(`保存失败：${err.message || err}`);
    } finally {
      setSavingKey(false);
    }
  };

  // Copy report summary to clipboard
  const handleCopyReport = () => {
    if (!summary) return;
    const targetDisplay = authed ? `${summary.target}:${summary.port}` : `${isIpString(summary.target) ? '已脱敏目标' : summary.target}:${summary.port}`;
    const lines = [
      `【全球与三网可达性检测报告】`,
      `目标: ${targetDisplay} (${summary.protocol})`,
      `结论: ${summary.verdictLabel}`,
      `说明: ${summary.verdictDescription}`,
      `国内三网: 电信 ${summary.results.find(r => r.region.id === 'cn-telecom')?.status === 'ok' ? `${summary.results.find(r => r.region.id === 'cn-telecom')?.timings.total}ms` : '不可达'} · 联通 ${summary.results.find(r => r.region.id === 'cn-unicom')?.status === 'ok' ? `${summary.results.find(r => r.region.id === 'cn-unicom')?.timings.total}ms` : '不可达'} · 移动 ${summary.results.find(r => r.region.id === 'cn-mobile')?.status === 'ok' ? `${summary.results.find(r => r.region.id === 'cn-mobile')?.timings.total}ms` : '不可达'}`,
      `国内平均: ${summary.stats.cnAverageMs ? `${summary.stats.cnAverageMs}ms` : '异常'} | 全球平均: ${summary.stats.globalAverageMs ? `${summary.stats.globalAverageMs}ms` : '异常'}`,
      `检测时间: ${new Date(summary.checkedAt).toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai' })}`
    ];
    navigator.clipboard.writeText(lines.join('\n'));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const filteredResults = useMemo(() => {
    if (filterGroup === 'all') return liveResults;
    return liveResults.filter(r => r.region.group === filterGroup);
  }, [liveResults, filterGroup]);

  return (
    <div className="space-y-6 animate-fade-in" aria-label="全球与三网可达性检测面板">
      {/* Top Banner & Return button */}
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-800 pb-4">
        <div>
          <div className="flex items-center gap-2">
            <Globe className="h-5 w-5 text-sky-400" />
            <h1 className="text-lg font-bold text-slate-100">全球与三网可达性 (Reach Check)</h1>
          </div>
          <p className="mt-1 text-xs text-slate-400">
            参考开源标准，系统每小时自动获取母机开放端口并随机选测，支持全球核心节点与国内三大运营商实时可达性与时延剖析。
          </p>
        </div>

        {onBackToTcping && (
          <button
            type="button"
            onClick={onBackToTcping}
            className="flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-800/80 px-3 py-1.5 text-xs font-medium text-slate-300 hover:bg-slate-700 hover:text-slate-100 transition"
          >
            <span>返回省份测速</span>
            <ArrowRight className="h-3.5 w-3.5" />
          </button>
        )}
      </div>

      {/* CLUSTER AUTOMATED HOURLY INSPECTION SECTION */}
      <section className="rounded-2xl border border-sky-900/50 bg-slate-900/70 p-5 shadow-xl space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-800 pb-3">
          <div className="flex items-center gap-2">
            <div className="h-2 w-2 rounded-full bg-sky-400 animate-pulse" />
            <h2 className="text-sm font-semibold text-slate-200">
              集群母机定时巡检结果 (1 小时定时自动测试 · 随机开放端口)
            </h2>
          </div>

          <div className="flex items-center gap-2">
            {triggerMessage && (
              <span className="text-xs text-sky-300 font-mono animate-fade-in">{triggerMessage}</span>
            )}
            {authed && (
              <button
                type="button"
                onClick={() => {
                  setApiKeyInput(localStorage.getItem('narwhal_globalping_key') || '');
                  setShowKeyModal(true);
                }}
                className="flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-800/80 px-2.5 py-1.5 text-xs font-medium text-slate-300 hover:bg-slate-700 hover:text-slate-100 transition"
                title="配置 Globalping 探针 API Key"
              >
                <Key className="h-3.5 w-3.5 text-amber-400" />
                <span>{quota?.api_key_configured ? 'API Key (已绑定)' : '配置 API Key'}</span>
              </button>
            )}
            <button
              type="button"
              disabled={loadingCluster}
              onClick={fetchClusterSummary}
              className="p-1.5 rounded-lg border border-slate-700 bg-slate-800/80 text-slate-400 hover:text-slate-200 hover:bg-slate-700 transition"
              title="刷新最新巡检数据"
            >
              <RefreshCw className={`h-3.5 w-3.5 ${loadingCluster ? 'animate-spin' : ''}`} />
            </button>
            {authed && (
              <button
                type="button"
                disabled={triggeringCluster}
                onClick={handleTriggerCluster}
                className="flex items-center gap-1.5 rounded-lg bg-sky-600/90 hover:bg-sky-500 px-3 py-1.5 text-xs font-semibold text-white shadow-xs transition disabled:opacity-50"
              >
                <Zap className={`h-3.5 w-3.5 ${triggeringCluster ? 'animate-spin' : ''}`} />
                <span>立即全量巡检</span>
              </button>
            )}
          </div>
        </div>

        {/* Cluster Stats Ribbon */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs font-mono">
          <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-3">
            <span className="text-slate-400 block font-sans text-[11px]">纳入巡检母机</span>
            <span className="text-lg font-bold text-slate-100">{clusterData?.total_hosts || availableHosts.length || 0} 台</span>
          </div>
          <div className="rounded-xl border border-emerald-900/40 bg-emerald-950/20 p-3">
            <span className="text-emerald-400 block font-sans text-[11px]">三网全通畅母机</span>
            <span className="text-lg font-bold text-emerald-300">{clusterData?.ok_hosts || 0} 台</span>
          </div>
          <div className="rounded-xl border border-rose-900/40 bg-rose-950/20 p-3">
            <span className="text-rose-400 block font-sans text-[11px]">疑似受阻 / 异常</span>
            <span className="text-lg font-bold text-rose-300">{clusterData?.blocked_hosts || 0} 台</span>
          </div>
          <div className="rounded-xl border border-sky-900/40 bg-sky-950/20 p-3">
            <span className="text-sky-400 block font-sans text-[11px]">巡检状态</span>
            <span className="text-sm font-semibold text-sky-300 mt-1 block">
              {clusterData?.items?.length ? '每小时自动轮询中' : '等待初次巡检'}
            </span>
          </div>
        </div>

        {/* Quota & Pacing Intelligence Ribbon */}
        <div className="rounded-xl border border-slate-800 bg-slate-950/70 p-3.5 space-y-2">
          <div className="flex flex-wrap items-center justify-between gap-3 text-xs">
            <div className="flex items-center gap-2">
              <Sparkles className="h-4 w-4 text-amber-400" />
              <span className="font-semibold text-slate-200">探针配额与规划调度</span>
              <span className={`inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-[11px] font-medium border ${
                quota?.is_rate_limited
                  ? 'border-purple-500/50 bg-purple-950/60 text-purple-300'
                  : (quota?.remaining ?? 250) < 20
                  ? 'border-amber-500/40 bg-amber-950/60 text-amber-300'
                  : 'border-emerald-500/40 bg-emerald-950/60 text-emerald-300'
              }`}>
                {quota?.is_rate_limited
                  ? `探针配额受限 (${Math.ceil((quota.reset_seconds || 0) / 60)} 分钟后重置)`
                  : (quota?.remaining ?? 250) < 20
                  ? `额度紧张 (剩余 ${quota?.remaining ?? 250} / ${quota?.limit ?? 250} 点)`
                  : `额度充裕 (剩余 ${quota?.remaining ?? 250} / ${quota?.limit ?? 250} 点)`}
              </span>
            </div>

            <div className="flex items-center gap-2 text-[11px] text-slate-400 font-sans">
              {quota?.api_key_configured ? (
                <span className="text-emerald-400 flex items-center gap-1">
                  <Key className="h-3 w-3" /> 专属 API Key 额度
                </span>
              ) : (
                <span className="text-slate-400 flex items-center gap-1">
                  <Shield className="h-3 w-3 text-sky-400" /> 公共 IP 免费额度 (250/h)
                </span>
              )}
            </div>
          </div>

          <div className="text-[11px] text-slate-400 leading-relaxed font-sans border-t border-slate-800/60 pt-2 flex items-center gap-2">
            <Clock className="h-3.5 w-3.5 text-sky-400 shrink-0" />
            <span>
              <strong>平滑时序规划与双栈优化：</strong>集群 {clusterData?.total_hosts || availableHosts.length || 28} 台母机均匀分散至 1 小时时间轴（每约 {quota?.pacing_seconds || 128} 秒自动调度 1 台），双栈机器采用智能配额预算（IPv4 5探针 + IPv6 3探针 = 8点/台），杜绝突发 429 限流并兼顾 IPv4/IPv6 双栈三网全覆盖。
            </span>
          </div>
        </div>

        {/* Cluster Results Table */}
        <div className="overflow-x-auto rounded-xl border border-slate-800 bg-slate-950/50">
          <table className="w-full text-left text-xs text-slate-300">
            <thead className="bg-slate-900/80 text-[11px] font-semibold text-slate-400 border-b border-slate-800 uppercase tracking-wider">
              <tr>
                <th className="p-3">宿主机 / 目标</th>
                <th className="p-3">开放端口</th>
                <th className="p-3">可达性判定</th>
                <th className="p-3">中国电信 (4134)</th>
                <th className="p-3">中国联通 (4837)</th>
                <th className="p-3">中国移动 (9808)</th>
                <th className="p-3">全球均延</th>
                <th className="p-3">巡检时间</th>
                <th className="p-3 text-right">操作</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono">
              {(!clusterData?.items || clusterData.items.length === 0) ? (
                <tr>
                  <td colSpan={9} className="p-8 text-center text-slate-500 font-sans">
                    暂无母机巡检数据。点击右上角“立即全量巡检”启动首轮测试，或等待下一次整点自动测试。
                  </td>
                </tr>
              ) : (
                clusterData.items.map((item: ReachabilitySummaryItem) => {
                  const isOk = item.verdict === 'ok';
                  const isBlocked = item.verdict === 'gfw_blocked';
                  const isLimited = item.verdict_label === '探针配额受限';
                  const isExpanded = expandedHostId === item.host_id;

                  const v4Telecom = item.stats?.cnTelecomMs ?? (item.stats as any)?.cn_telecom_ms;
                  const v4Unicom = item.stats?.cnUnicomMs ?? (item.stats as any)?.cn_unicom_ms;
                  const v4Mobile = item.stats?.cnMobileMs ?? (item.stats as any)?.cn_mobile_ms;
                  const v4Global = item.stats?.globalAverageMs ?? (item.stats as any)?.global_avg_ms;

                  const v6Telecom = item.stats_v6?.cnTelecomMs ?? (item.stats_v6 as any)?.cn_telecom_ms;
                  const v6Unicom = item.stats_v6?.cnUnicomMs ?? (item.stats_v6 as any)?.cn_unicom_ms;
                  const v6Mobile = item.stats_v6?.cnMobileMs ?? (item.stats_v6 as any)?.cn_mobile_ms;
                  const v6Global = item.stats_v6?.globalAverageMs ?? (item.stats_v6 as any)?.global_avg_ms;
                  const v6CnAvg = item.stats_v6?.cnAverageMs ?? (item.stats_v6 as any)?.cn_avg_ms;

                  const inspection = formatInspectionTime(item.checked_at, item.checked_at_iso_utc8);

                  return (
                    <React.Fragment key={item.host_id}>
                      <tr className={`hover:bg-slate-900/40 transition ${isExpanded ? 'bg-slate-900/70 border-l-2 border-l-sky-500' : ''}`}>
                        {/* Host ID & Target */}
                        <td className="p-3 font-sans">
                          <div className="h-6 flex items-center gap-1.5 flex-wrap">
                            <span className="font-semibold text-slate-100 truncate max-w-[200px]" title={item.host_id}>
                              {item.host_id}
                            </span>
                            {item.is_dual_stack && (
                              <span className="inline-flex items-center gap-1 rounded bg-indigo-950/80 border border-indigo-700/50 text-indigo-300 px-1.5 py-0.2 text-[10px] font-medium font-sans">
                                双栈 IPv4/IPv6
                              </span>
                            )}
                            {!item.is_dual_stack && item.has_ipv6 && (
                              <span className="inline-flex items-center gap-1 rounded bg-purple-950/80 border border-purple-700/50 text-purple-300 px-1.5 py-0.2 text-[10px] font-medium font-sans">
                                纯 IPv6
                              </span>
                            )}
                          </div>
                          {authed ? (
                            <div className="h-6 flex items-center text-[11px] font-mono text-slate-400 truncate max-w-[240px]">
                              {item.is_dual_stack ? (
                                <span title={`V4: ${item.target} · V6: ${item.target_v6}`}>
                                  V4: {item.target} · V6: {item.target_v6}
                                </span>
                              ) : (
                                <span>{item.target || item.target_v6 || '—'}</span>
                              )}
                            </div>
                          ) : (
                            <div className="h-6 flex items-center text-[11px] text-slate-500">
                              <span>已脱敏目标</span>
                            </div>
                          )}
                        </td>

                        {/* Open Port */}
                        <td className="p-3">
                          <div className="h-6 flex items-center whitespace-nowrap">
                            <span className="rounded bg-slate-800/80 px-2 py-0.5 text-sky-300 font-bold">
                              {item.port <= 0 || item.protocol === 'PING' ? 'PING' : item.port}
                            </span>
                            <span className="text-[10px] text-slate-500 ml-1 font-sans">{item.protocol}</span>
                          </div>
                          {item.is_dual_stack ? (
                            <div className="h-6 flex items-center whitespace-nowrap text-[10px] text-slate-400 font-mono">
                              <span>
                                V6: {item.port_v6 && item.port_v6 !== item.port ? (item.port_v6 <= 0 ? 'PING' : item.port_v6) : '同 V4'}
                              </span>
                            </div>
                          ) : null}
                        </td>

                        {/* Verdict */}
                        <td className="p-3 font-sans">
                          <div className="h-6 flex items-center whitespace-nowrap">
                            <span className={`inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-[11px] font-medium border ${
                              isOk
                                ? 'border-emerald-500/40 bg-emerald-950/60 text-emerald-300'
                                : isBlocked
                                ? 'border-rose-500/50 bg-rose-950/60 text-rose-300 animate-pulse'
                                : isLimited
                                ? 'border-purple-500/40 bg-purple-950/60 text-purple-300'
                                : 'border-amber-500/40 bg-amber-950/60 text-amber-300'
                            }`}>
                              {isOk ? <CheckCircle2 className="h-3 w-3 text-emerald-400" /> : isLimited ? <Clock className="h-3 w-3 text-purple-400" /> : <AlertTriangle className="h-3 w-3" />}
                              <span>{item.is_dual_stack ? `V4: ${item.verdict_label}` : item.verdict_label}</span>
                            </span>
                          </div>
                          {item.is_dual_stack ? (
                            <div className="h-6 flex items-center whitespace-nowrap">
                              {item.verdict_label_v6 ? (
                                <span className={`inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-[10px] font-medium border ${
                                  item.verdict_v6 === 'ok'
                                    ? 'border-emerald-500/40 bg-emerald-950/60 text-emerald-300'
                                    : item.verdict_v6 === 'gfw_blocked'
                                    ? 'border-rose-500/50 bg-rose-950/60 text-rose-300 animate-pulse'
                                    : 'border-amber-500/40 bg-amber-950/60 text-amber-300'
                                }`}>
                                  {item.verdict_v6 === 'ok' ? <CheckCircle2 className="h-2.5 w-2.5 text-emerald-400" /> : <AlertTriangle className="h-2.5 w-2.5" />}
                                  <span>V6: {item.verdict_label_v6}</span>
                                </span>
                              ) : (
                                <span className="text-[10px] text-slate-500">V6: 待测试</span>
                              )}
                            </div>
                          ) : null}
                        </td>

                        {/* China Telecom */}
                        <td className="p-3">
                          <div className="h-6 flex items-center whitespace-nowrap">
                            {v4Telecom ? (
                              <span className={`inline-block px-1.5 py-0.5 rounded text-xs font-mono ${latencyBadgeColor(v4Telecom)}`}>
                                {item.is_dual_stack ? 'V4: ' : ''}{v4Telecom} ms
                              </span>
                            ) : (
                              <span className="text-slate-600">—</span>
                            )}
                          </div>
                          {item.is_dual_stack ? (
                            <div className="h-6 flex items-center whitespace-nowrap">
                              {v6Telecom ? (
                                <span className={`inline-block px-1.5 py-0.5 rounded text-[10px] font-mono ${latencyBadgeColor(v6Telecom)}`}>
                                  V6: {v6Telecom} ms
                                </span>
                              ) : (
                                <span className="text-slate-600 text-[10px] font-mono">V6: —</span>
                              )}
                            </div>
                          ) : null}
                        </td>

                        {/* China Unicom */}
                        <td className="p-3">
                          <div className="h-6 flex items-center whitespace-nowrap">
                            {v4Unicom ? (
                              <span className={`inline-block px-1.5 py-0.5 rounded text-xs font-mono ${latencyBadgeColor(v4Unicom)}`}>
                                {item.is_dual_stack ? 'V4: ' : ''}{v4Unicom} ms
                              </span>
                            ) : (
                              <span className="text-slate-600">—</span>
                            )}
                          </div>
                          {item.is_dual_stack ? (
                            <div className="h-6 flex items-center whitespace-nowrap">
                              {v6Unicom ? (
                                <span className={`inline-block px-1.5 py-0.5 rounded text-[10px] font-mono ${latencyBadgeColor(v6Unicom)}`}>
                                  V6: {v6Unicom} ms
                                </span>
                              ) : (
                                <span className="text-slate-600 text-[10px] font-mono">V6: —</span>
                              )}
                            </div>
                          ) : null}
                        </td>

                        {/* China Mobile */}
                        <td className="p-3">
                          <div className="h-6 flex items-center whitespace-nowrap">
                            {v4Mobile ? (
                              <span className={`inline-block px-1.5 py-0.5 rounded text-xs font-mono ${latencyBadgeColor(v4Mobile)}`}>
                                {item.is_dual_stack ? 'V4: ' : ''}{v4Mobile} ms
                              </span>
                            ) : (
                              <span className="text-slate-600">—</span>
                            )}
                          </div>
                          {item.is_dual_stack ? (
                            <div className="h-6 flex items-center whitespace-nowrap">
                              {v6Mobile ? (
                                <span className={`inline-block px-1.5 py-0.5 rounded text-[10px] font-mono ${latencyBadgeColor(v6Mobile)}`}>
                                  V6: {v6Mobile} ms
                                </span>
                              ) : (
                                <span className="text-slate-600 text-[10px] font-mono">V6: —</span>
                              )}
                            </div>
                          ) : null}
                        </td>

                        {/* Global Average */}
                        <td className="p-3">
                          <div className="h-6 flex items-center whitespace-nowrap font-mono text-xs text-slate-300">
                            {v4Global ? `${item.is_dual_stack ? 'V4: ' : ''}${v4Global} ms` : '—'}
                          </div>
                          {item.is_dual_stack ? (
                            <div className="h-6 flex items-center whitespace-nowrap font-mono text-[10px] text-slate-400">
                              {v6Global ? `V6: ${v6Global} ms` : (v6CnAvg ? `V6三网: ${v6CnAvg} ms` : 'V6: —')}
                            </div>
                          ) : null}
                        </td>

                        {/* Inspection Time */}
                        <td className="p-3">
                          <div className="h-6 flex items-center whitespace-nowrap text-xs text-slate-300 font-mono" title={inspection.full}>
                            {inspection.time}
                          </div>
                          <div className="h-6 flex items-center whitespace-nowrap text-[10px] text-slate-500 font-sans" title={inspection.full}>
                            {inspection.relative}
                          </div>
                        </td>

                        {/* Actions */}
                        <td className="p-3 text-right font-sans">
                          <div className="flex items-center justify-end gap-2">
                            <button
                              type="button"
                              onClick={() => toggleExpandHost(item)}
                              className={`rounded-lg border px-2.5 py-1 text-xs font-medium transition flex items-center gap-1 ${
                                isExpanded
                                  ? 'border-sky-500 bg-sky-950/70 text-sky-300 shadow-xs'
                                  : 'border-slate-700 bg-slate-800/80 text-slate-200 hover:bg-slate-700'
                              }`}
                              title={isExpanded ? '收起此机详细巡检成果' : '展开此机最新诊断与各区域时延详情'}
                            >
                              <span>{isExpanded ? '收起详情' : '查看详情'}</span>
                              {isExpanded ? <ChevronUp className="h-3.5 w-3.5" /> : <ChevronDown className="h-3.5 w-3.5" />}
                            </button>
                            {authed && (
                              <button
                                type="button"
                                disabled={triggeringHostId === item.host_id}
                                onClick={() => handleTriggerHost(item.host_id)}
                                className="rounded-lg border border-slate-700 bg-slate-800/80 px-2.5 py-1 text-xs text-slate-300 hover:text-slate-100 hover:bg-slate-700 transition flex items-center gap-1.5 disabled:opacity-60"
                                title="单独重新检测此机 (即时执行)"
                              >
                                <RefreshCw className={`h-3.5 w-3.5 ${triggeringHostId === item.host_id ? 'animate-spin text-sky-400' : 'text-slate-400'}`} />
                                <span className="font-medium text-[11px]">{triggeringHostId === item.host_id ? '检测中' : '刷新'}</span>
                              </button>
                            )}
                          </div>
                        </td>
                      </tr>

                      {/* IN-PLACE ACCORDION SUB-ROW UNDER THIS HOST */}
                      {isExpanded && (
                        <tr key={`${item.host_id}-details`} className="bg-slate-950/90 border-b-2 border-sky-500/40">
                          <td colSpan={9} className="p-4 sm:p-6 space-y-5">
                            {summary ? (
                              <div className="space-y-4">
                                {/* Diagnostic Verdict Card */}
                                <div className={`rounded-xl border p-5 transition-all space-y-4 ${
                                  summary.verdict === 'ok'
                                    ? 'border-emerald-500/40 bg-gradient-to-br from-emerald-950/40 via-slate-900/80 to-slate-950'
                                    : summary.verdict === 'gfw_blocked'
                                    ? 'border-rose-500/50 bg-gradient-to-br from-rose-950/40 via-slate-900/80 to-slate-950'
                                    : summary.verdict === 'partial'
                                    ? 'border-amber-500/40 bg-gradient-to-br from-amber-950/40 via-slate-900/80 to-slate-950'
                                    : 'border-slate-700 bg-slate-900/80'
                                }`}>
                                  <div className="flex flex-wrap items-start justify-between gap-4">
                                    <div className="space-y-1">
                                      <div className="flex items-center gap-2 flex-wrap">
                                        <span className={`inline-flex items-center gap-1.5 rounded-full px-3 py-1 text-xs font-bold ${
                                          summary.verdict === 'ok'
                                            ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
                                            : summary.verdict === 'gfw_blocked'
                                            ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40 animate-pulse'
                                            : summary.verdict === 'partial'
                                            ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40'
                                            : 'bg-slate-700/50 text-slate-300 border border-slate-600'
                                        }`}>
                                          {summary.verdict === 'ok' ? <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400" /> : <AlertTriangle className="h-3.5 w-3.5" />}
                                          <span>{summary.verdictLabel}</span>
                                        </span>
                                        <span className="font-mono text-sm font-semibold text-slate-100">
                                          {authed ? `${summary.target}:${summary.port <= 0 ? 'PING' : summary.port}` : `${isIpString(summary.target) ? '目标节点' : summary.target}:${summary.port <= 0 ? 'PING' : summary.port}`}
                                        </span>
                                        <span className="text-xs text-slate-400 font-mono">
                                          ({summary.protocol} 探测 · 18 节点巡检)
                                        </span>
                                      </div>
                                      <p className="text-xs text-slate-300 leading-relaxed pt-1">
                                        {summary.verdictDescription}
                                      </p>
                                    </div>

                                    <div className="flex items-center gap-2 flex-wrap">
                                      {item.is_dual_stack && (
                                        <div className="flex items-center rounded-lg bg-slate-950/90 p-0.5 border border-slate-700/80">
                                          <button
                                            type="button"
                                            onClick={() => handleSelectClusterItem(item, 'v4')}
                                            className={`px-2.5 py-1 text-xs rounded-md font-medium transition ${
                                              activeStackTab === 'v4'
                                                ? 'bg-sky-600 text-white shadow-xs'
                                                : 'text-slate-400 hover:text-slate-200'
                                            }`}
                                          >
                                            IPv4 探测结果
                                          </button>
                                          <button
                                            type="button"
                                            onClick={() => handleSelectClusterItem(item, 'v6')}
                                            className={`px-2.5 py-1 text-xs rounded-md font-medium transition ${
                                              activeStackTab === 'v6'
                                                ? 'bg-indigo-600 text-white shadow-xs'
                                                : 'text-slate-400 hover:text-slate-200'
                                            }`}
                                          >
                                            IPv6 探测结果
                                          </button>
                                        </div>
                                      )}
                                      <button
                                        type="button"
                                        onClick={handleCopyReport}
                                        className="flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-800/80 px-3 py-1.5 text-xs font-medium text-slate-300 hover:bg-slate-700 transition"
                                      >
                                        {copied ? <Check className="h-3.5 w-3.5 text-emerald-400" /> : <Copy className="h-3.5 w-3.5" />}
                                        <span>{copied ? '已复制' : '复制诊断报告'}</span>
                                      </button>
                                    </div>
                                  </div>

                                  {/* Metrics strip */}
                                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 pt-2 border-t border-slate-800/60 font-mono">
                                    <div className="rounded-lg bg-slate-950/60 p-2.5 border border-slate-800/60">
                                      <span className="text-[11px] text-slate-400 block font-sans">国内三网平均时延</span>
                                      <span className="text-base font-bold text-sky-300">
                                        {summary.stats.cnAverageMs ? `${summary.stats.cnAverageMs} ms` : '—'}
                                      </span>
                                      <span className="text-[10px] text-slate-500 block font-sans mt-0.5">
                                        可达: {summary.stats.cnSuccess} / {summary.stats.cnTotal} 运营商
                                      </span>
                                    </div>

                                    <div className="rounded-lg bg-slate-950/60 p-2.5 border border-slate-800/60">
                                      <span className="text-[11px] text-slate-400 block font-sans">海外区域平均时延</span>
                                      <span className="text-base font-bold text-emerald-300">
                                        {(() => {
                                          const ovs = summary.results.filter(r => r.region.group !== 'cn' && r.status === 'ok');
                                          return ovs.length ? `${Math.round(ovs.reduce((a, b) => a + b.timings.total, 0) / ovs.length)} ms` : '—';
                                        })()}
                                      </span>
                                      <span className="text-[10px] text-slate-500 block font-sans mt-0.5">
                                        可达: {summary.results.filter(r => r.region.group !== 'cn' && r.status === 'ok').length} / {summary.results.filter(r => r.region.group !== 'cn').length} 区域
                                      </span>
                                    </div>

                                    <div className="rounded-lg bg-slate-950/60 p-2.5 border border-slate-800/60">
                                      <span className="text-[11px] text-slate-400 block font-sans">全球核心可达率</span>
                                      <span className="text-base font-bold text-slate-100">
                                        {Math.round((summary.stats.success / (summary.stats.total || 1)) * 100)}%
                                      </span>
                                      <span className="text-[10px] text-slate-500 block font-sans mt-0.5">
                                        成功: {summary.stats.success} / {summary.stats.total} 节点
                                      </span>
                                    </div>

                                    <div className="rounded-lg bg-slate-950/60 p-2.5 border border-slate-800/60">
                                      <span className="text-[11px] text-slate-400 block font-sans">巡检探测口径</span>
                                      <span className="text-base font-bold text-indigo-300 font-sans">
                                        {summary.protocol === 'PING' ? 'ICMP Ping' : `TCP :${summary.port}`}
                                      </span>
                                      <span className="text-[10px] text-slate-500 block font-sans mt-0.5">
                                        18 核心节点分布式探测
                                      </span>
                                    </div>
                                  </div>

                                  {/* Actionable troubleshooting advice */}
                                  {summary.advice && summary.advice.length > 0 && (
                                    <div className="rounded-lg border border-slate-800 bg-slate-950/70 p-3 space-y-1.5 text-xs">
                                      <div
                                        className="flex items-center justify-between text-slate-300 cursor-pointer font-semibold"
                                        onClick={() => setShowAdvice(!showAdvice)}
                                      >
                                        <div className="flex items-center gap-1.5">
                                          <HelpCircle className="h-3.5 w-3.5 text-sky-400" />
                                          <span>排错指引与建议措施</span>
                                        </div>
                                        {showAdvice ? <ChevronUp className="h-3.5 w-3.5" /> : <ChevronDown className="h-3.5 w-3.5" />}
                                      </div>
                                      {showAdvice && (
                                        <ul className="list-disc list-inside space-y-1 text-slate-400 pl-1 pt-1 leading-relaxed">
                                          {summary.advice.map((adviceText, idx) => (
                                            <li key={idx}>{adviceText}</li>
                                          ))}
                                        </ul>
                                      )}
                                    </div>
                                  )}
                                </div>

                                {/* 18-Region Results Grid */}
                                <div className="space-y-3">
                                  <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-800 pb-2">
                                    <div className="flex items-center gap-2 flex-wrap">
                                      <h3 className="text-sm font-semibold text-slate-200">各区域及运营商探测结果</h3>
                                      <span className="rounded-full bg-slate-800 px-2 py-0.5 text-xs text-slate-400 font-mono">
                                        {liveResults.length} 节点
                                      </span>
                                      {item.is_dual_stack && (
                                        <span className="rounded-full bg-indigo-950/80 border border-indigo-700/60 px-2 py-0.5 text-xs text-indigo-300 font-sans">
                                          当前显示: {activeStackTab === 'v6' ? 'IPv6 栈探测' : 'IPv4 栈探测'}
                                        </span>
                                      )}
                                    </div>

                                    {/* Region Tabs */}
                                    <div className="flex items-center gap-1 text-xs">
                                      {[
                                        { id: 'all', label: '全部' },
                                        { id: 'cn', label: '中国大陆三网' },
                                        { id: 'apac', label: '亚太' },
                                        { id: 'emea', label: '欧洲/中东/非洲' },
                                        { id: 'am', label: '美洲' },
                                      ].map(tab => (
                                        <button
                                          key={tab.id}
                                          type="button"
                                          onClick={() => setFilterGroup(tab.id as any)}
                                          className={`rounded-lg px-2.5 py-1 transition font-medium ${
                                            filterGroup === tab.id
                                              ? 'bg-sky-600 text-white shadow-xs'
                                              : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'
                                          }`}
                                        >
                                          {tab.label}
                                        </button>
                                      ))}
                                    </div>
                                  </div>

                                  {/* Region cards */}
                                  {liveResults.length === 0 ? (
                                    <div className="rounded-xl border border-slate-800 bg-slate-950/40 p-6 text-center text-xs text-slate-400 space-y-2">
                                      <Globe className="h-6 w-6 text-slate-600 mx-auto" />
                                      <p className="font-semibold text-slate-300">暂无此栈的区域探测明细</p>
                                    </div>
                                  ) : (
                                    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
                                      {filteredResults.map(res => {
                                        const rOk = res.status === 'ok';
                                        const rTesting = res.status === 'testing';
                                        const rCn = res.region.group === 'cn';

                                        return (
                                          <div
                                            key={res.region.id}
                                            className={`rounded-xl border p-3.5 space-y-2.5 transition ${
                                              rTesting
                                                ? 'border-slate-800 bg-slate-900/40 animate-pulse'
                                                : rOk
                                                ? rCn
                                                  ? 'border-sky-500/30 bg-slate-900/80 shadow-xs'
                                                  : 'border-slate-800 bg-slate-900/60 hover:border-slate-700'
                                                : 'border-rose-900/40 bg-rose-950/10 hover:border-rose-800/60'
                                            }`}
                                          >
                                            <div className="flex items-start justify-between gap-2">
                                              <div className="min-w-0 flex-1">
                                                <div className="flex items-center gap-1.5">
                                                  <span className="text-sm shrink-0">{res.region.flag}</span>
                                                  <h4 className="font-semibold text-xs text-slate-100 truncate" title={res.region.name}>
                                                    {res.region.name}
                                                  </h4>
                                                </div>
                                                <div className="flex items-center gap-1.5 mt-0.5">
                                                  {res.region.asn && (
                                                    <span className="text-[10px] font-mono text-slate-400">
                                                      AS{res.region.asn}
                                                    </span>
                                                  )}
                                                  {authed && res.ip && (
                                                    <span className="text-[10px] font-mono text-slate-500 truncate" title={res.ip}>
                                                      · {res.ip}
                                                    </span>
                                                  )}
                                                </div>
                                              </div>

                                              <span className={`shrink-0 rounded-full border px-2 py-0.5 text-[10px] font-mono font-bold ${
                                                rTesting
                                                  ? 'border-sky-500/40 bg-sky-950/40 text-sky-400'
                                                  : rOk
                                                  ? latencyBadgeColor(res.timings.total)
                                                  : res.status === 'timeout'
                                                  ? 'border-rose-500/40 bg-rose-950/40 text-rose-300'
                                                  : res.status === 'refused'
                                                  ? 'border-amber-500/40 bg-amber-950/40 text-amber-300'
                                                  : 'border-slate-700 bg-slate-800 text-slate-400'
                                              }`}>
                                                {rTesting
                                                  ? '检测中...'
                                                  : rOk
                                                  ? `${res.timings.total} ms`
                                                  : res.status === 'timeout'
                                                  ? '连接超时'
                                                  : res.status === 'refused'
                                                  ? '端口拒绝'
                                                  : res.status === 'dns_error'
                                                  ? 'DNS失败'
                                                  : res.status === 'tls_error'
                                                  ? 'TLS错误'
                                                  : '检测失败'}
                                              </span>
                                            </div>

                                            {/* Timings breakdown bar */}
                                            {rOk && (
                                              <div className="space-y-1 pt-1 border-t border-slate-800/60 text-[10px] font-mono">
                                                <div className="flex items-center justify-between text-slate-400">
                                                  <span>时延构成</span>
                                                  <span className="text-slate-200 font-bold">{res.timings.total} ms</span>
                                                </div>
                                                <div className="flex gap-1.5 text-slate-400 flex-wrap">
                                                  {res.timings.dns !== undefined && (
                                                    <span className="rounded bg-slate-800/80 px-1 py-0.2">
                                                      DNS: {res.timings.dns}ms
                                                    </span>
                                                  )}
                                                  {res.timings.tcp !== undefined && (
                                                    <span className="rounded bg-slate-800/80 px-1 py-0.2">
                                                      TCP: {res.timings.tcp}ms
                                                    </span>
                                                  )}
                                                  {res.timings.tls !== undefined && (
                                                    <span className="rounded bg-slate-800/80 px-1 py-0.2">
                                                      TLS: {res.timings.tls}ms
                                                    </span>
                                                  )}
                                                  {res.timings.ttfb !== undefined && (
                                                    <span className="rounded bg-slate-800/80 px-1 py-0.2">
                                                      TTFB: {res.timings.ttfb}ms
                                                    </span>
                                                  )}
                                                </div>
                                              </div>
                                            )}

                                            {!rOk && !rTesting && res.error && (
                                              <div className="pt-1 border-t border-slate-800/60 text-[10px] text-rose-300/80 font-mono truncate" title={res.error}>
                                                {res.error}
                                              </div>
                                            )}
                                          </div>
                                        );
                                      })}
                                    </div>
                                  )}
                                </div>
                              </div>
                            ) : (
                              <div className="p-4 text-center text-slate-500 font-sans text-xs">
                                正在加载该机器巡检详情...
                              </div>
                            )}
                          </td>
                        </tr>
                      )}
                    </React.Fragment>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </section>

      {/* API Key Modal */}
      {showKeyModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-xs p-4 animate-fade-in">
          <div className="w-full max-w-md rounded-2xl border border-slate-700 bg-slate-900 p-5 shadow-2xl space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2">
                <Key className="h-4 w-4 text-amber-400" />
                <h3 className="text-sm font-semibold text-slate-100">配置 Globalping API Key</h3>
              </div>
              <button
                type="button"
                onClick={() => { setShowKeyModal(false); setKeyFeedback(''); }}
                className="text-slate-400 hover:text-slate-200 text-sm font-bold"
              >
                ✕
              </button>
            </div>

            <div className="text-xs text-slate-400 space-y-2 leading-relaxed">
              <p>
                默认未认证公共 IP 探针额度为 250 点/小时。若需要测试全球全量 18 区域或频繁重测，可在{' '}
                <a
                  href="https://globalping.io"
                  target="_blank"
                  rel="noreferrer"
                  className="text-sky-400 underline hover:text-sky-300"
                >
                  globalping.io
                </a>{' '}
                免费注册账号并在个人面板创建 API Key。
              </p>
              <p className="text-slate-500">
                免费账户额度通常为 500 ~ 2,500+ 点/小时。留空并保存可恢复为公共 IP 模式。
              </p>
            </div>

            <form onSubmit={handleSaveApiKey} className="space-y-3">
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">
                  Globalping API Key / Token
                </label>
                <input
                  type="password"
                  value={apiKeyInput}
                  onChange={(e) => setApiKeyInput(e.target.value)}
                  placeholder="留空则使用公共 IP 额度"
                  className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-xs text-slate-200 font-mono focus:border-sky-500 focus:outline-hidden"
                />
              </div>

              {keyFeedback && (
                <div className={`text-xs p-2 rounded ${keyFeedback.includes('失败') ? 'bg-rose-950/60 text-rose-300' : 'bg-emerald-950/60 text-emerald-300'}`}>
                  {keyFeedback}
                </div>
              )}

              <div className="flex items-center justify-end gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => { setShowKeyModal(false); setKeyFeedback(''); }}
                  className="rounded-lg border border-slate-700 bg-slate-800 px-3 py-1.5 text-xs text-slate-300 hover:bg-slate-700"
                >
                  取消
                </button>
                <button
                  type="submit"
                  disabled={savingKey}
                  className="rounded-lg bg-sky-600 hover:bg-sky-500 px-4 py-1.5 text-xs font-semibold text-white transition disabled:opacity-50"
                >
                  {savingKey ? '保存中...' : '保存并同步'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
