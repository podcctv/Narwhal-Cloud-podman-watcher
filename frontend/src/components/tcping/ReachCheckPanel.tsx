import React, { useState, useEffect, useCallback, useMemo } from 'react';
import {
  Globe, Shield, AlertTriangle, CheckCircle2, RefreshCw,
  Zap, ArrowRight, HelpCircle, ChevronDown, ChevronUp, Copy, Check,
  Key, Clock, Sparkles
} from 'lucide-react';
import {
  RegionResult, ReachCheckSummary,
  executeReachCheck, validateTarget
} from '../../utils/reachCheck';
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

const PORT_PRESETS = [
  { label: 'Web (443 HTTPS)', port: 443, protocol: 'HTTPS' as const },
  { label: 'Web (80 HTTP)', port: 80, protocol: 'HTTP' as const },
  { label: 'SSH (22)', port: 22, protocol: 'TCP' as const },
  { label: 'RDP (3389)', port: 3389, protocol: 'TCP' as const },
  { label: 'Home Assistant (8123)', port: 8123, protocol: 'HTTP' as const },
  { label: 'Minecraft (25565)', port: 25565, protocol: 'TCP' as const },
  { label: 'Plex / Emby (8096)', port: 8096, protocol: 'HTTP' as const },
];

export const ReachCheckPanel: React.FC<ReachCheckPanelProps> = ({
  initialTarget = '',
  initialPort = 443,
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

  const [target, setTarget] = useState(() => (authed ? initialTarget : (isIpString(initialTarget) ? '' : initialTarget)));
  const [port, setPort] = useState(initialPort);
  const [protocol, setProtocol] = useState<'TCP' | 'HTTP' | 'HTTPS'>('TCP');
  const [running, setRunning] = useState(false);
  const [progress, setProgress] = useState<{ finished: number; total: number }>({ finished: 0, total: 18 });
  const [summary, setSummary] = useState<ReachCheckSummary | null>(null);
  const [liveResults, setLiveResults] = useState<RegionResult[]>([]);
  const [error, setError] = useState<string>('');
  const [copied, setCopied] = useState(false);
  const [showAdvice, setShowAdvice] = useState(true);
  const [filterGroup, setFilterGroup] = useState<'all' | 'cn' | 'apac' | 'emea' | 'am'>('all');

  // Automated hourly cluster check state
  const [clusterData, setClusterData] = useState<ReachabilityClusterSummary | null>(null);
  const [quota, setQuota] = useState<ReachabilityQuotaInfo | null>(null);
  const [loadingCluster, setLoadingCluster] = useState(false);
  const [triggeringCluster, setTriggeringCluster] = useState(false);
  const [triggerMessage, setTriggerMessage] = useState<string>('');
  const [showKeyModal, setShowKeyModal] = useState(false);
  const [apiKeyInput, setApiKeyInput] = useState('');
  const [savingKey, setSavingKey] = useState(false);
  const [keyFeedback, setKeyFeedback] = useState<string>('');

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

  useEffect(() => {
    fetchClusterSummary();
    const timer = setInterval(fetchClusterSummary, 60000);
    return () => clearInterval(timer);
  }, [fetchClusterSummary]);

  const handleTriggerCluster = async (hostId?: string) => {
    if (!authed) {
      setTriggerMessage('需管理员登录后触发巡检');
      return;
    }
    setTriggeringCluster(true);
    setTriggerMessage('');
    try {
      const res: any = await api.triggerReachabilityCheck(hostId);
      setTriggerMessage(res?.message || '巡检已触发，正在后台异步探测...');
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

  const handleSelectClusterItem = useCallback((item: ReachabilitySummaryItem) => {
    if (item.target && authed) {
      setTarget(item.target);
    } else if (!authed) {
      setTarget(item.host_id || '');
    }
    if (item.port) setPort(item.port);
    if (item.protocol) setProtocol(item.protocol as any || 'TCP');
    if (item.results && item.results.length > 0) {
      setLiveResults(item.results);
      const isOk = item.verdict === 'ok';
      const displayTarget = authed ? (item.target || item.host_id) : (item.host_id || '已脱敏目标');
      setSummary({
        target: displayTarget,
        port: item.port || 443,
        protocol: (item.protocol as any) || 'TCP',
        verdict: (item.verdict as any) || 'ok',
        verdictLabel: item.verdict_label || '可达性检测完毕',
        verdictDescription: item.verdict_desc || '',
        advice: [
          isOk
            ? '当前开放端口从全球各核心区域及中国大陆电信、联通、移动三大运营商均可正常建立 TCP 连接。'
            : '检测到部分区域或运营商可能存在握手丢包或超时，请根据下方探针时延与状态排查。'
        ],
        results: item.results,
        stats: {
          total: item.stats?.total || 18,
          success: item.stats?.success ?? item.stats?.ok ?? item.results.filter((r: any) => r.status === 'ok').length,
          failed: item.stats?.failed ?? ((item.stats?.total || 18) - (item.stats?.success ?? item.stats?.ok ?? item.results.filter((r: any) => r.status === 'ok').length)),
          cnSuccess: item.stats?.cn_success ?? item.results.filter((r: any) => r.region?.group === 'cn' && r.status === 'ok').length,
          cnTotal: item.stats?.cn_total ?? (item.results.filter((r: any) => r.region?.group === 'cn').length || 3),
          cnAverageMs: item.stats?.cnAverageMs ?? (item.stats as any)?.cn_avg_ms ?? null,
          globalAverageMs: item.stats?.globalAverageMs ?? (item.stats as any)?.global_avg_ms ?? null,
          minLatencyMs: item.stats?.min_ms ?? null,
          maxLatencyMs: item.stats?.max_ms ?? null,
        },
        checkedAt: (item.checked_at || Math.floor(Date.now() / 1000)) * 1000,
      });
    }
  }, [authed]);

  // Automatically hydrate summary and 18-region breakdown from cluster hourly data
  useEffect(() => {
    if (summary || liveResults.length > 0) return;
    if (!clusterData?.items || clusterData.items.length === 0) return;

    let match = clusterData.items.find(
      it => it.host_id === initialTarget || it.target === initialTarget
    );
    if (!match && target) {
      match = clusterData.items.find(
        it => it.host_id === target || it.target === target
      );
    }
    if (!match && clusterData.items.length > 0) {
      match = clusterData.items[0];
    }

    if (match) {
      handleSelectClusterItem(match);
    }
  }, [clusterData, initialTarget, target, summary, liveResults.length, handleSelectClusterItem]);

  // Load cached result from sessionStorage if available
  useEffect(() => {
    if (!target) return;
    try {
      const cached = sessionStorage.getItem(`reach:${target}:${port}`);
      if (cached) {
        const parsed: ReachCheckSummary = JSON.parse(cached);
        setSummary(parsed);
        setLiveResults(parsed.results);
      }
    } catch {}
  }, [target, port]);

  const handleStartCheck = useCallback(async (customTarget?: string, customPort?: number) => {
    if (!authed) {
      setError('实时测速与主动探测仅对管理员开放，请先登录');
      return;
    }
    const tHost = (customTarget ?? target).trim();
    const tPort = customPort ?? port;

    const val = validateTarget(tHost, tPort);
    if (!val.valid) {
      setError(val.error || '目标参数无效');
      return;
    }

    setError('');
    setRunning(true);
    setProgress({ finished: 0, total: 18 });
    setSummary(null);

    try {
      const res = await executeReachCheck(
        tHost,
        tPort,
        protocol,
        (interimResults, finished, total) => {
          setLiveResults([...interimResults]);
          setProgress({ finished, total });
        }
      );
      setSummary(res);
      setLiveResults(res.results);
      try {
        sessionStorage.setItem(`reach:${tHost}:${tPort}`, JSON.stringify(res));
      } catch {}
    } catch (err: any) {
      setError(err?.message || '可达性检测失败');
    } finally {
      setRunning(false);
    }
  }, [authed, target, port, protocol]);

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

  const latencyBadgeColor = (ms: number) => {
    if (ms <= 60) return 'border-emerald-500/40 bg-emerald-950/40 text-emerald-300';
    if (ms <= 150) return 'border-sky-500/40 bg-sky-950/40 text-sky-300';
    if (ms <= 260) return 'border-amber-500/40 bg-amber-950/40 text-amber-300';
    return 'border-rose-500/40 bg-rose-950/40 text-rose-300';
  };

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
            参考开源标准，系统每小时自动获取母机开放端口并随机选测，支持全球 18 个核心节点（含国内三大运营商）实时可达性与时延剖析。
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
                onClick={() => handleTriggerCluster()}
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
              <strong>平滑时序规划：</strong>集群 {clusterData?.total_hosts || availableHosts.length || 28} 台母机均匀分散至 1 小时时间轴（每约 {quota?.pacing_seconds || 128} 秒自动调度 1 台），每小时稳定消耗 ~224 点，严格受控于 250 点/小时上限内，杜绝突发 429 报错。
            </span>
          </div>
        </div>

        {/* Cluster Results Table */}
        <div className="overflow-x-auto rounded-xl border border-slate-800 bg-slate-950/50">
          <table className="w-full text-left text-xs text-slate-300">
            <thead className="bg-slate-900/80 text-[11px] font-semibold text-slate-400 border-b border-slate-800 uppercase tracking-wider">
              <tr>
                <th className="p-3">宿主机 / 目标</th>
                <th className="p-3">随机开放端口</th>
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
                  return (
                    <tr key={item.host_id} className="hover:bg-slate-900/40 transition">
                      <td className="p-3 font-sans">
                        <div className="font-semibold text-slate-100 truncate max-w-[200px]" title={item.host_id}>
                          {item.host_id}
                        </div>
                        {authed && item.target ? (
                          <div className="text-[11px] font-mono text-slate-500 truncate max-w-[200px]">
                            {item.target}
                          </div>
                        ) : null}
                      </td>
                      <td className="p-3">
                        <span className="rounded bg-slate-800/80 px-2 py-0.5 text-sky-300 font-bold">
                          {item.port <= 0 || item.protocol === 'PING' ? 'PING' : item.port}
                        </span>
                        <span className="text-[10px] text-slate-500 ml-1">{item.protocol}</span>
                      </td>
                      <td className="p-3 font-sans">
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
                          <span>{item.verdict_label}</span>
                        </span>
                      </td>
                      <td className="p-3">
                        {(item.stats?.cnTelecomMs ?? (item.stats as any)?.cn_telecom_ms) ? (
                          <span className={`px-1.5 py-0.5 rounded ${latencyBadgeColor(item.stats?.cnTelecomMs ?? (item.stats as any).cn_telecom_ms)}`}>
                            {item.stats?.cnTelecomMs ?? (item.stats as any).cn_telecom_ms} ms
                          </span>
                        ) : (
                          <span className="text-slate-600">—</span>
                        )}
                      </td>
                      <td className="p-3">
                        {(item.stats?.cnUnicomMs ?? (item.stats as any)?.cn_unicom_ms) ? (
                          <span className={`px-1.5 py-0.5 rounded ${latencyBadgeColor(item.stats?.cnUnicomMs ?? (item.stats as any).cn_unicom_ms)}`}>
                            {item.stats?.cnUnicomMs ?? (item.stats as any).cn_unicom_ms} ms
                          </span>
                        ) : (
                          <span className="text-slate-600">—</span>
                        )}
                      </td>
                      <td className="p-3">
                        {(item.stats?.cnMobileMs ?? (item.stats as any)?.cn_mobile_ms) ? (
                          <span className={`px-1.5 py-0.5 rounded ${latencyBadgeColor(item.stats?.cnMobileMs ?? (item.stats as any).cn_mobile_ms)}`}>
                            {item.stats?.cnMobileMs ?? (item.stats as any).cn_mobile_ms} ms
                          </span>
                        ) : (
                          <span className="text-slate-600">—</span>
                        )}
                      </td>
                      <td className="p-3">
                        <span className="text-slate-300">
                          {item.stats?.globalAverageMs ? `${item.stats.globalAverageMs} ms` : '—'}
                        </span>
                      </td>
                      <td className="p-3 text-[11px] text-slate-400">
                        {item.checked_at_iso_utc8 || '刚刚'}
                      </td>
                      <td className="p-3 text-right font-sans">
                        <div className="flex items-center justify-end gap-1.5">
                          <button
                            type="button"
                            onClick={() => {
                              handleSelectClusterItem(item);
                              window.scrollTo({ top: 380, behavior: 'smooth' });
                            }}
                            className="rounded-lg border border-slate-700 bg-slate-800/80 px-2 py-1 text-[11px] font-medium text-slate-200 hover:bg-slate-700 transition"
                            title="载入此机最新巡检成果并在上方展开 18 区域明细"
                          >
                            查看详情
                          </button>
                          {authed && (
                            <button
                              type="button"
                              onClick={() => handleTriggerCluster(item.host_id)}
                              className="rounded-lg border border-slate-700 bg-slate-800/80 p-1 text-slate-400 hover:text-slate-100 hover:bg-slate-700 transition"
                              title="单独重新检测此机"
                            >
                              <RefreshCw className="h-3 w-3" />
                            </button>
                          )}
                        </div>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </section>

      {/* INTERACTIVE SINGLE-TARGET TEST PANEL */}
      <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-5 shadow-xl space-y-5">
        <div className="border-b border-slate-800 pb-3">
          <h2 className="text-sm font-semibold text-slate-200">
            自定义目标实时探测 (18 核心节点与访客浏览器同步发起)
          </h2>
        </div>

        {/* Target Input form */}
        <div className="grid grid-cols-1 md:grid-cols-12 gap-3 items-end">
          <div className="md:col-span-6 space-y-1.5">
            <label className="block text-xs font-medium text-slate-300">
              检测目标 (域名或公网 IP)
            </label>
            <div className="flex gap-2">
              {availableHosts.length > 0 && (
                <div className="relative shrink-0">
                  <select
                    aria-label="快速选机"
                    disabled={!authed}
                    onChange={(e) => {
                      const sel = availableHosts.find(h => h.id === e.target.value);
                      if (sel) {
                        const clusterItem = clusterData?.items?.find(it => it.host_id === sel.id || it.host_id === sel.name);
                        if (clusterItem) {
                          handleSelectClusterItem(clusterItem);
                        } else {
                          setTarget(authed ? (sel.ip || sel.name || sel.id) : (sel.name || sel.id));
                        }
                      }
                    }}
                    className="h-10 rounded-lg border border-slate-700 bg-slate-800/90 px-2.5 text-xs font-medium text-slate-200 hover:bg-slate-700 transition cursor-pointer disabled:opacity-60"
                    defaultValue=""
                  >
                    <option value="" disabled>快速选机</option>
                    {availableHosts.map(h => (
                      <option key={h.id} value={h.id}>
                        {h.name} {authed && h.ip ? `(${h.ip})` : ''}
                      </option>
                    ))}
                  </select>
                </div>
              )}
              <input
                type="text"
                placeholder={authed ? "例如: 15.204.57.108 或 narwhal.example.com" : "例如: narwhal.example.com (需登录测速)"}
                value={authed ? target : (isIpString(target) ? '' : target)}
                onChange={(e) => authed && setTarget(e.target.value)}
                disabled={!authed}
                onKeyDown={(e) => e.key === 'Enter' && authed && handleStartCheck()}
                className="h-10 w-full rounded-lg border border-slate-700 bg-slate-950/80 px-3 text-sm text-slate-100 placeholder-slate-500 font-mono focus:border-sky-500 focus:outline-hidden transition disabled:opacity-60"
              />
            </div>
          </div>

          <div className="md:col-span-2 space-y-1.5">
            <label className="block text-xs font-medium text-slate-300">
              端口 (1-65535)
            </label>
            <input
              type="number"
              min={1}
              max={65535}
              value={port}
              disabled={!authed}
              onChange={(e) => setPort(Number(e.target.value))}
              onKeyDown={(e) => e.key === 'Enter' && authed && handleStartCheck()}
              className="h-10 w-full rounded-lg border border-slate-700 bg-slate-950/80 px-3 text-sm text-slate-100 font-mono focus:border-sky-500 focus:outline-hidden transition disabled:opacity-60"
            />
          </div>

          <div className="md:col-span-2 space-y-1.5">
            <label className="block text-xs font-medium text-slate-300">
              测试协议
            </label>
            <select
              value={protocol}
              disabled={!authed}
              onChange={(e) => setProtocol(e.target.value as any)}
              className="h-10 w-full rounded-lg border border-slate-700 bg-slate-950/80 px-2.5 text-xs text-slate-200 font-medium focus:border-sky-500 focus:outline-hidden transition cursor-pointer disabled:opacity-60"
            >
              <option value="TCP">TCP (全端口推荐)</option>
              <option value="HTTPS">HTTPS (443)</option>
              <option value="HTTP">HTTP (80/Web)</option>
            </select>
          </div>

          <div className="md:col-span-2">
            {authed ? (
              <button
                type="button"
                disabled={running || !target.trim()}
                onClick={() => handleStartCheck()}
                className="w-full flex items-center justify-center gap-2 rounded-lg bg-sky-600 px-4 py-2 text-sm font-semibold text-white shadow-xs hover:bg-sky-500 transition disabled:opacity-50 disabled:cursor-not-allowed h-10"
              >
                {running ? (
                  <>
                    <RefreshCw className="h-4 w-4 animate-spin" />
                    <span>探测中 ({progress.finished}/{progress.total})</span>
                  </>
                ) : (
                  <>
                    <Zap className="h-4 w-4" />
                    <span>开始可达性检测</span>
                  </>
                )}
              </button>
            ) : (
              <a
                href="/login"
                className="w-full flex items-center justify-center gap-1.5 rounded-lg border border-sky-500/30 bg-sky-950/40 px-3 py-2 text-xs font-semibold text-sky-300 hover:bg-sky-900/50 hover:text-sky-200 transition h-10 text-center"
                title="登录后可使用实时探测与测速功能"
              >
                <Shield className="h-3.5 w-3.5 text-sky-400 shrink-0" />
                <span>登录后测速</span>
              </a>
            )}
          </div>
        </div>

        {/* Presets & SSRF Warning */}
        <div className="flex flex-wrap items-center justify-between gap-2 pt-2 border-t border-slate-800/80 text-xs">
          <div className="flex flex-wrap items-center gap-1.5 text-slate-400">
            <span>常见预设:</span>
            {PORT_PRESETS.map(p => (
              <button
                key={p.label}
                type="button"
                disabled={running || !authed}
                onClick={() => {
                  setPort(p.port);
                  setProtocol(p.protocol);
                }}
                className={`rounded border px-2 py-0.5 transition font-mono disabled:opacity-50 ${
                  port === p.port && protocol === p.protocol
                    ? 'border-sky-500 bg-sky-950/60 text-sky-300 font-semibold'
                    : 'border-slate-800 bg-slate-950/60 hover:border-slate-700 text-slate-300'
                }`}
              >
                {p.label}
              </button>
            ))}
          </div>

          <div className="flex items-center gap-1 text-[11px] text-slate-500">
            <Shield className="h-3 w-3 text-emerald-400" />
            <span>SSRF 保护与安全端口策略生效中 (零守护进程开销)</span>
          </div>
        </div>
      </div>

      {/* Error alert */}
      {error && (
        <div className="flex items-center gap-2.5 rounded-xl border border-rose-500/50 bg-rose-950/40 p-3.5 text-xs text-rose-200">
          <AlertTriangle className="h-4 w-4 text-rose-400 shrink-0" />
          <p>{error}</p>
        </div>
      )}

      {/* Diagnostic Verdict Card */}
      {summary && (
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
                  {authed ? `${summary.target}:${summary.port}` : `${isIpString(summary.target) ? '目标节点' : summary.target}:${summary.port}`}
                </span>
                <span className="text-xs text-slate-400 font-mono">
                  ({summary.protocol} 探测 · 18 节点 + 访客浏览器)
                </span>
              </div>
              <p className="text-xs text-slate-300 leading-relaxed pt-1">
                {summary.verdictDescription}
              </p>
            </div>

            <div className="flex items-center gap-2">
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
              <span className="text-[11px] text-slate-400 block font-sans">访客本地直连时延</span>
              <span className="text-base font-bold text-indigo-300">
                {summary.browserResult?.status === 'ok' ? `${summary.browserResult.timings.total} ms` : '跳过/受限'}
              </span>
              <span className="text-[10px] text-slate-500 block font-sans mt-0.5">
                本地浏览器 Performance API
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
                  {summary.advice.map((item, idx) => (
                    <li key={idx}>{item}</li>
                  ))}
                </ul>
              )}
            </div>
          )}
        </div>
      )}

      {/* 18-Region Results Grid */}
      <div className="space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-800 pb-2">
          <div className="flex items-center gap-2">
            <h2 className="text-sm font-semibold text-slate-200">各区域及运营商探测结果</h2>
            <span className="rounded-full bg-slate-800 px-2 py-0.5 text-xs text-slate-400 font-mono">
              {liveResults.length} 节点
            </span>
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

        {/* Results cards or Empty / Quota Limited Notice */}
        {liveResults.length === 0 ? (
          summary?.verdictLabel === '探针配额受限' ? (
            <div className="rounded-2xl border border-purple-900/60 bg-purple-950/20 p-6 text-xs text-purple-200 space-y-3">
              <div className="flex items-center gap-2 text-sm font-semibold text-purple-300">
                <Clock className="h-5 w-5 text-purple-400" />
                <span>探针公共免费配额已达上限 (HTTP 429)</span>
              </div>
              <p className="text-purple-300/80 leading-relaxed font-sans">
                Globalping 未认证公共 IP 每小时限额 250 点已在上一轮突发请求中耗尽。后台调度系统已自动切换为<strong>平滑时序分散调度</strong>（每约 {quota?.pacing_seconds || 128} 秒轮询 1 台母机），整点重置后将平稳刷新。
              </p>
              <p className="text-purple-400/80 font-sans">
                历史上的有效快照已被服务端严格保护，绝不被空数据覆盖。建议配置专属 API Key 彻底解除限流。
              </p>
              <div className="flex flex-wrap items-center gap-3 pt-2">
                <button
                  type="button"
                  onClick={() => {
                    setApiKeyInput(localStorage.getItem('narwhal_globalping_key') || '');
                    setShowKeyModal(true);
                  }}
                  className="rounded-lg bg-purple-600 hover:bg-purple-500 px-3.5 py-1.5 font-semibold text-white transition flex items-center gap-1.5 shadow-sm"
                >
                  <Key className="h-3.5 w-3.5" />
                  <span>绑定免费 Globalping Key</span>
                </button>
                <button
                  type="button"
                  onClick={fetchClusterSummary}
                  className="rounded-lg border border-purple-800 bg-purple-900/40 hover:bg-purple-900/60 px-3 py-1.5 font-medium text-purple-200 transition flex items-center gap-1"
                >
                  <RefreshCw className="h-3.5 w-3.5" />
                  <span>刷新状态</span>
                </button>
              </div>
            </div>
          ) : (
            <div className="rounded-xl border border-slate-800 bg-slate-950/40 p-8 text-center text-xs text-slate-400 space-y-2">
              <Globe className="h-8 w-8 text-slate-600 mx-auto" />
              <p className="font-semibold text-slate-300">暂无展开的区域明细</p>
              <p className="text-slate-500 max-w-md mx-auto">
                请在上方母机列表中点击「查看详情」载入历史巡检快照{authed ? '，或在自定义输入框输入目标并点击「开始可达性检测」' : ''}。
              </p>
            </div>
          )
        ) : (
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
            {filteredResults.map(item => {
              const isOk = item.status === 'ok';
              const isTesting = item.status === 'testing';
              const isCn = item.region.group === 'cn';

              return (
                <div
                  key={item.region.id}
                  className={`rounded-xl border p-3.5 space-y-2.5 transition ${
                    isTesting
                      ? 'border-slate-800 bg-slate-900/40 animate-pulse'
                      : isOk
                      ? isCn
                        ? 'border-sky-500/30 bg-slate-900/80 shadow-xs'
                        : 'border-slate-800 bg-slate-900/60 hover:border-slate-700'
                      : 'border-rose-900/40 bg-rose-950/10 hover:border-rose-800/60'
                  }`}
                >
                  <div className="flex items-start justify-between gap-2">
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center gap-1.5">
                        <span className="text-sm shrink-0">{item.region.flag}</span>
                        <h3 className="font-semibold text-xs text-slate-100 truncate" title={item.region.name}>
                          {item.region.name}
                        </h3>
                      </div>
                      <div className="flex items-center gap-1.5 mt-0.5">
                        {item.region.asn && (
                          <span className="text-[10px] font-mono text-slate-400">
                            AS{item.region.asn}
                          </span>
                        )}
                        {authed && item.ip && (
                          <span className="text-[10px] font-mono text-slate-500 truncate" title={item.ip}>
                            · {item.ip}
                          </span>
                        )}
                      </div>
                    </div>

                    <span className={`shrink-0 rounded-full border px-2 py-0.5 text-[10px] font-mono font-bold ${
                      isTesting
                        ? 'border-sky-500/40 bg-sky-950/40 text-sky-400'
                        : isOk
                        ? latencyBadgeColor(item.timings.total)
                        : item.status === 'timeout'
                        ? 'border-rose-500/40 bg-rose-950/40 text-rose-300'
                        : item.status === 'refused'
                        ? 'border-amber-500/40 bg-amber-950/40 text-amber-300'
                        : 'border-slate-700 bg-slate-800 text-slate-400'
                    }`}>
                      {isTesting
                        ? '检测中...'
                        : isOk
                        ? `${item.timings.total} ms`
                        : item.status === 'timeout'
                        ? '连接超时'
                        : item.status === 'refused'
                        ? '端口拒绝'
                        : item.status === 'dns_error'
                        ? 'DNS失败'
                        : item.status === 'tls_error'
                        ? 'TLS错误'
                        : '检测失败'}
                    </span>
                  </div>

                  {/* Timings breakdown bar */}
                  {isOk && (
                    <div className="space-y-1 pt-1 border-t border-slate-800/60 text-[10px] font-mono">
                      <div className="flex items-center justify-between text-slate-400">
                        <span>时延构成</span>
                        <span className="text-slate-200 font-bold">{item.timings.total} ms</span>
                      </div>
                      <div className="flex gap-1.5 text-slate-400 flex-wrap">
                        {item.timings.dns !== undefined && (
                          <span className="rounded bg-slate-800/80 px-1 py-0.2">
                            DNS: {item.timings.dns}ms
                          </span>
                        )}
                        {item.timings.tcp !== undefined && (
                          <span className="rounded bg-slate-800/80 px-1 py-0.2">
                            TCP: {item.timings.tcp}ms
                          </span>
                        )}
                        {item.timings.tls !== undefined && (
                          <span className="rounded bg-slate-800/80 px-1 py-0.2">
                            TLS: {item.timings.tls}ms
                          </span>
                        )}
                        {item.timings.ttfb !== undefined && (
                          <span className="rounded bg-slate-800/80 px-1 py-0.2">
                            TTFB: {item.timings.ttfb}ms
                          </span>
                        )}
                      </div>
                    </div>
                  )}

                  {!isOk && !isTesting && item.error && (
                    <div className="pt-1 border-t border-slate-800/60 text-[10px] text-rose-300/80 font-mono truncate" title={item.error}>
                      {item.error}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </div>

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
