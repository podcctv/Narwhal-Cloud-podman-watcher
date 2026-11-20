import React, { useState, useEffect, useCallback, useMemo } from 'react';
import {
  Globe,
  AlertTriangle,
  CheckCircle2,
  RefreshCw,
  Zap,
  ArrowRight,
  HelpCircle,
  ChevronDown,
  ChevronUp,
  Copy,
  Check,
  Key,
  Clock,
  Activity,
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
  const d = new Date(checkedAt * 1000);
  const timeStr = d.toLocaleTimeString('zh-CN', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });
  const fullStr = isoUtc8 || d.toLocaleString('zh-CN', { hour12: false });

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

function getHostTag(hostId: string): string {
  const lower = hostId.toLowerCase();
  if (lower.includes('香港') || lower.includes('hkt') || lower.includes('hongkong') || lower.includes(' hk') || lower.startsWith('hk')) return 'HK';
  if (lower.includes('日本') || lower.includes('tokyo') || lower.includes('osaka') || lower.includes(' jp') || lower.startsWith('jp')) return 'JP';
  if (lower.includes('美国') || lower.includes('洛杉矶') || lower.includes('us') || lower.includes('america') || lower.includes('sjc') || lower.includes('lax') || lower.includes('硅谷')) return 'US';
  if (lower.includes('新加坡') || lower.includes('singapore') || lower.includes(' sg') || lower.startsWith('sg')) return 'SG';
  if (lower.includes('德国') || lower.includes('germany') || lower.includes('frankfurt') || lower.includes(' de') || lower.startsWith('de')) return 'DE';
  if (lower.includes('英国') || lower.includes('uk') || lower.includes('london') || lower.includes(' gb')) return 'UK';
  if (lower.includes('韩国') || lower.includes('korea') || lower.includes('seoul') || lower.includes(' kr')) return 'KR';
  if (lower.includes('台湾') || lower.includes('taiwan') || lower.includes('taipei') || lower.includes(' tw')) return 'TW';
  if (lower.includes('瑞典') || lower.includes('sweden') || lower.includes('stockholm') || lower.includes(' se')) return 'SE';
  if (lower.includes('法国') || lower.includes('france') || lower.includes('paris') || lower.includes(' fr')) return 'FR';
  if (lower.includes('荷兰') || lower.includes('netherlands') || lower.includes('amsterdam') || lower.includes(' nl')) return 'NL';
  if (lower.includes('俄罗斯') || lower.includes('russia') || lower.includes('moscow') || lower.includes(' ru')) return 'RU';
  if (lower.includes('澳大利亚') || lower.includes('australia') || lower.includes('sydney') || lower.includes(' au')) return 'AU';
  return 'GL';
}

const latencyBadgeTextColor = (ms?: number | null) => {
  if (!ms || ms <= 0) return 'text-[#64748b]';
  if (ms <= 60) return 'text-[#147468]';
  if (ms <= 150) return 'text-[#087bff]';
  if (ms <= 260) return 'text-[#9a5b00]';
  return 'text-[#b41835]';
};

const getStatusDot = (item: ReachabilitySummaryItem) => {
  if (item.verdict === 'ok') return 'bg-[#147468]';
  if (item.verdict === 'gfw_blocked') return 'bg-[#dc2626] animate-pulse';
  if (item.verdict_label === '探针配额受限') return 'bg-[#7c3aed]';
  return 'bg-[#d97706]';
};

const ReachabilitySparkline: React.FC<{
  trend?: { ts: number; verdict: string; cn_ms?: number | null; global_ms?: number | null }[];
}> = ({ trend = [] }) => {
  if (!trend || trend.length === 0) {
    return (
      <div className="flex items-center gap-2 py-1 font-mono text-[11px] text-[#506483]">
        <Activity className="h-3.5 w-3.5 text-[#087bff]" aria-hidden="true" />
        <span>24h 时延趋势采集中（每小时自动生成快照）</span>
      </div>
    );
  }

  const validPoints = trend.map((p) => ({
    ts: p.ts,
    val:
      typeof p.cn_ms === 'number' && p.cn_ms > 0
        ? p.cn_ms
        : typeof p.global_ms === 'number' && p.global_ms > 0
          ? p.global_ms
          : null,
    verdict: p.verdict,
  }));

  const numericVals = validPoints.filter(
    (p): p is { ts: number; val: number; verdict: string } => typeof p.val === 'number' && p.val > 0
  );
  const minVal = numericVals.length ? Math.min(...numericVals.map((p) => p.val)) : 0;
  const maxVal = numericVals.length ? Math.max(...numericVals.map((p) => p.val)) : 100;
  const latestVal = numericVals.length ? numericVals[numericVals.length - 1].val : null;
  const avgVal = numericVals.length ? Math.round(numericVals.reduce((a, b) => a + b.val, 0) / numericVals.length) : null;

  const w = 320;
  const h = 42;
  const padY = 6;
  const padX = 6;
  const range = maxVal - minVal || 1;

  const coords = validPoints.map((p, idx) => {
    const x = padX + (idx / Math.max(1, validPoints.length - 1)) * (w - 2 * padX);
    const y = p.val != null ? h - padY - ((p.val - minVal) / range) * (h - 2 * padY) : h / 2;
    return { x, y, val: p.val, verdict: p.verdict, ts: p.ts };
  });

  const pathD = coords.reduce((acc, pt, i) => `${acc} ${i === 0 ? 'M' : 'L'} ${pt.x.toFixed(1)} ${pt.y.toFixed(1)}`, '');
  const areaD =
    coords.length > 1
      ? `${pathD} L ${coords[coords.length - 1].x.toFixed(1)} ${h} L ${coords[0].x.toFixed(1)} ${h} Z`
      : '';

  const strokeColor =
    latestVal != null
      ? latestVal <= 80
        ? '#147468'
        : latestVal <= 180
          ? '#087bff'
          : latestVal <= 280
            ? '#d97706'
            : '#dc2626'
      : '#64748b';

  return (
    <div className="space-y-2 rounded-xl border border-[#cedae7] bg-white p-3.5">
      <div className="flex flex-wrap items-center justify-between gap-2 text-xs">
        <span className="flex items-center gap-1.5 font-sans font-bold text-[#0b1636]">
          <Activity className="h-3.5 w-3.5 text-[#087bff]" aria-hidden="true" />
          <span>24小时三网时延趋势 (24h Latency Sparkline)</span>
        </span>
        <div className="flex items-center gap-3 font-mono text-[11px] text-[#506483]">
          <span>
            最低: <b className="text-[#147468]">{minVal ? `${minVal}ms` : '—'}</b>
          </span>
          <span>
            最高: <b className="text-[#9a5b00]">{maxVal ? `${maxVal}ms` : '—'}</b>
          </span>
          <span>
            均值: <b className="text-[#087bff]">{avgVal ? `${avgVal}ms` : '—'}</b>
          </span>
        </div>
      </div>

      <div className="relative flex h-[44px] w-full items-center">
        <svg viewBox={`0 0 ${w} ${h}`} className="h-full w-full overflow-visible" preserveAspectRatio="none">
          <defs>
            <linearGradient id="sparkline-fill" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor={strokeColor} stopOpacity="0.24" />
              <stop offset="100%" stopColor={strokeColor} stopOpacity="0.0" />
            </linearGradient>
          </defs>
          {areaD && <path d={areaD} fill="url(#sparkline-fill)" />}
          {pathD && (
            <path
              d={pathD}
              fill="none"
              stroke={strokeColor}
              strokeWidth="2"
              strokeLinecap="round"
              strokeLinejoin="round"
            />
          )}
          {coords.map((pt, idx) => (
            <circle
              key={idx}
              cx={pt.x}
              cy={pt.y}
              r={idx === coords.length - 1 ? 3.5 : 2}
              className={
                pt.verdict === 'ok'
                  ? 'fill-[#147468]'
                  : pt.verdict === 'gfw_blocked'
                    ? 'fill-[#dc2626]'
                    : 'fill-[#d97706]'
              }
            />
          ))}
        </svg>
      </div>
      <div className="flex items-center justify-between pt-0.5 font-mono text-[10px] text-[#697b9c]">
        <span>24 小时前</span>
        <span>最近 12 小时</span>
        <span>当前最新采样</span>
      </div>
    </div>
  );
};

const latencyBadgeColor = (ms: number) => {
  if (ms <= 60) return 'border-[#9de2d8] bg-[#e6f7f4] text-[#147468]';
  if (ms <= 150) return 'border-[#a9d1ff] bg-[#e8f3ff] text-[#0657b8]';
  if (ms <= 260) return 'border-[#f7d58b] bg-[#fef6e4] text-[#9a5b00]';
  return 'border-[#f9b8c4] bg-[#ffeef1] text-[#b41835]';
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
    api
      .getAuthStatus()
      .then((s) => {
        if (alive) setAuthed(!!s?.authenticated);
      })
      .catch(() => {
        if (alive) setAuthed(false);
      });
    return () => {
      alive = false;
    };
  }, [isLoggedIn]);

  const [clusterData, setClusterData] = useState<ReachabilityClusterSummary | null>(null);
  const [quota, setQuota] = useState<ReachabilityQuotaInfo | null>(null);
  const [loadingCluster, setLoadingCluster] = useState(false);
  const [triggeringCluster, setTriggeringCluster] = useState(false);
  const [triggeringHostId, setTriggeringHostId] = useState<string | null>(null);
  const [triggerMessage, setTriggerMessage] = useState<string>('');

  const [showKeyModal, setShowKeyModal] = useState(false);
  const [apiKeyInput, setApiKeyInput] = useState('');
  const [savingKey, setSavingKey] = useState(false);
  const [keyFeedback, setKeyFeedback] = useState<string>('');

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
        setClusterData((prev) => {
          if (!prev) return prev;
          const items = prev.items.map((it) => (it.host_id === hostId ? res.item : it));
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

  const handleSelectClusterItem = useCallback(
    (item: ReachabilitySummaryItem, stack: 'v4' | 'v6' = 'v4') => {
      setActiveStackTab(stack);

      const isV6 = stack === 'v6';
      const targetIp = isV6 ? item.target_v6 || '' : item.target || '';
      const displayTarget = authed ? targetIp || item.host_id : item.host_id || '已脱敏目标';
      const portNum = isV6 ? item.port_v6 || item.port || 0 : item.port || 0;
      const protoStr = isV6 ? item.protocol_v6 || item.protocol || 'TCP' : item.protocol || 'TCP';
      const verdictStr = isV6 ? item.verdict_v6 || item.verdict || 'ok' : item.verdict || 'ok';
      const verdictLabelStr = isV6
        ? item.verdict_label_v6 || item.verdict_label || '可达性检测完毕'
        : item.verdict_label || '可达性检测完毕';
      const verdictDescStr = isV6 ? item.verdict_desc_v6 || item.verdict_desc || '' : item.verdict_desc || '';
      const resList = isV6
        ? item.results_v6 && item.results_v6.length > 0
          ? item.results_v6
          : item.results || []
        : item.results || [];
      const statsObj = isV6 ? item.stats_v6 || item.stats : item.stats;

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
            : `检测到部分区域或运营商可能存在${isV6 ? ' IPv6 ' : ''}握手丢包或超时，请根据下方探针时延与状态排查。`,
        ],
        results: resList,
        stats: {
          total: statsObj?.total || resList.length || 18,
          success: statsObj?.success ?? statsObj?.ok ?? resList.filter((r: any) => r.status === 'ok').length,
          failed:
            statsObj?.failed ??
            (statsObj?.total || resList.length) -
              (statsObj?.success ?? statsObj?.ok ?? resList.filter((r: any) => r.status === 'ok').length),
          cnSuccess: statsObj?.cn_success ?? resList.filter((r: any) => r.region?.group === 'cn' && r.status === 'ok').length,
          cnTotal: statsObj?.cn_total ?? (resList.filter((r: any) => r.region?.group === 'cn').length || 3),
          cnAverageMs: statsObj?.cnAverageMs ?? (statsObj as any)?.cn_avg_ms ?? null,
          globalAverageMs: statsObj?.globalAverageMs ?? (statsObj as any)?.global_avg_ms ?? null,
          minLatencyMs: statsObj?.min_ms ?? null,
          maxLatencyMs: statsObj?.max_ms ?? null,
        },
        checkedAt: (isV6 ? item.checked_at_v6 || item.checked_at : item.checked_at || Math.floor(Date.now() / 1000)) * 1000,
      });
    },
    [authed]
  );

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

  const handleCopyReport = () => {
    if (!summary) return;
    const targetDisplay = authed
      ? `${summary.target}:${summary.port <= 0 ? 'PING' : summary.port}`
      : `${isIpString(summary.target) ? '已脱敏目标' : summary.target}:${summary.port <= 0 ? 'PING' : summary.port}`;
    const lines = [
      `【全球与三网可达性检测报告】`,
      `目标: ${targetDisplay} (${summary.protocol})`,
      `结论: ${summary.verdictLabel}`,
      `说明: ${summary.verdictDescription}`,
      `国内三网: 电信 ${summary.results.find((r) => r.region.id === 'cn-telecom')?.status === 'ok' ? `${summary.results.find((r) => r.region.id === 'cn-telecom')?.timings.total}ms` : '不可达'} · 联通 ${summary.results.find((r) => r.region.id === 'cn-unicom')?.status === 'ok' ? `${summary.results.find((r) => r.region.id === 'cn-unicom')?.timings.total}ms` : '不可达'} · 移动 ${summary.results.find((r) => r.region.id === 'cn-mobile')?.status === 'ok' ? `${summary.results.find((r) => r.region.id === 'cn-mobile')?.timings.total}ms` : '不可达'}`,
      `国内平均: ${summary.stats.cnAverageMs ? `${summary.stats.cnAverageMs}ms` : '异常'} | 全球平均: ${summary.stats.globalAverageMs ? `${summary.stats.globalAverageMs}ms` : '异常'}`,
      `检测时间: ${new Date(summary.checkedAt).toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai' })}`,
    ];
    navigator.clipboard.writeText(lines.join('\n'));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const filteredResults = useMemo(() => {
    if (filterGroup === 'all') return liveResults;
    return liveResults.filter((r) => r.region.group === filterGroup);
  }, [liveResults, filterGroup]);

  return (
    <div className="space-y-4 text-[#0b1636]" aria-label="全球与三网可达性检测面板">
      {/* Header Card with Midnight Header & Light-Ice Spec Strip */}
      <section className="rn2-card overflow-hidden">
        <div className="rn2-card-head">
          <div className="flex min-w-0 items-center gap-3">
            <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl border border-[#54c7ff]/40 bg-[#087bff]/25 text-[#54c7ff]">
              <Globe className="h-5 w-5" aria-hidden="true" />
            </div>
            <div className="min-w-0">
              <span className="rn2-eyebrow block">GLOBAL REACHABILITY · 18-NODE MATRIX</span>
              <div className="mt-0.5 flex flex-wrap items-center gap-2">
                <h1 className="text-base font-bold text-white sm:text-lg">全球与三网网络巡检大盘</h1>
                <span className="rounded-md border border-[#54c7ff]/40 bg-[#073365]/75 px-2 py-0.5 font-mono text-[11px] font-semibold text-[#cde8ff]">
                  1 小时定时自动轮询
                </span>
                {triggerMessage && (
                  <span className="rounded-md border border-[#54c7ff]/45 bg-[#087bff]/30 px-2.5 py-0.5 font-mono text-xs text-white">
                    {triggerMessage}
                  </span>
                )}
              </div>
              <p className="mt-0.5 text-xs text-[#b9d3ee]">
                基于 Globalping 18 节点分布式探测，涵盖中国电信、联通、移动及全球主要区域网络握手与时延分析。
              </p>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            {onBackToTcping && (
              <button
                type="button"
                onClick={onBackToTcping}
                className="rn2-btn rn2-btn-ghost rn2-btn-sm"
                title="返回 VPS 发起的全国网络连接测速"
              >
                <span>省份测速</span>
                <ArrowRight className="h-3.5 w-3.5" aria-hidden="true" />
              </button>
            )}

            {authed && (
              <button
                type="button"
                onClick={() => {
                  setApiKeyInput(localStorage.getItem('narwhal_globalping_key') || '');
                  setShowKeyModal(true);
                }}
                className="rn2-btn rn2-btn-ghost rn2-btn-sm"
                title="配置 Globalping 探针专属 API Key"
              >
                <Key className="h-3.5 w-3.5 text-[#fcd34d]" aria-hidden="true" />
                <span className="hidden sm:inline">{quota?.api_key_configured ? '已绑 Key' : 'API Key'}</span>
              </button>
            )}

            <button
              type="button"
              disabled={loadingCluster}
              onClick={fetchClusterSummary}
              className="rn2-btn rn2-btn-ghost rn2-btn-sm min-w-11"
              title="刷新最新巡检数据"
              aria-label="刷新最新巡检数据"
            >
              <RefreshCw className={`h-3.5 w-3.5 ${loadingCluster ? 'animate-spin' : ''}`} aria-hidden="true" />
            </button>

            {authed && (
              <button
                type="button"
                disabled={triggeringCluster}
                onClick={handleTriggerCluster}
                className="rn2-btn rn2-btn-orange rn2-btn-sm"
              >
                <Zap className={`h-3.5 w-3.5 ${triggeringCluster ? 'animate-spin' : ''}`} aria-hidden="true" />
                <span>立即全量巡检</span>
              </button>
            )}
          </div>
        </div>

        {/* 4-Col Spec Strip */}
        <div className="rn2-spec-strip grid-cols-2 sm:grid-cols-4">
          <div className="rn2-spec-cell">
            <span className="block text-[11px] font-bold uppercase tracking-wider text-[#697b9c]">巡检主机</span>
            <span className="mt-1 block font-mono text-xl font-bold text-[#0b1636] tabular-nums">
              {clusterData?.total_hosts || availableHosts.length || 0} 台
            </span>
          </div>
          <div className="rn2-spec-cell">
            <span className="block text-[11px] font-bold uppercase tracking-wider text-[#697b9c]">三网畅通</span>
            <span className="mt-1 block font-mono text-xl font-bold text-[#147468] tabular-nums">
              {clusterData?.ok_hosts || 0} 台
            </span>
          </div>
          <div className="rn2-spec-cell">
            <span className="block text-[11px] font-bold uppercase tracking-wider text-[#697b9c]">疑似受阻</span>
            <span className="mt-1 block font-mono text-xl font-bold text-[#b41835] tabular-nums">
              {clusterData?.blocked_hosts || 0} 台
            </span>
          </div>
          <div
            className="rn2-spec-cell cursor-help"
            title={
              quota?.is_rate_limited
                ? `探针配额受限，约 ${Math.ceil((quota.reset_seconds || 0) / 60)} 分钟后重置`
                : `剩余额度: ${quota?.remaining ?? 250} / ${quota?.limit ?? 250} 点`
            }
          >
            <span className="block text-[11px] font-bold uppercase tracking-wider text-[#697b9c]">探针配额</span>
            <span className="mt-1 block font-mono text-xl font-bold text-[#087bff] tabular-nums">
              {quota?.is_rate_limited ? '受限待重置' : `${quota?.remaining ?? 250} / ${quota?.limit ?? 250}`}
            </span>
          </div>
        </div>
      </section>

      {/* Pacing Bar */}
      <div className="flex flex-wrap items-center justify-between gap-2 rounded-xl border border-[#cedae7] bg-white px-4 py-2.5 text-xs text-[#31485e] shadow-xs">
        <div className="flex items-center gap-2">
          <Clock className="h-4 w-4 shrink-0 text-[#087bff]" aria-hidden="true" />
          <span>
            <strong className="text-[#0b1636]">平滑时序调度：</strong>集群 {clusterData?.total_hosts || availableHosts.length || 0}{' '}
            台母机均匀分散至 1 小时时间轴（每约 {quota?.pacing_seconds || 128} 秒自动调度 1 台），双栈机器采用智能配额预算（IPv4 5探针 + IPv6 3探针），杜绝 429 限流并兼顾三网全覆盖。
          </span>
        </div>
        <div className="hidden items-center gap-2 font-mono text-[11px] text-[#506483] md:flex">
          <span>口径: Globalping 18 核心节点分布式采样</span>
        </div>
      </div>

      {/* Host Cards */}
      {!clusterData?.items || clusterData.items.length === 0 ? (
        <div className="rounded-2xl border border-dashed border-[#cedae7] bg-white p-8 text-center text-xs text-[#506483]">
          暂无母机巡检数据。点击右上角“立即全量巡检”启动首轮测试，或等待下一次整点自动测试。
        </div>
      ) : (
        <div className="space-y-3">
          {clusterData.items.map((item: ReachabilitySummaryItem) => {
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
            const isPing = item.port <= 0 || item.protocol === 'PING';
            const portDisplay = isPing ? 'ICMP Ping' : `${item.port} ${item.protocol}`;

            return (
              <div
                key={item.host_id}
                className={`rn2-card overflow-hidden p-4 transition-colors md:p-5 ${
                  isExpanded ? 'rn2-card-featured' : 'hover:border-[#087bff]/50'
                }`}
              >
                {/* Card Top */}
                <div className="flex flex-wrap items-center justify-between gap-3 border-b border-[#dce5ef] pb-3.5">
                  <div className="flex min-w-0 flex-wrap items-center gap-2.5">
                    <span className={`h-2.5 w-2.5 shrink-0 rounded-full ${getStatusDot(item)}`} />
                    <span className="shrink-0 rounded-md border border-[#cedae7] bg-[#f4f8fd] px-1.5 py-0.5 font-mono text-[10px] font-bold text-[#0657b8]">
                      {getHostTag(item.host_id)}
                    </span>
                    <h3
                      className="max-w-[280px] truncate text-sm font-bold tracking-wide text-[#0b1636] sm:max-w-[420px]"
                      title={item.host_id}
                    >
                      {item.host_id}
                    </h3>
                    {item.is_dual_stack && (
                      <span className="rn2-pill rn2-pill-blue rn2-pill-sm">双栈 IPv4/IPv6</span>
                    )}
                    {!item.is_dual_stack && item.has_ipv6 && (
                      <span className="rn2-pill rn2-pill-slate rn2-pill-sm">纯 IPv6</span>
                    )}
                    <span className="rounded-md border border-[#cedae7] bg-[#f4f8fd] px-2 py-0.5 font-mono text-[11px] font-semibold text-[#31485e]">
                      {portDisplay}
                    </span>
                  </div>

                  <div className="ml-auto flex shrink-0 items-center gap-2 text-xs">
                    <div
                      className="hidden items-center gap-1.5 font-mono text-[11px] text-[#506483] sm:flex"
                      title={inspection.full}
                    >
                      <Clock className="h-3.5 w-3.5 text-[#697b9c]" aria-hidden="true" />
                      <span>{inspection.time}</span>
                      <span className="font-sans text-[#697b9c]">({inspection.relative})</span>
                    </div>
                    {authed && (
                      <button
                        type="button"
                        disabled={triggeringHostId === item.host_id}
                        onClick={() => handleTriggerHost(item.host_id)}
                        className="rn2-btn rn2-btn-ghost rn2-btn-sm"
                        title="单独重新检测此机 (即时执行)"
                      >
                        <RefreshCw
                          className={`h-3.5 w-3.5 ${triggeringHostId === item.host_id ? 'animate-spin text-[#087bff]' : ''}`}
                          aria-hidden="true"
                        />
                        <span>{triggeringHostId === item.host_id ? '检测中' : '刷新'}</span>
                      </button>
                    )}
                    <button
                      type="button"
                      onClick={() => toggleExpandHost(item)}
                      className={`rn2-btn rn2-btn-sm ${isExpanded ? 'rn2-btn-blue' : 'rn2-btn-ghost'}`}
                      title={isExpanded ? '收起此机详细巡检成果' : '展开此机最新诊断与各区域时延详情'}
                    >
                      <span>{isExpanded ? '收起详情' : '查看详情'}</span>
                      {isExpanded ? <ChevronUp className="h-3.5 w-3.5" aria-hidden="true" /> : <ChevronDown className="h-3.5 w-3.5" aria-hidden="true" />}
                    </button>
                  </div>
                </div>

                {/* Card Middle */}
                <div className="grid grid-cols-1 items-center gap-4 pt-3.5 lg:grid-cols-12">
                  <div className="space-y-1 font-mono text-xs lg:col-span-3">
                    <div className="flex items-center gap-2 text-[#31485e]">
                      <span className="w-5 shrink-0 font-sans text-[11px] font-bold text-[#697b9c]">V4</span>
                      <span className="truncate font-semibold text-[#0b1636]" title={authed ? item.target : '已脱敏'}>
                        {authed ? item.target || '—' : '已脱敏公网 IP'}
                      </span>
                    </div>
                    {item.is_dual_stack && (
                      <div className="flex items-center gap-2 text-[#506483]">
                        <span className="w-5 shrink-0 font-sans text-[11px] font-bold text-[#697b9c]">V6</span>
                        <span className="truncate font-semibold text-[#0657b8]" title={authed ? item.target_v6 : '已脱敏'}>
                          {authed ? item.target_v6 || '—' : '已脱敏 IPv6'}
                        </span>
                      </div>
                    )}
                    <div className="flex items-center gap-1 pt-0.5 font-mono text-[11px] text-[#506483] sm:hidden">
                      <Clock className="h-3 w-3" aria-hidden="true" />
                      <span>
                        {inspection.time} ({inspection.relative})
                      </span>
                    </div>
                  </div>

                  <div className="space-y-1.5 lg:col-span-3">
                    <div>
                      <span
                        className={`rn2-pill ${
                          isOk
                            ? 'rn2-pill-teal'
                            : isBlocked
                              ? 'rn2-pill-crimson'
                              : isLimited
                                ? 'rn2-pill-slate'
                                : 'rn2-pill-amber'
                        }`}
                      >
                        {isOk ? (
                          <CheckCircle2 className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
                        ) : isLimited ? (
                          <Clock className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
                        ) : (
                          <AlertTriangle className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
                        )}
                        <span className="truncate">
                          {item.is_dual_stack ? `V4: ${item.verdict_label}` : item.verdict_label}
                        </span>
                      </span>
                    </div>
                    {item.is_dual_stack && (
                      <div>
                        {item.verdict_label_v6 ? (
                          <span
                            className={`rn2-pill ${
                              item.verdict_v6 === 'ok'
                                ? 'rn2-pill-teal'
                                : item.verdict_v6 === 'gfw_blocked'
                                  ? 'rn2-pill-crimson'
                                  : 'rn2-pill-amber'
                            }`}
                          >
                            {item.verdict_v6 === 'ok' ? (
                              <CheckCircle2 className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
                            ) : (
                              <AlertTriangle className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
                            )}
                            <span className="truncate">V6: {item.verdict_label_v6}</span>
                          </span>
                        ) : (
                          <span className="font-mono text-[11px] text-[#697b9c]">V6: 待测试</span>
                        )}
                      </div>
                    )}
                  </div>

                  <div className="grid grid-cols-2 gap-2 font-mono text-xs sm:grid-cols-4 lg:col-span-6">
                    {[
                      { label: '中国电信 (4134)', v4: v4Telecom, v6: v6Telecom },
                      { label: '中国联通 (4837)', v4: v4Unicom, v6: v6Unicom },
                      { label: '中国移动 (9808)', v4: v4Mobile, v6: v6Mobile },
                    ].map((c) => (
                      <div key={c.label} className="space-y-1 rounded-xl border border-[#d2dfec] bg-[#f4f8fd] p-2.5">
                        <span className="block truncate font-sans text-[10px] font-bold text-[#697b9c]">{c.label}</span>
                        <div className="whitespace-nowrap font-bold tabular-nums">
                          {c.v4 ? (
                            <span className={latencyBadgeTextColor(c.v4)}>
                              {item.is_dual_stack ? 'V4 ' : ''}
                              {c.v4} ms
                            </span>
                          ) : isBlocked ? (
                            <span className="font-semibold text-[#b41835]">V4 — (超时)</span>
                          ) : (
                            <span className="font-medium text-[#697b9c]">V4 —</span>
                          )}
                        </div>
                        {item.is_dual_stack && (
                          <div className="whitespace-nowrap text-[11px] tabular-nums">
                            {c.v6 ? (
                              <span className={latencyBadgeTextColor(c.v6)}>V6 {c.v6} ms</span>
                            ) : (
                              <span className="text-[#697b9c]">V6 —</span>
                            )}
                          </div>
                        )}
                      </div>
                    ))}

                    <div className="space-y-1 rounded-xl border border-[#d2dfec] bg-[#f4f8fd] p-2.5">
                      <span className="block truncate font-sans text-[10px] font-bold text-[#697b9c]">全球核心均延</span>
                      <div className="whitespace-nowrap font-bold text-[#0b1636] tabular-nums">
                        {v4Global ? `${item.is_dual_stack ? 'V4 ' : ''}${v4Global} ms` : '—'}
                      </div>
                      {item.is_dual_stack && (
                        <div className="truncate whitespace-nowrap text-[11px] font-semibold text-[#0657b8] tabular-nums">
                          {v6Global ? `V6 ${v6Global} ms` : v6CnAvg ? `V6 ${v6CnAvg} ms` : 'V6 —'}
                        </div>
                      )}
                    </div>
                  </div>
                </div>

                {/* Expanded Detail Accordion */}
                {isExpanded && (
                  <div className="-mx-4 -mb-4 mt-4 space-y-4 rounded-b-[13px] border-t border-[#dce5ef] bg-[#f4f8fd] p-4 md:-mx-5 md:-mb-5 md:p-5">
                    {summary ? (
                      <div className="space-y-4">
                        <div
                          className={`space-y-4 rounded-xl border p-4 sm:p-5 ${
                            summary.verdict === 'ok'
                              ? 'border-[#9de2d8] bg-white'
                              : summary.verdict === 'gfw_blocked'
                                ? 'border-[#f9b8c4] bg-white'
                                : summary.verdict === 'partial'
                                  ? 'border-[#f7d58b] bg-white'
                                  : 'border-[#cedae7] bg-white'
                          }`}
                        >
                          <div className="flex flex-wrap items-start justify-between gap-4">
                            <div className="space-y-1">
                              <div className="flex flex-wrap items-center gap-2">
                                <span
                                  className={`rn2-pill ${
                                    summary.verdict === 'ok'
                                      ? 'rn2-pill-teal'
                                      : summary.verdict === 'gfw_blocked'
                                        ? 'rn2-pill-crimson'
                                        : summary.verdict === 'partial'
                                          ? 'rn2-pill-amber'
                                          : 'rn2-pill-slate'
                                  }`}
                                >
                                  {summary.verdict === 'ok' ? (
                                    <CheckCircle2 className="h-3.5 w-3.5" aria-hidden="true" />
                                  ) : (
                                    <AlertTriangle className="h-3.5 w-3.5" aria-hidden="true" />
                                  )}
                                  <span>{summary.verdictLabel}</span>
                                </span>
                                <span className="font-mono text-sm font-bold text-[#0b1636]">
                                  {authed
                                    ? `${summary.target}:${summary.port <= 0 ? 'PING' : summary.port}`
                                    : `${isIpString(summary.target) ? '目标节点' : summary.target}:${summary.port <= 0 ? 'PING' : summary.port}`}
                                </span>
                                <span className="font-mono text-xs text-[#506483]">({summary.protocol} 探测 · 18 节点巡检)</span>
                              </div>
                              <p className="pt-1 text-xs leading-relaxed text-[#31485e]">{summary.verdictDescription}</p>
                            </div>

                            <div className="flex flex-wrap items-center gap-2">
                              {item.is_dual_stack && (
                                <div className="flex items-center rounded-lg border border-[#cedae7] bg-[#f4f8fd] p-0.5">
                                  <button
                                    type="button"
                                    onClick={() => handleSelectClusterItem(item, 'v4')}
                                    className={`min-h-9 rounded-md px-3 py-1 text-xs font-semibold transition-colors ${
                                      activeStackTab === 'v4'
                                        ? 'bg-[#087bff] text-white shadow-xs'
                                        : 'text-[#31485e] hover:text-[#087bff]'
                                    }`}
                                  >
                                    IPv4 探测结果
                                  </button>
                                  <button
                                    type="button"
                                    onClick={() => handleSelectClusterItem(item, 'v6')}
                                    className={`min-h-9 rounded-md px-3 py-1 text-xs font-semibold transition-colors ${
                                      activeStackTab === 'v6'
                                        ? 'bg-[#087bff] text-white shadow-xs'
                                        : 'text-[#31485e] hover:text-[#087bff]'
                                    }`}
                                  >
                                    IPv6 探测结果
                                  </button>
                                </div>
                              )}
                              <button type="button" onClick={handleCopyReport} className="rn2-btn rn2-btn-ghost rn2-btn-sm">
                                {copied ? (
                                  <Check className="h-3.5 w-3.5 text-[#147468]" aria-hidden="true" />
                                ) : (
                                  <Copy className="h-3.5 w-3.5" aria-hidden="true" />
                                )}
                                <span>{copied ? '已复制' : '复制诊断报告'}</span>
                              </button>
                            </div>
                          </div>

                          <div className="rn2-spec-strip grid-cols-2 rounded-xl border border-[#dce5ef] sm:grid-cols-4">
                            <div className="rn2-spec-cell">
                              <span className="block text-[11px] font-bold text-[#697b9c]">国内三网平均时延</span>
                              <span className="mt-1 block font-mono text-base font-bold text-[#087bff] tabular-nums">
                                {summary.stats.cnAverageMs ? `${summary.stats.cnAverageMs} ms` : '—'}
                              </span>
                              <span className="mt-0.5 block text-[10px] text-[#506483]">
                                可达: {summary.stats.cnSuccess} / {summary.stats.cnTotal} 运营商
                              </span>
                            </div>

                            <div className="rn2-spec-cell">
                              <span className="block text-[11px] font-bold text-[#697b9c]">海外区域平均时延</span>
                              <span className="mt-1 block font-mono text-base font-bold text-[#147468] tabular-nums">
                                {(() => {
                                  const ovs = summary.results.filter((r) => r.region.group !== 'cn' && r.status === 'ok');
                                  return ovs.length
                                    ? `${Math.round(ovs.reduce((a, b) => a + b.timings.total, 0) / ovs.length)} ms`
                                    : '—';
                                })()}
                              </span>
                              <span className="mt-0.5 block text-[10px] text-[#506483]">
                                可达: {summary.results.filter((r) => r.region.group !== 'cn' && r.status === 'ok').length} /{' '}
                                {summary.results.filter((r) => r.region.group !== 'cn').length} 区域
                              </span>
                            </div>

                            <div className="rn2-spec-cell">
                              <span className="block text-[11px] font-bold text-[#697b9c]">全球核心可达率</span>
                              <span className="mt-1 block font-mono text-base font-bold text-[#0b1636] tabular-nums">
                                {Math.round((summary.stats.success / (summary.stats.total || 1)) * 100)}%
                              </span>
                              <span className="mt-0.5 block text-[10px] text-[#506483]">
                                成功: {summary.stats.success} / {summary.stats.total} 节点
                              </span>
                            </div>

                            <div className="rn2-spec-cell">
                              <span className="block text-[11px] font-bold text-[#697b9c]">巡检探测口径</span>
                              <span className="mt-1 block font-bold text-[#0657b8]">
                                {summary.protocol === 'PING' ? 'ICMP Ping' : `TCP :${summary.port}`}
                              </span>
                              <span className="mt-0.5 block text-[10px] text-[#506483]">18 核心节点分布式探测</span>
                            </div>
                          </div>

                          <ReachabilitySparkline trend={item.trend_24h} />

                          {summary.advice && summary.advice.length > 0 && (
                            <div className="space-y-1.5 rounded-xl border border-[#dce5ef] bg-[#f4f8fd] p-3 text-xs">
                              <button
                                type="button"
                                className="flex w-full items-center justify-between font-bold text-[#0b1636]"
                                onClick={() => setShowAdvice(!showAdvice)}
                              >
                                <span className="flex items-center gap-1.5">
                                  <HelpCircle className="h-3.5 w-3.5 text-[#087bff]" aria-hidden="true" />
                                  <span>排错指引与建议措施</span>
                                </span>
                                {showAdvice ? <ChevronUp className="h-3.5 w-3.5" aria-hidden="true" /> : <ChevronDown className="h-3.5 w-3.5" aria-hidden="true" />}
                              </button>
                              {showAdvice && (
                                <ul className="list-inside list-disc space-y-1 pl-1 pt-1 leading-relaxed text-[#31485e]">
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
                          <div className="flex flex-wrap items-center justify-between gap-3 border-b border-[#cedae7] pb-2.5">
                            <div className="flex flex-wrap items-center gap-2">
                              <h3 className="text-sm font-bold text-[#0b1636]">各区域及运营商探测结果</h3>
                              <span className="rn2-pill rn2-pill-slate rn2-pill-sm font-mono">{liveResults.length} 节点</span>
                              {item.is_dual_stack && (
                                <span className="rn2-pill rn2-pill-blue rn2-pill-sm">
                                  当前显示: {activeStackTab === 'v6' ? 'IPv6 栈探测' : 'IPv4 栈探测'}
                                </span>
                              )}
                            </div>

                            <div className="flex flex-wrap items-center gap-1 text-xs">
                              {[
                                { id: 'all', label: '全部' },
                                { id: 'cn', label: '中国大陆三网' },
                                { id: 'apac', label: '亚太' },
                                { id: 'emea', label: '欧洲/中东/非洲' },
                                { id: 'am', label: '美洲' },
                              ].map((tab) => (
                                <button
                                  key={tab.id}
                                  type="button"
                                  onClick={() => setFilterGroup(tab.id as any)}
                                  className={`min-h-9 rounded-lg px-2.5 py-1 font-semibold transition-colors ${
                                    filterGroup === tab.id
                                      ? 'bg-[#087bff] text-white shadow-xs'
                                      : 'bg-white text-[#31485e] border border-[#cedae7] hover:border-[#087bff] hover:text-[#087bff]'
                                  }`}
                                >
                                  {tab.label}
                                </button>
                              ))}
                            </div>
                          </div>

                          {liveResults.length === 0 ? (
                            <div className="space-y-2 rounded-xl border border-[#cedae7] bg-white p-6 text-center text-xs text-[#506483]">
                              <Globe className="mx-auto h-6 w-6 text-[#087bff]" aria-hidden="true" />
                              <p className="font-bold text-[#0b1636]">暂无此栈的区域探测明细</p>
                            </div>
                          ) : (
                            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
                              {filteredResults.map((res) => {
                                const rOk = res.status === 'ok';
                                const rTesting = res.status === 'testing';
                                const rCn = res.region.group === 'cn';

                                return (
                                  <div
                                    key={res.region.id}
                                    className={`space-y-2.5 rounded-xl border p-3.5 transition-colors ${
                                      rTesting
                                        ? 'border-[#cedae7] bg-white animate-pulse'
                                        : rOk
                                          ? rCn
                                            ? 'border-[#a9d1ff] bg-white shadow-xs'
                                            : 'border-[#cedae7] bg-white hover:border-[#087bff]/50'
                                          : 'border-[#f9b8c4] bg-[#ffeef1]/60'
                                    }`}
                                  >
                                    <div className="flex items-start justify-between gap-2">
                                      <div className="min-w-0 flex-1">
                                        <div className="flex items-center gap-1.5">
                                          <span className="shrink-0 text-sm">{res.region.flag}</span>
                                          <h4 className="truncate text-xs font-bold text-[#0b1636]" title={res.region.name}>
                                            {res.region.name}
                                          </h4>
                                        </div>
                                        <div className="mt-0.5 flex items-center gap-1.5">
                                          {res.region.asn && (
                                            <span className="font-mono text-[10px] text-[#506483]">AS{res.region.asn}</span>
                                          )}
                                          {authed && res.ip && (
                                            <span className="truncate font-mono text-[10px] text-[#697b9c]" title={res.ip}>
                                              · {res.ip}
                                            </span>
                                          )}
                                        </div>
                                      </div>

                                      <span
                                        className={`shrink-0 rounded-full border px-2 py-0.5 font-mono text-[10px] font-bold ${
                                          rTesting
                                            ? 'border-[#a9d1ff] bg-[#e8f3ff] text-[#0657b8]'
                                            : rOk
                                              ? latencyBadgeColor(res.timings.total)
                                              : res.status === 'timeout'
                                                ? 'border-[#f9b8c4] bg-[#ffeef1] text-[#b41835]'
                                                : res.status === 'refused'
                                                  ? 'border-[#f7d58b] bg-[#fef6e4] text-[#9a5b00]'
                                                  : 'border-[#cbd7e6] bg-[#eef3f9] text-[#4a607a]'
                                        }`}
                                      >
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

                                    {rOk && (
                                      <div className="space-y-1 border-t border-[#dce5ef] pt-1.5 font-mono text-[10px]">
                                        <div className="flex items-center justify-between text-[#506483]">
                                          <span>时延构成</span>
                                          <span className="font-bold text-[#0b1636]">{res.timings.total} ms</span>
                                        </div>
                                        <div className="flex flex-wrap gap-1.5 text-[#31485e]">
                                          {res.timings.dns !== undefined && (
                                            <span className="rounded bg-[#f4f8fd] px-1.5 py-0.5">DNS: {res.timings.dns}ms</span>
                                          )}
                                          {res.timings.tcp !== undefined && (
                                            <span className="rounded bg-[#f4f8fd] px-1.5 py-0.5">TCP: {res.timings.tcp}ms</span>
                                          )}
                                          {res.timings.tls !== undefined && (
                                            <span className="rounded bg-[#f4f8fd] px-1.5 py-0.5">TLS: {res.timings.tls}ms</span>
                                          )}
                                          {res.timings.ttfb !== undefined && (
                                            <span className="rounded bg-[#f4f8fd] px-1.5 py-0.5">TTFB: {res.timings.ttfb}ms</span>
                                          )}
                                        </div>
                                      </div>
                                    )}

                                    {!rOk && !rTesting && res.error && (
                                      <div className="truncate border-t border-[#f9b8c4] pt-1 font-mono text-[10px] text-[#b41835]" title={res.error}>
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
                      <div className="p-4 text-center text-xs text-[#506483]">正在加载该机器巡检详情...</div>
                    )}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}

      {/* API Key Modal */}
      {showKeyModal && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-[#02182f]/70 p-4 backdrop-blur-xs"
          role="dialog"
          aria-modal="true"
          aria-label="配置 Globalping API Key"
        >
          <div className="rn2-card w-full max-w-md overflow-hidden shadow-2xl">
            <div className="rn2-card-head">
              <div className="flex items-center gap-2">
                <Key className="h-4 w-4 text-[#fcd34d]" aria-hidden="true" />
                <h3 className="text-sm font-bold text-white">配置 Globalping API Key</h3>
              </div>
              <button
                type="button"
                aria-label="关闭弹窗"
                onClick={() => {
                  setShowKeyModal(false);
                  setKeyFeedback('');
                }}
                className="flex h-8 w-8 items-center justify-center rounded-lg text-[#cde8ff] hover:bg-white/10 hover:text-white"
              >
                ✕
              </button>
            </div>

            <div className="space-y-4 p-5">
              <div className="space-y-2 text-xs leading-relaxed text-[#31485e]">
                <p>
                  默认未认证公共 IP 探针额度为 250 点/小时。若需要测试全球全量 18 区域或频繁重测，可在{' '}
                  <a
                    href="https://globalping.io"
                    target="_blank"
                    rel="noreferrer"
                    className="font-semibold text-[#087bff] underline hover:text-[#0657b8]"
                  >
                    globalping.io
                  </a>{' '}
                  免费注册账号并在个人面板创建 API Key。
                </p>
                <p className="text-[#506483]">免费账户额度通常为 500 ~ 2,500+ 点/小时。留空并保存可恢复为公共 IP 模式。</p>
              </div>

              <form onSubmit={handleSaveApiKey} className="space-y-3">
                <div>
                  <label htmlFor="globalping-api-key-input" className="mb-1.5 block text-xs font-semibold text-[#31485e]">
                    Globalping API Key / Token
                  </label>
                  <input
                    id="globalping-api-key-input"
                    type="password"
                    value={apiKeyInput}
                    onChange={(e) => setApiKeyInput(e.target.value)}
                    placeholder="留空则使用公共 IP 额度"
                    className="rn2-input font-mono text-xs"
                  />
                </div>

                {keyFeedback && (
                  <div
                    className={`rounded-lg border p-2.5 text-xs font-medium ${
                      keyFeedback.includes('失败')
                        ? 'border-[#f9b8c4] bg-[#ffeef1] text-[#b41835]'
                        : 'border-[#9de2d8] bg-[#e6f7f4] text-[#147468]'
                    }`}
                  >
                    {keyFeedback}
                  </div>
                )}

                <div className="flex items-center justify-end gap-2 border-t border-[#dce5ef] pt-3">
                  <button
                    type="button"
                    onClick={() => {
                      setShowKeyModal(false);
                      setKeyFeedback('');
                    }}
                    className="rn2-btn rn2-btn-ghost rn2-btn-sm"
                  >
                    取消
                  </button>
                  <button type="submit" disabled={savingKey} className="rn2-btn rn2-btn-orange rn2-btn-sm">
                    {savingKey ? '保存中...' : '保存并同步'}
                  </button>
                </div>
              </form>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
