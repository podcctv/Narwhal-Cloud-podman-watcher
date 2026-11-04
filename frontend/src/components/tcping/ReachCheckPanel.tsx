import React, { useState, useEffect, useCallback, useMemo } from 'react';
import {
  Globe, Shield, AlertTriangle, CheckCircle2, RefreshCw,
  Zap, ArrowRight, HelpCircle, ChevronDown, ChevronUp, Copy, Check
} from 'lucide-react';
import {
  RegionResult, ReachCheckSummary,
  executeReachCheck, validateTarget
} from '../../utils/reachCheck';

interface ReachCheckPanelProps {
  initialTarget?: string;
  initialPort?: number;
  availableHosts?: Array<{ id: string; name: string; ip?: string }>;
  onBackToTcping?: () => void;
}

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
}) => {
  const [target, setTarget] = useState(initialTarget);
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
    } catch (err: any) {
      setError(err?.message || '可达性检测失败');
    } finally {
      setRunning(false);
    }
  }, [target, port, protocol]);

  // Copy report summary to clipboard
  const handleCopyReport = () => {
    if (!summary) return;
    const lines = [
      `【全球与三网可达性检测报告】`,
      `目标: ${summary.target}:${summary.port} (${summary.protocol})`,
      `结论: ${summary.verdictLabel}`,
      `说明: ${summary.verdictDescription}`,
      `国内三网: 成功 ${summary.stats.cnSuccess}/${summary.stats.cnTotal} 节点, 平均延迟: ${summary.stats.cnAverageMs ? `${summary.stats.cnAverageMs}ms` : '—'}`,
      `全球综合: 成功 ${summary.stats.success}/${summary.stats.total} 节点, 平均延迟: ${summary.stats.globalAverageMs ? `${summary.stats.globalAverageMs}ms` : '—'}`,
      `检测时间: ${new Date(summary.checkedAt).toLocaleString('zh-CN', { hour12: false })}`,
      ``,
      `【节点详情】`,
      ...summary.results.map(r => `${r.region.flag} ${r.region.name}: ${r.status === 'ok' ? `${r.timings.total}ms` : r.error || '失败'}`),
    ];
    if (summary.browserResult) {
      lines.push(`${summary.browserResult.region.flag} ${summary.browserResult.region.name}: ${summary.browserResult.status === 'ok' ? `${summary.browserResult.timings.total}ms` : summary.browserResult.error || '失败'}`);
    }
    navigator.clipboard.writeText(lines.join('\n'));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const filteredResults = useMemo(() => {
    if (filterGroup === 'all') return liveResults;
    return liveResults.filter(r => r.region.group === filterGroup);
  }, [liveResults, filterGroup]);

  const latencyBadgeColor = (ms: number) => {
    if (ms <= 80) return 'text-emerald-400 border-emerald-500/30 bg-emerald-950/40';
    if (ms <= 160) return 'text-sky-400 border-sky-500/30 bg-sky-950/40';
    if (ms <= 260) return 'text-amber-400 border-amber-500/30 bg-amber-950/40';
    return 'text-rose-400 border-rose-500/30 bg-rose-950/40';
  };

  return (
    <div className="space-y-6">
      {/* Header bar */}
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-800 pb-4">
        <div>
          <div className="flex items-center gap-2">
            <span className="flex h-7 w-7 items-center justify-center rounded-lg bg-sky-500/20 text-sky-400 border border-sky-500/30">
              <Globe className="h-4 w-4" />
            </span>
            <h1 className="text-xl font-bold tracking-tight text-slate-100">全球与三网可达性 (Reach Check)</h1>
          </div>
          <p className="mt-1 text-xs text-slate-400">
            参考开源标准，从全球 18 个核心区域（含中国电信、联通、移动三大运营商）及本地浏览器同步发起实时 TCP/HTTP 可达性与时延剖析。
          </p>
        </div>

        {onBackToTcping && (
          <button
            type="button"
            onClick={onBackToTcping}
            className="flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-800 px-3 py-1.5 text-xs font-medium text-slate-300 hover:bg-slate-700 transition"
          >
            <span>返回省份测速</span>
            <ArrowRight className="h-3.5 w-3.5" />
          </button>
        )}
      </div>

      {/* Target input & Controls */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4 space-y-4">
        <div className="grid grid-cols-1 md:grid-cols-12 gap-3 items-end">
          {/* Target Host */}
          <div className="md:col-span-5 space-y-1.5">
            <label className="block text-xs font-medium text-slate-300">
              检测目标 (域名或公网 IP)
            </label>
            <div className="flex gap-2">
              <input
                type="text"
                placeholder="例如: example.com 或 15.204.57.108"
                value={target}
                onChange={e => setTarget(e.target.value)}
                disabled={running}
                className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 placeholder-slate-500 focus:border-sky-500 focus:outline-hidden font-mono"
              />
              {availableHosts.length > 0 && (
                <select
                  aria-label="快速选择集群节点"
                  className="rounded-lg border border-slate-700 bg-slate-950 px-2 py-2 text-xs text-slate-300 focus:border-sky-500 focus:outline-hidden max-w-[130px]"
                  onChange={e => {
                    if (e.target.value) {
                      setTarget(e.target.value);
                    }
                  }}
                  value=""
                >
                  <option value="" disabled>快速选机</option>
                  {availableHosts.map(h => (
                    <option key={h.id} value={h.ip || h.name}>
                      {h.name}
                    </option>
                  ))}
                </select>
              )}
            </div>
          </div>

          {/* Target Port */}
          <div className="md:col-span-2 space-y-1.5">
            <label className="block text-xs font-medium text-slate-300">
              端口 (1-65535)
            </label>
            <input
              type="number"
              min={1}
              max={65535}
              value={port}
              onChange={e => setPort(Number(e.target.value))}
              disabled={running}
              className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 placeholder-slate-500 focus:border-sky-500 focus:outline-hidden font-mono"
            />
          </div>

          {/* Protocol */}
          <div className="md:col-span-2 space-y-1.5">
            <label className="block text-xs font-medium text-slate-300">
              测试协议
            </label>
            <select
              value={protocol}
              onChange={e => setProtocol(e.target.value as any)}
              disabled={running}
              className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 focus:border-sky-500 focus:outline-hidden"
            >
              <option value="TCP">TCP (全端口推荐)</option>
              <option value="HTTPS">HTTPS (443)</option>
              <option value="HTTP">HTTP (80)</option>
            </select>
          </div>

          {/* Action Button */}
          <div className="md:col-span-3">
            <button
              type="button"
              disabled={running || !target.trim()}
              onClick={() => handleStartCheck()}
              className="w-full flex items-center justify-center gap-2 rounded-lg bg-sky-600 px-4 py-2 text-sm font-semibold text-white shadow-xs hover:bg-sky-500 transition disabled:opacity-50 disabled:cursor-not-allowed"
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
                disabled={running}
                onClick={() => {
                  setPort(p.port);
                  setProtocol(p.protocol);
                }}
                className={`rounded border px-2 py-0.5 transition font-mono ${
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
                  {summary.target}:{summary.port}
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
              <span className="text-[11px] text-slate-400 block font-sans">全球节点平均时延</span>
              <span className="text-base font-bold text-slate-100">
                {summary.stats.globalAverageMs ? `${summary.stats.globalAverageMs} ms` : '—'}
              </span>
              <span className="text-[10px] text-slate-500 block font-sans mt-0.5">
                成功率: {Math.round((summary.stats.success / summary.stats.total) * 100)}% ({summary.stats.success}/{summary.stats.total})
              </span>
            </div>

            <div className="rounded-lg bg-slate-950/60 p-2.5 border border-slate-800/60">
              <span className="text-[11px] text-slate-400 block font-sans">最低 / 最高往返</span>
              <span className="text-sm font-semibold text-emerald-400">
                {summary.stats.minLatencyMs ?? '—'} <span className="text-xs text-slate-500 font-sans">/</span> <span className="text-amber-400">{summary.stats.maxLatencyMs ?? '—'} ms</span>
              </span>
              <span className="text-[10px] text-slate-500 block font-sans mt-0.5">
                抖动范围: {(summary.stats.maxLatencyMs && summary.stats.minLatencyMs) ? `${summary.stats.maxLatencyMs - summary.stats.minLatencyMs} ms` : '—'}
              </span>
            </div>

            <div className="rounded-lg bg-slate-950/60 p-2.5 border border-slate-800/60">
              <span className="text-[11px] text-slate-400 block font-sans">本地访客直连时延</span>
              <span className="text-base font-bold text-indigo-300">
                {summary.browserResult?.status === 'ok'
                  ? `${summary.browserResult.timings.total} ms`
                  : summary.browserResult?.status === 'skipped'
                  ? '已跳过'
                  : '连接失败'}
              </span>
              <span className="text-[10px] text-slate-500 block font-sans mt-0.5">
                当前客户端浏览器视角
              </span>
            </div>
          </div>

          {/* Actionable Advice Section */}
          {summary.advice.length > 0 && (
            <div className="rounded-lg border border-slate-800 bg-slate-950/70 p-3 text-xs space-y-1.5">
              <button
                type="button"
                onClick={() => setShowAdvice(!showAdvice)}
                className="flex items-center justify-between w-full font-semibold text-slate-200"
              >
                <span className="flex items-center gap-1.5">
                  <HelpCircle className="h-3.5 w-3.5 text-sky-400" />
                  <span>下一步排查与处置建议 (What to check next)</span>
                </span>
                {showAdvice ? <ChevronUp className="h-3.5 w-3.5 text-slate-400" /> : <ChevronDown className="h-3.5 w-3.5 text-slate-400" />}
              </button>
              {showAdvice && (
                <ul className="list-disc list-inside space-y-1 text-slate-300 pl-1 pt-1 leading-relaxed">
                  {summary.advice.map((adv, idx) => (
                    <li key={idx}>{adv}</li>
                  ))}
                </ul>
              )}
            </div>
          )}
        </div>
      )}

      {/* 18-Region Vantage Points Grid */}
      <div className="space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <h2 className="text-sm font-bold text-slate-200">各区域及运营商探测结果</h2>
            <span className="rounded-full bg-slate-800 px-2 py-0.5 text-[11px] font-mono text-slate-400">
              {filteredResults.length} 节点
            </span>
          </div>

          {/* Filter tabs */}
          <div className="flex items-center gap-1 bg-slate-900 p-1 rounded-lg border border-slate-800 text-xs">
            {(
              [
                ['all', '全部'],
                ['cn', '中国大陆三网'],
                ['apac', '亚太'],
                ['emea', '欧洲/中东/非洲'],
                ['am', '美洲'],
              ] as const
            ).map(([key, label]) => (
              <button
                key={key}
                type="button"
                onClick={() => setFilterGroup(key)}
                className={`rounded-md px-2.5 py-1 text-xs transition ${
                  filterGroup === key
                    ? 'bg-sky-600 text-white font-semibold'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {label}
              </button>
            ))}
          </div>
        </div>

        {/* Results grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
          {/* Visitor browser card first if present */}
          {summary?.browserResult && filterGroup === 'all' && (
            <div className="rounded-xl border border-indigo-500/30 bg-slate-900/60 p-3.5 space-y-2">
              <div className="flex items-start justify-between gap-2">
                <div>
                  <div className="flex items-center gap-1.5 font-semibold text-xs text-indigo-300">
                    <span>🌐</span>
                    <span>访客本地浏览器 (Your Browser)</span>
                  </div>
                  <span className="text-[10px] text-slate-400 block mt-0.5">
                    从当前浏览器客户端直接请求
                  </span>
                </div>
                <span className={`rounded-full border px-2 py-0.5 text-[10px] font-mono font-bold ${
                  summary.browserResult.status === 'ok'
                    ? 'text-emerald-400 border-emerald-500/30 bg-emerald-950/40'
                    : summary.browserResult.status === 'skipped'
                    ? 'text-slate-400 border-slate-700 bg-slate-800/40'
                    : 'text-rose-400 border-rose-500/30 bg-rose-950/40'
                }`}>
                  {summary.browserResult.status === 'ok' ? '连通正常' : summary.browserResult.status === 'skipped' ? '已跳过' : '连接失败'}
                </span>
              </div>
              <div className="flex items-baseline justify-between font-mono pt-1 border-t border-slate-800/60">
                <span className="text-[11px] text-slate-400 font-sans">本地往返耗时:</span>
                <span className="text-sm font-bold text-indigo-300">
                  {summary.browserResult.status === 'ok' ? `${summary.browserResult.timings.total} ms` : '—'}
                </span>
              </div>
              {summary.browserResult.error && (
                <p className="text-[10px] text-amber-400/90 font-mono truncate" title={summary.browserResult.error}>
                  {summary.browserResult.error}
                </p>
              )}
            </div>
          )}

          {/* 18 External Regions */}
          {filteredResults.map(item => {
            const isOk = item.status === 'ok';
            const isTesting = item.status === 'testing';
            const isCn = item.region.group === 'cn';

            return (
              <div
                key={item.region.id}
                className={`rounded-xl border p-3.5 space-y-2 transition ${
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
                      {item.ip && (
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
      </div>
    </div>
  );
};
