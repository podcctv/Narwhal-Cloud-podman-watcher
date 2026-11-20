import React, { useEffect, useRef, useState } from 'react';
import { AlertTriangle, ArrowRight, Box, CheckCircle2, Clock3, HelpCircle, Search, ShieldAlert, Users, X } from 'lucide-react';
import { api } from '../../api/client';
import type { InvestigationResponse, InvestigationIncident } from '../../api/types';

const time = (ts: number | null) =>
  ts ? new Date(ts * 1000).toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai', hour12: false }) : '尚无记录';
const ownerName = (id: string) =>
  id ? `用户 ${id.length > 16 ? `${id.slice(0, 8)}…${id.slice(-4)}` : id}` : '未知归属';
const states: Record<string, string> = {
  active: '风险存在',
  awaiting_report: '已执行，待复查',
  awaiting_verification: '等待新采样复查',
  verified: '复查通过',
  resolved: '告警结束 · 未验证',
  suppressed: '已放行 / 本次忽略',
  recurring: '风险复发',
  retrying: '复查失败 · 重试中',
  unverified: '证据不足，待核实',
};
const stateColor = (state: string) =>
  state === 'verified'
    ? 'text-[#147468]'
    : ['active', 'recurring'].includes(state)
      ? 'text-[#b41835]'
      : ['awaiting_report', 'retrying'].includes(state)
        ? 'text-[#9a5b00]'
        : 'text-[#506483]';
const categoryName = (kind: string) =>
  ({
    security: '安全配置风险',
    security_attention: '安全待核实',
    network_signal: '出站网络异常 · 原因待核实',
    external_signal: '外部攻击信号 · 非违规结论',
    protection_signal: '网络保护提醒 · 不计用户滥用',
    operational: '运行异常',
  }[kind] || '待核实');
const actionName = (kind: string) =>
  ({
    enforce_socks_auth: '关闭不安全代理',
    remediate_panel_pairing: '清理未授权面板',
    remediate_malicious_process: '清理恶意进程',
    stop_container: '停止容器',
    restart_container: '重启容器',
    apply_udp_throttle: '限制 UDP 流量',
    release_udp_throttle: '解除 UDP 限速',
    release_socks_auth: '解除代理保护',
    allow_panel_domains: '放行面板域名',
    disallow_panel_domains: '取消面板放行',
  }[kind] || kind);
const receiptName = (kind: string) =>
  ({
    process: '停止进程',
    stop_service: '停止服务',
    service: '删除服务',
    config: '删除配置',
    binary: '删除程序',
    startup: '删除自启项',
  }[kind] || kind);

export const UserInvestigationView: React.FC = () => {
  const [host, setHost] = useState('');
  const [days, setDays] = useState(30);
  const [draft, setDraft] = useState('');
  const [query, setQuery] = useState('');
  const [user, setUser] = useState<string | undefined>();
  const [offset, setOffset] = useState(0);
  const [expanded, setExpanded] = useState(false);
  const [data, setData] = useState<InvestigationResponse | null>(null);
  const [responseUser, setResponseUser] = useState<string | undefined>();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [refresh, setRefresh] = useState(0);
  const [selected, setSelected] = useState<InvestigationIncident | null>(null);
  const [history, setHistory] = useState<InvestigationIncident[]>([]);
  const [historyTotal, setHistoryTotal] = useState(0);
  const [historyBusy, setHistoryBusy] = useState(false);
  const [historyError, setHistoryError] = useState('');
  const closeRef = useRef<HTMLButtonElement>(null);
  const drawerRef = useRef<HTMLElement>(null);
  const historyController = useRef<AbortController | null>(null);

  useEffect(() => {
    const controller = new AbortController();
    setBusy(true);
    setError('');
    api
      .getInvestigation({ host_id: host, days, query, user_id: user, offset, limit: 30 }, controller.signal)
      .then((result) => {
        if (!host && result.hosts.length) {
          setHost(result.hosts[0].host_id);
          return;
        }
        setData(result);
        setResponseUser(user);
        if (user === undefined && result.users.length) setUser(result.users[0].user_id);
      })
      .catch((e) => {
        if (!controller.signal.aborted) {
          setError(e.message || '加载失败');
          setData(null);
        }
      })
      .finally(() => {
        if (!controller.signal.aborted) setBusy(false);
      });
    return () => controller.abort();
  }, [host, days, query, user, offset, refresh]);

  useEffect(() => {
    if (!selected) return;
    const trigger = document.activeElement as HTMLElement | null;
    closeRef.current?.focus();
    const key = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setSelected(null);
    };
    const previous = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    document.addEventListener('keydown', key);
    return () => {
      document.body.style.overflow = previous;
      document.removeEventListener('keydown', key);
      trigger?.focus();
    };
  }, [selected]);

  useEffect(() => {
    if (!selected) return;
    const controller = new AbortController();
    historyController.current = controller;
    setHistory([]);
    setHistoryError('');
    setHistoryBusy(true);
    api
      .getInvestigation({ host_id: host, days, identity_key: selected.identity_key, limit: 100 }, controller.signal)
      .then((result) => {
        setHistory(result.items);
        setHistoryTotal(result.total);
      })
      .catch((e) => {
        if (!controller.signal.aborted) setHistoryError(e.message || '历史加载失败');
      })
      .finally(() => {
        if (!controller.signal.aborted) setHistoryBusy(false);
      });
    return () => controller.abort();
  }, [selected, host, days]);

  const changeScope = () => {
    setUser(undefined);
    setOffset(0);
    setSelected(null);
    setData(null);
  };
  const selectedUser = data?.users.find((g) => g.user_id === user);
  const leading = data?.concentration;
  const detailsReady = !busy && responseUser === user;
  const latest = (detailsReady ? data?.items || [] : []).filter(
    (i, index, items) => items.findIndex((other) => other.identity_key === i.identity_key) === index
  );

  return (
    <section className="pb-8 text-[#0b1636]" aria-busy={busy}>
      {/* Top Filter Card */}
      <div className="rn2-card overflow-hidden">
        <div className="rn2-card-head">
          <div>
            <span className="rn2-eyebrow block">INVESTIGATION · USER &amp; CONTAINER</span>
            <h2 className="mt-0.5 text-xl font-bold text-white sm:text-2xl">用户与容器排查</h2>
            <p className="mt-1 text-xs text-[#b9d3ee] sm:text-sm">
              查看已确认的容器安全问题与处置记录。没有账号认证等用户归因证据的网络、连接数和扫描信号只作保护提醒，不计入用户异常或滥用统计。
            </p>
          </div>
        </div>

        <form
          className="grid gap-3 bg-white p-4 sm:grid-cols-2 sm:p-5 lg:grid-cols-[1fr_180px_1.2fr_auto]"
          onSubmit={(e) => {
            e.preventDefault();
            setQuery(draft.trim());
            setUser(undefined);
            setOffset(0);
            setRefresh((n) => n + 1);
          }}
        >
          <label className="grid gap-1 text-xs font-semibold text-[#31485e] lg:flex lg:items-center lg:gap-3">
            <span className="shrink-0">母鸡主机</span>
            <select
              className="rn2-select flex-1"
              value={host}
              onChange={(e) => {
                changeScope();
                setHost(e.target.value);
              }}
            >
              {data?.hosts.length ? (
                data.hosts.map((h) => (
                  <option key={h.host_id} value={h.host_id}>
                    {h.host_id}
                  </option>
                ))
              ) : (
                <option value={host}>{host || '等待主机数据'}</option>
              )}
            </select>
          </label>

          <label className="grid gap-1 text-xs font-semibold text-[#31485e] lg:flex lg:items-center lg:gap-3">
            <span className="shrink-0">时间范围</span>
            <select
              className="rn2-select flex-1"
              value={days}
              onChange={(e) => {
                changeScope();
                setDays(Number(e.target.value));
              }}
            >
              <option value={7}>最近 7 天</option>
              <option value={30}>最近 30 天</option>
              <option value={90}>最近 90 天</option>
            </select>
          </label>

          <label className="grid gap-1 text-xs font-semibold text-[#31485e] lg:flex lg:items-center lg:gap-3">
            <span className="shrink-0">用户 / 容器</span>
            <input
              className="rn2-input flex-1"
              value={draft}
              onChange={(e) => setDraft(e.target.value)}
              placeholder="输入用户标识、容器名或异常名称"
            />
          </label>

          <button disabled={busy} className="rn2-btn rn2-btn-orange mt-auto">
            <Search size={16} aria-hidden="true" />
            {busy ? '查询中…' : '查询 / 刷新'}
          </button>
        </form>
      </div>

      {error && (
        <p role="alert" className="my-4 rounded-xl border border-[#f9b8c4] bg-[#ffeef1] p-4 text-sm font-medium text-[#b41835]">
          {error}，请点击查询重试。
        </p>
      )}
      {!data && !error && (
        <p className="mt-4 rounded-xl border border-[#cedae7] bg-white py-12 text-center text-sm text-[#506483]">
          {busy ? '正在核对母鸡、容器和用户历史…' : '尚无历史数据，等待 Client 上报。'}
        </p>
      )}

      {data && (
        <>
          {/* 5-col Spec Strip */}
          <div className="rn2-card mt-4 overflow-hidden">
            <div className="rn2-spec-strip grid-cols-2 bg-[#f4f8fd] divide-y divide-[#d2dfec] sm:grid-cols-3 sm:divide-y-0 lg:grid-cols-5">
              {(
                [
                  { label: '已监测容器', value: data.summary.observed, icon: Box, color: 'text-[#087bff]' },
                  { label: '异常容器', value: data.summary.affected, icon: ShieldAlert, color: 'text-[#b41835]' },
                  {
                    label: '保护提醒 · 不计滥用',
                    value: data.summary.protection_signals,
                    icon: ShieldAlert,
                    color: 'text-[#9a5b00]',
                  },
                  { label: '涉及用户', value: data.summary.users, icon: Users, color: 'text-[#087bff]' },
                  { label: '未知归属', value: data.summary.unknown, icon: HelpCircle, color: 'text-[#506483]' },
                ] as const
              ).map((k) => (
                <div key={k.label} className="rn2-spec-cell flex items-center gap-3 p-4">
                  <k.icon className={`h-6 w-6 shrink-0 ${k.color}`} aria-hidden="true" />
                  <div className="min-w-0">
                    <div className="text-[11px] font-bold uppercase tracking-wider text-[#697b9c]">{k.label}</div>
                    <div className="mt-1 font-mono text-2xl font-bold text-[#0b1636] tabular-nums">{k.value}</div>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Concentration Callout */}
          <div className="mt-4 flex flex-wrap items-center gap-x-5 gap-y-2 rounded-xl border border-[#f7d58b] bg-[#fef6e4] px-4 py-3 text-sm">
            <AlertTriangle className="h-5 w-5 shrink-0 text-[#9a5b00]" aria-hidden="true" />
            <span className="font-bold text-[#0b1636]">
              {leading
                ? `异常集中线索：${ownerName(leading.user_id)} 有 ${leading.affected} / ${leading.observed} 个容器出现异常`
                : '暂无可归属用户的异常集中线索'}
            </span>
            <span className="text-xs font-medium text-[#31485e]">
              {leading ? `占已归属异常容器 ${leading.share}%（${leading.affected} / ${data.summary.attributed}）；` : ''}
              不是用户违规结论
            </span>
          </div>

          <p className="my-2.5 text-xs leading-5 text-[#31485e]">
            历史有效范围起点：{time(data.coverage.from)}（北京时间）。
            {!data.coverage.complete_window && '所选时间范围数据不完整。'}
            {data.summary.legacy > 0 && ` ${data.summary.legacy} 条旧告警缺少完整事件/归属证据，不计入独立事件数。`}
            仅统计已有观测，不编造持续时长。
          </p>

          {/* Users Table Card */}
          <div className="rn2-card overflow-hidden">
            <div className="rn2-card-head">
              <div>
                <span className="rn2-eyebrow block">OWNER ATTRIBUTION</span>
                <h3 className="font-bold text-white">按容器映射用户查看</h3>
              </div>
              <span className="text-xs text-[#cde8ff]">网络保护提醒单独展示、不计用户异常；重复上报不增加独立事件数</span>
            </div>

            <div className="hidden grid-cols-[1.6fr_1fr_1.4fr_.8fr_.8fr_auto] gap-4 border-b border-[#cedae7] bg-[#edf5fc] px-5 py-3 text-[11px] font-bold uppercase tracking-wider text-[#31485e] lg:grid">
              <span>容器映射用户</span>
              <span>异常 / 已监测容器</span>
              <span>映射内异常率</span>
              <span>独立事件</span>
              <span>待核实事件</span>
              <span>操作</span>
            </div>

            {!data.users.length && <p className="p-8 text-center text-sm text-[#506483]">没有符合条件的用户或容器记录。</p>}

            {data.users.map((g) => (
              <button
                type="button"
                disabled={busy}
                key={g.user_id}
                aria-pressed={user === g.user_id}
                onClick={() => {
                  setUser(g.user_id);
                  setOffset(0);
                  setExpanded(false);
                }}
                className={`grid w-full grid-cols-2 items-center gap-3 border-b border-[#eaf0f7] px-5 py-3.5 text-left text-sm transition-colors last:border-0 sm:grid-cols-3 lg:grid-cols-[1.6fr_1fr_1.4fr_.8fr_.8fr_auto] lg:gap-4 ${
                  user === g.user_id
                    ? 'border-l-4 border-l-[#087bff] bg-[#e8f3ff]'
                    : 'bg-white hover:bg-[#f4f8fd]'
                } disabled:opacity-60`}
              >
                <span className="break-all font-bold text-[#0657b8]">{ownerName(g.user_id)}</span>
                <span className="font-mono font-semibold text-[#0b1636] tabular-nums">
                  {g.affected} / {g.observed}
                  {g.protection_signals > 0 && (
                    <span className="mt-1 block font-sans text-xs font-medium text-[#9a5b00]">
                      另有 {g.protection_signals} 条保护提醒，不计用户异常
                    </span>
                  )}
                </span>
                <span className="flex items-center gap-3 font-mono text-[#31485e] tabular-nums">
                  {g.rate === null ? (
                    g.user_id ? (
                      `${g.unassessed}个容器未评估`
                    ) : (
                      '未知归属不计算占比'
                    )
                  ) : (
                    <>
                      <span className="min-w-12 font-semibold text-[#0b1636]">{g.rate.toFixed(1)}%</span>
                      <progress
                        aria-label={`${ownerName(g.user_id)}异常容器占比`}
                        max={100}
                        value={g.rate}
                        className="hidden h-2 w-24 min-w-0 xl:block"
                      />
                    </>
                  )}
                  {g.user_id && g.observed < 3 && <span className="font-sans text-xs text-[#697b9c]">小样本</span>}
                </span>
                <span className="font-mono font-semibold text-[#0b1636] tabular-nums">
                  <span className="mr-2 font-sans text-xs font-normal text-[#506483] lg:hidden">独立事件</span>
                  {g.episodes}
                </span>
                <span className="font-mono font-semibold text-[#0b1636] tabular-nums">
                  <span className="mr-2 font-sans text-xs font-normal text-[#506483] lg:hidden">待核实</span>
                  {g.pending}
                </span>
                <span className="flex items-center gap-1 font-semibold text-[#087bff]">
                  查看容器
                  <ArrowRight size={14} aria-hidden="true" />
                </span>
              </button>
            ))}
          </div>

          {/* Container Lifetime Table Card */}
          <div className="rn2-card mt-4 overflow-hidden">
            <div className="rn2-card-head">
              <div>
                <span className="rn2-eyebrow block">CONTAINER LIFETIME</span>
                <h3 className="font-bold text-white">
                  {user === undefined ? '请选择用户' : ownerName(user)} · 容器历史
                </h3>
              </div>
              <span className="font-mono text-xs text-[#cde8ff] tabular-nums">
                {selectedUser?.episodes || 0} 个独立事件 · 归属按事件发生时记录
              </span>
            </div>

            <div className="hidden grid-cols-[1.3fr_1.5fr_1.2fr_1.5fr_auto] gap-4 border-b border-[#cedae7] bg-[#edf5fc] px-5 py-3 text-[11px] font-bold uppercase tracking-wider text-[#31485e] lg:grid">
              <span>容器 / 运行时 / 项目</span>
              <span>最近异常</span>
              <span>最近异常采样</span>
              <span>处置与复查</span>
              <span>历史</span>
            </div>

            {(expanded ? latest : latest.slice(0, 4)).map((i) => (
              <div
                key={i.identity_key}
                className="grid gap-3 border-b border-[#eaf0f7] bg-white px-5 py-3.5 text-sm transition-colors hover:bg-[#f4f8fd] last:border-0 sm:grid-cols-2 lg:grid-cols-[1.3fr_1.5fr_1.2fr_1.5fr_auto] lg:items-center lg:gap-4 lg:py-2.5"
              >
                <div className="min-w-0 break-all font-bold text-[#0b1636] lg:flex lg:flex-wrap lg:items-center lg:gap-x-3">
                  {i.container_name}
                  <div className="mt-1 text-xs font-normal text-[#506483] lg:mt-0">
                    {i.runtime} / {i.project || '默认项目'}
                  </div>
                </div>
                <div
                  className={`font-semibold ${
                    i.category === 'protection_signal'
                      ? 'text-[#9a5b00]'
                      : i.severity === 'critical'
                        ? 'text-[#b41835]'
                        : 'text-[#9a5b00]'
                  }`}
                >
                  {i.title}
                  <div className="mt-1 text-xs font-normal text-[#506483] lg:ml-2 lg:mt-0 lg:inline">
                    {categoryName(i.category)}
                    {i.legacy ? ' · 历史不完整' : ''}
                  </div>
                </div>
                <div className="font-mono text-xs text-[#31485e] tabular-nums">{time(i.last_anomaly)}</div>
                <div className={`flex items-center gap-2 font-semibold ${stateColor(i.state)}`}>
                  {i.state === 'verified' ? <CheckCircle2 size={16} aria-hidden="true" /> : <Clock3 size={16} aria-hidden="true" />}
                  {states[i.state] || '待核实'}
                </div>
                <button
                  type="button"
                  className="rn2-btn rn2-btn-blue rn2-btn-sm justify-self-start"
                  onClick={() => setSelected(i)}
                >
                  查看历史
                  <ArrowRight size={14} aria-hidden="true" />
                </button>
              </div>
            ))}

            {!detailsReady && <p className="p-8 text-center text-sm text-[#506483]">正在核对所选用户的容器历史…</p>}
            {detailsReady && !latest.length && (
              <p className="p-8 text-center text-sm text-[#506483]">该用户在所选母鸡和时间范围内没有匹配的告警事件。</p>
            )}
            {latest.length > 4 && (
              <div className="border-t border-[#dce5ef] bg-[#f4f8fd] px-5 py-2.5">
                <button
                  type="button"
                  className="min-h-11 text-sm font-semibold text-[#087bff] hover:text-[#0657b8]"
                  onClick={() => setExpanded((value) => !value)}
                >
                  {expanded ? '收起容器明细' : `展开本页其余 ${latest.length - 4} 个容器`}
                </button>
              </div>
            )}
            {data.total > 30 && (
              <div className="flex items-center justify-between border-t border-[#dce5ef] bg-[#f4f8fd] p-4 text-xs text-[#31485e]">
                <button
                  type="button"
                  disabled={busy || offset === 0}
                  className="min-h-11 font-semibold text-[#087bff] disabled:text-[#94a3b8]"
                  onClick={() => setOffset((n) => Math.max(0, n - 30))}
                >
                  上一页事件
                </button>
                <span className="font-mono font-semibold tabular-nums">
                  事件 {offset + 1}–{Math.min(offset + 30, data.total)} / {data.total}
                </span>
                <button
                  type="button"
                  disabled={busy || offset + 30 >= data.total}
                  className="min-h-11 font-semibold text-[#087bff] disabled:text-[#94a3b8]"
                  onClick={() => setOffset((n) => n + 30)}
                >
                  下一页事件
                </button>
              </div>
            )}
          </div>

          {data.public_total > 0 && (
            <details className="rn2-card mt-4 p-4">
              <summary className="cursor-pointer text-sm font-bold text-[#9a5b00]">
                母鸡公共告警 {data.public_total} 个事件 · 不归属用户
              </summary>
              <div className="mt-3 space-y-2">
                {data.public_items.map((i) => (
                  <div key={i.id} className="rounded-lg border border-[#dce5ef] bg-[#f4f8fd] p-2.5 text-sm text-[#31485e]">
                    {i.title} · {time(i.last_anomaly)} · {states[i.state] || '待核实'}
                  </div>
                ))}
              </div>
            </details>
          )}

          <p className="mt-4 text-xs leading-5 text-[#506483]">
            用户字段仅表示容器映射关系，不代表网络行为由该用户发起。有效异常归属覆盖：{data.summary.attributed} /{' '}
            {data.summary.affected} 个异常容器。{data.coverage.note} 本页手动查询，不随实时轮询重排。
          </p>
        </>
      )}

      {/* Light-Ice Slide-Over History Drawer with Sticky Midnight Header */}
      {selected && (
        <div
          className="fixed inset-0 z-50 flex justify-end bg-[#02182f]/70 backdrop-blur-xs"
          onClick={() => setSelected(null)}
        >
          <aside
            ref={drawerRef}
            role="dialog"
            aria-modal="true"
            aria-labelledby="investigation-history-title"
            onClick={(e) => e.stopPropagation()}
            onKeyDown={(e) => {
              if (e.key !== 'Tab') return;
              const controls = drawerRef.current?.querySelectorAll<HTMLButtonElement>('button:not(:disabled)');
              if (!controls?.length) return;
              const first = controls[0];
              const last = controls[controls.length - 1];
              if ((e.shiftKey && document.activeElement === first) || (!e.shiftKey && document.activeElement === last)) {
                e.preventDefault();
                (e.shiftKey ? last : first).focus();
              }
            }}
            className="h-full w-full max-w-2xl overflow-y-auto border-l border-[#cedae7] bg-white text-[#0b1636] shadow-2xl"
          >
            {/* Sticky Midnight Header */}
            <div className="sticky top-0 z-10 rn2-card-head rounded-none border-b border-[#0f3459] px-5 py-4 sm:px-6">
              <div className="min-w-0 flex-1">
                <span className="rn2-eyebrow block">INCIDENT HISTORY DRAWER</span>
                <h3 id="investigation-history-title" className="mt-0.5 break-all text-lg font-bold text-white">
                  {selected.container_name} · 历史告警
                </h3>
                <p className="mt-1 break-all font-mono text-xs text-[#cde8ff]">
                  {host} · {selected.runtime} / {selected.project} · {ownerName(selected.user_id)} · 最近 {days} 天
                </p>
              </div>
              <button
                ref={closeRef}
                type="button"
                aria-label="关闭历史面板"
                className="flex min-h-11 min-w-11 shrink-0 items-center justify-center rounded-xl border border-[#54c7ff]/40 bg-[#073365]/75 text-white transition-colors hover:border-[#54c7ff] hover:bg-[#087bff]"
                onClick={() => setSelected(null)}
              >
                <X size={18} aria-hidden="true" />
              </button>
            </div>

            <div className="space-y-4 p-5 sm:p-7">
              <p className="rounded-xl border border-[#d2dfec] bg-[#f4f8fd] p-3.5 text-xs leading-5 text-[#31485e]">
                这里的用户仅表示事件发生时容器的映射关系，不单独证明行为来源。网络保护提醒不会计入用户异常；转售前记录不会归到当前映射用户。同名重建有实例 ID / 创建时间证据时分开；没有证据时不声称已区分。检测与处置时间均为北京时间。
              </p>

              {historyBusy && <p className="py-8 text-center text-sm text-[#506483]">加载容器历史…</p>}
              {historyError && (
                <p role="alert" className="rounded-xl border border-[#f9b8c4] bg-[#ffeef1] p-4 text-sm text-[#b41835]">
                  {historyError}
                </p>
              )}

              {history.map((i) => (
                <article
                  key={i.id}
                  className="rounded-xl border border-[#cedae7] bg-white p-4 shadow-xs"
                >
                  <h4 className="text-sm font-bold text-[#0b1636]">
                    {i.title}{' '}
                    <span className={`ml-2 text-xs font-bold ${stateColor(i.state)}`}>{states[i.state] || '待核实'}</span>
                  </h4>
                  <p className="mt-2 text-xs font-semibold text-[#0657b8]">
                    {i.category === 'protection_signal'
                      ? `容器映射用户：${ownerName(i.user_id)}（网络行为未归因到该用户）`
                      : `事件时容器映射用户：${ownerName(i.user_id)}`}
                  </p>
                  <p className="mt-2 font-mono text-xs leading-5 text-[#31485e]">
                    首次检测：{time(i.first_seen)}
                    <br />
                    最近异常采样：{time(i.last_anomaly)}
                    <br />
                    历史开始记录：{time(i.recorded_from)}
                    {i.legacy ? '（旧告警：之前的事件和用户归属无法还原）' : ''}
                  </p>
                  {(i.initial_value !== 0 || i.initial_threshold !== 0 || i.value !== 0 || i.threshold !== 0) && (
                    <div className="mt-3 flex flex-wrap gap-x-6 gap-y-1 rounded-lg border border-[#dce5ef] bg-[#f4f8fd] px-3 py-2 font-mono text-xs text-[#0b1636] tabular-nums">
                      <span>
                        首次记录值 {i.initial_value ?? '未采集'} / 阈值 {i.initial_threshold ?? '未采集'}
                      </span>
                      <span>
                        最近值 {i.value ?? '未采集'} / 阈值 {i.threshold ?? '未采集'}
                      </span>
                    </div>
                  )}
                  {i.evidence.auth_mode && (
                    <p className="mt-3 text-xs font-medium text-[#31485e]">
                      认证检测：
                      {i.evidence.auth_mode === 'no_auth'
                        ? '无密码访问已确认'
                        : i.evidence.auth_mode === 'weak_password'
                          ? '弱密码已确认'
                          : '认证状态待核实'}
                    </p>
                  )}
                  {i.evidence.service_listeners?.map((l, index) => (
                    <p key={index} className="mt-2 break-all font-mono text-xs text-[#31485e]">
                      {l.process} · {l.local} · PID {l.pid}
                    </p>
                  ))}

                  <ol className="mt-4 space-y-2.5">
                    {i.transitions.map((t, index) => (
                      <li key={index} className="rounded-lg border border-[#dce5ef] bg-[#f4f8fd] p-3 text-xs">
                        <div className="flex flex-wrap items-center justify-between gap-2">
                          <time className="font-mono font-semibold text-[#31485e] tabular-nums">{time(t.ts)}</time>
                          <span className={`font-bold ${stateColor(t.state)}`}>{states[t.state] || '待核实'}</span>
                        </div>
                        {t.action?.action_type && (
                          <p className="mt-2 font-medium text-[#0b1636]">
                            处置：{actionName(t.action.action_type)} ·{' '}
                            {t.action.status === 'succeeded'
                              ? '执行成功（复查另计）'
                              : t.action.status === 'failed'
                                ? '执行失败'
                                : '等待执行'}
                          </p>
                        )}
                        {t.action?.action_type === 'restart_container' && t.action.result_message && (
                          <p className="mt-1 break-all text-[#31485e]">{t.action.result_message}</p>
                        )}
                        {t.action?.items?.map((r, n) => (
                          <p
                            key={n}
                            className={`mt-1 break-all font-mono ${r.status === 'ok' ? 'text-[#147468]' : 'text-[#b41835]'}`}
                          >
                            {receiptName(r.kind)} · {r.target}：{r.status === 'ok' ? '完成' : '失败'}
                          </p>
                        ))}
                      </li>
                    ))}
                  </ol>

                  {i.evidence.automatic_remediation?.attempted && (
                    <p className="mt-3 text-xs font-medium text-[#31485e]">
                      Client 自动处置：
                      {i.evidence.automatic_remediation.succeeded ? '执行成功，是否恢复以复查为准' : '执行失败'}
                      {i.evidence.automatic_remediation.items?.map((r) => (
                        <span key={`${r.kind}-${r.target}`} className="block break-all font-mono">
                          {r.target}：{r.status === 'ok' ? '完成' : '失败'}
                        </span>
                      ))}
                    </p>
                  )}
                </article>
              ))}

              {!historyBusy && historyTotal > history.length && (
                <button
                  type="button"
                  className="rn2-btn rn2-btn-blue"
                  disabled={historyBusy}
                  onClick={async () => {
                    const signal = historyController.current?.signal;
                    setHistoryBusy(true);
                    try {
                      const r = await api.getInvestigation(
                        { host_id: host, days, identity_key: selected.identity_key, offset: history.length, limit: 100 },
                        signal
                      );
                      if (!signal?.aborted) setHistory((previous) => [...previous, ...r.items]);
                    } catch {
                      if (!signal?.aborted) setHistoryError('更多历史加载失败，请关闭后重试。');
                    } finally {
                      if (!signal?.aborted) setHistoryBusy(false);
                    }
                  }}
                >
                  加载更多历史事件（{history.length} / {historyTotal}）
                </button>
              )}
            </div>
          </aside>
        </div>
      )}
    </section>
  );
};
