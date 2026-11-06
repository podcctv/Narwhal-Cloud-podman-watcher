import React from 'react';
import { ContainerSecurity } from '../../api/types';

export const AdmissionStatus: React.FC<{ data?: ContainerSecurity['admission']; compact?: boolean; stale?: boolean }> = ({ data, compact = false, stale = false }) => {
  if (!data) return null;
  const now = Date.now() / 1000;
  const verified = !stale && data.state === 'enforced' && now - (data.observed_at || 0) <= 90;
  // Missing means a legacy Agent that still enforces the five-source rule.
  const sourceLimitEnforced = data.source_limit_enforced !== false;
  const sourceLimit = data.source_limit || (sourceLimitEnforced ? 10 : 5);
  const isModernEnforced = sourceLimitEnforced && (data.source_policy === 'active_limit_enforced' || (data.source_limit && data.source_limit >= 10));
  const blocked = Object.entries(data.blocked || {}).filter(([, x]) => now - x.last_seen < 120);
  const sources = data.sources || [];
  const confirmedCount = data.confirmed_sources?.length ?? sources.filter(x => x.confirmed !== false).length;
  const tone = !verified ? 'border-amber-500/30 text-amber-300' : sourceLimitEnforced && blocked.length ? 'border-rose-500/40 text-rose-300' : data.limited ? 'border-amber-500/30 text-amber-300' : 'border-emerald-500/30 text-emerald-300';
  const minutes = Math.max(0, Math.ceil(((data.review_at || 0) - now) / 60));
  return <section aria-label="容器网络准入保护" className={`min-w-0 rounded-lg border bg-slate-950/50 p-2 text-xs ${tone}`}>
    <div className="flex min-w-0 flex-wrap items-center justify-between gap-1 font-medium">
      <span>{verified ? isModernEnforced ? `业务入站准入 ${confirmedCount}/${sourceLimit} IP` : sourceLimitEnforced ? `旧版入站准入 ${sources.length}/5` : `入站来源观测 ${sources.length} 个样本` : '准入保护未确认'}</span>
      <span>{verified && sourceLimitEnforced && blocked.length > 0 ? (isModernEnforced ? `已拦截 ${blocked.length} 个超限来源` : `旧版规则已拦 ${blocked.length} 个来源`) : verified && data.limited ? 'TCP 上限 500' : ''}</span>
    </div>
    {!compact && <div className="mt-2 space-y-2 text-slate-300">
      <p>{verified ? isModernEnforced ? `默认限制单容器最多保持 ${sourceLimit} 个活跃并发业务 IP；已启用业务监听端口聚焦与真实已建立会话识别，公网扫描不消耗配额。超过上限的新来源连接已被自动阻断。空闲来源 120 秒无活动自动释放名额。` : sourceLimitEnforced ? '该节点 Agent 仍在按旧版前 5 个来源限制新连接；来源 IP 不等于真实用户数，扫描流量可能占用名额。请升级 Agent。' : '当前节点未开启来源 IP 数量限制（观察模式）。下方最多显示已建立连接来源样本。' : data.error || '采样已过期或执行未验证，不能确认当前保护状态。'}</p>
      {data.limited && <p>TCP 当前 {data.tcp_connections ?? '未知'} 条；{minutes > 0 ? `${minutes} 分钟后复查` : '等待有效采样复查'}，已追加 {data.extensions || 0} 次。已有连接自然回落。</p>}
      <div className="grid min-w-0 gap-3 sm:grid-cols-2">
        <div><div className="mb-1 font-medium text-sky-300">{isModernEnforced ? `活跃并发业务来源 (${confirmedCount}/${sourceLimit})` : sourceLimitEnforced ? '旧版保留来源' : '已建立连接来源样本'}</div>{sources.length ? sources.map(x => <div key={x.ip} className="break-all font-mono text-[11px]">{x.ip}<span className="ml-2 font-sans text-slate-400">首次观测 {new Date(x.first_seen * 1000).toLocaleString('zh-CN')}</span></div>) : <p className="text-slate-400">暂未观测到来源</p>}</div>
        <div><div className="mb-1 font-medium text-amber-300">{isModernEnforced ? '近两分钟超限阻断来源' : sourceLimitEnforced ? '近两分钟旧版拒绝记录' : '历史拒绝记录（旧版规则）'}</div>{blocked.length ? blocked.map(([ip, x]) => <div key={ip} className="break-all font-mono text-[11px]">{ip}<span className="ml-2 font-sans text-slate-400">阻断 {x.packets} 包</span></div>) : <p className="text-slate-400">未记录到拒绝事件</p>}</div>
      </div>
      <p className="text-[11px] text-slate-400">TCP 并发统计已建立连接：超过 1000 持续 2 分钟后，新 TCP 连接上限为 500，至少 30 分钟；复查仍 ≥500 会追加 30 分钟。持续低于 500 且有效采样满 2 分钟、当前期限已到才解除。缺数据不会当成恢复。</p>
    </div>}
  </section>;
};
