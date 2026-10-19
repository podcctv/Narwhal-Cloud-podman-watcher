import React from 'react';
import { ContainerSecurity } from '../../api/types';

export const AdmissionStatus: React.FC<{ data?: ContainerSecurity['admission']; compact?: boolean; stale?: boolean }> = ({ data, compact = false, stale = false }) => {
  if (!data) return null;
  const now = Date.now() / 1000;
  const verified = !stale && data.state === 'enforced' && now - (data.observed_at || 0) <= 90;
  const blocked = Object.entries(data.blocked || {}).filter(([, x]) => now - x.last_seen < 120);
  const sources = data.sources || [];
  const tone = !verified ? 'border-amber-500/30 text-amber-300' : blocked.length ? 'border-rose-500/40 text-rose-300' : data.limited || sources.length === 5 ? 'border-amber-500/30 text-amber-300' : 'border-emerald-500/30 text-emerald-300';
  const minutes = Math.max(0, Math.ceil(((data.review_at || 0) - now) / 60));
  return <section aria-label="容器网络准入保护" className={`min-w-0 rounded-lg border bg-slate-950/50 p-2 text-xs ${tone}`}>
    <div className="flex min-w-0 flex-wrap items-center justify-between gap-1 font-medium">
      <span>{verified ? `入站准入 ${sources.length}/5` : '准入保护未确认'}</span>
      <span>{verified && blocked.length > 0 ? `已拦 ${blocked.length} 个新增来源` : verified && data.limited ? 'TCP 上限 500' : ''}</span>
    </div>
    {!compact && <div className="mt-2 space-y-2 text-slate-300">
      <p>{verified ? '保留前 5 个观测到的活跃来源；IPv4/IPv6 共用名额。仅作用于此容器。' : data.error || '采样已过期或执行未验证，不能确认当前保护状态。'}</p>
      {data.limited && <p>TCP 当前 {data.tcp_connections ?? '未知'} 条；{minutes > 0 ? `${minutes} 分钟后复查` : '等待有效采样复查'}，已追加 {data.extensions || 0} 次。已有连接自然回落。</p>}
      <div className="grid min-w-0 gap-3 sm:grid-cols-2">
        <div><div className="mb-1 font-medium text-emerald-300">保留来源</div>{sources.length ? sources.map(x => <div key={x.ip} className="break-all font-mono text-[11px]">{x.ip}<span className="ml-2 font-sans text-slate-400">首次观测 {new Date(x.first_seen * 1000).toLocaleString('zh-CN')}</span></div>) : <p className="text-slate-400">暂未观测到来源</p>}</div>
        <div><div className="mb-1 font-medium text-rose-300">近两分钟拒绝来源</div>{blocked.length ? blocked.map(([ip, x]) => <div key={ip} className="break-all font-mono text-[11px]">{ip}<span className="ml-2 font-sans text-slate-400">拒绝 {x.packets} 包</span></div>) : <p className="text-slate-400">未记录到拒绝事件</p>}</div>
      </div>
      <p className="text-[11px] text-slate-400">TCP 超过 1000 持续 2 分钟：限制新连接上限为 500，至少 30 分钟；复查仍 ≥500 会追加 30 分钟。持续低于 500 且有效采样满 2 分钟、当前期限已到才解除。缺数据不会当成恢复。</p>
    </div>}
  </section>;
};
