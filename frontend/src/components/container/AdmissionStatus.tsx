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
  const confirmedSources = data.confirmed_sources ?? sources.filter(x => x.confirmed !== false);
  const probationSources = data.probation_sources ?? sources.filter(x => x.confirmed === false);
  const confirmedCount = confirmedSources.length;
  const displaySources = isModernEnforced ? confirmedSources : sources;

  const cardTone = !verified
    ? 'border-[#e8bf70]'
    : sourceLimitEnforced && blocked.length
      ? 'border-[#f1b4bf]'
      : data.limited
        ? 'border-[#e8bf70]'
        : 'border-[#cedae7]';

  const headerTone = !verified
    ? 'border-[#e8bf70] bg-[#fef6e4] text-[#9a5b00]'
    : sourceLimitEnforced && blocked.length
      ? 'border-[#f1b4bf] bg-[#ffeef1] text-[#b41835]'
      : data.limited
        ? 'border-[#e8bf70] bg-[#fef6e4] text-[#9a5b00]'
        : 'border-[#cedae7] bg-[#f4f8fd] text-[#0e233c]';

  const badgeTone = !verified
    ? 'text-[#9a5b00]'
    : sourceLimitEnforced && blocked.length
      ? 'text-[#b41835]'
      : data.limited
        ? 'text-[#9a5b00]'
        : 'text-[#147468]';

  const minutes = Math.max(0, Math.ceil(((data.review_at || 0) - now) / 60));

  return (
    <section
      aria-label="容器网络准入保护"
      className={`min-w-0 overflow-hidden rounded-[14px] border bg-white text-xs text-[#0b1636] shadow-xs ${cardTone}`}
    >
      <div className={`flex min-w-0 flex-wrap items-center justify-between gap-1.5 border-b px-3.5 py-2.5 font-bold ${headerTone}`}>
        <span className="tabular-nums">
          {verified
            ? isModernEnforced
              ? `业务入站准入 ${confirmedCount}/${sourceLimit} IP`
              : sourceLimitEnforced
                ? `旧版入站准入 ${sources.length}/5`
                : `入站来源观测 ${sources.length} 个样本`
            : '准入保护未确认'}
        </span>
        <span className={`tabular-nums ${badgeTone}`}>
          {verified && sourceLimitEnforced && blocked.length > 0
            ? isModernEnforced
              ? `已拦截 ${blocked.length} 个超限来源`
              : `旧版规则已拦 ${blocked.length} 个来源`
            : verified && data.limited
              ? 'TCP 上限 500'
              : verified
                ? '运行受保护'
                : ''}
        </span>
      </div>

      {!compact && (
        <div className="min-w-0 space-y-3 p-3.5 text-[#31485e]">
          <p className="leading-5">
            {verified
              ? isModernEnforced
                ? `默认限制单容器最多保持 ${sourceLimit} 个已建连业务 IP（仅统计容器监听端口上已完成 TCP 三次握手进入 ESTABLISHED 状态的真实客户端 IP，未建连 SYN 扫描探针不计入且 15 秒自动清理）。超过上限的新来源连接已被自动阻断；已确认来源断开后空闲 120 秒自动释放名额。`
                : sourceLimitEnforced
                  ? '该节点 Agent 仍在按旧版前 5 个来源限制新连接；来源 IP 不等于真实用户数，扫描流量可能占用名额。请升级 Agent。'
                  : '当前节点未开启来源 IP 数量限制（观察模式）。下方最多显示已建立连接来源样本。'
              : data.error || '采样已过期或执行未验证，不能确认当前保护状态。'}
          </p>

          {data.limited && (
            <p className="rounded-lg border border-[#e8bf70] bg-[#fef6e4] px-2.5 py-2 font-medium text-[#9a5b00]">
              TCP 当前 {data.tcp_connections ?? '未知'} 条；{minutes > 0 ? `${minutes} 分钟后复查` : '等待有效采样复查'}，已追加 {data.extensions || 0} 次。已有连接自然回落。
            </p>
          )}

          <div className="grid min-w-0 gap-3 sm:grid-cols-2">
            <div className="min-w-0 rounded-lg border border-[#d2dfec] bg-[#f4f8fd] p-2.5">
              <div className="mb-1.5 font-bold text-[#0657b8]">
                {isModernEnforced
                  ? `已建连活跃业务来源 (${confirmedCount}/${sourceLimit})`
                  : sourceLimitEnforced
                    ? '旧版保留来源'
                    : '已建立连接来源样本'}
              </div>
              {displaySources.length ? (
                <div className="min-w-0 space-y-1.5">
                  {displaySources.map(x => (
                    <div key={x.ip} className="min-w-0 break-all font-mono text-[11px] text-[#0b1636]">
                      <span className="min-w-0 break-all font-semibold">{x.ip}</span>
                      {isModernEnforced && (
                        <span
                          className={`ml-1.5 inline-block rounded border px-1.5 py-0.5 font-sans text-[10px] font-semibold ${
                            x.active_established === false
                              ? 'border-[#cedae7] bg-[#eef3f9] text-[#4a607a]'
                              : 'border-[#b4e4dc] bg-[#e6f7f4] text-[#147468]'
                          }`}
                        >
                          {x.active_established === false ? '空闲保持(120s内)' : '已建连(ESTABLISHED)'}
                        </span>
                      )}
                      <span className="ml-2 font-sans text-[#4a607a]">
                        首次观测 {new Date(x.first_seen * 1000).toLocaleString('zh-CN')}
                      </span>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-[#4a607a]">暂未观测到已建连业务来源</p>
              )}
              {isModernEnforced && probationSources.length > 0 && (
                <p className="mt-1.5 text-[10px] text-[#4a607a]">
                  另有 {probationSources.length} 个未完成握手的 SYN 探测/待确认来源（不占用业务配额，15 秒未建连自动丢弃）。
                </p>
              )}
            </div>

            <div className="min-w-0 rounded-lg border border-[#d2dfec] bg-[#f4f8fd] p-2.5">
              <div className="mb-1.5 font-bold text-[#9a5b00]">
                {isModernEnforced
                  ? '近两分钟超限阻断来源'
                  : sourceLimitEnforced
                    ? '近两分钟旧版拒绝记录'
                    : '历史拒绝记录（旧版规则）'}
              </div>
              {blocked.length ? (
                <div className="min-w-0 space-y-1">
                  {blocked.map(([ip, x]) => (
                    <div key={ip} className="min-w-0 break-all font-mono text-[11px] text-[#0b1636]">
                      <span className="min-w-0 break-all font-semibold">{ip}</span>
                      <span className="ml-2 font-sans text-[#4a607a]">阻断 {x.packets} 包</span>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-[#4a607a]">未记录到拒绝事件</p>
              )}
            </div>
          </div>

          <p className="text-[11px] leading-4 text-[#4a607a]">
            TCP 并发统计已建立连接：超过 1000 持续 2 分钟后，新 TCP 连接上限为 500，至少 30 分钟；复查仍 ≥500 会追加 30 分钟。持续低于 500 且有效采样满 2 分钟、当前期限已到才解除。缺数据不会当成恢复。
          </p>

          {(data.sni_blocked_total || 0) > 0 && (
            <div className="space-y-1.5 rounded-lg border border-[#e8bf70] bg-[#fef6e4] p-2.5 text-[11px] text-[#784600]">
              <div className="font-bold text-[#9a5b00]">
                SNI 白名单阻断：累计 {data.sni_blocked_total} 次（CN 无 SNI {data.sni_cn_missing_total || 0} 次）
              </div>
              {data.sni_recent_blocked && data.sni_recent_blocked.length > 0 && (
                <div className="flex min-w-0 flex-wrap gap-1.5">
                  {data.sni_recent_blocked.slice(0, 6).map((item, idx) => (
                    <span
                      key={idx}
                      className="min-w-0 break-all rounded border border-[#e8bf70] bg-white px-1.5 py-0.5 font-mono text-[10px] font-semibold text-[#9a5b00]"
                    >
                      {item.sni || 'CN-NO-SNI'} ({(item.proto || 'tls').toUpperCase()}/{item.dst_port ?? '-'}) ×{item.count}
                    </span>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </section>
  );
};
