import React, { useEffect, useMemo, useState } from 'react';
import { ChinaMap } from './ChinaMap';
import { carrierComparison, compareProvinces, connectionSummary, mainCarriers, summaryState, ConnectionSummary } from './model';
import { carriers, latencyColor, Target } from './types';

const Summary: React.FC<{ value: ConnectionSummary }> = ({ value: s }) => <>
  <strong title="有效目标中位时延" style={{ color: s.value === null ? '#94a3b8' : latencyColor(s.value) }}>{s.value === null ? '—' : s.value.toFixed(1)}{s.value !== null && <small> ms</small>}</strong>
  <span>{s.completed ? s.attempts ? `${s.success}/${s.attempts} 建连成功` : '未执行 TCP 尝试' : s.total ? '等待结果' : '—'}</span>
  <small className={s.failed || s.partial ? 'tcp-failure' : ''}>{summaryState(s)}</small>
</>;
export const LatencyLegend = () => <div className="tcp-legend">{[['#34d399', '<50'], ['#a3e635', '50–100'], ['#facc15', '100–200'], ['#fb923c', '200–250'], ['#f87171', '≥250 ms'], ['#334155', '未返回 / 无目标'], ['#7f1d1d', '无成功连接']].map(([color, label]) => <span key={label}><i style={{ background: color }} />{label}</span>)}<span><i className="tcp-partial-key" />含失败 / 部分成功</span></div>;

export const CarrierComparison: React.FC<{ nodes: Target[]; province: string; onSelect: (province: string) => void; onDetail: (carrier: string) => void }> = ({ nodes, province, onSelect, onDetail }) => {
  const [mobileCarrier, setMobileCarrier] = useState('telecom');
  const [mobile, setMobile] = useState(() => window.matchMedia('(max-width: 850px)').matches);
  useEffect(() => {
    const query = window.matchMedia('(max-width: 850px)'), change = () => setMobile(query.matches);
    query.addEventListener('change', change); return () => query.removeEventListener('change', change);
  }, []);
  const [sort, setSort] = useState('issues');
  const rows = useMemo(() => carrierComparison(nodes).sort((a, b) => compareProvinces(a, b, sort)), [nodes, sort]);
  const custom = nodes.filter(n => !mainCarriers.includes(n.carrier as typeof mainCarriers[number]));
  return <section className="tcp-comparison" aria-label="三网对比">
    <article className="tcp-panel">
      <div className="tcp-panel-title"><h2>三网连接分布</h2><span>同一色阶 · {province || '全国'} · ms</span></div>
      <div className="tcp-carrier-tabs" role="group" aria-label="手机地图运营商">{mainCarriers.map(c => <button key={c} aria-pressed={mobileCarrier === c} onClick={() => setMobileCarrier(c)}>{carriers[c]}</button>)}</div>
      <div className="tcp-carrier-maps">{mainCarriers.filter(c => !mobile || mobileCarrier === c).map(c => <div className={`tcp-carrier-map ${mobileCarrier === c ? 'is-mobile-active' : ''}`} key={c}>
        <div className="tcp-carrier-heading"><h3>{carriers[c]}</h3><button className="tcp-text" onClick={() => onDetail(c)}>查看节点明细</button></div>
        <ChinaMap nodes={nodes} province={province} carrier={c} status="" onSelect={onSelect} />
        <div className="tcp-carrier-summary"><Summary value={connectionSummary(nodes.filter(n => n.carrier === c && (!province || n.province === province)))} /></div>
      </div>)}</div>
      <LatencyLegend />
      <p className="tcp-map-note">三网独立统计，不混合时延。黄色描边表示含失败或部分成功；未返回不等于失败。点击地图或下表省份同步聚焦；结果仅反映本次 TCP 建连，不代表长期质量。</p>
    </article>
    <article className="tcp-panel tcp-compare-panel">
      <div className="tcp-panel-title"><h2>省份三网对照</h2><label>排序 <select aria-label="三网对照排序" value={sort} onChange={e => setSort(e.target.value)}><option value="issues">失败 / 部分成功优先</option><option value="latency">高时延优先</option><option value="province">省份名称</option></select></label></div>
      <div className="tcp-compare-scroll" tabIndex={0} aria-label="省份三网对照表，可滚动"><table><caption className="tcp-sr">各省各运营商有效目标中位时延、TCP 建连成功次数及状态；省份按钮可同步聚焦三张地图。</caption><thead><tr><th scope="col">省份</th>{mainCarriers.map(c => <th scope="col" key={c}>{carriers[c]}<small>时延 / 成功次数</small></th>)}</tr></thead><tbody>{rows.map(row => <tr key={row.province} className={province === row.province ? 'is-focused' : ''}><th scope="row"><button aria-pressed={province === row.province} onClick={() => onSelect(row.province)}>{row.province}</button></th>{row.cells.map((s, i) => <td key={mainCarriers[i]}><Summary value={s} /></td>)}</tr>)}</tbody></table>{!rows.length && <div className="tcp-empty">本次记录没有三网目标，可在下方查看指定目标。</div>}</div>
      <p className="tcp-map-note">市级 / 全量记录按省份与运营商分别汇总；时延为有效目标中位数，失败与未返回单独列出。成功次数统计实际 TCP 尝试，不是丢包率。</p>
    </article>
    {!!custom.length && <article className="tcp-panel tcp-custom-targets"><div className="tcp-panel-title"><h2>指定目标</h2><span>独立展示，不纳入三网统计</span></div>{custom.map(n => <div key={n.id}><b>{n.province}{n.city ? ` · ${n.city}` : ''} · TCP {n.port}</b><Summary value={connectionSummary([n])} /></div>)}</article>}
  </section>;
};
