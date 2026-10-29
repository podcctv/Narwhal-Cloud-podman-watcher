import React, { lazy, Suspense, useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Activity, ArrowDown, ArrowRight, Check, ExternalLink, Globe2, Loader2, Play, RotateCw, Server, ShieldCheck } from 'lucide-react';
import { CarrierComparison } from './CarrierComparison';
import { filterTargets } from './model';
import { active, carriers, Directory, Job, jobStatus, latencyColor, median, publicRequest, PublicError, Scope, scopes, Source, sourceStatus, utc, virtualizationLabel } from './types';
import './tcping.css';
import './tcping-catalog.css';
import './tcping-carriers.css';

const ChinaMap = lazy(() => import('./ChinaMap').then(module => ({ default: module.ChinaMap })));

const resultLabel = (error: string) => ({ timeout: '连接超时', refused: '连接被拒', network_error: '网络错误', dns_error: 'DNS 失败', blocked_dns: '地址不安全', deadline: '执行超时', worker_error: '执行错误', cancelled: '已取消' }[error] || '无有效连接');
const productNameKey = (value: string) => value.replace(/\s+/g, ' ').trim().toLocaleLowerCase();
export const TcpingPage: React.FC = () => {
  const [directory, setDirectory] = useState<Directory>();
  const [sources, setSources] = useState<Source[]>([]), [enabled, setEnabled] = useState(false);
  const [selected, setSelected] = useState(''), [scope, setScope] = useState<Scope>('province');
  const [job, setJob] = useState<Job | null>(null), [busy, setBusy] = useState(false);
  const [error, setError] = useState(''), [notice, setNotice] = useState(''), [loading, setLoading] = useState(true);
  const [province, setProvince] = useState(''), [carrier, setCarrier] = useState(''), [status, setStatus] = useState('');
  const [view, setView] = useState<'compare' | 'detail'>('compare');
  const [search, setSearch] = useState(''), [now, setNow] = useState(Date.now() / 1000);
  const selectedRef = useRef(''), epoch = useRef(0), resumeDone = useRef(false);
  const refreshSources = useCallback(async () => {
    const result = await publicRequest<{ items: Source[]; enabled: boolean }>('sources');
    if (selectedRef.current && !result.items.some(s => s.id === selectedRef.current)) {
      epoch.current++; selectedRef.current = ''; setSelected(''); setJob(null); setNotice('该测试来源已撤回，请选择其他小鸡。');
    }
    setSources(result.items); setEnabled(result.enabled); return result.items;
  }, []);
  const showJob = useCallback(async (id: string, sourceId: string, generation: number) => {
    const result = await publicRequest<Job>('jobs/' + encodeURIComponent(id));
    if (epoch.current === generation && selectedRef.current === sourceId && result.source_id === sourceId) {
      setJob(result);
    }
    return result;
  }, []);
  useEffect(() => {
    let alive = true;
    document.title = '全国 TCP PING · Narwhal Network Lab';
    Promise.all([publicRequest<Directory>('directory'), refreshSources()]).then(async ([d, list]) => {
      if (!alive) return; setDirectory(d);
      const id = new URLSearchParams(window.location.search).get('job');
      if (id && /^[0-9a-f-]{36}$/.test(id)) {
        try {
          const resumed = await publicRequest<Job>('jobs/' + id);
          if (alive && list.some(s => s.id === resumed.source_id)) {
            selectedRef.current = resumed.source_id; setSelected(resumed.source_id); setJob(resumed); resumeDone.current = true;
          }
        } catch { if (alive) setNotice('原测试记录已过期或来源已撤回，请重新选择小鸡'); }
      }
    }).catch(e => { if (alive) setError(e.message); }).finally(() => { if (alive) setLoading(false); });
    const tick = window.setInterval(() => setNow(Date.now() / 1000), 1000);
    const refresh = window.setInterval(() => { if (!document.hidden) refreshSources().catch(() => {}); }, 15000);
    return () => { alive = false; window.clearInterval(tick); window.clearInterval(refresh); };
  }, [refreshSources]);
  useEffect(() => {
    if (!selected) return;
    if (resumeDone.current) { resumeDone.current = false; return; }
    const item = sources.find(s => s.id === selected), generation = epoch.current;
    if (item?.latest_job) showJob(item.latest_job.id, selected, generation).catch(e => { if (epoch.current === generation) setNotice(e.message); });
    // Selection changes restore its own last result, not later catalogue refreshes.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selected, showJob]);
  useEffect(() => {
    if (!active(job)) return;
    const id = job!.id, sourceId = selected, generation = epoch.current;
    let inFlight = false;
    const poll = window.setInterval(async () => {
      if (document.hidden || inFlight) return; inFlight = true;
      try { await showJob(id, sourceId, generation); }
      catch (e) { if (epoch.current === generation) setNotice((e as Error).message); }
      finally { inFlight = false; }
    }, 2000);
    return () => window.clearInterval(poll);
  }, [job?.id, job?.status, selected, showJob]);
  const source = sources.find(s => s.id === selected);
  const selectSource = (id: string) => {
    if (selectedRef.current === id) return;
    epoch.current++; selectedRef.current = id; setSelected(id); setScope('province'); setJob(null); setNotice(''); setError(''); setProvince(''); setCarrier(''); setStatus('');
    window.history.replaceState(null, '', '/tcping');
    document.querySelector('.tcp-console')?.scrollIntoView({ behavior: window.matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth', block: 'start' });
  };
  const start = async () => {
    if (!source || busy) return;
    const id = source.id, generation = epoch.current; setBusy(true); setError(''); setNotice('');
    try {
      const result = await publicRequest<{ job: Job; reused: string }>('jobs', { source_id: id, scope });
      if (epoch.current !== generation) return;
      setJob(result.job);
      setNotice(result.reused === 'cache' ? '已复用 15 分钟内的完整结果，没有重复探测。' : result.reused === 'running' ? '该小鸡已有测试进行中，已合并到同一任务。' : '任务已提交，等待所选小鸡接收。');
      window.history.replaceState(null, '', '/tcping?job=' + result.job.id);
      await refreshSources();
    } catch (e) {
      if (epoch.current !== generation) return;
      setError((e as Error).message);
      if (e instanceof PublicError && e.latest) await showJob(e.latest, id, generation).catch(() => {});
    } finally { setBusy(false); }
  };
  const nodes = job?.nodes || directory?.nodes.filter(n => scope === 'all' || n.kind === scope) || [];
  const rows = filterTargets(nodes, { province, carrier, status });
  const good = nodes.filter(n => n.result?.median_ms != null), completed = nodes.filter(n => n.result);
  const overall = median(good.map(n => n.result!.median_ms!));
  const provinceOptions = useMemo(() => [...new Set(nodes.map(n => n.province))].sort((a, b) => a.localeCompare(b, 'zh')), [nodes]);
  const countdown = Math.max(0, Math.ceil((source?.cooldown_until || 0) - now));
  const displayedSources = sources.filter(s => (s.name + ' ' + s.region).toLowerCase().includes(search.toLowerCase()));
  if (loading) return <main className="tcp-lab"><div className="tcp-empty" role="status">正在加载公开目录与测试记录…</div></main>;
  return <main className="tcp-lab">
    <header className="tcp-top"><a className="tcp-brand" href="/tcping"><span className="tcp-mark"><Activity size={23} /></span><span>NARWHAL <small>NETWORK LAB</small></span></a><nav aria-label="页面导航"><a href="#sources">选择小鸡 <ArrowDown size={14} /></a><a href="/tcping/manage">测速配置</a><a href="/">监控后台 <ArrowRight size={14} /></a></nav></header>
    <section className="tcp-heading"><div><p className="tcp-eyebrow">PUBLIC NETWORK MEASUREMENT / 01</p><h1>全国 TCP PING<span>从这里，看见连接。</span></h1><p>测试方向：<strong>所选 VPS → 中国大陆及台湾目标节点</strong>。测量 TCP 建连时延，不是国内节点向 VPS 发起的反向测试。</p></div><div className="tcp-catalog"><Globe2 size={19} /><span><b>{directory?.counts.province_groups ?? '—'}</b> Zstatic 省级组</span><span><b>{directory?.counts.province_nodes ?? '—'}</b> 运营商节点</span><span><b>{directory?.counts.city_nodes ?? '—'}</b> 市级节点</span><span><b>+{directory?.counts.extra_nodes ?? 0}</b> 台湾指定目标</span></div></section>
    {loading && <div className="tcp-message" role="status"><Loader2 size={16} className="tcp-spin" />正在加载公开目录…</div>}
    {error && <div className="tcp-message tcp-error" role="alert">{error}<button onClick={() => window.location.reload()} aria-label="重新加载页面"><RotateCw size={16} /></button></div>}
    {notice && <div className="tcp-message" role="status">{notice}</div>}
    {job && job.scope !== scope && <div className="tcp-message" role="status">当前展示{scopes[job.scope]}的测试记录；下次新测试按所选的{scopes[scope]}执行。</div>}
    {directory?.stale && <div className="tcp-message">上游目录暂未刷新，正在使用最近一次有效目录：{directory.updated_at}。</div>}
    {job && directory && job.generation !== directory.generation && <div className="tcp-message">当前为历史目录的测试记录。新增台湾目标将在下次新测试中采集；冷却期内不会强制重复探测。</div>}
    {!enabled && !loading && <div className="tcp-message">当前暂停新测试，已有公开结果仍可查看。</div>}
    <section className="tcp-console" aria-label="测试控制台"><div className="tcp-selected"><span className="tcp-label">当前测试来源</span><strong>{source?.name || '请先选择下方的小鸡'}</strong><small>{source ? `${source.region || 'VPS 主机'} · ${sourceStatus[source.status] || '不可用'}` : '仅可测试已公开的自有 VPS，不接受任意 IP 或端口'}</small></div><div className="tcp-controls"><label>测试范围<select value={scope} disabled={active(job) || busy} onChange={e => { setScope(e.target.value as Scope); setJob(null); setProvince(''); }}><option value="province">省级 / 台湾 · {directory?.counts.province_targets ?? directory?.counts.province_nodes ?? 93} 节点</option><option value="city">市级节点 · {directory?.counts.city_nodes ?? 223} 节点</option><option value="all">全部节点 · {directory?.counts.total ?? 317} 节点</option></select></label><button className="tcp-primary" disabled={!source || source.status !== 'ready' || !enabled || busy || !directory} onClick={start}>{busy || active(job) ? <Loader2 className="tcp-spin" size={17} /> : <Play size={17} />}{active(job) ? '查看进行中的测试' : countdown ? '复用结果 / 检查冷却' : '开始测试'}</button></div><div className="tcp-guard"><ShieldCheck size={14} /><span>{countdown ? `该小鸡冷却剩余 ${Math.floor(countdown / 60)}:${String(countdown % 60).padStart(2, '0')}` : '省级 15 分钟 / 市级与全量 30 分钟冷却'} · 并发合并 · 缓存复用</span></div></section>
    <section className="tcp-metrics" aria-label="测试摘要"><div><span>返回目标</span><b>{completed.length}<small> / {nodes.length}</small></b></div><div><span>连接成功目标</span><b>{good.length}<small> / {nodes.length}</small></b></div><div><span>有效目标中位时延</span><b style={{ color: latencyColor(overall) }}>{overall === null ? '—' : overall.toFixed(1)}<small> ms</small></b></div><div><span>任务状态</span><b className="tcp-state">{job ? jobStatus[job.status] || job.status : '尚未测试'}</b><small>{job ? scopes[job.scope] : '等待选择来源'}</small></div></section>
    <div className="tcp-view-controls"><div className="tcp-view-switch" role="group" aria-label="地图展示方式"><button aria-pressed={view === 'compare'} onClick={() => setView('compare')}>三网对比</button><button aria-pressed={view === 'detail'} onClick={() => { setView('detail'); if (!carrier) setCarrier('telecom'); }}>单网明细</button></div>{province && <button className="tcp-text tcp-map-reset" onClick={() => setProvince('')}><RotateCw size={13} />全国视图</button>}</div>
    {view === 'compare' && <CarrierComparison nodes={nodes} province={province} onSelect={p => setProvince(prev => prev === p ? '' : p)} onDetail={c => { setCarrier(c); setStatus(''); setView('detail'); }} />}
    {view === 'compare' && <p className="tcp-map-note">下方节点明细可单独筛选运营商和状态，不会隐藏上方三网对比中的失败结果。</p>}
    <section className={`tcp-workspace ${view === 'compare' ? 'tcp-comparison-details' : ''}`}>{view === 'detail' && <article className="tcp-panel tcp-map-panel">
      <div className="tcp-panel-title"><h2>连接分布</h2><div className="tcp-map-title-tools"><span>{province ? `${province} · 省级聚焦` : '全国'} · {carriers[carrier] || '全部运营商'} · ms</span>{province && <button className="tcp-text tcp-map-reset" onClick={() => setProvince('')}><RotateCw size={13} />全国视图</button>}</div></div>
      <Suspense fallback={<div className="tcp-map-loading" role="status">正在载入全国节点地图…</div>}>
        <ChinaMap nodes={nodes} province={province} carrier={carrier} status={status} onSelect={p => setProvince(prev => prev === p ? '' : p)} />
      </Suspense>
      <div className="tcp-legend">{[['#34d399', '<50'], ['#a3e635', '50–100'], ['#facc15', '100–200'], ['#fb923c', '200–250'], ['#f87171', '≥250'], ['#334155', '未测'], ['#7f1d1d', '全失败']].map(([color, label]) => <span key={label}><i style={{ background: color }} />{label}</span>)}</div>
      <p className="tcp-map-note">地图与列表按同一省份、运营商和状态筛选染色；选择省份后地图单独放大该省，点“全国视图”返回。未返回不等于失败。台湾使用指定 TCP 目标（端口 36901）；港澳暂无节点。</p>
    </article>}
      <article className="tcp-panel tcp-results"><div className="tcp-panel-title"><h2>全部测试结果 <small>{rows.length} / {nodes.length}</small></h2>{active(job) && <span className="tcp-live"><i />实时返回</span>}</div><div className="tcp-filters"><label><span className="tcp-sr">省份</span><select aria-label="筛选省份" value={province} onChange={e => setProvince(e.target.value)}><option value="">全部省份</option>{provinceOptions.map(p => <option key={p}>{p}</option>)}</select></label><label><span className="tcp-sr">运营商</span><select aria-label="筛选运营商" value={carrier} onChange={e => setCarrier(e.target.value)}><option value="">全部运营商</option>{Object.entries(carriers).map(([key, label]) => <option value={key} key={key}>{label}</option>)}</select></label><label><span className="tcp-sr">状态</span><select aria-label="筛选状态" value={status} onChange={e => setStatus(e.target.value)}><option value="">全部状态</option><option value="ok">有成功连接</option><option value="failed">无成功连接</option><option value="pending">未返回</option></select></label>{(province || carrier || status) && <button className="tcp-text" onClick={() => { setProvince(''); setCarrier(''); setStatus(''); }}>清除</button>}</div><div className="tcp-table-scroll" tabIndex={0} aria-label="完整测试结果，可滚动查看所有节点"><table><thead><tr><th>目标节点</th><th>中位时延</th><th>成功 / 尝试</th><th>状态 / 地址</th></tr></thead><tbody>{rows.map(n => <tr key={n.id}><td><strong>{n.province}{n.city ? ` · ${n.city}` : ' · 省级'}</strong><small>{carriers[n.carrier]} · TCP {n.port}</small></td><td><span className="tcp-latency" style={{ color: n.result?.median_ms != null ? latencyColor(n.result.median_ms) : '#94a3b8' }}>{n.result?.median_ms == null ? '—' : n.result.median_ms.toFixed(1)}<small> ms</small></span></td><td>{n.result ? `${n.result.success} / ${n.result.attempts}` : `— / ${job?.samples || '—'}`}</td><td><span className={n.result && !n.result.success ? 'tcp-failure' : ''}>{!n.result ? '未返回' : n.result.status === 'ok' ? '连接成功' : n.result.success ? '部分成功' : resultLabel(n.result.error)}</span><small title={`${n.host}:${n.port}`}>{n.result?.ip || n.host}</small></td></tr>)}</tbody></table>{!rows.length && <div className="tcp-empty">{loading ? '等待目录载入' : '没有符合筛选条件的节点'}</div>}</div></article></section>
    <div className="tcp-job-meta" aria-live="polite"><span>{job ? `测试时间：${utc(job.created_at)} · ${job.samples} 次/目标 · ${job.completed}/${job.nodes.length} 已返回` : '尚无测量数据；地图与表格不会生成示例时延。'}</span><span>{job?.message}</span></div>
    <section id="sources" className="tcp-source-section"><div className="tcp-section-title"><div><p className="tcp-eyebrow">MEASUREMENT SOURCES</p><h2>选择你的下一站 <small>{sources.length} 台小鸡</small></h2><p>选择来源主机后开始测试；套餐状态与虚拟化信息按上游公开商品数据更新。</p></div><label><span className="tcp-sr">搜索小鸡</span><input aria-label="搜索小鸡" type="search" placeholder="搜索名称 / 地区" value={search} onChange={e => setSearch(e.target.value)} /></label></div><div className="tcp-source-grid">{displayedSources.map(s => {
      const product = s.product;
      const productNameMatches = !!product?.product_name && productNameKey(product.product_name) === productNameKey(s.name);
      const mappingMismatch = product?.mapping_state === 'mismatch' || (!!product?.product_name && !productNameMatches);
      const mappingVerified = !!product && !mappingMismatch && (product.mapping_state === 'verified' || (!product.mapping_state && productNameMatches));
      const freshProduct = mappingVerified && product && !product.catalog_stale;
      const soldOut = freshProduct && product.sale_status === 'sold_out';
      const available = freshProduct && product.sale_status === 'available' && product.remaining !== null;
      const purchaseUrl = available && product?.purchase_url ? product.purchase_url : '';
      const purchaseNote = mappingMismatch ? '商品与来源不匹配，已隐藏购买链接'
        : product?.catalog_stale ? '库存信息更新中'
          : product?.sale_status === 'unknown' ? '库存暂不可确认'
            : product?.sale_status === 'unavailable' ? '商品暂不可购买'
              : product?.sale_status === 'available' ? '套餐链接暂不可验证'
                : product ? '库存状态暂不可确认' : s.purchase_url ? '套餐信息未验证，已隐藏购买链接' : '商品关联更新中，请稍后刷新';
      const virtualization = virtualizationLabel(mappingVerified ? product.virtualization_type : '');
      return <article key={s.id} className={`tcp-source ${selected === s.id ? 'is-selected' : ''}`}><button className="tcp-source-select" onClick={() => selectSource(s.id)} aria-pressed={selected === s.id}><span className="tcp-source-icon"><Server size={20} /></span><span className="tcp-source-name"><strong>{s.name}</strong><small>{s.region || 'VPS 主机'} · 虚拟化 {virtualization}</small></span><span className="tcp-check">{selected === s.id ? <Check size={16} /> : null}</span></button><div className="tcp-source-detail"><span className={s.status === 'ready' ? 'tcp-ready' : ''}><i />{sourceStatus[s.status] || '不可用'}</span><span>{s.cooldown_until > now ? `冷却 ${Math.ceil((s.cooldown_until - now) / 60)} 分钟` : '无冷却限制'}</span></div><div className="tcp-source-bottom"><span>{s.latest_job ? `${scopes[s.latest_job.scope]} · ${jobStatus[s.latest_job.status] || '有记录'}` : '尚无测试记录'}</span>{soldOut ? <span className="tcp-sold-out" role="status">已售罄</span> : purchaseUrl ? <span className="tcp-purchase-action"><a href={purchaseUrl} target="_blank" rel="noopener noreferrer" title={product?.product_name || undefined}>{`查看套餐 / 购买（剩余 ${product?.remaining} 台）`} <ExternalLink size={13} /></a></span> : <span className={mappingMismatch ? 'tcp-product-warning' : 'tcp-product-status'} role="status">{purchaseNote}</span>}</div></article>;
    })}</div>{!displayedSources.length && <div className="tcp-empty">{sources.length ? '没有匹配的小鸡' : '管理员尚未公开测试来源'}</div>}</section>
    <footer className="tcp-footer"><span>NARWHAL / NETWORK LAB</span><p>大陆目标目录由 <a href="https://www.zstaticcdn.com/" target="_blank" rel="noopener noreferrer">Zstatic</a> 提供；台湾为用户指定目标，仅供个人网络测试研究。结果反映测试时刻的单向 TCP 连接情况，不代表 SLA、吞吐量或购买承诺。目录更新：{directory?.updated_at || '—'}</p></footer>
  </main>;
};
