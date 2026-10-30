import React, { lazy, Suspense, useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  Activity, ArrowDown, ArrowRight, Check, ChevronDown, CircleCheck, Clock3,
  Download, ExternalLink, Globe2, Info, Loader2, MapPin, Play, RotateCw,
  Search, Server, Share2, ShieldCheck, Signal, X,
} from 'lucide-react';
import { CarrierComparison, LatencyLegend } from './CarrierComparison';
import { connectionSummary, filterTargets } from './model';
import {
  active, carriers, Directory, Job, jobStatus, latencyColor, median, publicRequest,
  PublicError, Scope, scopes, Source, sourceStatus, Target, utc, virtualizationLabel,
} from './types';
import './tcping.css';
import './tcping-catalog.css';
import './tcping-carriers.css';
import './tcping-redesign.css';

const ChinaMap = lazy(() => import('./ChinaMap').then(module => ({ default: module.ChinaMap })));
const mainCarriers = ['telecom', 'unicom', 'mobile'] as const;
const resultLabel = (error: string) => ({
  timeout: '连接超时', refused: '连接被拒', network_error: '网络错误', dns_error: 'DNS 失败',
  blocked_dns: '地址不安全', deadline: '执行超时', worker_error: '执行错误', cancelled: '已取消',
}[error] || '无有效连接');
const productNameKey = (value: string) => value.replace(/\s+/g, ' ').trim().toLocaleLowerCase();
const csvCell = (value: unknown) => `"${String(value ?? '').replace(/"/g, '""')}"`;

export const TcpingPage: React.FC = () => {
  const [directory, setDirectory] = useState<Directory>();
  const [sources, setSources] = useState<Source[]>([]), [enabled, setEnabled] = useState(false);
  const [selected, setSelected] = useState(''), [scope, setScope] = useState<Scope>('province');
  const [job, setJob] = useState<Job | null>(null), [busy, setBusy] = useState(false);
  const [error, setError] = useState(''), [notice, setNotice] = useState(''), [loading, setLoading] = useState(true);
  const [province, setProvince] = useState(''), [carrier, setCarrier] = useState(''), [status, setStatus] = useState('');
  const [resultView, setResultView] = useState<'map' | 'compare' | 'list'>('map');
  const [sourceSearch, setSourceSearch] = useState(''), [targetSearch, setTargetSearch] = useState('');
  const [now, setNow] = useState(Date.now() / 1000), [selectedNode, setSelectedNode] = useState<Target | null>(null);
  const selectedRef = useRef(''), epoch = useRef(0), resumeDone = useRef(false), nodeModalRef = useRef<HTMLElement | null>(null);

  const refreshSources = useCallback(async () => {
    const result = await publicRequest<{ items: Source[]; enabled: boolean }>('sources');
    if (selectedRef.current && !result.items.some(s => s.id === selectedRef.current)) {
      epoch.current++; selectedRef.current = ''; setSelected(''); setJob(null); setNotice('该测试来源已撤回，请选择其他小鸡。');
    }
    setSources(result.items); setEnabled(result.enabled); return result.items;
  }, []);

  const showJob = useCallback(async (id: string, sourceId: string, generation: number) => {
    const result = await publicRequest<Job>('jobs/' + encodeURIComponent(id));
    if (epoch.current === generation && selectedRef.current === sourceId && result.source_id === sourceId) setJob(result);
    return result;
  }, []);

  useEffect(() => {
    let alive = true;
    document.title = '全国 TCP PING · Narwhal Network Lab';
    Promise.all([publicRequest<Directory>('directory'), refreshSources()]).then(async ([d, list]) => {
      if (!alive) return;
      setDirectory(d);
      const id = new URLSearchParams(window.location.search).get('job');
      if (id && /^[0-9a-f-]{36}$/.test(id)) {
        try {
          const resumed = await publicRequest<Job>('jobs/' + id);
          if (alive && list.some(s => s.id === resumed.source_id)) {
            selectedRef.current = resumed.source_id; setSelected(resumed.source_id); setJob(resumed); resumeDone.current = true;
          }
        } catch { if (alive) setNotice('原测试记录已过期或来源已撤回，请重新选择小鸡。'); }
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
    if (item?.latest_job) showJob(item.latest_job.id, selected, generation).catch(e => {
      if (epoch.current === generation) setNotice(e.message);
    });
    // Selection changes restore its own last result, not later catalogue refreshes.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selected, showJob]);

  useEffect(() => {
    if (!active(job)) return;
    const id = job!.id, sourceId = selected, generation = epoch.current;
    let inFlight = false;
    const poll = window.setInterval(async () => {
      if (document.hidden || inFlight) return;
      inFlight = true;
      try { await showJob(id, sourceId, generation); }
      catch (e) { if (epoch.current === generation) setNotice((e as Error).message); }
      finally { inFlight = false; }
    }, 2000);
    return () => window.clearInterval(poll);
  }, [job?.id, job?.status, selected, showJob]);

  useEffect(() => {
    if (!selectedNode) return;
    const previous = document.activeElement as HTMLElement | null;
    const closeOnEscape = (event: KeyboardEvent) => { if (event.key === 'Escape') setSelectedNode(null); };
    nodeModalRef.current?.focus();
    document.addEventListener('keydown', closeOnEscape);
    return () => { document.removeEventListener('keydown', closeOnEscape); previous?.focus(); };
  }, [selectedNode]);

  const source = sources.find(s => s.id === selected);
  const selectSource = (id: string) => {
    if (selectedRef.current === id) return;
    epoch.current++; selectedRef.current = id; setSelected(id); setScope('province'); setJob(null);
    setNotice(''); setError(''); setProvince(''); setCarrier(''); setStatus(''); setTargetSearch(''); setResultView('map');
    window.history.replaceState(null, '', '/tcping');
    document.querySelector('.tcp-r-config')?.scrollIntoView({
      behavior: window.matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth', block: 'start',
    });
  };

  const start = async () => {
    if (!source || busy) return;
    const id = source.id, generation = epoch.current;
    setBusy(true); setError(''); setNotice('');
    try {
      const result = await publicRequest<{ job: Job; reused: string }>('jobs', { source_id: id, scope });
      if (epoch.current !== generation) return;
      setJob(result.job); setResultView('map');
      setNotice(result.reused === 'cache' ? '已复用 15 分钟内的完整结果，没有重复探测。'
        : result.reused === 'running' ? '该小鸡已有测试进行中，已合并到同一任务。'
          : '任务已提交，等待所选小鸡接收。');
      window.history.replaceState(null, '', '/tcping?job=' + result.job.id);
      await refreshSources();
    } catch (e) {
      if (epoch.current !== generation) return;
      setError((e as Error).message);
      if (e instanceof PublicError && e.latest) await showJob(e.latest, id, generation).catch(() => {});
    } finally { setBusy(false); }
  };

  const nodes = job?.nodes || directory?.nodes.filter(n => scope === 'all' || n.kind === scope) || [];
  const filteredByControls = filterTargets(nodes, { province, carrier, status });
  const rows = filteredByControls.filter(n => !targetSearch || `${n.province} ${n.city} ${carriers[n.carrier] || ''} ${n.host} ${n.port}`.toLowerCase().includes(targetSearch.toLowerCase()));
  const completed = nodes.filter(n => n.result), good = nodes.filter(n => n.result?.success && n.result.median_ms !== null);
  const failed = nodes.filter(n => n.result && !n.result.success), pending = nodes.length - completed.length;
  const overall = median(good.map(n => n.result!.median_ms!));
  const provinceOptions = useMemo(() => [...new Set(nodes.map(n => n.province))].sort((a, b) => a.localeCompare(b, 'zh')), [nodes]);
  const displayedSources = sources.filter(s => (s.name + ' ' + s.region).toLowerCase().includes(sourceSearch.toLowerCase()));
  const countdown = Math.max(0, Math.ceil((source?.cooldown_until || 0) - now));
  const progress = job?.nodes.length ? Math.min(100, Math.round(job.completed / job.nodes.length * 100)) : 0;
  const canStart = !!source && source.status === 'ready' && enabled && !busy && !!directory;

  const exportCsv = () => {
    const columns = ['省份', '城市', '运营商', '目标', '端口', '中位时延(ms)', '成功次数', '尝试次数', '状态'];
    const content = [columns, ...rows.map(n => [n.province, n.city, carriers[n.carrier] || n.carrier, n.result?.ip || n.host,
      n.port, n.result?.median_ms ?? '', n.result?.success ?? '', n.result?.attempts ?? '',
      !n.result ? '未返回' : n.result.status === 'ok' ? '连接成功' : n.result.success ? '部分成功' : resultLabel(n.result.error)])]
      .map(row => row.map(csvCell).join(',')).join('\r\n');
    const url = URL.createObjectURL(new Blob(['\uFEFF' + content], { type: 'text/csv;charset=utf-8' }));
    const link = document.createElement('a'); link.href = url; link.download = `tcping-${source?.name || 'results'}.csv`;
    link.click(); URL.revokeObjectURL(url); setNotice(`已导出当前筛选的 ${rows.length} 条结果。`);
  };
  const shareResults = async () => {
    try { await navigator.clipboard.writeText(window.location.href); setNotice('结果链接已复制。'); }
    catch { setNotice('浏览器未授予剪贴板权限，请从地址栏复制当前链接。'); }
  };
  const setQuickStatus = (value: string) => { setStatus(status === value ? '' : value); setResultView('list'); };
  const setQuickCarrier = (value: string) => { setCarrier(carrier === value ? '' : value); setResultView('list'); };
  const displayLatency = (value: number | null | undefined) => value == null ? '—' : `${value.toFixed(1)} ms`;

  if (loading) return <main className="tcp-lab tcp-redesign"><div className="tcp-empty" role="status">正在加载公开目录与测试记录…</div></main>;

  return <main className="tcp-lab tcp-redesign">
    <header className="tcp-r-top">
      <a className="tcp-r-brand" href="/tcping" aria-label="Narwhal Network Lab 首页">
        <span className="tcp-r-mark"><Activity size={20} /></span><span>NARWHAL<small>NETWORK LAB</small></span>
      </a>
      <nav aria-label="页面导航"><a className="is-current" href="/tcping"><Globe2 size={15} />全国 TCP Ping</a><a href="#tcp-r-guide">探测说明</a><a href="/tcping/manage">测速配置 <ArrowRight size={14} /></a></nav>
    </header>

    <section className="tcp-r-hero">
      <div className="tcp-r-hero-copy">
        <p className="tcp-r-eyebrow">PUBLIC NETWORK MEASUREMENT / TCP CONNECT</p>
        <h1>全国网络连接地图</h1>
        <p>从你的 VPS 出发，查看各地 TCP 建连时延。</p>
        <div className="tcp-r-direction"><Info size={15} /><span>方向：<b>所选 VPS → 中国大陆及台湾目标节点</b>。只测 TCP 连接建立，不代表吞吐量或长期 SLA。</span></div>
      </div>
      <div className="tcp-r-catalog" aria-label="探测目录规模">
        <div><b>{directory?.counts.province_groups ?? '—'}</b><span>省级地区</span></div>
        <div><b>{directory?.counts.province_nodes ?? '—'}</b><span>省级运营商</span></div>
        <div><b>{directory?.counts.city_nodes ?? '—'}</b><span>市级节点</span></div>
        <div><b>{directory?.counts.total ?? '—'}</b><span>全部目标</span></div>
      </div>
    </section>

    <ol className="tcp-r-steps" aria-label="测试流程">
      <li className={selected ? 'is-done' : 'is-active'}><span>1</span><b>选择来源</b></li><i />
      <li className={selected ? 'is-active' : ''}><span>2</span><b>设置范围</b></li><i />
      <li className={job ? 'is-active' : ''}><span>3</span><b>查看结果</b></li>
    </ol>

    {error && <div className="tcp-r-alert tcp-r-alert-error" role="alert"><Info size={17} /><span>{error}</span><button onClick={() => window.location.reload()} aria-label="重新加载页面"><RotateCw size={16} />重试</button></div>}
    {notice && <div className="tcp-r-alert" role="status"><CircleCheck size={17} /><span>{notice}</span><button onClick={() => setNotice('')} aria-label="关闭提示"><X size={16} /></button></div>}
    {directory?.stale && <div className="tcp-r-alert tcp-r-alert-warn" role="status"><Info size={17} /><span>上游目录暂未刷新，正在使用最近一次有效目录：{directory.updated_at}。</span></div>}
    {job && directory && job.generation !== directory.generation && <div className="tcp-r-alert tcp-r-alert-warn" role="status"><Info size={17} /><span>当前是历史目录的测试记录。新增目标将在下次新测试时采集。</span></div>}
    {!enabled && <div className="tcp-r-alert tcp-r-alert-warn" role="status"><ShieldCheck size={17} /><span>当前暂停新测试，已有公开结果仍可查看。</span></div>}

    <div className="tcp-r-layout">
      <aside className="tcp-r-source-panel" id="sources" aria-label="测试来源">
        <div className="tcp-r-panel-heading"><div><span className="tcp-r-step-tag">01 / SOURCE</span><h2>选择测试来源</h2><p>仅显示已公开的自有 VPS</p></div><span className="tcp-r-count">{sources.length} 台</span></div>
        <label className="tcp-r-search"><Search size={16} /><input type="search" aria-label="搜索小鸡" placeholder="搜索名称 / 地区" value={sourceSearch} onChange={e => setSourceSearch(e.target.value)} /><kbd>/</kbd></label>
        <div className="tcp-r-source-list">
          {displayedSources.map(s => {
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
                      : product ? '库存状态暂不可确认' : s.purchase_url ? '套餐信息未验证' : '商品关联更新中';
            const virtualization = virtualizationLabel(mappingVerified ? product.virtualization_type : '');
            return <article className={`tcp-r-source tcp-source ${selected === s.id ? 'is-selected' : ''}`} key={s.id}>
              <button className="tcp-r-source-select" onClick={() => selectSource(s.id)} aria-pressed={selected === s.id}>
                <span className="tcp-r-source-icon"><Server size={17} /></span>
                <span className="tcp-r-source-copy"><strong>{s.name}</strong><small>{s.region || 'VPS 主机'} · {virtualization}</small></span>
                <span className={`tcp-r-online ${s.status === 'ready' ? 'ready' : ''}`} title={sourceStatus[s.status] || '不可用'}><i />{s.status === 'ready' ? '在线' : sourceStatus[s.status] || '不可用'}</span>
                <span className="tcp-r-source-check">{selected === s.id ? <Check size={15} /> : null}</span>
              </button>
              <div className="tcp-r-source-meta"><span>{s.latest_job ? `${scopes[s.latest_job.scope]} · ${jobStatus[s.latest_job.status] || '有记录'}` : '尚无测试记录'}</span><span>{s.cooldown_until > now ? `冷却 ${Math.ceil((s.cooldown_until - now) / 60)} 分钟` : '可发起测试'}</span></div>
              <div className="tcp-r-source-product">{soldOut ? <span className="tcp-r-soldout">已售罄</span> : purchaseUrl ? <a href={purchaseUrl} target="_blank" rel="noopener noreferrer" title={product?.product_name || undefined} aria-label={`查看套餐 / 购买（剩余 ${product?.remaining} 台）`}>剩余 {product?.remaining} 台 · 查看套餐 <ExternalLink size={12} /></a> : <span className={mappingMismatch ? 'tcp-r-product-warn' : ''}>{purchaseNote}</span>}</div>
            </article>;
          })}
          {!displayedSources.length && <div className="tcp-r-empty">{sources.length ? '没有匹配的来源主机' : '管理员尚未公开测试来源'}</div>}
        </div>
        <div className="tcp-r-source-foot"><ShieldCheck size={14} /><span>目标目录来自公开探测节点；不接受任意 IP 或端口。</span></div>
      </aside>

      <div className="tcp-r-main">
        <section className="tcp-r-config" aria-label="测试设置">
          <div className="tcp-r-config-head">
            <div><span className="tcp-r-step-tag">02 / CONFIGURE</span><h2>设置测试范围</h2><p>范围越大，覆盖越全，任务完成时间也越长。</p></div>
            <div className={`tcp-r-selected-source ${source ? 'has-source' : ''}`}><span>当前来源</span><b>{source?.name || '请先在左侧选择小鸡'}</b><small><i />{source ? `${source.region || 'VPS'} · ${sourceStatus[source.status] || '状态未知'}` : '仅测试公开的自有 VPS'}</small></div>
          </div>
          <div className="tcp-r-scope-label"><span>选择本次探测范围</span><small>修改范围不会立即开始测试</small></div>
          <div className="tcp-r-scope-grid" role="group" aria-label="测试范围">
            {([
              { value: 'province', title: '省级运营商', detail: '快速查看全国三网', count: directory?.counts.province_targets ?? directory?.counts.province_nodes ?? 93, time: '较快' },
              { value: 'city', title: '市级节点', detail: '查看城市覆盖情况', count: directory?.counts.city_nodes ?? 223, time: '较慢' },
              { value: 'all', title: '全部节点', detail: '省级 + 市级 + 指定目标', count: directory?.counts.total ?? 317, time: '耗时较长' },
            ] as const).map(item => <button key={item.value} className={`tcp-r-scope ${scope === item.value ? 'is-selected' : ''}`} aria-pressed={scope === item.value} disabled={active(job) || busy} onClick={() => { setScope(item.value); setJob(null); setProvince(''); setCarrier(''); setStatus(''); setTargetSearch(''); }}>
              <span className="tcp-r-scope-radio"><i /></span><span className="tcp-r-scope-copy"><b>{item.title}</b><small>{item.detail}</small></span><span className="tcp-r-scope-count"><b>{item.count}</b><small>{item.time}</small></span>
            </button>)}
          </div>
          {job && job.scope !== scope && <div className="tcp-r-result-scope-note" role="status">当前显示的是{scopes[job.scope]}历史结果；新测试将按“{scopes[scope]}”执行。</div>}
          <div className="tcp-r-run-row">
            <div className="tcp-r-run-hint"><ShieldCheck size={16} /><span>{countdown ? `该来源仍在冷却，约 ${Math.floor(countdown / 60)} 分 ${String(countdown % 60).padStart(2, '0')} 秒` : scope === 'province' ? '省级范围 15 分钟冷却' : '市级与全量范围 30 分钟冷却'}<small>正在测试时会合并到同一任务；完整缓存会优先复用</small></span></div>
            <button className="tcp-r-primary" disabled={!canStart} onClick={start}>{busy || active(job) ? <Loader2 className="tcp-spin" size={17} /> : <Play size={17} />}{active(job) ? '查看进行中的测试' : countdown ? '复用结果 / 检查冷却' : '开始 TCP Ping'}<ArrowRight size={15} /></button>
          </div>
          {job && active(job) && <div className="tcp-r-progress" role="status" aria-live="polite"><div className="tcp-r-progress-track"><i style={{ width: `${progress}%` }} /></div><div><span>{jobStatus[job.status] || job.status} · {job.completed}/{job.nodes.length} 个目标已返回</span><b>{progress}%</b></div></div>}
        </section>

        <section className="tcp-r-results" id="tcp-r-results" aria-label="测试结果">
          <header className="tcp-r-results-head">
            <div><span className="tcp-r-step-tag">03 / RESULTS</span><h2>本次测试概览</h2><p>{source?.name || '尚未选择来源'}{source ? ` · ${source.region || 'VPS'}` : ''} → 中国大陆及台湾 · {scopes[job?.scope || scope]}</p></div>
            <div className="tcp-r-result-actions"><button onClick={shareResults} disabled={!job}><Share2 size={15} />分享链接</button><button onClick={exportCsv} disabled={!nodes.length}><Download size={15} />导出 CSV</button></div>
          </header>
          <div className="tcp-r-kpis" aria-label="本次结果统计">
            <button className={status === '' ? 'is-active' : ''} onClick={() => setQuickStatus('')}><span>已返回目标</span><b>{completed.length}<small> / {nodes.length}</small></b><i>{pending ? `${pending} 个尚未返回` : job ? jobStatus[job.status] || job.status : '等待首次测试'}</i></button>
            <button className={status === 'ok' ? 'is-active is-good' : 'is-good'} onClick={() => setQuickStatus('ok')}><span>至少一次连接成功</span><b>{good.length}<small> / {nodes.length}</small></b><i>有效连接样本</i></button>
            <button className={status === 'failed' ? 'is-active is-warn' : 'is-warn'} onClick={() => setQuickStatus('failed')}><span>无成功连接</span><b>{failed.length}<small> 个目标</small></b><i>拒绝 / 超时 / 其他失败</i></button>
            <button className="is-latency" onClick={() => setResultView('list')}><span>有效目标中位时延</span><b style={{ color: latencyColor(overall) }}>{displayLatency(overall)}</b><i>只统计已成功建连目标</i></button>
          </div>
          {!source && <div className="tcp-r-no-result"><Signal size={19} /><span><b>先选择测试来源，再查看该来源的测量结果。</b><small>当前只显示目标目录，不会把未执行的节点误报成连接失败。</small></span><a href="#sources">选择来源 <ArrowDown size={14} /></a></div>}
          {source && !job && <div className="tcp-r-no-result"><Clock3 size={19} /><span><b>该来源暂无本次范围的测量记录。</b><small>确认范围后点击“开始 TCP Ping”。尚未测量的目标显示为“未返回”，不等于失败。</small></span></div>}

          <div className="tcp-r-view-tabs" role="tablist" aria-label="结果展示方式">
            <button role="tab" aria-selected={resultView === 'map'} className={resultView === 'map' ? 'is-active' : ''} onClick={() => setResultView('map')}><Globe2 size={16} />全国地图</button>
            <button role="tab" aria-selected={resultView === 'compare'} className={resultView === 'compare' ? 'is-active' : ''} onClick={() => setResultView('compare')}><Activity size={16} />省份三网对比</button>
            <button role="tab" aria-selected={resultView === 'list'} className={resultView === 'list' ? 'is-active' : ''} onClick={() => setResultView('list')}><Signal size={16} />节点明细 <small>{rows.length}</small></button>
          </div>

          {resultView === 'map' && <div className="tcp-r-map-layout">
            <article className="tcp-r-map-card">
              <div className="tcp-r-map-heading"><div><h3>{province || '全国'} TCP 连接时延热力图</h3><p>点击省份，同步筛选地图与节点明细</p></div>{province && <button className="tcp-r-reset" onClick={() => setProvince('')}><RotateCw size={14} />全国视图</button>}</div>
              <Suspense fallback={<div className="tcp-map-loading" role="status">正在载入全国节点地图…</div>}><ChinaMap nodes={nodes} province={province} carrier={carrier} status={status} onSelect={p => setProvince(current => current === p ? '' : p)} /></Suspense>
              <LatencyLegend />
              <p className="tcp-r-map-note">颜色代表 TCP 建连中位时延；未返回不会按失败着色。仅测连接建立，不测吞吐量。</p>
            </article>
            <aside className="tcp-r-map-aside">
              <article className="tcp-r-side-card"><div className="tcp-r-side-title"><span><MapPin size={15} />快速定位省份</span><small>{provinceOptions.length} 个地区</small></div><div className="tcp-r-province-chips">{provinceOptions.slice(0, 8).map(p => <button key={p} className={province === p ? 'is-active' : ''} onClick={() => setProvince(current => current === p ? '' : p)}>{p}</button>)}{province && <button className="tcp-r-clear-chip" onClick={() => setProvince('')}>清除 ×</button>}</div></article>
              <article className="tcp-r-side-card"><div className="tcp-r-side-title"><span><Signal size={15} />运营商概览</span><small>{province || '全国'}</small></div><div className="tcp-r-carrier-list">{mainCarriers.map(key => {
                const carrierNodes = nodes.filter(n => n.carrier === key && (!province || n.province === province));
                const summary = connectionSummary(carrierNodes);
                const successful = carrierNodes.filter(n => n.result?.success).length;
                return <button key={key} className={`tcp-r-carrier-row ${carrier === key ? 'is-active' : ''}`} onClick={() => setQuickCarrier(key)}><span className={`tcp-r-carrier-icon ${key}`}>{carriers[key].slice(0, 1)}</span><span><b>{carriers[key]}</b><small>{successful}/{summary.total} 目标至少一次连接成功</small></span><strong style={{ color: latencyColor(summary.value) }}>{displayLatency(summary.value)}</strong><ChevronDown size={14} /></button>;
              })}</div><p className="tcp-r-side-foot">三网分别统计，不混合时延。</p></article>
              <article className="tcp-r-side-card tcp-r-how-card"><div className="tcp-r-side-title"><span><Info size={15} />如何读结果</span></div><p>时延为有效目标的 TCP 建连中位数。连接被拒、超时和未返回分别统计；“未返回”可能是任务尚未完成或 Agent 没有回报。</p><button onClick={() => setResultView('list')}>查看节点明细 <ArrowRight size={14} /></button></article>
            </aside>
          </div>}

          {resultView === 'compare' && <div className="tcp-r-compare-view"><CarrierComparison nodes={nodes} province={province} onSelect={p => setProvince(current => current === p ? '' : p)} onDetail={c => { setCarrier(c); setStatus(''); setResultView('list'); }} /></div>}

          {resultView === 'list' && <div className="tcp-r-list-view">
            <div className="tcp-r-list-toolbar"><div><b>节点结果</b><span>{rows.length} / {nodes.length} 个目标</span></div><div className="tcp-r-filters">
              <label className="tcp-r-search"><Search size={15} /><input aria-label="搜索地区、节点或地址" type="search" placeholder="搜索地区 / 节点 / 地址" value={targetSearch} onChange={e => setTargetSearch(e.target.value)} /></label>
              <label><span className="tcp-r-sr">省份筛选</span><select aria-label="筛选省份" value={province} onChange={e => setProvince(e.target.value)}><option value="">全部省份</option>{provinceOptions.map(p => <option key={p}>{p}</option>)}</select></label>
              <label><span className="tcp-r-sr">运营商筛选</span><select aria-label="筛选运营商" value={carrier} onChange={e => setCarrier(e.target.value)}><option value="">全部运营商</option>{Object.entries(carriers).map(([key, label]) => <option value={key} key={key}>{label}</option>)}</select></label>
              <label><span className="tcp-r-sr">状态筛选</span><select aria-label="筛选连接状态" value={status} onChange={e => setStatus(e.target.value)}><option value="">全部状态</option><option value="ok">有成功连接</option><option value="failed">无成功连接</option><option value="pending">未返回</option></select></label>
              {(province || carrier || status || targetSearch) && <button className="tcp-r-clear-filters" onClick={() => { setProvince(''); setCarrier(''); setStatus(''); setTargetSearch(''); }}>清除筛选</button>}
            </div></div>
            <div className="tcp-r-table-scroll" tabIndex={0} aria-label="完整测试结果，可横向滚动查看所有列"><table><thead><tr><th>目标区域</th><th>运营商 / 端口</th><th>建连中位时延</th><th>成功 / 尝试</th><th>连接状态</th><th>目标地址</th></tr></thead><tbody>{rows.map(n => <tr key={n.id}>
              <td><button className="tcp-r-node-open" onClick={() => setSelectedNode(n)}><b>{n.province}{n.city ? ` · ${n.city}` : ' · 省级'}</b><small>查看连接详情 <ArrowRight size={12} /></small></button></td>
              <td>{carriers[n.carrier] || n.carrier}<small>TCP {n.port}</small></td>
              <td><b className="tcp-r-latency" style={{ color: n.result?.median_ms != null ? latencyColor(n.result.median_ms) : '#94a3b8' }}>{displayLatency(n.result?.median_ms)}</b></td>
              <td>{n.result ? `${n.result.success} / ${n.result.attempts}` : `— / ${job?.samples || '—'}`}</td>
              <td><span className={`tcp-r-node-status ${!n.result ? 'pending' : n.result.success ? 'ok' : 'failed'}`}><i />{!n.result ? '未返回' : n.result.status === 'ok' ? '连接成功' : n.result.success ? '部分成功' : resultLabel(n.result.error)}</span></td>
              <td className="tcp-r-address" title={`${n.host}:${n.port}`}>{n.result?.ip || n.host}<small>:{n.port}</small></td>
            </tr>)}</tbody></table>{!rows.length && <div className="tcp-r-empty">{loading ? '等待目录载入' : '没有符合筛选条件的目标'}</div>}</div>
            <p className="tcp-r-list-note">目标由公开目录提供。结果是来源 VPS 对目标 TCP 端口的连接测试，不代表目标服务完整健康。</p>
          </div>}

          <footer className="tcp-r-job-meta" aria-live="polite"><span>{job ? `测试时间：${utc(job.created_at)} · 每目标 ${job.samples} 次尝试 · ${job.completed}/${job.nodes.length} 已返回` : '尚无测量数据'}</span><span>{job?.message}</span></footer>
        </section>
      </div>
    </div>

    <section className="tcp-r-guide" id="tcp-r-guide"><div><span className="tcp-r-step-tag">MEASUREMENT NOTES</span><h2>怎样理解 TCP Ping 结果</h2></div><div className="tcp-r-guide-grid">
      <article><b><CircleCheck size={16} />连接成功</b><p>至少一次 TCP 建连成功。时延统计只使用有效连接样本。</p></article>
      <article><b><X size={16} />失败</b><p>收到拒绝、超时或网络错误时分别显示原因，不把它们混作同一种故障。</p></article>
      <article><b><Clock3 size={16} />未返回</b><p>Agent 仍在处理或尚未回传结果。未返回不等于连接失败。</p></article>
    </div><p className="tcp-r-directory-note">大陆节点目录由 <a href="https://www.zstaticcdn.com/" target="_blank" rel="noopener noreferrer">Zstatic</a> 提供；台湾为用户指定目标。结果反映测试时刻的单向 TCP 连接情况，不代表 SLA、吞吐量或购买承诺。目录更新：{directory?.updated_at || '—'}</p></section>

    <div className="tcp-r-mobile-run"><div><b>{source?.name || '选择测试来源'}</b><small>{scope === 'province' ? '省级范围' : scope === 'city' ? '市级范围' : '全部节点'} · {active(job) ? `${progress}% 已返回` : countdown ? `冷却 ${Math.ceil(countdown / 60)} 分钟` : '准备就绪'}</small></div><button disabled={!canStart} onClick={start}>{busy || active(job) ? <Loader2 className="tcp-spin" size={17} /> : <Play size={17} />}{active(job) ? '查看进度' : '开始测试'}</button></div>

    {selectedNode && <div className="tcp-r-modal-backdrop" role="presentation" onMouseDown={event => { if (event.target === event.currentTarget) setSelectedNode(null); }}><section ref={nodeModalRef} className="tcp-r-node-modal" role="dialog" aria-modal="true" aria-labelledby="tcp-r-node-title" tabIndex={-1}>
      <header><div><span className="tcp-r-step-tag">TARGET DETAIL</span><h2 id="tcp-r-node-title">{selectedNode.province}{selectedNode.city ? ` · ${selectedNode.city}` : ' · 省级运营商'}</h2></div><button aria-label="关闭节点详情" onClick={() => setSelectedNode(null)}><X size={18} /></button></header>
      <dl><div><dt>运营商</dt><dd>{carriers[selectedNode.carrier] || selectedNode.carrier}</dd></div><div><dt>测试目标</dt><dd>{selectedNode.result?.ip || selectedNode.host}:{selectedNode.port}</dd></div><div><dt>建连时延</dt><dd style={{ color: latencyColor(selectedNode.result?.median_ms ?? null) }}>{displayLatency(selectedNode.result?.median_ms)}</dd></div><div><dt>成功 / 尝试</dt><dd>{selectedNode.result ? `${selectedNode.result.success} / ${selectedNode.result.attempts}` : `— / ${job?.samples || '—'}`}</dd></div><div><dt>连接状态</dt><dd>{!selectedNode.result ? '未返回' : selectedNode.result.status === 'ok' ? '连接成功' : selectedNode.result.success ? '部分成功' : resultLabel(selectedNode.result.error)}</dd></div><div><dt>样本时延</dt><dd>{selectedNode.result?.samples_ms?.map(value => value == null ? '—' : `${value} ms`).join(' · ') || '暂无样本'}</dd></div></dl>
      <p>此详情仅说明来源 VPS 到该目标的 TCP 建连状态，不检查目标应用登录或业务响应。</p>
    </section></div>}
  </main>;
};
