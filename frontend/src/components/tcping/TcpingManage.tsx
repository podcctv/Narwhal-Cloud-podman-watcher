import React, { useCallback, useEffect, useState } from 'react';
import { ArrowLeft, ArrowUpRight, Loader2, Plus, Save } from 'lucide-react';
import { request } from '../../api/client';
import { Source, sourceStatus } from './types';
import { GfwProbeManage } from './GfwProbeManage';
import './tcping.css';

interface PrivateSource extends Source { host_id: string; node_id: string; enabled: boolean }
interface Management { enabled: boolean; auto_publish_new_hosts: boolean; sources: PrivateSource[]; candidates: { host_id: string; node_id: string; agent_version: string }[] }
interface Form { id: string; host_id: string; name: string; region: string; purchase_url: string; enabled: boolean }
const empty: Form = { id: '', host_id: '', name: '', region: '', purchase_url: '', enabled: false };
export const TcpingManage: React.FC = () => {
  const [data, setData] = useState<Management>(), [form, setForm] = useState<Form>(empty);
  const [busy, setBusy] = useState(false), [message, setMessage] = useState(''), [error, setError] = useState('');
  const load = useCallback(async () => setData(await request<Management>('/api/v1/tcping/manage')), []);
  useEffect(() => { document.title = '公开测速配置 · Narwhal'; load().catch(e => setError(e.message)); }, [load]);
  const perform = async (path: string, payload: unknown, success: string) => {
    setBusy(true); setError(''); setMessage('');
    try {
      const result = await request<{ id?: string }>(path, { method: 'POST', body: JSON.stringify(payload) });
      if (result.id && path.endsWith('/sources')) setForm(current => ({ ...current, id: result.id! }));
      await load(); setMessage(success);
    }
    catch (e) { setError((e as Error).message); } finally { setBusy(false); }
  };
  const edit = (s: PrivateSource) => { setForm({ id: s.id, host_id: s.host_id, name: s.name, region: s.region, purchase_url: s.purchase_url, enabled: s.enabled }); setMessage(''); };
  return <main className="tcp-lab"><div className="tcp-manage"><header className="tcp-top"><a href="/" className="tcp-brand"><ArrowLeft size={18} />监控后台</a><a href="/tcping" target="_blank" rel="noopener noreferrer">查看公开页面 <ArrowUpRight size={15} style={{ display: 'inline' }} /></a></header><h1>公开测速配置</h1><p>公开页面展示已发布的 VPS 名称、地区、测试结果和商品链接。内部节点身份、监控数据和经营数据不会出现在公开页面。来源绑定稳定节点身份，不能通过改名绕过冷却。</p>
    {error && <div className="tcp-message tcp-error" role="alert">{error}</div>}{message && <div className="tcp-message" role="status">{message}</div>}
    <div className="tcp-console"><div className="tcp-selected"><strong>新测试：{data?.enabled ? '已开启' : '已暂停'}</strong><small>暂停会取消进行中的任务；已有结果仍可查看。省级冷却 15 分钟，全量/市级 30 分钟；全站最多 2 个并发、每小时 20 个新任务。</small></div><button className="tcp-primary" disabled={busy || !data} onClick={() => perform('/api/v1/tcping/settings', { enabled: !data?.enabled }, '公开测试开关已更新')}>{data?.enabled ? '暂停新测试' : '开启新测试'}</button></div>
    <GfwProbeManage />
    <section className="tcp-auto-source" aria-label="新主机自动同步" aria-busy={busy}>
      <label htmlFor="tcp-auto-publish"><input id="tcp-auto-publish" type="checkbox" checked={!!data?.auto_publish_new_hosts} disabled={busy || !data} aria-describedby="tcp-auto-publish-help" onChange={e => perform('/api/v1/tcping/settings', { auto_publish_new_hosts: e.target.checked }, e.target.checked ? '自动同步已开启，遗漏主机已补齐' : '自动同步已关闭，现有来源保持不变')} />自动加入新主机</label>
      {busy && <span role="status"><Loader2 className="tcp-spin" size={16} />正在保存…</span>}
      <p id="tcp-auto-publish-help">开启后，已注册及今后新增的主机会自动公开名称并加入 TCP PING；只有在线且支持测速的主机可以执行测试。手动撤回的来源不会重新公开。关闭仅停止新增，不撤回已有来源。</p>
    </section>
    <div className="tcp-admin-grid"><section><div className="tcp-panel-title"><h2>已关联来源 · {data?.sources.length || 0}</h2><button className="tcp-text" onClick={() => setForm(empty)}><Plus size={14} style={{ display: 'inline' }} /> 新增</button></div><div className="tcp-admin-list">{data?.sources.map(s => <button key={s.id} onClick={() => edit(s)} aria-pressed={form.id === s.id}><span>{s.name}<small style={{ display: 'block', marginTop: 4 }}>{s.region || '未标注地区'} · {sourceStatus[s.status] || s.status}</small></span><small>{s.enabled ? '公开' : '未公开'}</small></button>)}{data && !data.sources.length && <p className="tcp-empty">尚未关联 VPS，请在右侧新增。</p>}</div></section>
      <form className="tcp-admin-form" onSubmit={e => { e.preventDefault(); perform('/api/v1/tcping/sources', form, '来源与购买链接已保存'); }}><h2>{form.id ? '编辑公开来源' : '新增公开来源'}</h2><label>来源 VPS<select required disabled={!!form.id || busy} value={form.host_id} onChange={e => setForm({ ...form, host_id: e.target.value, name: form.name || e.target.value })}><option value="">选择已注册主机</option>{data?.candidates.map(c => <option key={c.node_id} value={c.host_id}>{c.host_id} · v{c.agent_version}</option>)}</select></label><label>公开名称<input required maxLength={120} value={form.name} onChange={e => setForm({ ...form, name: e.target.value })} /></label><label>地区 / 线路说明<input maxLength={80} value={form.region} onChange={e => setForm({ ...form, region: e.target.value })} /></label><label>直接购买 / 套餐链接<input type="url" placeholder="https://dash.fuckip.me/deploy?machine_id=…" value={form.purchase_url} onChange={e => setForm({ ...form, purchase_url: e.target.value })} /><small>仅 HTTPS，不含 Token、API Key 或登录凭据。留空时按已验证的实例 UUID 映射自动关联商品；无法唯一确认时不显示购买按钮。</small></label><label className="tcp-checkbox"><input type="checkbox" checked={form.enabled} onChange={e => setForm({ ...form, enabled: e.target.checked })} />在公开页面展示该小鸡</label><button className="tcp-primary" disabled={busy || !data}>{busy ? <Loader2 className="tcp-spin" size={16} /> : <Save size={16} />}保存来源</button><small style={{ color: '#a8b7cb', lineHeight: 1.8 }}>撤回公开会取消该来源当前任务。未升级 Agent 的来源可以展示，但不能开始测试。首次上线建议先开放一个来源完成实测。</small></form></div>
    </div></main>;
};
