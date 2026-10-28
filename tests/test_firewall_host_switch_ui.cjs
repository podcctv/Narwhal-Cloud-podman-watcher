/* Component-level race regression; synthetic loopback API only, no Agent calls. */
const { chromium } = require('playwright');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const http = require('node:http');
const path = require('node:path');
const frontend = path.resolve('frontend');
const esbuild = require(require.resolve('esbuild', { paths: [frontend] }));
const deferred = () => { let resolve; const promise = new Promise(done => { resolve = done; }); return { promise, resolve }; };
const abuse = { speedtest: false, mining: false, bt: false, interfaces: [], runtimes: [] };
const rule = port => ({ key: `rule-${port}`, priority: 100, direction: 'in', protocol: 'tcp', action: 'block', enabled: true, port_start: port, ip_type: 'any' });
const policy = host => ({
  host_id: host, agent_ready: true, revision: 1, source_fleet_revision: 0,
  policy: { rules: [rule(host === 'host-a' ? 1111 : 2222)], abuse },
  runtime_status: { control_api: 'ready', stale: false },
  interface_inventory: { status: 'ready', stale: false, interfaces: [] },
  live_readback: { status: 'ready', stale: false, sync_status: 'in_sync', capabilities_known: true, supported_protocols: [], snapshot: null },
  latest_action: null, policy_history: [], updated_by: 'fixture', updated_at_utc8: '',
});
const fleet = { revision: 0, policy: { rules: [], abuse }, hosts: [], counts: { total: 2, online: 2 }, updated_by: '', updated_at_utc8: '' };

(async () => {
  const output = path.resolve(process.env.NARWHAL_UI_OUTPUT || '.codex/tmp/firewall-host-switch-ui');
  fs.mkdirSync(output, { recursive: true });
  const bundle = await esbuild.build({
    absWorkingDir: frontend, bundle: true, write: false, format: 'iife', jsx: 'automatic',
    stdin: { resolveDir: frontend, loader: 'tsx', contents: `
      import React from 'react';
      import {createRoot} from 'react-dom/client';
      import {FirewallView} from './src/components/firewall/FirewallView';
      const hosts=['host-a','host-b'].map(host_id=>({host_id,node_id:host_id,stale:false}));
      const toast=(type,message)=>{document.getElementById('toast').textContent=message};
      createRoot(document.getElementById('root')).render(<FirewallView containers={[]} telemetry={hosts} onToast={toast}/>);
    ` },
  });
  const cssName = fs.readdirSync('server/static/assets').find(name => /^index-.*\.css$/.test(name));
  const css = cssName ? fs.readFileSync(path.join('server/static/assets', cssName)) : '';
  const server = http.createServer((req, res) => {
    if (req.url === '/fixture.js') { res.setHeader('Content-Type', 'text/javascript'); return res.end(bundle.outputFiles[0].contents); }
    if (req.url === '/fixture.css') { res.setHeader('Content-Type', 'text/css'); return res.end(css); }
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.end('<!doctype html><meta charset="utf-8"><link rel="stylesheet" href="/fixture.css"><div id="toast" role="status"></div><div id="root"></div><script src="/fixture.js"></script>');
  });
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(8796, '127.0.0.1', resolve); });
  const browser = await chromium.launch({ headless: true, executablePath: process.env.NARWHAL_BROWSER || process.env.CHROMIUM_PATH || undefined });
  const errors = [], mutations = [];
  const base = 'http://127.0.0.1:8796';
  async function fixture({ holdA = false, holdB = false, holdSave = false } = {}) {
    const page = await browser.newPage({ viewport: { width: 1440, height: 1000 }, reducedMotion: 'reduce' });
    page.on('pageerror', error => errors.push(error.message));
    const aRequested = deferred(), bRequested = deferred(), saveRequested = deferred();
    const a = deferred(), b = deferred(), save = deferred();
    if (!holdA) a.resolve(); if (!holdB) b.resolve(); if (!holdSave) save.resolve();
    await page.route('**/*', async route => {
      const request = route.request(), url = new URL(request.url());
      if (url.origin !== base) return route.abort();
      if (!url.pathname.startsWith('/api/')) return route.continue();
      if (url.pathname === '/api/v1/firewall/fleet-policy' && request.method() === 'GET') return route.fulfill({ json: fleet });
      const host = url.pathname.match(/^\/api\/v1\/hosts\/(host-[ab])\/firewall-policy$/)?.[1];
      if (host && request.method() === 'GET') {
        (host === 'host-a' ? aRequested : bRequested).resolve();
        await (host === 'host-a' ? a : b).promise;
        return route.fulfill({ json: policy(host) });
      }
      if (host && request.method() === 'POST') {
        mutations.push({ host, body: request.postDataJSON() }); saveRequested.resolve();
        await save.promise;
        return route.fulfill({ json: { ok: true, revision: 2, action_id: 7 } });
      }
      throw new Error(`Unexpected fixture request: ${request.method()} ${url.pathname}`);
    });
    await page.goto(base);
    await aRequested.promise;
    return { page, a, b, save, bRequested, saveRequested };
  }
  try {
    const { page, a, b, save, bRequested, saveRequested } = await fixture({ holdA: true, holdB: true, holdSave: true });
    const picker = page.getByRole('region', { name: '选择防火墙节点' });
    const hostButton = host => picker.getByRole('button').filter({ hasText: host });
    const saveButton = page.getByRole('button', { name: '保存并应用到这台母鸡', exact: true });
    await hostButton('host-b').click(); await bRequested.promise;
    assert.equal(await page.getByLabel('优先级', { exact: true }).isEnabled(), false);
    assert.equal(await saveButton.isEnabled(), false);
    const aResponse = page.waitForResponse(response => response.url().includes('/host-a/firewall-policy'));
    a.resolve(); await (await aResponse).finished();
    await page.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))));
    // A's completed read must not unlock B or inject A's rules while B is pending.
    assert.equal(await page.getByLabel('优先级', { exact: true }).isEnabled(), false);
    assert.equal(await page.getByRole('cell', { name: '1111', exact: true }).count(), 0);
    b.resolve(); await page.getByRole('cell', { name: '2222', exact: true }).waitFor();
    assert.equal(await page.getByLabel('优先级', { exact: true }).isEnabled(), true);
    await page.getByLabel('起始端口（0 表示任意）').fill('3333');
    await page.getByRole('button', { name: '加入期望规则', exact: true }).click();
    await hostButton('host-a').click();
    const switchDialog = page.getByRole('alertdialog', { name: '切换母鸡？' });
    await switchDialog.waitFor(); await switchDialog.getByRole('button', { name: '取消', exact: true }).click();
    assert.equal(await hostButton('host-b').getAttribute('aria-pressed'), 'true');
    await page.getByRole('cell', { name: '3333', exact: true }).waitFor();
    await hostButton('host-a').click();
    await switchDialog.getByRole('button', { name: '放弃草稿并切换母鸡', exact: true }).click();
    await page.getByRole('cell', { name: '1111', exact: true }).waitFor();
    assert.equal(await page.getByRole('cell', { name: '3333', exact: true }).count(), 0);
    assert.equal(await page.getByRole('cell', { name: '2222', exact: true }).count(), 0);
    await page.getByLabel('起始端口（0 表示任意）').fill('4444');
    await page.getByRole('button', { name: '加入期望规则', exact: true }).click(); await saveButton.click();
    await page.getByRole('alertdialog').getByRole('button', { name: '确认并排队', exact: true }).click(); await saveRequested.promise;
    assert.equal(await hostButton('host-b').isEnabled(), false);
    assert.equal(await page.getByRole('tab', { name: /全体母鸡/ }).isEnabled(), false);
    save.resolve(); await page.getByRole('alertdialog').waitFor({ state: 'hidden' });
    assert.equal(mutations.length, 1); assert.equal(mutations[0].host, 'host-a');
    assert.deepEqual(mutations[0].body.rules.map(rule => rule.port_start), [1111, 4444]);
    for (const width of [375, 1440]) {
      await page.setViewportSize({ width, height: 1000 });
      assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
      await page.screenshot({ path: `${output}/firewall-${width}.png`, fullPage: true });
    }
    await page.close();

    const scopeRace = await fixture({ holdA: true });
    await scopeRace.page.getByRole('tab', { name: /全体母鸡/ }).click();
    const lateRead = scopeRace.page.waitForResponse(response => response.url().includes('/host-a/firewall-policy'));
    scopeRace.a.resolve(); await (await lateRead).finished();
    await scopeRace.page.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))));
    assert.equal(await scopeRace.page.getByRole('cell', { name: '1111', exact: true }).count(), 0);
    assert.equal(await scopeRace.page.getByRole('tab', { name: /全体母鸡/ }).getAttribute('aria-selected'), 'true');
    assert.deepEqual(errors, []);
    console.log(JSON.stringify({ delayed_host_response_rejected: true, host_load_edit_gate: true, dirty_switch_cancel_and_confirm: true, mutation_selection_lock: true, late_host_response_in_fleet_rejected: true, responsive: [375, 1440], synthetic_mutations: mutations.length }));
  } finally {
    await browser.close();
    await new Promise(resolve => server.close(resolve));
  }
})().catch(error => { console.error(error.stack); process.exit(1); });
