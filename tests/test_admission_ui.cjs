/* Synthetic localhost only: never sends notices or enforcement actions. */
const { chromium } = require('playwright');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
(async () => {
  const output = path.resolve(process.env.NARWHAL_UI_OUTPUT || '.codex/tmp/admission-ui');
  fs.mkdirSync(output, { recursive: true });
  const browser = await chromium.launch({ headless: true, executablePath: process.env.NARWHAL_BROWSER || process.env.CHROMIUM_PATH || undefined });
  try {
    const page = await browser.newPage({ viewport: { width: 1440, height: 1100 }, reducedMotion: 'reduce' });
    const errors = [], mutations = [];
    page.on('pageerror', error => errors.push(error.message));
    page.on('request', request => { if (request.method() === 'POST' && !request.url().includes('/auth/')) mutations.push(request.url()); });
    await page.route('**/api/v1/latest*', async route => {
      const response = await route.fetch(); const data = await response.json();
      for (const item of data.items || []) if (item.security?.admission) {
        item.security.admission.observed_at = Math.floor(Date.now() / 1000);
        item.security.admission.source_limit_enforced = false;
        for (const value of Object.values(item.security.admission.blocked || {})) value.last_seen = Math.floor(Date.now() / 1000);
      }
      await route.fulfill({ response, json: data });
    });
    await page.goto('http://127.0.0.1:8795/login');
    await page.getByLabel('用户名', { exact: true }).fill('preview');
    await page.getByLabel('密码', { exact: true }).fill('local-preview-only');
    await page.getByRole('button', { name: '登录控制台' }).click();
    // The dashboard now keeps healthy host cards collapsed until expanded;
    // exercise the explicit master toggle before inspecting container detail.
    await page.getByTitle('展开所有母鸡').click();
    await page.getByText('入站来源观测 5 个样本', { exact: true }).waitFor();
    await page.getByText('synthetic-instance-1', { exact: true }).last().click();
    await page.getByText('已建立连接来源样本', { exact: true }).waitFor();
    await page.getByText(/TCP 当前 499 条/).waitFor();
    await page.getByText('2001:db8:ffff:ffff:ffff:ffff:ffff:ffff', { exact: false }).last().waitFor();
    const panel = page.getByRole('region', { name: '容器网络准入保护' }).last();
    for (const width of [375, 768, 1440]) {
      await page.setViewportSize({ width, height: 1100 });
      assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true, `page overflow ${width}`);
      const bounds = await panel.boundingBox();
      assert.ok(bounds.x >= 0 && bounds.x + bounds.width <= width, `panel outside viewport ${width}`);
      assert.equal(await panel.evaluate(e => e.scrollWidth <= e.clientWidth), true, `panel overflow ${width}`);
      await panel.screenshot({ path: `${output}/admission-${width}.png` });
    }
    assert.deepEqual(errors, []);
    assert.deepEqual(mutations, []);
    console.log(JSON.stringify({ passed: true, widths: [375, 768, 1440], source_count_is_observation_only: true, blocked_ipv6_wrap: true, tcp_cap_and_extensions: true, no_mutations: true, screenshots: output }));
  } finally { await browser.close(); }
})().catch(error => { console.error(error.stack); process.exit(1); });
