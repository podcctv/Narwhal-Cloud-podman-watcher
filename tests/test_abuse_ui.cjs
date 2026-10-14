// Run built frontend with: python -m tests.abuse_preview. Synthetic localhost only.
const { chromium } = require('playwright');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

(async () => {
  const output = path.resolve(process.env.NARWHAL_UI_OUTPUT || '.codex/tmp/abuse-ui');
  fs.mkdirSync(output, { recursive: true });
  const browser = await chromium.launch({ executablePath: process.env.CHROMIUM_PATH, headless: true });
  const errors = [];
  try {
    const page = await browser.newPage({ viewport: { width: 1440, height: 1000 } });
    page.on('pageerror', error => errors.push(error.message));
    page.on('response', response => { if (response.status() >= 500) errors.push(`${response.status()} ${response.url()}`); });
    await page.goto('http://127.0.0.1:8787/');
    await page.getByLabel('用户名', { exact: true }).fill('preview');
    await page.getByLabel('密码', { exact: true }).fill('local-preview-only');
    await page.getByRole('button', { name: '登录控制台' }).click();
    const panel = page.getByRole('region', { name: '违规活动隔离 · 待管理员复核' });
    await panel.getByText('已双向隔离', { exact: true }).waitFor();
    for (const width of [320, 375, 768, 1440]) {
      await page.setViewportSize({ width, height: 1000 });
      await panel.screenshot({ path: path.join(output, `quarantine-${width}.png`) });
      const overflowing = await page.evaluate(() => Array.from(document.querySelectorAll('body *'))
        .filter(el => el.getBoundingClientRect().right > innerWidth+1)
        .slice(0, 15).map(el => ({ tag: el.tagName, className: el.className, right: el.getBoundingClientRect().right })));
      assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true, `overflow ${width}: ${JSON.stringify(overflowing)}`);
    }
    const restore = panel.getByRole('button', { name: '管理员复核后解除隔离', exact: true });
    await restore.click();
    await page.getByRole('alertdialog').waitFor();
    assert.equal(await page.getByRole('button', { name: '取消', exact: true }).evaluate(el => el === document.activeElement), true);
    await page.screenshot({ path: path.join(output, 'release-confirm.png') });
    await page.keyboard.press('Escape');
    await page.getByRole('alertdialog').waitFor({ state: 'detached' });
    await restore.click();
    await page.getByRole('button', { name: '确认复核并恢复网络', exact: true }).click();
    await panel.getByRole('button', { name: '等待解除隔离回执', exact: true }).waitFor();
    assert.equal(await panel.getByRole('button', { name: '等待解除隔离回执', exact: true }).isDisabled(), true);
    // Real authenticated endpoint queued an action; no node is contacted.
    const actual = await (await page.request.get('http://127.0.0.1:8787/api/v1/security/quarantines')).json();
    assert.equal(actual.items[0].release_action_status, 'queued');
    await page.route('**/api/v1/security/quarantines', route => route.fulfill({ json: {
      items: actual.items.map(item => ({ ...item, status: 'release_failed', release_action_status: 'failed' })) } }));
    await panel.getByRole('button', { name: '刷新隔离状态' }).click();
    await panel.getByText('解除隔离未验证成功', { exact: true }).waitFor();
    assert.equal(await restore.isEnabled(), true, 'failed restore must be retryable');
    await page.unroute('**/api/v1/security/quarantines');
    await page.route('**/api/v1/security/quarantines', route => route.fulfill({ json: {
      items: actual.items.map(item => ({ ...item, host_last_seen: 1, updated_at: 1 })) } }));
    await panel.getByRole('button', { name: '刷新隔离状态' }).click();
    await panel.getByText('节点或隔离采样已过期 · 当前状态待确认', { exact: true }).waitFor();
    assert.equal(await panel.getByRole('button', { name: '等待解除隔离回执', exact: true }).isDisabled(), true);
    assert.deepEqual(errors, []);
    console.log(JSON.stringify({ ok: true, viewports: [320, 375, 768, 1440],
      checks: 'real login, quarantine proof, no overflow, confirmation focus/Escape, real queue ACK, failed retry, stale refusal', output }));
  } finally {
    await browser.close();
  }
})().catch(error => { console.error(error); process.exitCode = 1; });
