// Real local authentication and API queue. No real node, filesystem cleanup or bot.
const { chromium } = require('playwright');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
(async () => {
  const output = path.resolve(process.env.NARWHAL_UI_OUTPUT || '.codex/tmp/disk-cleanup-ui');
  fs.mkdirSync(output, { recursive: true });
  const browser = await chromium.launch({ headless: true, executablePath: process.env.NARWHAL_BROWSER || process.env.CHROMIUM_PATH || undefined });
  const errors = [];
  try {
    const page = await browser.newPage({ viewport: { width: 1440, height: 1000 } });
    page.on('pageerror', e => errors.push(e.message));
    page.on('response', r => { if (r.status() >= 500) errors.push(r.url()); });
    await page.goto('http://127.0.0.1:8788/');
    await page.getByLabel('用户名', { exact: true }).fill('preview');
    await page.getByLabel('密码', { exact: true }).fill('local-preview-only');
    await page.getByRole('button', { name: '登录控制台' }).click();
    await page.getByText('宿主机磁盘空间不足 · 93.0%', { exact: true }).waitFor();
    await page.screenshot({ path: path.join(output, 'host-disk-pressure.png') });
    await page.getByRole('button', { name: '运维中心', exact: true }).click();
    await page.getByRole('button', { name: '3 存储管理', exact: true }).click();
    const panel = page.getByRole('region', { name: '安全磁盘清理' });
    await panel.getByRole('button', { name: /synthetic-host-0/ }).click();
    assert.equal(await panel.getByLabel('启用自动清理', { exact: true }).isChecked(), false);
    const execute = panel.getByRole('button', { name: '确认清理本次扫描', exact: true });
    await execute.waitFor();assert.equal(await execute.isEnabled(), true);
    for (const width of [320, 375, 768, 1440]) {
      await page.setViewportSize({ width, height: 1000 });
      await panel.screenshot({ path: path.join(output, `cleanup-${width}.png`) });
      assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true, `overflow at ${width}`);
    }
    await execute.click();
    await page.getByRole('alertdialog').waitFor();
    assert.equal(await page.getByRole('button', { name: '取消', exact: true }).evaluate(el => el === document.activeElement), true);
    await page.keyboard.press('Escape');await page.getByRole('alertdialog').waitFor({ state: 'detached' });
    await execute.click();await page.getByRole('button', { name: '确认', exact: true }).click();
    await panel.getByText('任务排队或执行中，不代表已释放空间', { exact: true }).waitFor();
    assert.equal(await execute.isDisabled(), true);
    const live = await (await page.request.get('http://127.0.0.1:8788/api/v1/ops/disk-cleanup')).json();
    assert.equal(live.actions[0].status, 'queued');assert.equal(live.hosts[0].policy.enabled, false);
    const expired = await page.request.post('http://127.0.0.1:8788/api/v1/ops/cleanup-preview-expire', { data: {}, headers: { Origin: 'http://127.0.0.1:8788' } });
    assert.equal(expired.ok(), true);
    await panel.getByRole('button', { name: '刷新状态', exact: true }).click();
    await panel.getByText('节点采样过期', { exact: true }).waitFor();assert.equal(await execute.isDisabled(), true);
    assert.deepEqual(errors, []);
    const reader = await browser.newPage({ viewport: { width: 375, height: 900 }, reducedMotion: 'reduce' });
    await reader.goto('http://127.0.0.1:8788/');
    await reader.getByLabel('用户名', { exact: true }).fill('reader');await reader.getByLabel('密码', { exact: true }).fill('local-preview-only');await reader.getByRole('button', { name: '登录控制台' }).click();
    await reader.getByRole('button', { name: '运维中心', exact: true }).click();await reader.getByRole('button', { name: '3 存储管理', exact: true }).click();
    const readonly = reader.getByRole('region', { name: '安全磁盘清理' });await readonly.getByRole('button', { name: /synthetic-host-1/ }).click();
    assert.equal(await readonly.getByRole('button', { name: '扫描预览（不删除）', exact: true }).isDisabled(), true);
    await readonly.screenshot({ path: path.join(output, 'readonly-375.png') });
    console.log('PASS cleanup UI 320/375/768/1440, disk warning, authentication, confirmation/Escape, actual queued ACK, stale refusal and readonly role');
  } finally { await browser.close(); }
})().catch(e => { console.error(e); process.exit(1); });
