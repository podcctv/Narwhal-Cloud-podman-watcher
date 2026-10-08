// Run after building the frontend and starting: python -m tests.login_preview.
// Uses fixture credentials only; never pointed at a public deployment.
const { chromium } = require('playwright');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

(async () => {
  const output = path.resolve(process.env.NARWHAL_UI_OUTPUT || '.codex/tmp/login-ui');
  fs.mkdirSync(output, { recursive: true });
  const browser = await chromium.launch({ executablePath: process.env.CHROMIUM_PATH, headless: true });
  try {
    const context = await browser.newContext({ viewport: { width: 1440, height: 980 } });
    const page = await context.newPage();
    const errors = [];
    page.on('pageerror', error => errors.push(error.message));
    page.on('response', response => { if (response.status() >= 500) errors.push(`${response.status()} ${response.url()}`); });
    await page.goto('http://127.0.0.1:8786/');
    await page.getByRole('heading', { name: '登录监控控制台' }).waitFor();
    assert.match(page.url(), /\/login\?next=/);
    assert.equal(await page.locator('#login-username').evaluate(el => el === document.activeElement), true);
    await page.screenshot({ path: path.join(output, 'desktop.png'), fullPage: true });
    for (const width of [320, 375, 768, 1024]) {
      await page.setViewportSize({ width, height: 900 });
      assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true, `overflow at ${width}`);
      const buttonHeight = await page.getByRole('button', { name: '登录控制台' }).evaluate(el => el.getBoundingClientRect().height);
      assert.ok(buttonHeight >= 44);
      await page.screenshot({ path: path.join(output, `login-${width}.png`), fullPage: true });
    }
    await page.setViewportSize({ width: 1440, height: 980 });
    await page.getByLabel('用户名', { exact: true }).fill('preview');
    await page.getByLabel('密码', { exact: true }).fill('wrong');
    await page.getByRole('button', { name: '显示密码', exact: true }).click();
    assert.equal(await page.locator('#login-password').getAttribute('type'), 'text');
    await page.getByRole('button', { name: '隐藏密码', exact: true }).click();
    await page.getByRole('button', { name: '登录控制台' }).click();
    await page.getByRole('alert').filter({ hasText: '用户名或密码不正确' }).waitFor();
    await page.getByLabel('密码', { exact: true }).fill('local-preview-only');
    await page.getByLabel('密码', { exact: true }).press('Enter');
    await page.getByRole('button', { name: '退出登录', exact: true }).waitFor();
    assert.equal(await page.evaluate(() => localStorage.length + sessionStorage.length), 0);
    assert.equal(await page.evaluate(() => document.cookie.includes('narwhal_session')), false);
    assert.equal((await context.cookies()).find(c => c.name === 'narwhal_session').httpOnly, true);
    await page.reload();
    await page.getByRole('button', { name: '退出登录', exact: true }).waitFor();
    await page.setViewportSize({ width: 375, height: 900 });
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true, 'dashboard mobile overflow');
    await page.getByRole('button', { name: '退出登录', exact: true }).click();
    await page.getByRole('heading', { name: '登录监控控制台' }).waitFor();
    await page.goto('http://127.0.0.1:8786/');
    await page.getByRole('heading', { name: '登录监控控制台' }).waitFor();
    await page.route('**/api/v1/auth/login', route => route.abort());
    await page.getByLabel('用户名', { exact: true }).fill('preview');
    await page.getByLabel('密码', { exact: true }).fill('local-preview-only');
    await page.getByRole('button', { name: '登录控制台' }).click();
    await page.getByRole('alert').filter({ hasText: '连接未成功' }).waitFor();
    await page.unroute('**/api/v1/auth/login');
    await page.getByRole('button', { name: '登录控制台' }).click();
    await page.getByRole('button', { name: '退出登录', exact: true }).waitFor();
    await context.clearCookies();
    await page.getByRole('button', { name: '退出登录', exact: true }).click();
    await page.getByRole('heading', { name: '登录监控控制台' }).waitFor();
    assert.deepEqual(errors, []);
    console.log(JSON.stringify({ ok: true, viewports: [320, 375, 768, 1024, 1440], checks: 'redirect, keyboard, password toggle, errors, login, reload, logout, expiry, network failure, no browser storage', output }));
    await context.close();
  } finally {
    await browser.close();
  }
})().catch(error => { console.error(error); process.exitCode = 1; });
