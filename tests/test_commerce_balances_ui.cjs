/* Synthetic localhost only: NARWHAL_PREVIEW_PORT=8793 python -m tests.commerce_preview. */
const {chromium}=require('playwright');const assert=require('node:assert/strict');
(async()=>{
 const browser=await chromium.launch({headless:true,executablePath:process.env.NARWHAL_BROWSER||process.env.CHROMIUM_PATH||undefined});
 try{
  const page=await browser.newPage({viewport:{width:1440,height:1000},reducedMotion:'reduce'}),errors=[];page.on('pageerror',e=>errors.push(e.message));
  await page.goto('http://127.0.0.1:8793/login');await page.getByLabel('用户名',{exact:true}).fill('preview');await page.getByLabel('密码',{exact:true}).fill('local-preview-only');
  await page.getByRole('button',{name:'登录控制台'}).click();await page.waitForURL('http://127.0.0.1:8793/');
  await page.getByRole('navigation',{name:'主导航'}).getByRole('button',{name:'经营分析'}).click();
  await page.getByLabel('配置个人 API Key',{exact:true}).fill('synthetic-key-only');await page.getByRole('button',{name:'保存并同步',exact:true}).click();
  await page.getByText('个人 API Key 已配置，经营数据已同步',{exact:true}).waitFor();
  const balance=page.getByRole('group',{name:'可用余额（不可提现）',exact:true}),escrow=page.getByRole('group',{name:'托管可用余额',exact:true});
  assert.ok((await balance.innerText()).includes('1.23'));assert.ok((await escrow.innerText()).includes('4.44'));
  assert.equal(await page.getByText('可提现余额',{exact:true}).count(),0);
  for(const width of [375,768,1024,1440]){
   await page.setViewportSize({width,height:1000});assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true,`overflow at ${width}`);
  }
  // The client must not derive a guessed amount when a server lacks the field.
  await page.route('**/api/v1/commerce/overview',async route=>{
   const response=await route.fetch(),data=await response.json();delete data.profile.escrow_available_balance;
   await route.fulfill({response,json:data});
  });
  await page.getByRole('navigation',{name:'主导航'}).getByRole('button',{name:'总览看板'}).click();await page.getByRole('navigation',{name:'主导航'}).getByRole('button',{name:'经营分析'}).click();
  await escrow.getByText('未提供',{exact:true}).waitFor();assert.deepEqual(errors,[]);
  console.log(JSON.stringify({balances_ui:'passed',ordinary_not_withdrawable:true,escrow_available:'4.44',missing_not_fabricated:true,widths:[375,768,1024,1440]}));
 }finally{await browser.close()}
})().catch(e=>{console.error(e.stack);process.exit(1)});
