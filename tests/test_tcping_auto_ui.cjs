/* Run against python -m tests.tcping_auto_preview only; never production. */
const {chromium}=require('playwright');const path=require('node:path');
const assert=require('node:assert/strict');
const fs=require('node:fs');
(async()=>{
 const browser=await chromium.launch({headless:true,executablePath:process.env.NARWHAL_BROWSER||process.env.CHROMIUM_PATH||undefined});
 const base='http://127.0.0.1:8791';const output=path.resolve(process.env.NARWHAL_UI_OUTPUT||'.codex/tmp/tcping-auto-ui');fs.mkdirSync(output,{recursive:true});
 try {
  const page=await browser.newPage({viewport:{width:1440,height:1000},reducedMotion:'reduce'});
  const errors=[];page.on('pageerror',e=>errors.push(e.message));
  await page.addInitScript(()=>{window.__mapTexts=[];const original=CanvasRenderingContext2D.prototype.fillText;CanvasRenderingContext2D.prototype.fillText=function(text,...args){window.__mapTexts.push(String(text));return original.call(this,text,...args)}});
  await page.goto(base+'/tcping');
  const catalog=await (await page.request.get(base+'/api/public/tcping/sources')).json();
  const historical=catalog.items.find(i=>i.id==='existing').latest_job;
  const historyResponse=page.waitForResponse(r=>r.url()===base+'/api/public/tcping/jobs/'+historical.id);
  await page.getByRole('button',{name:/Hytron2.0/}).click();await historyResponse;
  await page.getByRole('status').filter({hasText:'当前展示全部节点'}).waitFor();
  assert.equal(await page.locator('.tcp-controls select').inputValue(),'province');
  assert.equal(await page.evaluate(()=>window.__mapTexts.some(t=>t==='台湾'||t==='台湾省')),false);
  await page.goto(base+'/tcping?job='+historical.id);
  await page.getByRole('status').filter({hasText:'当前展示全部节点'}).waitFor();
  assert.equal(await page.locator('.tcp-controls select').inputValue(),'province');
  await page.goto(base+'/login');
  await page.getByLabel('用户名',{exact:true}).fill('preview');
  await page.getByLabel('密码',{exact:true}).fill('local-preview-only');
  await page.getByRole('button',{name:'登录控制台'}).click();
  await page.waitForURL(base+'/');
  await page.goto(base+'/tcping/manage');
  const toggle=page.getByRole('checkbox',{name:'自动加入新主机',exact:true});
  await page.waitForFunction(el=>!el.disabled,await toggle.elementHandle());
  assert.equal(await toggle.isChecked(),false);
  await toggle.focus();
  const saved=page.waitForResponse(r=>r.url()===base+'/api/v1/tcping/settings'&&r.request().method()==='POST');
  await page.keyboard.press('Space');assert.equal((await saved).status(),200);
  await page.getByRole('status').filter({hasText:'自动同步已开启'}).waitFor();
  const publicData=await (await page.request.get(base+'/api/public/tcping/sources')).json();
  assert.equal(publicData.items.length,2);assert.equal(publicData.items.find(i=>i.name==='GB CN2 合成伦敦节点').status,'ready');assert.equal(publicData.items.some(i=>i.id==='hidden'),false);
  for(const width of [375,768,1440]){
   await page.setViewportSize({width,height:1000});
   await page.getByRole('region',{name:'新主机自动同步'}).screenshot({path:`${output}/auto-${width}.png`});
   assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true);
  }
  await page.reload();await page.waitForFunction(el=>!el.disabled,await toggle.elementHandle());assert.equal(await toggle.isChecked(),true);
  await toggle.click();await page.getByRole('status').filter({hasText:'自动同步已关闭'}).waitFor();assert.equal(await toggle.isChecked(),false);
  const after=await (await page.request.get(base+'/api/public/tcping/sources')).json();assert.equal(after.items.length,2);assert.equal(after.enabled,true);
  await page.goto(base+'/tcping');await page.getByRole('button',{name:/Hytron2.0/}).click();
  await page.locator('.tcp-controls select').selectOption('all');
  await page.getByRole('button',{name:/GB CN2 合成伦敦节点/}).click();
  assert.equal(await page.locator('.tcp-controls select').inputValue(),'province');
  assert.deepEqual(errors,[]);console.log(JSON.stringify({loopback_ui:'passed',keyboard_save:true,backfill:true,hidden_source_preserved:true,persistent_toggle:true,historical_scope_does_not_override_default:true,taiwan_canvas_label_hidden:true,widths:[375,768,1440],probe_jobs_started:0}));
 }finally{await browser.close()}
})().catch(e=>{console.error(e.message);process.exit(1)});
