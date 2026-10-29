/* Synthetic API fixtures only: no Agent or network probes. Serve server/static on port 8795. */
const {chromium}=require('playwright');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
(async()=>{
 const browser=await chromium.launch({headless:true,executablePath:process.env.NARWHAL_BROWSER||process.env.CHROMIUM_PATH||undefined});
 const output=process.env.NARWHAL_UI_OUTPUT||require('node:path').resolve('.codex/tmp/tcping-carriers-ui');fs.mkdirSync(output,{recursive:true});
 try{
  const page=await browser.newPage({viewport:{width:1440,height:1000},reducedMotion:'reduce'}), errors=[],posts=[];
  page.on('pageerror',e=>errors.push(e.stack || e.message));
  const nodes=[];
  const add=(province,carrier,value,success=2,attempts=2,error='')=>nodes.push({id:String(nodes.length),kind:'province',province,city:'',carrier,host:'fixture.invalid',port:443,result:value===undefined?null:{median_ms:value,min_ms:value,max_ms:value,samples_ms:[value,value],success,attempts,error,status:success===attempts?'ok':success?'partial':'failed',ip:'192.0.2.1'}});
  add('河北','telecom',1170.1,1,2,'timeout');add('河北','unicom',70.4);add('河北','mobile',57.5);
  add('广东','telecom',null,0,0,'dns_error');add('广东','mobile',undefined);
  add('北京','telecom',32);add('北京','unicom',80);add('北京','mobile',null,0,2,'timeout');
  add('台湾','custom',17);
  const id='00000000-0000-4000-8000-000000000001';
  const job={id,source_id:'fixture',scope:'province',generation:'fixture',samples:2,status:'completed',created_at:1792050000,nodes,completed:8};
  const directory={generation:'fixture',counts:{province_groups:3,province_nodes:8,province_targets:9,city_nodes:0,total:9,extra_nodes:1},nodes};
  await page.route('**/api/public/tcping/**',async route=>{
   const req=route.request(), endpoint=new URL(req.url()).pathname.split('/api/public/tcping/')[1];
   if(req.method()!=='GET'){posts.push(req.url());return route.abort();}
   const data=endpoint==='directory'?directory:endpoint==='sources'?{enabled:true,items:[{id:'fixture',name:'三网对比合成测试',status:'ready',cooldown_until:0,latest_job:{id,status:'completed',scope:'province'}}]}:job;
   await route.fulfill({json:data});
  });
  await page.route('**/tcping?*',route=>route.fulfill({contentType:'text/html',body:fs.readFileSync(path.resolve('server/static/index.html'),'utf8')}));
  await page.goto('http://127.0.0.1:8795/tcping?job='+id);
  await page.getByRole('heading',{name:'三网连接分布'}).waitFor();
  await page.locator('.tcp-carrier-maps canvas').nth(2).waitFor({state:'attached'});
  assert.equal(await page.locator('.tcp-carrier-maps canvas').count(),3);
  const hebei=page.locator('.tcp-compare-scroll tbody tr').filter({has:page.getByRole('button',{name:'河北',exact:true})});
  await assert.doesNotReject(()=>hebei.getByText('1170.1',{exact:false}).waitFor());
  assert.match(await hebei.innerText(),/70.4/);assert.match(await hebei.innerText(),/57.5/);assert.match(await hebei.innerText(),/部分成功/);
  assert.match(await page.locator('.tcp-compare-scroll').innerText(),/DNS 失败/);assert.match(await page.locator('.tcp-compare-scroll').innerText(),/未返回/);assert.match(await page.locator('.tcp-compare-scroll').innerText(),/无目标/);
  await page.getByLabel('三网对照排序').selectOption('latency');assert.match(await page.locator('.tcp-compare-scroll tbody tr').first().innerText(),/河北/);
  await page.getByRole('button',{name:'河北',exact:true}).focus();await page.keyboard.press('Enter');
  assert.equal(await page.getByLabel('筛选省份').inputValue(),'河北');assert.equal(await page.locator('.tcp-carrier-maps [aria-label*="河北省级区域聚焦图"]').count(),3);
  await page.getByRole('button',{name:'全国视图',exact:true}).first().click();
  await page.locator('.tcp-comparison').screenshot({path:output+'/desktop.png'});
  await page.getByRole('button',{name:'单网明细',exact:true}).click();assert.equal(await page.getByLabel('筛选运营商').inputValue(),'telecom');
  await page.getByLabel('筛选运营商').selectOption('unicom');assert.equal(await page.locator('.tcp-workspace .tcp-map').isVisible(),true);
  await page.getByRole('button',{name:'三网对比',exact:true}).click();await page.locator('.tcp-carrier-maps canvas').nth(2).waitFor({state:'attached'});assert.equal(await page.locator('.tcp-carrier-maps canvas').count(),3);
  for(const width of [375,768,1024,1440]){
   await page.setViewportSize({width,height:1000});await page.waitForTimeout(150);
   assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true,`overflow at ${width}`);
   assert.equal(await page.locator('.tcp-carrier-maps canvas').count(),width<=850?1:3);
   if(width<=850){await page.getByRole('group',{name:'手机地图运营商'}).getByRole('button',{name:'移动',exact:true}).click();assert.match(await page.locator('.tcp-carrier-heading').innerText(),/移动/);}
   await page.locator('.tcp-comparison').screenshot({path:`${output}/compare-${width}.png`});
  }
  await page.setViewportSize({width:812,height:375});assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true);
  assert.deepEqual(errors,[]);assert.deepEqual(posts,[]);
  console.log(JSON.stringify({carrier_maps:true,independent_medians:true,partial_dns_pending_missing:true,keyboard_province_focus:true,sort:true,single_network_mode:true,responsive:[375,768,1024,1440],landscape:true,probe_jobs_started:0}));
 }finally{await browser.close();}
})().catch(e=>{console.error(e);process.exit(1)});
