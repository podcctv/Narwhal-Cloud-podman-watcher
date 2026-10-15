/* Synthetic localhost only: python -m tests.tcping_stock_preview. */
const {chromium}=require('playwright');const assert=require('node:assert/strict');
(async()=>{
 const browser=await chromium.launch({headless:true,executablePath:'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe'});
 try{
  const page=await browser.newPage({viewport:{width:1440,height:1100},reducedMotion:'reduce'}),errors=[];page.on('pageerror',e=>errors.push(e.message));
  await page.request.get('http://127.0.0.1:8794/api/public/tcping/sources');
  await page.goto('http://127.0.0.1:8794/tcping');
  const card=name=>page.locator('article.tcp-source').filter({has:page.locator('strong').getByText(name,{exact:true})});
  const buy=card('自动关联新增节点').getByRole('link',{name:'查看套餐 / 购买（剩余 9 台）'});await buy.waitFor();
  const href=await buy.getAttribute('href');assert.equal(new URL(href).host,'dash.fuckip.me');assert.ok(new URL(href).searchParams.get('machine_id'));assert.ok(new URL(href).searchParams.get('plan_id'));
  await card('手动关联售罄节点').getByText('已售罄',{exact:true}).waitFor();assert.equal(await card('手动关联售罄节点').getByRole('link').count(),0);
  assert.equal(await card('冲突关联节点').getByRole('link').count(),0);assert.equal(await card('冲突关联节点').getByText('已售罄',{exact:true}).count(),0);
  await card('名称不符节点').getByText('商品与来源不匹配，已隐藏购买链接',{exact:true}).waitFor();
  assert.equal(await page.getByText('暂无购买链接',{exact:true}).count(),0);
  for(const width of [375,768,1024,1440]){await page.setViewportSize({width,height:1100});assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true);}
  await page.getByLabel('搜索小鸡',{exact:true}).fill('自动关联');assert.equal(await page.locator('article.tcp-source').count(),1);await page.getByLabel('搜索小鸡',{exact:true}).fill('');
  assert.deepEqual(errors,[]);console.log(JSON.stringify({stock_ui:'passed',auto_link_and_quantity:true,sold_out_no_link:true,conflict_not_sold_out:true,wrong_product_blocked:true,widths:[375,768,1024,1440],probe_jobs_started:0}));
 }finally{await browser.close()}
})().catch(e=>{console.error(e.stack);process.exit(1)});
