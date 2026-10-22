/* Synthetic localhost only: python -m tests.tcping_auto_preview. */
const {chromium}=require('playwright');const assert=require('node:assert/strict');const fs=require('node:fs');
(async()=>{
 const browser=await chromium.launch({headless:true,executablePath:'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe'});
 const base='http://127.0.0.1:8791',output='C:/Users/Flanker/AppData/Local/Temp/narwhal-header-ui-v1731';fs.mkdirSync(output,{recursive:true});
 try {
  const page=await browser.newPage({viewport:{width:1440,height:1000},reducedMotion:'reduce'});const errors=[];page.on('pageerror',e=>errors.push(e.message));
  await page.goto(base+'/login');await page.getByLabel('用户名',{exact:true}).fill('preview');await page.getByLabel('密码',{exact:true}).fill('local-preview-only');
  await page.getByRole('button',{name:'登录控制台'}).click();await page.waitForURL(base+'/');
  const header=page.locator('.app-header'),nav=page.getByRole('navigation',{name:'主导航'});await nav.waitFor();
  assert.equal(await nav.getByRole('button').count(),8);assert.equal(await nav.getByRole('link').count(),1);
  for(const width of [320,375,540,720,768,900,960,1024,1152,1440,1920]){
   await page.setViewportSize({width,height:1000});
   assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true,`overflow at ${width}`);
   const rects=await nav.locator('button,a').evaluateAll(items=>items.map(el=>{const r=el.getBoundingClientRect();return {left:r.left,right:r.right,height:r.height}}));
   assert.ok(rects.every(r=>r.left>=0&&r.right<=width+1&&r.height>=44),`clipped or undersized navigation at ${width}`);
   // Eight sections plus the TCP link use three rows in the four-column mobile grid.
   const h=(await header.boundingBox()).height;assert.ok(h<(width<=900?300:240),`excessive header height at ${width}: ${h}`);
   if([375,768,1440,1920].includes(width))await header.screenshot({path:`${output}/header-${width}.png`});
  }
  await page.setViewportSize({width:1440,height:1000});
  for(const name of ['安全告警','用户排查','数据统计','经营分析','运维中心','母机防火墙','系统设置','总览看板']){
   await nav.getByRole('button',{name:new RegExp(name)}).click();assert.equal(await nav.locator('[aria-current="page"]').count(),1);assert.ok((await nav.locator('[aria-current="page"]').innerText()).includes(name));
  }
  await header.getByRole('button',{name:'暂停自动刷新'}).click();await header.getByRole('button',{name:'恢复自动刷新'}).waitFor();
  await header.getByRole('button',{name:'恢复自动刷新'}).click();
  await header.getByRole('button',{name:'打开全局检索'}).click();
  try {await page.getByRole('textbox',{name:'搜索节点、容器或用户邮箱'}).waitFor({timeout:5000});}
  catch(error){console.log(JSON.stringify({url:page.url(),errors,visible_text:(await page.locator('body').innerText()).slice(0,600)}));throw error;}
  await page.keyboard.press('Escape');
  await page.getByRole('textbox',{name:'搜索节点、容器或用户邮箱'}).waitFor({state:'hidden'});
  assert.equal(await header.getByRole('button',{name:'退出登录'}).isEnabled(),true);
  assert.deepEqual(errors,[]);console.log(JSON.stringify({header_ui:'passed',widths:[320,375,540,720,768,900,960,1024,1152,1440,1920],zoom_equivalent_widths:[1152,960,720],all_navigation_and_tools:true}));
 }finally{await browser.close()}
})().catch(e=>{console.error(e.stack);process.exit(1)});
