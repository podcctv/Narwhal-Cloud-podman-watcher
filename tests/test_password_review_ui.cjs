/* Run tests.password_review_preview first. Synthetic localhost, never production. */
const {chromium}=require('playwright');
const assert=require('node:assert/strict');
const fs=require('node:fs');
(async()=>{
 const output='C:/Users/Flanker/AppData/Local/Temp/narwhal-password-review-ui';fs.mkdirSync(output,{recursive:true});
 const browser=await chromium.launch({headless:true,executablePath:'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe'});
 try {
  const page=await browser.newPage({viewport:{width:1440,height:1100},reducedMotion:'reduce'}), errors=[], posts=[];
  page.on('pageerror',e=>errors.push(e.message));
  page.on('request',r=>{if(r.method()==='POST'&&/notify-user|disposition/.test(r.url()))posts.push(r)});
  await page.goto('http://127.0.0.1:8793/login');
  await page.getByLabel('用户名',{exact:true}).fill('preview');await page.getByLabel('密码',{exact:true}).fill('local-preview-only');
  await page.getByRole('button',{name:'登录控制台'}).click();await page.waitForURL('http://127.0.0.1:8793/');
  await page.getByText('账号 #1：8 位字符',{exact:true}).waitFor();
  await page.getByText('检测到独立代理管理面板（仅提醒）',{exact:true}).first().waitFor();
  const panelCard=page.locator('div.p-5').filter({has:page.getByText('检测到独立代理管理面板（仅提醒）',{exact:true})});
  assert.equal(await panelCard.getByRole('button',{name:'人工决定停止',exact:true}).count(),0);
  assert.equal(await panelCard.getByRole('button',{name:'定向处置',exact:true}).count(),0);
  const reviewNotice=()=>page.locator('div.p-5').filter({has:page.getByText('SOCKS 密码待人工评估',{exact:true})}).getByRole('button',{name:'通知用户',exact:true}).first();
  assert.equal(await page.getByText(/Dante 使用系统\/PAM 认证/).count(),1);
  assert.equal(await page.getByText('Aa1112!!',{exact:false}).count(),0);
  for(const width of [375,768,1440]){
   await page.setViewportSize({width,height:1100});
   assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true,`overflow at ${width}`);
   await page.locator('section').filter({has:page.getByText('安全告警中心',{exact:true})}).screenshot({path:`${output}/review-${width}.png`});
  }
  await page.getByRole('button',{name:'人工决定停止',exact:true}).first().click();
  await page.getByRole('alertdialog').getByRole('button',{name:'取消',exact:true}).click();assert.equal(posts.length,0);
  await reviewNotice().click();
  let dialog=page.getByRole('alertdialog');await dialog.getByText(/收件范围：用户 synthetic-user-1/).waitFor();
  let box=await dialog.boundingBox();assert.ok(box.y>=0&&box.y+box.height<=1100,'desktop dialog must fit viewport');
  await dialog.screenshot({path:`${output}/notice-desktop.png`});
  await dialog.getByRole('button',{name:'取消',exact:true}).click();assert.equal(posts.length,0);
  await page.setViewportSize({width:375,height:900});
  await reviewNotice().click();dialog=page.getByRole('alertdialog');
  await dialog.getByRole('button',{name:'确认通知用户',exact:true}).waitFor();
  box=await dialog.boundingBox();assert.ok(box.y>=0&&box.y+box.height<=900,'mobile dialog must fit viewport');
  assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true);
  await dialog.screenshot({path:`${output}/notice-mobile.png`});
  await dialog.getByRole('button',{name:'确认通知用户',exact:true}).click();
  await dialog.getByText('通知已登记',{exact:true}).waitFor();assert.equal(posts.filter(r=>/notify-user/.test(r.url())).length,1);
  await dialog.getByRole('button',{name:'完成',exact:true}).click();
  await page.setViewportSize({width:1440,height:1100});
  await page.getByRole('button',{name:'人工决定停止',exact:true}).first().click();
  await page.getByRole('alertdialog').getByRole('button',{name:'确认人工停止',exact:true}).click();
  await page.getByRole('alertdialog').waitFor({state:'hidden'});
  assert.equal(posts.filter(r=>/disposition/.test(r.url())).length,1);
  assert.equal(posts.find(r=>/disposition/.test(r.url())).postDataJSON().decision,'stop_reviewed_socks');
  await page.getByRole('button',{name:'查看全部告警记录',exact:true}).click();
  await page.getByText('安全告警与处置审计历史',{exact:true}).waitFor();
  await page.getByText('账号 #1：8 位字符',{exact:true}).waitFor();
  await page.getByText(/告警持续 6 小时 34 分钟 后确认恢复/).waitFor();
  for(const width of [375,768,1440]){
   await page.setViewportSize({width,height:1100});
   assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true,`history overflow at ${width}`);
   const recoveredCard=page.locator('div.p-4').filter({has:page.getByText('历史连接数告警',{exact:true})});
   await recoveredCard.scrollIntoViewIfNeeded();
   await recoveredCard.screenshot({path:`${output}/recovery-history-${width}.png`});
  }
  assert.equal(await page.getByRole('button',{name:'通知用户',exact:true}).count(),4);
  assert.deepEqual(errors,[]);
  console.log(JSON.stringify({passed:true,widths:[375,768,1440],preview_cancel_no_posts:true,notification_posts:1,manual_stop_posts:1,history:true,screenshots:output}));
 } finally {await browser.close()}
})().catch(e=>{console.error(e.stack);process.exit(1)});
