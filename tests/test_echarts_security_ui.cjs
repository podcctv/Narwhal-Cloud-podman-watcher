// Local library regression for GHSA-fgmj-fm8m-jvvx; no external traffic.
const {chromium}=require('playwright');
const assert=require('node:assert/strict');
const fs=require('node:fs');
(async()=>{
 const browser=await chromium.launch({headless:true,executablePath:process.env.NARWHAL_BROWSER||'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe'});
 try{
  const page=await browser.newPage({viewport:{width:800,height:600}}),errors=[];
  page.on('pageerror',error=>errors.push(error.message));
  await page.route('**/*',route=>route.abort());
  await page.setContent('<div id="chart" style="width:700px;height:500px"></div>');
  await page.addScriptTag({content:fs.readFileSync('frontend/node_modules/echarts/dist/echarts.min.js','utf8')});
  const version=await page.evaluate(()=>{
   window.__xss=0;
   echarts.registerMap('security-fixture',{type:'FeatureCollection',features:[{type:'Feature',properties:{name:'test'},geometry:{type:'Polygon',coordinates:[[[0,0],[2,0],[2,2],[0,2],[0,0]]]}}]});
   const chart=echarts.init(document.getElementById('chart'));
   chart.setOption({animation:false,tooltip:{trigger:'item',renderMode:'html'},geo:{map:'security-fixture'},series:[{type:'lines',coordinateSystem:'geo',data:[{name:'<img src=x onerror="window.__xss=1">security-probe',coords:[[0.3,0.3],[1.5,1.5]],value:42}]}]});
   chart.dispatchAction({type:'showTip',seriesIndex:0,dataIndex:0});
   return echarts.version;
  });
  await page.waitForFunction(()=>document.body.textContent.includes('security-probe'));
  await page.waitForTimeout(150);
  assert.equal(await page.evaluate(()=>window.__xss),0);
  assert.equal(await page.locator('img').count(),0);
  assert.match(await page.locator('body').innerText(),/<img src=x/);
  assert.deepEqual(errors,[]);
  console.log(JSON.stringify({echarts:version,lines_tooltip_html_escaped:true,script_execution:false}));
 }finally{await browser.close()}
})().catch(error=>{console.error(error.stack);process.exit(1)});
