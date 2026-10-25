// Local integration check. Requires Playwright and installed Edge.
const {chromium}=require(process.env.C3_PLAYWRIGHT_MODULE || 'playwright');
const fs=require('fs'), path=require('path');
(async()=>{
  const output=path.resolve(__dirname,'../local/pcap_demo'); fs.mkdirSync(output,{recursive:true});
  const browser=await chromium.launch({channel:'msedge',headless:true});
  const errors=[];
  try {
    const page=await browser.newPage({viewport:{width:1366,height:768}});
    page.on('pageerror',e=>errors.push(String(e)));
    await page.goto('http://127.0.0.1:8503',{waitUntil:'domcontentloaded'});
    const run=page.getByRole('button',{name:'Run detection',exact:true});
    await run.waitFor({timeout:60000}); await run.click();
    await page.getByText('Detection complete · fresh inference on an existing development capture',{exact:true}).waitFor({timeout:60000});
    await page.getByText('27',{exact:true}).waitFor();
    await page.getByText('Analyze traffic',{exact:true}).evaluate(el=>el.scrollIntoView({block:'start'}));
    await page.screenshot({path:path.join(output,'pcap_detection.png')});
    const downloadPromise=page.waitForEvent('download');
    await page.getByRole('button',{name:'Download replay decisions (CSV)',exact:true}).click();
    const download=await downloadPromise; await download.saveAs(path.join(output,'decisions.csv'));
    const csv=fs.readFileSync(path.join(output,'decisions.csv'),'utf8').trim().split(/\r?\n/);
    if(csv.length!==2273 || csv[0].split(',').includes('label')) throw new Error('Unexpected replay export');
    await page.getByRole('tab',{name:'Results',exact:true}).click();
    await page.getByText('Per-class metrics and confusion matrix',{exact:true}).click();
    await page.getByText('Confusion matrix: rows are true classes; columns are predictions. “—” means undefined, not zero.',{exact:true}).waitFor();
    await page.getByText('Per-class metrics and confusion matrix',{exact:true}).evaluate(el=>el.scrollIntoView({block:'start'}));
    await page.screenshot({path:path.join(output,'evaluation_metrics.png')});
    const result={status:errors.length?'FAILED':'PASSED',page_errors:errors,
      run:'MX025',messages:2272,predicted_alerts:27,exported_rows:csv.length-1,
      checked:['PCAP model inference button','fresh confidence','CSV export','per-class metrics','confusion matrix'],
      scope:'Development replay only; original final metrics read, never regenerated.'};
    fs.writeFileSync(path.resolve(__dirname,'../reports/pcap_frontend_check.json'),JSON.stringify(result,null,2));
    console.log(JSON.stringify(result)); if(errors.length) process.exitCode=1;
  } finally {await browser.close();}
})().catch(e=>{console.error(e);process.exitCode=1;});
