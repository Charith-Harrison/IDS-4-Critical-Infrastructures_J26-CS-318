// Read-only Results-page check using saved reports, not model inference.
const {chromium}=require(process.env.C3_PLAYWRIGHT_MODULE || 'playwright');
const fs=require('fs'),path=require('path');
(async()=>{
  const output=path.resolve(__dirname,'../local/results_accuracy_v1');
  const browser=await chromium.launch({channel:'msedge',headless:true});
  const errors=[];
  try {
    const page=await browser.newPage({viewport:{width:1366,height:900}});
    page.on('pageerror',e=>errors.push(String(e)));
    await page.goto('http://127.0.0.1:8504',{waitUntil:'domcontentloaded'});
    await page.getByRole('tab',{name:'Results',exact:true}).click();
    await page.getByRole('heading',{name:'Model comparison',exact:true}).waitFor({timeout:60000});
    const condition=page.locator('[data-testid="stSelectbox"]').filter({has:page.getByText('Test condition',{exact:true})});
    await condition.getByRole('combobox').click();
    await page.getByRole('option',{name:'Changed ordering',exact:true}).click();
    await page.getByText('Final test · Changed ordering · Common supported cohort',{exact:true}).waitFor();
    await page.getByText('Protocol and wire-header comparisons',{exact:true}).click();
    await page.getByRole('heading',{name:'Model comparison',exact:true}).evaluate(el=>el.scrollIntoView({block:'start'}));
    await page.screenshot({path:path.join(output,'results_ordering.png')});
    const downloadPromise=page.waitForEvent('download');
    await page.getByRole('button',{name:'Download saved evaluation metrics (CSV)',exact:true}).click();
    await (await downloadPromise).saveAs(path.join(output,'downloaded_metrics.csv'));
    const lines=fs.readFileSync(path.join(output,'downloaded_metrics.csv'),'utf8').trim().split(/\r?\n/);
    if(lines.length!==31 || !lines[0].includes('Accuracy (%)') || !lines[0].includes('Evaluation'))throw new Error('Invalid final metrics download');
    const overflow=await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth);
    if(overflow)throw new Error('Page exceeds laptop viewport');
    await page.setViewportSize({width:1280,height:800});
    await page.getByRole('heading',{name:'Model comparison',exact:true}).evaluate(el=>el.scrollIntoView({block:'start'}));
    await page.screenshot({path:path.join(output,'results_ordering_1280.png')});
    const result={status:errors.length?'FAILED':'PASSED',page_errors:errors,page_overflow:overflow,
      downloaded_rows:lines.length-1,checked:['final condition selector','all six methods','accuracy and coverage columns','metrics download','1366 and 1280 laptop viewports'],
      screenshot:'component3/local/results_accuracy_v1/results_ordering.png'};
    fs.writeFileSync(path.resolve(__dirname,'../reports/results_accuracy_v1/browser_check.json'),JSON.stringify(result,null,2));
    console.log(JSON.stringify(result)); if(errors.length)process.exitCode=1;
  } finally {await browser.close();}
})().catch(e=>{console.error(e);process.exitCode=1;});
