// Upload integration test against localhost; fixtures remain local/ignored.
const {chromium}=require(process.env.C3_PLAYWRIGHT_MODULE || 'playwright');
const fs=require('fs'),path=require('path');
(async()=>{
  const fixtures=path.resolve(__dirname,'../local/csv_demo');
  const browser=await chromium.launch({channel:'msedge',headless:true}); const errors=[];
  try {
    // Use isolated sessions instead of relying on version-specific uploader delete buttons.
    async function upload(name) {
      const page=await browser.newPage({viewport:{width:1366,height:768}});
      page.on('pageerror',e=>errors.push(String(e)));
      await page.goto('http://127.0.0.1:8503',{waitUntil:'domcontentloaded'});
      await page.getByText('Analyze traffic',{exact:true}).waitFor({timeout:60000});
      await page.getByText('CSV',{exact:true}).first().click();
      await page.locator('input[type=file]').setInputFiles(path.join(fixtures,name));
      return page;
    }
    let page=await upload('incompatible.csv');
    const schemaError=page.getByText(/This CSV does not contain the fields required to reconstruct/);
    await schemaError.waitFor();
    await page.close();
    page=await upload('observations.csv');
    await page.getByText('CSV schema valid.',{exact:true}).waitFor();
    await page.getByText('These observations use the declared single-writer and trusted-anchor testbed policy.',{exact:true}).click();
    await page.getByRole('button',{name:'Run detection on CSV',exact:true}).click();
    await page.getByRole('heading',{name:'Detection results',exact:true}).waitFor({timeout:60000});
    await page.getByText('VALIDATION RUN',{exact:true}).first().waitFor();
    await page.getByRole('heading',{name:'Detection results',exact:true}).evaluate(el=>el.scrollIntoView({block:'start'}));
    await page.screenshot({path:path.join(fixtures,'unlabelled_predictions.png')});
    await page.close();
    page=await upload('labelled_observations.csv');
    await page.getByText('CSV schema valid.',{exact:true}).waitFor();
    await page.getByText('These observations use the declared single-writer and trusted-anchor testbed policy.',{exact:true}).click();
    await page.getByRole('button',{name:'Run detection on CSV',exact:true}).click();
    await page.getByText('Evaluate predictions',{exact:true}).waitFor({timeout:60000});
    await page.getByText('Evaluate predictions',{exact:true}).click();
    await page.getByRole('button',{name:'Calculate uploaded-label metrics',exact:true}).click();
    await page.getByText('Ground-truth labels were used only to score predictions, not to generate them.',{exact:true}).waitFor();
    await page.getByText('Evaluate predictions',{exact:true}).evaluate(el=>el.scrollIntoView({block:'start'}));
    await page.screenshot({path:path.join(fixtures,'evaluation_status.png')});
    const downloadPromise=page.waitForEvent('download');
    await page.getByRole('button',{name:'Download prediction report',exact:true}).click();
    await (await downloadPromise).saveAs(path.join(fixtures,'prediction_report.csv'));
    const records=fs.readFileSync(path.join(fixtures,'prediction_report.csv'),'utf8').trim().split(/\r?\n/);
    if(records.length!==2273) throw new Error('CSV predictions lost rows');
    if(!records[0].includes('ground_truth') || !records[0].includes('context_available')) throw new Error('Incomplete prediction report');
    const result={status:errors.length?'FAILED':'PASSED',page_errors:errors,
      checked:['incompatible schema rejected','unlabelled CSV predicted','validation badge','labelled CSV scored after prediction','prediction report downloaded'],
      report_rows:records.length-1,screenshots:'component3/local/csv_demo'};
    fs.writeFileSync(path.resolve(__dirname,'../reports/csv_frontend_check.json'),JSON.stringify(result,null,2));
    console.log(JSON.stringify(result)); if(errors.length) process.exitCode=1;
  } finally {await browser.close();}
})().catch(e=>{console.error(e);process.exitCode=1;});
