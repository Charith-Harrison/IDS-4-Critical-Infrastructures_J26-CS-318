// Optional visual QA. Requires Playwright and an installed Edge browser.
const {chromium} = require(process.env.C3_PLAYWRIGHT_MODULE || 'playwright');
const fs = require('fs');
const path = require('path');
(async () => {
  const output = path.resolve(__dirname, '../local/frontend_redesign');
  fs.mkdirSync(output, {recursive:true});
  const browser = await chromium.launch({channel:'msedge', headless:true});
  const errors = [], views = [], overflow = [];
  try {
    const page = await browser.newPage({viewport:{width:1366,height:768}});
    page.on('pageerror', e => errors.push(String(e)));
    const response = await page.goto('http://127.0.0.1:8503', {waitUntil:'domcontentloaded'});
    await page.getByText('The current Modbus message is identical in both cases.',{exact:true}).waitFor({timeout:60000});
    async function capture(name) {
      await page.screenshot({path:path.join(output,name+'.png')});
      const dimensions=await page.evaluate(() => {
        const main=document.querySelector('[data-testid="stMain"]');
        return {width:innerWidth,body:document.documentElement.scrollWidth,main:main.scrollWidth,mainClient:main.clientWidth};
      });
      if(dimensions.body>dimensions.width || dimensions.main>dimensions.mainClient+2) overflow.push({name,...dimensions});
      views.push(name);
    }
    await capture('command-hidden-1366');
    await page.getByText('Show earlier context',{exact:true}).click();
    await page.locator('.verdict.injection').waitFor();
    await capture('command-context-1366');
    await page.getByText('Response injection',{exact:true}).first().click();
    await page.getByText('Setpoint = 118',{exact:true}).waitFor();
    await capture('response-context-1366');
    await page.getByRole('tab',{name:'How it works',exact:true}).click();
    if(await page.locator('.pipeline-step').count()!==6) throw new Error('Missing pipeline stages');
    await page.getByText('What if earlier context is missing?',{exact:true}).click();
    await page.getByText('No trustworthy recent anchor → abstain.',{exact:true}).waitFor();
    await capture('how-it-works-1366');
    await page.getByRole('tab',{name:'Results',exact:true}).click();
    await page.getByRole('heading',{name:'Model comparison',exact:true}).waitFor();
    await capture('results-1366');
    await page.getByRole('tab',{name:'Evidence',exact:true}).click();
    await page.getByRole('heading',{name:'Verify this example',exact:true}).waitFor();
    await page.getByText('Show raw packet evidence',{exact:true}).click();
    await capture('evidence-1366');
    await page.getByRole('tab',{name:'Dataset & scope',exact:true}).click();
    await page.getByText('250,066',{exact:true}).waitFor();
    await capture('dataset-1366');
    await page.setViewportSize({width:1280,height:800});
    await page.getByRole('tab',{name:'Demo',exact:true}).click();
    await capture('response-context-1280');
    await page.getByText('Command injection',{exact:true}).first().click();
    await page.getByText('Mode 0 · ON forbidden',{exact:true}).waitFor();
    await capture('command-context-1280');
    const visible=await page.locator('[data-testid="stMain"]').innerText();
    for(const phrase of ['supervisor acceptance','what to say in the viva','PP1 talking points','suggested presentation']) {
      if(visible.toLowerCase().includes(phrase.toLowerCase())) throw new Error('Meta commentary remains: '+phrase);
    }
    const result={status:errors.length || overflow.length ? 'FAILED':'PASSED',http_status:response.status(),
      page_errors:errors,horizontal_overflow:overflow,browser:'installed Edge via Playwright',views,
      screenshot_directory:'component3/local/frontend_redesign',
      scope:'Presentation check at 1366×768 and 1280×800. Saved predictions/results only.'};
    fs.writeFileSync(path.resolve(__dirname,'../reports/frontend_redesign_browser.json'),JSON.stringify(result,null,2));
    console.log(JSON.stringify(result));
    if(result.status!=='PASSED') process.exitCode=1;
  } finally { await browser.close(); }
})().catch(e => { console.error(e); process.exitCode=1; });
