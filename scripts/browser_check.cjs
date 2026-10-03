'use strict';
// Starts a real loopback server with an isolated database, then exercises the UI.
// Run: npm test | npm run screenshots
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const assert = require('node:assert/strict');
const {spawn} = require('node:child_process');
const {chromium} = require(process.env.SOC_PLAYWRIGHT_MODULE || 'playwright');
const root = path.resolve(__dirname,'..');
const resultDirectory = path.join(root,'test-results');
const capture = process.argv.includes('--screenshots');
const temporary = fs.mkdtempSync(path.join(os.tmpdir(),'soc-browser-'));
const database = path.join(temporary,'soc.sqlite3');
const base = 'http://127.0.0.1:8766';
let server, browser, logs = '', checks = [], browserErrors = [], requestFailures = [];
const pause = ms => new Promise(resolve=>setTimeout(resolve,ms));
const check = (label,condition) => { assert.ok(condition,label); checks.push(label); };

async function start() {
  server = spawn(process.env.SOC_PYTHON || 'python',['-m','uvicorn','app.main:app','--host','127.0.0.1','--port','8766'],{cwd:root,env:{...process.env,SOC_DB_PATH:database},stdio:['ignore','pipe','pipe']});
  server.stdout.on('data',chunk=>logs += chunk.toString());
  server.stderr.on('data',chunk=>logs += chunk.toString());
  for (let attempt=0;attempt<120;attempt++) {
    try { if ((await fetch(`${base}/health`)).ok) return; } catch { /* Start-up polling. */ }
    if (server.exitCode !== null) throw new Error(`Server exited: ${logs}`);
    await pause(250);
  }
  throw new Error(`Server did not become healthy: ${logs}`);
}
async function stop() {
  if (!server || server.exitCode !== null) return;
  const done = new Promise(resolve=>server.once('exit',resolve)); server.kill('SIGTERM'); await done;
}
async function screenshot(page,name) {
  if (!capture) return;
  await page.locator('#toast').evaluate(element=>element.classList.remove('visible'));
  await page.screenshot({path:path.join(root,'docs/screenshots',name),fullPage:true,animations:'disabled'});
}
async function waitForView(page,view) {
  await page.locator(`main[data-ready='${view}']`).waitFor();
}
async function main() {
  fs.mkdirSync(resultDirectory,{recursive:true});
  await start();
  browser = await chromium.launch({headless:true,...(process.env.SOC_CHROMIUM_PATH ? {executablePath:process.env.SOC_CHROMIUM_PATH} : {})});
  const context = await browser.newContext({viewport:{width:1480,height:1080},timezoneId:'Europe/Istanbul',reducedMotion:'reduce'});
  const page = await context.newPage();
  page.on('pageerror',error=>browserErrors.push(error.message));
  page.on('console',message=>{if(message.type()==='error')browserErrors.push(message.text());});
  page.on('requestfailed',request=>{
    // Chromium hands report navigation to the download manager (ERR_ABORTED).
    if (request.url().startsWith(`${base}/api/reports/json?`) && request.failure()?.errorText === 'net::ERR_ABORTED') return;
    requestFailures.push(`${request.url()}: ${request.failure()?.errorText}`);
  });
  await page.goto(base); await waitForView(page,'overview');
  check('Empty workspace is usable',await page.getByText('Your SOC workspace is ready').isVisible());
  await page.getByRole('button',{name:'Load synthetic events',exact:true}).click();
  await page.getByRole('button',{name:'Load 553 synthetic events',exact:true}).click();
  await page.locator('[data-stat="Total events"]').filter({hasText:'553'}).waitFor();
  check('Demo ingestion through the actual UI',await page.locator('[data-stat="Total events"]').textContent() === '553');
  check('Five rendered Chart.js charts',await page.locator('canvas').count() === 5);
  check('Correct critical count',await page.locator('[data-stat="Critical alerts"]').textContent() === '2');
  check('Charts contain real telemetry',await page.evaluate(()=>Chart.getChart('timeline-chart').data.datasets.reduce((sum,set)=>sum+set.data.reduce((a,b)=>a+b,0),0)) === 553);
  await screenshot(page,'dashboard-desktop.png');
  await page.locator('nav a[data-view="alerts"]').click(); await waitForView(page,'alerts');
  await page.locator('#filter-severity').selectOption('critical');
  await page.getByRole('button',{name:'Apply filters'}).click();
  await page.getByText('2 matching alerts').waitFor();
  check('Severity filter narrows the queue',await page.locator('tbody tr').count() === 2);
  await screenshot(page,'alert-queue.png');
  await page.locator('a.detection-link').first().click(); await waitForView(page,'detail');
  check('Investigation exposes full evidence',await page.locator('.evidence-table tbody tr').count() === 6);
  await page.locator('#case-status').selectOption('Investigating');
  const note = 'Synthetic triage: reviewed the five failures and subsequent success. MFA and session ownership need validation; no compromise conclusion yet.';
  await page.locator('#case-note').fill(note);
  await page.getByRole('button',{name:'Save investigation'}).click();
  await page.locator('.activity-list').getByText(note,{exact:true}).waitFor();
  check('Status and note persist in the case journal',await page.locator('#case-status').inputValue() === 'Investigating');
  await screenshot(page,'alert-investigation.png');
  const caseUrl = page.url();
  // A second tab changes the revision. The first tab must retain its draft and show conflict.
  const second = await context.newPage(); await second.goto(caseUrl); await waitForView(second,'detail');
  await second.locator('#case-note').fill('Second-tab update for concurrency verification.');
  await second.getByRole('button',{name:'Save investigation'}).click();
  await second.locator('.activity-list').getByText('Second-tab update for concurrency verification.',{exact:true}).waitFor();
  await page.locator('#case-note').fill('First-tab draft must survive a stale revision.');
  await page.getByRole('button',{name:'Save investigation'}).click();
  await page.locator('#case-error').getByText(/changed since you opened/).waitFor();
  check('Stale updates are rejected without losing the analyst draft',await page.locator('#case-note').inputValue() === 'First-tab draft must survive a stale revision.');
  // This deliberately stale PATCH returns the expected HTTP 409.
  browserErrors = browserErrors.filter(message=>!message.includes('status of 409'));
  await second.close();
  await page.getByRole('button',{name:'Reload case'}).click();
  await page.locator('.activity-list').getByText('Second-tab update for concurrency verification.',{exact:true}).waitFor();
  await page.locator('nav a[data-view="events"]').click(); await waitForView(page,'events');
  await page.locator('#event-type').selectOption('authentication_failure');
  await page.getByRole('button',{name:'Search events'}).click();
  await page.getByText('94 normalized events').waitFor();
  check('Event outcome filter reflects the real dataset',await page.locator('tbody tr').count() === 25);
  const firstId = await page.locator('tbody tr').first().textContent();
  await page.getByRole('button',{name:'Next',exact:true}).click();
  await page.getByText('26–50 of 94').waitFor();
  check('Event pagination changes the records',await page.locator('tbody tr').first().textContent() !== firstId);
  await page.getByRole('button',{name:'Reset',exact:true}).click(); await page.getByText('553 normalized events').waitFor();
  await screenshot(page,'event-explorer.png');
  await page.locator('nav a[data-view="rules"]').click(); await waitForView(page,'rules');
  check('Seven explainable rule cards',await page.locator('.rule-card').count() === 7);
  await page.getByRole('button',{name:'Replay detections'}).click();
  await page.getByText('Replay complete · 18 matches · 0 new alerts').waitFor();
  check('Replay is idempotent',true);
  await screenshot(page,'detection-rules.png');
  await page.locator('nav a[data-view="reports"]').click(); await waitForView(page,'reports');
  const downloadPromise = page.waitForEvent('download');
  await page.getByRole('link',{name:'Download JSON'}).click();
  const download = await downloadPromise;
  const downloadedPath = await download.path();
  const exported = JSON.parse(fs.readFileSync(downloadedPath,'utf8'));
  check('UI exports every alert in the carried-over filter',exported.alert_count === 2 && exported.alerts.every(alert=>alert.severity === 'critical'));
  check('Report retains the analyst note',JSON.stringify(exported).includes(note));
  await screenshot(page,'reports.png');
  // Invalid import must show a recoverable error; a real CSV reimport is deduplicated.
  await page.locator('#sidebar-import').click();
  await page.locator('#log-file').setInputFiles({name:'invalid.json',mimeType:'application/json',buffer:Buffer.from('[{}]')});
  await page.getByRole('button',{name:'Validate & import'}).click();
  await page.locator('#import-error').getByText(/Event 1/).waitFor();
  check('Invalid upload is shown in the dialog',await page.locator('#import-dialog').isVisible());
  // Expected 422 produces a browser console error; capture it separately from unexpected errors.
  browserErrors = browserErrors.filter(message=>!message.includes('422'));
  await page.locator('#log-file').setInputFiles(path.join(root,'sample_data/security_events.csv'));
  await page.getByRole('button',{name:'Validate & import'}).click();
  await page.getByText('0 events imported · 553 duplicates skipped · 0 new alerts').waitFor();
  check('CSV import deduplicates JSON telemetry',true);
  await page.locator('nav a[data-view="overview"]').click(); await waitForView(page,'overview');
  check('No remote assets are requested',await page.evaluate(()=>performance.getEntriesByType('resource').every(resource=>new URL(resource.name).origin === location.origin)));
  await page.setViewportSize({width:390,height:844});
  await screenshot(page,'dashboard-mobile.png');
  check('Mobile dashboard fits the viewport',await page.evaluate(()=>document.documentElement.scrollWidth <= innerWidth));
  await page.getByRole('button',{name:'Toggle navigation'}).click();
  check('Mobile navigation opens',await page.locator('#sidebar').evaluate(element=>element.classList.contains('open')));
  await page.locator('nav a[data-view="alerts"]').click(); await waitForView(page,'alerts');
  check('Mobile alert filters fit the viewport',await page.evaluate(()=>document.documentElement.scrollWidth <= innerWidth));
  await page.locator('a.detection-link').first().click(); await waitForView(page,'detail');
  await screenshot(page,'investigation-mobile.png');
  check('Mobile investigation fits the viewport',await page.evaluate(()=>document.documentElement.scrollWidth <= innerWidth));
  await stop(); await start();
  await page.reload(); await waitForView(page,'detail');
  check('Case notes survive a real server restart',await page.locator('.activity-list').getByText(note,{exact:true}).isVisible());
  check('No unexpected browser errors',browserErrors.length === 0);
  check('No failed browser requests',requestFailures.length === 0);
  const result = {status:'passed',checked_at:new Date().toISOString(),checks:checks.length,details:checks,browser:browser.version(),screenshots:capture,unexpected_errors:browserErrors,failed_requests:requestFailures};
  fs.writeFileSync(path.join(resultDirectory,'browser-check.json'),JSON.stringify(result,null,2)+'\n');
  console.log(JSON.stringify(result,null,2));
}
main().catch(async error=>{
  fs.mkdirSync(resultDirectory,{recursive:true});
  fs.writeFileSync(path.join(resultDirectory,'failure.json'),JSON.stringify({error:error.message,checks,browserErrors,requestFailures,logs},null,2));
  console.error(error); process.exitCode=1;
}).finally(async()=>{if(browser)await browser.close();await stop();fs.rmSync(temporary,{recursive:true,force:true});});
