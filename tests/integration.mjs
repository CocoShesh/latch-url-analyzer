import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {spawn} from 'node:child_process';
import {analyzeSource,synthesize} from '../server/intelligence.mjs';
const temp=await fs.mkdtemp(path.join(os.tmpdir(),'latch-test-'));

const child=spawn(process.execPath,['server/index.mjs'],{cwd:new URL('..',import.meta.url),env:{...process.env,PORT:'18787',EGRESS_PROXY_PORT:'19788',LATCH_BROWSER_MOCK:'1',LATCH_DATA_DIR:temp,OPENAI_API_KEY:'',VIRUSTOTAL_API_KEY:'',GOOGLE_SAFE_BROWSING_API_KEY:'',URLHAUS_AUTH_KEY:''},stdio:['ignore','pipe','pipe']});let logs='';child.stderr.on('data',x=>logs+=x);
const base='http://127.0.0.1:18787';
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
try{
 let ready=false;for(let i=0;i<50;i++){try{if((await fetch(base+'/api/config')).ok){ready=true;break}}catch{}await sleep(100)}assert.ok(ready,logs);
 async function scan(url){const response=await fetch(base+'/api/scans',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({urls:[url],depth:'quick',timeoutSeconds:10})});assert.equal(response.status,202);let job=(await response.json()).scan;for(let i=0;i<60&&job.status!=='complete';i++){await sleep(100);job=(await(await fetch(base+'/api/scans/'+job.id)).json()).scan}assert.equal(job.status,'complete');return job.items[0]}
 const a=await scan('https://1.1.1.1/');assert.equal(a.browser.status,'complete');assert.equal(a.screenshots.length,1);const image=await fetch(base+'/'+a.screenshots[0]);assert.equal(image.status,200);assert.equal(image.headers.get('content-type'),'image/png');assert.ok(a.domainIntelligence);assert.equal(a.providerResults[0].status,'not_queried');assert.equal(a.browser.engine,'Firefox (Playwright)');assert.ok(a.redirects.some(x=>x.status===200));
 const b=await scan('https://1.1.1.1/login');assert.equal(b.screenshots.length,1);assert.equal(b.browser.status,'complete');
 const blocked=await scan('http://127.0.0.1/');assert.equal(blocked.status,'failed');assert.match(blocked.error,/private|reserved|non-public/);
 const badOrigin=await fetch(base+'/api/scans',{method:'POST',headers:{origin:'https://evil.example','content-type':'application/json'},body:JSON.stringify({urls:['https://1.1.1.1/']})});assert.equal(badOrigin.status,400);
 const source=analyzeSource('line one\neval(atob(data));\nfetch("/collect")','https://example.com/app.js');assert.equal(source.indicators.find(x=>x.id==='dynamic-eval').line,2);assert.equal(source.sha256.length,64);assert.ok(source.indicators.some(x=>x.id==='outbound-request'));
 const originalFetch=globalThis.fetch;let aiRequest;globalThis.fetch=async(_url,opts)=>{aiRequest=JSON.parse(opts.body);return {ok:true,json:async()=>({status:'completed',output:[{content:[{type:'output_text',text:JSON.stringify(Object.fromEntries(['executiveSummary','analystRationale','domainIntelligence','codeAnalysis','recommendedActions','uncertainties'].map(k=>[k,'Fixture evidence summary'])))}]}]})}};
 const ai=await synthesize(a,{key:'test',model:'fixture'});globalThis.fetch=originalFetch;assert.equal(ai.status,'complete');assert.equal(aiRequest.store,false);assert.equal(aiRequest.text.format.strict,true);assert.equal(ai.screenshotIncluded,false);
 console.log('PASS: API startup, queue, Firefox context evidence, PNG capture and serving, navigation response status, private-target blocking, origin guard, source indicators, structured AI contract. Mock Firefox/OpenAI only; no live engine or paid API used.');
}finally{const exited=new Promise(resolve=>child.once('exit',resolve));if(child.exitCode===null)child.kill('SIGTERM');await Promise.race([exited,sleep(2000)]);await fs.rm(temp,{recursive:true,force:true})}
