// Run inside the isolated VM, with Latch running; Playwright starts its Firefox process automatically.
const base='http://127.0.0.1:8787';
const config=await(await fetch(base+'/api/config')).json();
if(!config.browserAvailable)throw new Error('Firefox is unavailable. Run Run-Latch.bat to install the Playwright Firefox runtime.');
const response=await fetch(base+'/api/scans',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({urls:['https://example.com/'],depth:'standard',timeoutSeconds:60,concurrency:1,externalLookupConsent:false,aiConsent:false})});
if(!response.ok)throw new Error(await response.text());
let job=(await response.json()).scan;
for(let i=0;i<90&&!['complete','cancelled'].includes(job.status);i++){await new Promise(r=>setTimeout(r,1000));job=(await(await fetch(base+'/api/scans/'+job.id)).json()).scan;}
const item=job.items[0];
if(item.browser?.status!=='complete')throw new Error('Firefox visit failed: '+(item.browser?.error||item.error||item.status));
if(!item.screenshots?.length)throw new Error('Visit completed but no valid PNG was returned. Check the Playwright Firefox install and report the error.');
const image=await fetch(base+'/'+item.screenshots[0]);const bytes=Buffer.from(await image.arrayBuffer());
if(!image.ok||!bytes.subarray(0,8).equals(Buffer.from([137,80,78,71,13,10,26,10])))throw new Error('Screenshot evidence route did not return a PNG.');
console.log(`PASS: real Firefox visit and PNG (${bytes.length} bytes).\nReport: ${item.id}\nScreenshot: ${base}/${item.screenshots[0]}\nOpen the UI and select this URL report. Verdict may remain Unknown without reputation providers.\nStatic analysis: ${item.codeAnalysis?.status}. AI not exercised by this check.`);
