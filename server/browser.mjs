import { firefox } from 'playwright';
import fs from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';
const EGRESS_PROXY_PORT=Number(process.env.EGRESS_PROXY_PORT||9788);
let browserPromise;
let browserError=null;
const pngFixture=Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+jvXkAAAAASUVORK5CYII=','base64');
async function launchBrowser(){
  if(process.env.LATCH_BROWSER_MOCK==='1') return {
    newContext:async()=>({
      route:async()=>{},close:async()=>{},
      newPage:async()=>{const pageListeners={};const page={
        on:(name,fn)=>{if(name==='response')pageListeners.response=fn;},setDefaultNavigationTimeout:()=>{},
        goto:async url=>{pageListeners.response?.({url:()=>url,status:()=>200,request:()=>({isNavigationRequest:()=>true,frame:()=>page})});return {status:()=>200,url:()=>url};},
        mainFrame:()=>page,waitForTimeout:async()=>{},url:()=> 'https://1.1.1.1/',title:async()=> 'Fixture Firefox page',
        evaluate:async()=>({text:'Fixture Firefox page',forms:[{fields:[{tag:'input',type:'password',label:'password',name:'password'}],action:'https://1.1.1.1/',method:'post'}],links:[],images:[]}),
        screenshot:async()=>pngFixture
      };return page;}
    }),close:async()=>{}
  };
  return firefox.launch({headless:true,proxy:{server:`http://127.0.0.1:${EGRESS_PROXY_PORT}`}});
}
async function getBrowser(){
  if(!browserPromise) browserPromise=launchBrowser().catch(error=>{browserError=error;browserPromise=null;throw error});
  return browserPromise;
}
export async function firefoxHealth(){
  try{await getBrowser();browserError=null;return {available:true,engine:process.env.LATCH_BROWSER_MOCK==='1'?'Firefox (test fixture)':'Firefox (Playwright)'};}
  catch(error){return {available:false,engine:null,error:String(browserError?.message||error.message).slice(0,200)};}
}
function publicishHost(host){const h=host.toLowerCase().replace(/^\[|\]$/g,'');return !(h==='localhost'||h.endsWith('.localhost')||h.endsWith('.local')||h==='metadata.google.internal');}
export async function collectBrowserEvidence(item,scanId,timeoutSeconds,{evidenceDir,validateTarget}){
 const health=await firefoxHealth();if(!health.available)return {status:'unavailable',error:`Firefox could not start: ${health.error}. Run the launcher to install Playwright Firefox.`,redirects:[],screenshots:[],engine:'Firefox (Playwright)'};
 const screenshotPaths=[],redirects=[],resourceHosts=new Set(),linkedHosts=new Set();let responseStatus=null,finalUrl=item.original,title=null,visibleText='',forms=0,formFields=[],formActions=[],requestFailures=[];let context;
 const started=Date.now(),deadline=started+timeoutSeconds*1000,remaining=()=>Math.max(1,deadline-Date.now());
 const directory=path.join(evidenceDir,scanId,item.id);await fs.mkdir(directory,{recursive:true,mode:0o700});
 try{
   await validateTarget(item.original);
   const browser=await getBrowser();
   context=await browser.newContext({acceptDownloads:false,serviceWorkers:'block'});
   await context.route('**/*',async route=>{
     const raw=route.request().url();
     if(!/^https?:/i.test(raw)) return /^(?:data:|blob:|about:blank$)/i.test(raw)?route.continue():route.abort('blockedbyclient');
     try{const checked=await validateTarget(raw);if(!publicishHost(checked.host))throw new Error('Local destination blocked');return route.continue();}
     catch{return route.abort('blockedbyclient');}
   });
   const page=await context.newPage();page.setDefaultNavigationTimeout(remaining());
   page.on('requestfailed',request=>{if(requestFailures.length<30)requestFailures.push({url:request.url(),error:(request.failure()?.errorText||'request failed').slice(0,100)});});
   page.on('request',request=>{try{const u=new URL(request.url());if(/^https?:$/.test(u.protocol))resourceHosts.add(u.hostname)}catch{}});
   page.on('response',response=>{const request=response.request();if(request.isNavigationRequest()&&request.frame()===page.mainFrame()){const entry={url:response.url(),status:response.status(),observedAt:new Date().toISOString()};redirects.push(entry);responseStatus=response.status();}});
   let navigationResponse=null;
   try{navigationResponse=await page.goto(item.original,{waitUntil:'domcontentloaded',timeout:remaining()});}catch(error){if(!page.url()||page.url()==='about:blank')throw error;}
   if(navigationResponse)responseStatus=navigationResponse.status();
   await page.waitForTimeout(Math.min(800,remaining()));finalUrl=page.url();title=await page.title();
   const observed=await page.evaluate(()=>({text:(document.body?.innerText||'').slice(0,5000),forms:[...document.forms].slice(0,20).map(form=>({action:form.action,method:form.method,fields:[...form.elements].slice(0,50).map(field=>({tag:field.tagName.toLowerCase(),type:field.type||field.tagName.toLowerCase(),label:field.labels?.[0]?.innerText||field.getAttribute('aria-label')||field.name||field.placeholder||'',name:field.name||''}))})),links:[...document.links].slice(0,500).map(link=>link.href),images:[...document.images].slice(0,80).map(image=>({src:image.currentSrc||image.src,alt:image.alt}))}));
   visibleText=String(observed.text||'').replace(/\s+/g,' ').slice(0,1800);forms=observed.forms.length;
   formFields=observed.forms.flatMap(form=>form.fields).slice(0,50);
   formActions=observed.forms.map(form=>{let actionHost=null;try{actionHost=new URL(form.action||finalUrl).hostname}catch{}return {actionHost,method:String(form.method||'get').toUpperCase()}}).slice(0,20);
   for(const link of observed.links){try{linkedHosts.add(new URL(link).hostname)}catch{}}
   const logos=observed.images.filter(image=>image.alt).slice(0,10).map(image=>{let host=null;try{host=new URL(image.src).hostname}catch{}return {alt:String(image.alt).slice(0,100),host}});
   const rawPng=await page.screenshot({type:'png',fullPage:false,timeout:remaining()});let screenshot=rawPng,extension='png';
   if(screenshot.length>3*1024*1024){screenshot=await page.screenshot({type:'jpeg',quality:75,fullPage:false,timeout:remaining()});extension='jpg';}
   if(screenshot.length>3*1024*1024)throw new Error('Screenshot exceeds the 3 MiB evidence limit.');
   const imagePath=path.join(directory,`landing.${extension}`);await fs.writeFile(imagePath,screenshot,{mode:0o600});screenshotPaths.push(path.relative(path.dirname(evidenceDir),imagePath).split(path.sep).join('/'));
   const challenge=/just a moment|checking your browser|verify you are human|captcha|security challenge|access denied/i.test(visibleText);
   const error=responseStatus>=400?`HTTP navigation returned ${responseStatus}`:challenge?'Bot challenge or access interstitial detected':null;
   const baseHost=new URL(item.original).hostname,landingHost=new URL(finalUrl).hostname;
   return {status:error?'partial':'complete',initialUrl:item.original,finalUrl,title,visibleText,forms,formFields,formActions,brandingHints:{favicon:null,logos},resourceHosts:[...resourceHosts].slice(0,100),linkedHosts:[...linkedHosts].slice(0,80),outboundHosts:[],responseStatus,redirects:redirects.slice(0,20),screenshots:screenshotPaths,tls:null,engine:'Firefox (Playwright)',screenshotNote:`Captured live Firefox ${extension.toUpperCase()} screenshot`,evidenceGaps:[...(!redirects.length?['Firefox did not expose a navigation response chain.']:[]),...(requestFailures.length?['Some page requests failed; see requestFailures.']:[])],requestFailures,elapsedMs:Date.now()-started,error,hostChanged:baseHost!==landingHost};
 }catch(error){return {status:'failed',initialUrl:item.original,finalUrl,title,visibleText,forms,formFields,formActions,resourceHosts:[...resourceHosts].slice(0,100),linkedHosts:[...linkedHosts].slice(0,80),outboundHosts:[],responseStatus,redirects:redirects.slice(0,20),screenshots:screenshotPaths,tls:null,engine:'Firefox (Playwright)',requestFailures,error:String(error.message).slice(0,200),elapsedMs:Date.now()-started};}
 finally{await context?.close().catch(()=>{});}
}
export async function closeFirefox(){if(!browserPromise)return;try{const browser=await browserPromise;await browser.close();}catch{}browserPromise=null;}
