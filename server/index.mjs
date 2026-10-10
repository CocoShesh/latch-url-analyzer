import 'dotenv/config';
import { collectCode, domainIntel, synthesize } from './intelligence.mjs';
import { firefoxHealth, collectBrowserEvidence, closeFirefox } from './browser.mjs';
const AI_MODEL=process.env.OPENAI_MODEL || 'gpt-4.1-mini';
import http from 'node:http';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';
import dns from 'node:dns/promises';
import net from 'node:net';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { parse as parseDomain } from 'tldts';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const DATA = process.env.LATCH_DATA_DIR ? path.resolve(process.env.LATCH_DATA_DIR) : path.join(ROOT, 'data');
const EVIDENCE = path.join(DATA, 'evidence');
const DB = path.join(DATA, 'scans.json');
const HOST = process.env.HOST || '127.0.0.1';
const PORT = Number(process.env.PORT || 8787);
const EGRESS_PROXY_PORT = Number(process.env.EGRESS_PROXY_PORT || 9788);
if (!['127.0.0.1','localhost','::1'].includes(HOST)) throw new Error('Latch binds to loopback only. Use an SSH tunnel for remote access.');
const RETENTION_DAYS = Math.max(1, Math.min(30, Number(process.env.RETENTION_DAYS || 7)));
const MAX_BODY = 256_000, MAX_URLS = 250, MAX_REDIRECTS = 10, MAX_RESPONSE_BYTES = 10 * 1024 * 1024;
const providers = {
  virusTotal: Boolean(process.env.VIRUSTOTAL_API_KEY),
  safeBrowsing: Boolean(process.env.GOOGLE_SAFE_BROWSING_API_KEY),
  urlhaus: Boolean(process.env.URLHAUS_AUTH_KEY)
};
const DNSTWIST_WORKER = path.join(ROOT, 'scripts', 'dnstwist_worker.py');
const projectPython = process.platform === 'win32' ? path.join(ROOT,'.dnstwist-venv','Scripts','python.exe') : path.join(ROOT,'.dnstwist-venv','bin','python');
const pythonCandidates = [[projectPython,[]],...(process.platform === 'win32' ? [['py.exe',['-3']],['python.exe',[]],['python',[]]] : [['python3',[]],['python',[]]])];
async function callDnstwist(args, timeoutMs=2500) {
  if (process.env.LATCH_DNSTWIST_MOCK === '1') return {ok:true,mock:true,variants:[{fuzzer:'mock-omission',domain:'exampl.com'},{fuzzer:'mock-homoglyph',domain:'examp1e.com'}]};
  for (const [bin,prefix] of pythonCandidates) {
    const result=await new Promise(resolve=>{
      let stdout='',stderr='',settled=false;
      const child=spawn(bin,[...prefix,DNSTWIST_WORKER,...args],{windowsHide:true,stdio:['ignore','pipe','pipe']});
      const finish=value=>{if(settled)return;settled=true;clearTimeout(timer);resolve(value)};
      const timer=setTimeout(()=>{child.kill();finish({error:'DNSTwist helper timed out'})},timeoutMs);
      child.stdout.on('data',chunk=>{stdout+=chunk;if(stdout.length>2_000_000){child.kill();finish({error:'DNSTwist output exceeded the size limit'})}});
      child.stderr.on('data',chunk=>{stderr=(stderr+chunk).slice(-1000)});
      child.once('error',error=>finish({missing:true,error:error.message}));
      child.once('close',code=>{if(code===0){try{finish(JSON.parse(stdout))}catch{finish({error:'DNSTwist returned invalid JSON'})}}else finish({missing:code===9009,error:stderr.trim()||`DNSTwist helper exited with code ${code}`})});
    });
    if(result.missing) continue;
    return result;
  }
  return {error:'Python or the dnstwist package is not installed'};
}
const dnstwistCheck=await callDnstwist(['--check']);
const dnstwistAvailable=dnstwistCheck.ok===true;
async function lookupLookalikeAddresses(candidates, deadline) {
  const found=[];let cursor=0,attempted=0;
  async function worker(){while(cursor<candidates.length&&found.length<100&&Date.now()<deadline){const candidate=candidates[cursor++];attempted++;try{const addresses=await Promise.race([dns.lookup(candidate.domain,{all:true,verbatim:true}),new Promise((_,reject)=>setTimeout(()=>reject(new Error('DNS timeout')),1200))]);const publicAddresses=[...new Set(addresses.map(x=>x.address).filter(isPublicIP))];if(publicAddresses.length)found.push({domain:candidate.domain,fuzzer:candidate.fuzzer,addresses:publicAddresses})}catch{}}}
  await Promise.all(Array.from({length:12},worker));return {found:found.sort((a,b)=>a.domain.localeCompare(b.domain)),attempted};
}
async function analyzeLookalikes(domain, timeoutMs=7000) {
  const observedAt=new Date().toISOString();
  if(!dnstwistAvailable)return {status:'unavailable',engine:'dnstwist',observedAt,generated:0,checked:0,found:[],gaps:['Install Python 3 and dnstwist, then restart Latch.']};
  if(net.isIP(domain)||domain.length>60)return {status:'skipped',engine:'dnstwist',observedAt,generated:0,checked:0,found:[],gaps:['DNSTwist skipped for IP addresses or long registrable domains to limit DNS workload.']};
  const result=await callDnstwist([domain],Math.min(2500,timeoutMs));
  if(!result.ok||!Array.isArray(result.variants))return {status:'unavailable',engine:'dnstwist',observedAt,generated:0,checked:0,found:[],gaps:[result.error||'DNSTwist did not return domain variants.']};
  const unique=new Map();for(const x of result.variants){if(typeof x?.domain==='string'&&x.domain!==domain&&!unique.has(x.domain))unique.set(x.domain,{domain:x.domain,fuzzer:String(x.fuzzer||'unknown')})}
  if(result.mock)return {status:'complete',engine:'dnstwist',observedAt,generated:unique.size,checked:0,found:[],limited:false,gaps:['Mock DNSTwist fixture; no live DNS queries were made.']};
  const candidates=[...unique.values()].slice(0,120),deadline=Date.now()+Math.max(250,timeoutMs-2500);
  const lookup=await lookupLookalikeAddresses(candidates,deadline);
  return {status:'complete',engine:'dnstwist',observedAt,generated:unique.size,checked:lookup.attempted,found:lookup.found,limited:unique.size>lookup.attempted,gaps:['Similarity and DNS resolution are investigation leads only; they do not prove impersonation or malicious intent.',`Checked at most 120 generated variants (${lookup.attempted} DNS queries started). Candidate websites were not visited.`]};
}
let saveChain=Promise.resolve();
let scans = [];
const active = new Map();
let queue = [];
let running = 0;
let concurrencyLimit = 2;
const activeDomains = new Set();
const providerLastCall = new Map();
const PROVIDER_DELAY_MS = Math.max(250,Math.min(5000,Number(process.env.PROVIDER_DELAY_MS)||1000));

await fs.mkdir(EVIDENCE, { recursive: true, mode:0o700 }); await fs.chmod(DATA,0o700).catch(()=>{}); await fs.chmod(EVIDENCE,0o700).catch(()=>{});
try { scans = JSON.parse(await fs.readFile(DB, 'utf8')); } catch { scans = []; }
for (const job of scans) { if (['queued','running'].includes(job.status)) { job.status='interrupted'; job.updatedAt=new Date().toISOString(); for (const item of job.items) if (!['complete','partial','failed','cancelled'].includes(item.status)) { item.status='failed'; item.verdict='Unknown'; item.confidence=0; item.error='VM service restarted during this scan.'; } job.completed=job.items.length; } }
await prune();
const pruneTimer=setInterval(()=>prune().catch(()=>{}),60*60*1000); pruneTimer.unref();

function requireSameOrigin(req) {
  const allowed = new Set([`http://127.0.0.1:${PORT}`,`http://localhost:${PORT}`,`http://[::1]:${PORT}`]);
  if (req.headers.origin && !allowed.has(req.headers.origin)) throw new Error('Cross-origin API requests are blocked');
  if (req.headers['sec-fetch-site']==='cross-site') throw new Error('Cross-site API requests are blocked');
}
function json(res, status, body) {
  const data = JSON.stringify(body);
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'content-length': Buffer.byteLength(data), 'cache-control': 'no-store', 'x-content-type-options': 'nosniff' });
  res.end(data);
}
async function bodyJson(req) {
  let buf = '';
  for await (const chunk of req) { buf += chunk; if (Buffer.byteLength(buf) > MAX_BODY) throw new Error('Request body too large'); }
  return JSON.parse(buf || '{}');
}
function save() {
  const snapshot=JSON.stringify(scans); const temp=DB+`.${crypto.randomUUID()}.tmp`;
  const task=saveChain.then(async()=>{await fs.writeFile(temp,snapshot,{mode:0o600});await fs.rename(temp,DB)});
  saveChain=task.catch(()=>{});return task;
}
function publicJob(job) {
  return { id: job.id, status: job.status, createdAt: job.createdAt, updatedAt: job.updatedAt, total: job.total, completed: job.completed, cancelled: job.cancelled, settings: job.settings, items: job.items };
}
function ipv4Number(ip) { return ip.split('.').reduce((value, octet) => value * 256 + Number(octet), 0); }
function ipv4InCidr(ip, cidr) {
  const [base, bitsText] = cidr.split('/'); const bits = Number(bitsText);
  const shift = 32 - bits; return Math.floor(ipv4Number(ip) / 2 ** shift) === Math.floor(ipv4Number(base) / 2 ** shift);
}
const blockedIPv4 = ['0.0.0.0/8','10.0.0.0/8','100.64.0.0/10','127.0.0.0/8','169.254.0.0/16','172.16.0.0/12','192.0.0.0/24','192.0.2.0/24','192.88.99.0/24','192.168.0.0/16','198.18.0.0/15','198.51.100.0/24','203.0.113.0/24','224.0.0.0/4','240.0.0.0/4','255.255.255.255/32'];
function ipv6Number(ip) {
  let text=ip.toLowerCase().split('%')[0];
  if(text.includes('.')){const index=text.lastIndexOf(':');const v4=text.slice(index+1);if(!net.isIPv4(v4))return null;const value=ipv4Number(v4);text=text.slice(0,index+1)+((value>>>16).toString(16))+':'+((value&0xffff).toString(16));}
  const halves=text.split('::');if(halves.length>2)return null;
  const left=halves[0]?halves[0].split(':'):[],right=halves.length===2&&halves[1]?halves[1].split(':'):[];
  const groups=halves.length===2?[...left,...Array(8-left.length-right.length).fill('0'),...right]:left;
  if(groups.length!==8)return null;try{return groups.reduce((n,g)=>(n<<16n)+BigInt('0x'+(g||'0')),0n)}catch{return null}
}
function ipv6InCidr(ip,cidr){const [base,bitsText]=cidr.split('/');const value=ipv6Number(ip),baseValue=ipv6Number(base),bits=BigInt(bitsText);if(value===null||baseValue===null)return false;const shift=128n-bits;return(value>>shift)===(baseValue>>shift)}
const blockedIPv6=['2001::/23','2001:20::/28','2001:db8::/32','2002::/16','3fff::/20'];
function isPublicIP(ip) {
  if (net.isIPv4(ip)) return !blockedIPv4.some(range => ipv4InCidr(ip, range));
  if (!net.isIPv6(ip)) return false;
  const value=ipv6Number(ip);if(value===null)return false;
  if((value>>125n)!==1n)return false; // Globally routable unicast allocation, 2000::/3.
  return !blockedIPv6.some(range=>ipv6InCidr(ip,range));
}
async function validateTarget(raw) {
  let u;
  try { u = new URL(raw); } catch { throw new Error('Invalid absolute URL'); }
  if (!['http:', 'https:'].includes(u.protocol)) throw new Error('Only HTTP and HTTPS URLs are allowed');
  if (!u.hostname || u.username || u.password) throw new Error('Hostname missing or embedded credentials are present');
  const host = u.hostname.replace(/^\[|\]$/g, '').toLowerCase();
  if (host === 'localhost' || host.endsWith('.localhost') || host.endsWith('.local') || host === 'metadata.google.internal') throw new Error('Local and metadata hostnames are blocked');
  let addresses;
  if (net.isIP(host)) addresses = [{ address: host }];
  else {
    let lookupTimer;try { addresses = await Promise.race([dns.lookup(host, { all: true, verbatim: true }),new Promise((_,reject)=>{lookupTimer=setTimeout(()=>reject(new Error('DNS timeout')),3500)})]); }
    catch(e) { throw new Error(e.message==='DNS timeout'?'DNS resolution timed out':'Hostname did not resolve'); } finally { clearTimeout(lookupTimer); }
  }
  if (!addresses.length || addresses.some(a => !isPublicIP(a.address))) throw new Error('Hostname resolves to a private, reserved, or non-public address');
  return { url: u, host, addresses: addresses.map(a => a.address) };
}
function localSignals(url, host) {
  const out = [], lower = host.toLowerCase(), brands = ['paypal','microsoft','google','apple','amazon','netflix','facebook','instagram','whatsapp','icloud','chase','docusign','dropbox','adobe'];
  const shorteners = new Set(['bit.ly','t.co','tinyurl.com','goo.gl','ow.ly','buff.ly','is.gd','cutt.ly','rb.gy']);
  if (lower.split('.').some(label => label.startsWith('xn--'))) out.push(['Internationalized hostname', 'Hostname contains a punycode label; inspect for lookalike characters.', 'Local URL rules']);
  if (shorteners.has(lower)) out.push(['URL shortener', 'Destination is hidden behind a known shortening domain.', 'Local URL rules']);
  if (net.isIP(lower)) out.push(['IP address host', 'URL uses an IP address instead of a domain name.', 'Local URL rules']);
  const registrable = parseDomain(lower).domain || lower;
  const brand = brands.find(b => lower.includes(b) && registrable.split('.')[0] !== b);
  if (brand) out.push(['Brand/domain mismatch', `“${brand}” appears in the hostname but not as a matching hostname label. Verify independently.`, 'Local heuristic']);
  if (lower.split('.').length > 5) out.push(['Unusually deep subdomain', 'Hostname contains many labels; verify the registrable domain.', 'Local URL rules']);
  if (lower.length > 60) out.push(['Long hostname', 'Hostname is unusually long and may obscure the destination.', 'Local URL rules']);
  if (/%[0-9a-f]{2}/i.test(url.pathname)) out.push(['Encoded path', 'Path contains percent-encoded characters. This is context only.', 'Local URL rules', 'context']);
  if (url.search) out.push(['Query parameters present', 'Query values may contain campaign identifiers or personal tokens.', 'URL parser', 'context']);
  return out;
}
async function providerFetch(url, options = {}, timeout = 7000, allowPublicRedirect = false) {
  const ctrl = new AbortController(); const timer = setTimeout(() => ctrl.abort(), timeout);
  try {
    let current = new URL(url); const initialHost = current.hostname; const requestHeaders = { 'user-agent':'Latch-URL-Analyzer/1.0', ...(options.headers || {}) };
    for (let hop = 0; hop <= 3; hop++) {
      await validateTarget(current.href);
      const headers = current.hostname === initialHost ? requestHeaders : { 'user-agent':'Latch-URL-Analyzer/1.0' };
      const response = await fetch(current, { ...options, headers, signal:ctrl.signal, redirect:'manual' });
      if (![301,302,303,307,308].includes(response.status)) return response;
      const location = response.headers.get('location');
      if (!location || hop === 3) throw new Error('Provider redirect limit exceeded');
      const next = new URL(location, current);
      if (next.protocol !== 'https:' || (!allowPublicRedirect && next.hostname !== initialHost)) throw new Error('Provider redirect blocked');
      current = next;
    }
    throw new Error('Provider redirect limit exceeded');
  } finally { clearTimeout(timer); }
}
async function lookupVirusTotal(raw, timeout=7000) {
  const id = Buffer.from(raw).toString('base64url');
  const r = await providerFetch(`https://www.virustotal.com/api/v3/urls/${id}`, { headers: { 'x-apikey': process.env.VIRUSTOTAL_API_KEY } }, timeout);
  if (r.status === 404) return { source: 'VirusTotal', observedAt: new Date().toISOString(), status: 'no_match', malicious: 0, suspicious: 0, harmless: 0, explanation: 'Provider returned no URL report.' };
  if (!r.ok) throw new Error(`VirusTotal HTTP ${r.status}`);
  const x = await r.json(), s = x.data?.attributes?.last_analysis_stats || {};
  return { source: 'VirusTotal', observedAt: new Date().toISOString(), status: (s.malicious||0)>0||(s.suspicious||0)>0?'match':'no_match', malicious: s.malicious || 0, suspicious: s.suspicious || 0, harmless: s.harmless || 0, details:{malicious:s.malicious||0,suspicious:s.suspicious||0,harmless:s.harmless||0}, lastAnalysisAt: x.data?.attributes?.last_analysis_date ? new Date(x.data.attributes.last_analysis_date * 1000).toISOString() : null, explanation: `${s.malicious || 0} engines marked malicious; ${s.suspicious || 0} suspicious.` };
}
async function lookupSafeBrowsing(raw, timeout=7000) {
  const key = process.env.GOOGLE_SAFE_BROWSING_API_KEY;
  const r = await providerFetch(`https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${encodeURIComponent(key)}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ client: { clientId: 'latch-url-analyzer', clientVersion: '1.0' }, threatInfo: { threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'], platformTypes: ['ANY_PLATFORM'], threatEntryTypes: ['URL'], threatEntries: [{ url: raw }] } }) }, timeout);
  if (!r.ok) throw new Error(`Safe Browsing HTTP ${r.status}`);
  const x = await r.json(), matches = x.matches || [];
  return { source: 'Google Safe Browsing', observedAt: new Date().toISOString(), status: matches.length ? 'match' : 'no_match', matches: matches.map(m => ({ threatType: m.threatType, platformType: m.platformType })), details:{matches:matches.map(m=>m.threatType)}, explanation: matches.length ? `Matched ${matches.map(m => m.threatType).join(', ')}.` : 'No match returned by this check.' };
}
async function lookupUrlhaus(raw, timeout=7000) {
  const form = new URLSearchParams({ url: raw });
  const r = await providerFetch('https://urlhaus-api.abuse.ch/v1/url/', { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded', 'Auth-Key': process.env.URLHAUS_AUTH_KEY }, body: form }, timeout);
  if (!r.ok) throw new Error(`URLhaus HTTP ${r.status}`);
  const x = await r.json();
  return { source: 'URLhaus', observedAt: new Date().toISOString(), status: x.query_status === 'ok' ? 'match' : 'no_match', threat: x.threat || null, dateAdded: x.date_added || null, urlStatus: x.url_status || null, details:{threat:x.threat||null,dateAdded:x.date_added||null,urlStatus:x.url_status||null}, explanation: x.query_status === 'ok' ? `URLhaus malware URL match (${x.threat || 'threat type unavailable'}).` : 'No URLhaus malware URL match.' };
}
async function passiveChecks(raw, deadline) {
  const checks = [];
  const configured = [];
  if (providers.virusTotal) configured.push(['VirusTotal', timeout => lookupVirusTotal(raw,timeout)]);
  if (providers.safeBrowsing) configured.push(['Google Safe Browsing', timeout => lookupSafeBrowsing(raw,timeout)]);
  if (providers.urlhaus) configured.push(['URLhaus', timeout => lookupUrlhaus(raw,timeout)]);
  await Promise.all(configured.map(async ([name, fn]) => {
    try { const last=providerLastCall.get(name)||0; const wait=Math.max(0,PROVIDER_DELAY_MS-(Date.now()-last)); if(wait)await new Promise(resolve=>setTimeout(resolve,wait)); providerLastCall.set(name,Date.now()); const allowance=Math.max(1,Math.min(7000,deadline-Date.now())); checks.push(await fn(allowance)); } catch (e) { checks.push({ source: name, observedAt: new Date().toISOString(), status: 'error', explanation: `Lookup unavailable: ${String(e.message).slice(0,120)}` }); }
  }));
  return checks;
}
function scanVerdict(signals, providerResults, browser, failed) {
  const vt = providerResults.find(x => x.source === 'VirusTotal' && x.status === 'match');
  const sb = providerResults.find(x => x.source === 'Google Safe Browsing' && x.status === 'match');
  const uh = providerResults.find(x => x.source === 'URLhaus' && x.status === 'match');
  if (sb || uh || (vt && vt.malicious >= 3)) return { verdict: 'Dangerous', confidence: sb || uh ? 98 : 90, reasons: ['Confirmed threat intelligence match'] };
  if (signals.some(s=>s[3]!=='context') || (vt && vt.malicious > 0) || providerResults.some(x => x.status === 'match' && x.source === 'VirusTotal' && x.suspicious > 0) || (browser?.forms || 0) > 0) return { verdict: 'Suspicious', confidence: signals.some(s=>s[3]!=='context') ? Math.min(78, 42 + signals.filter(s=>s[3]!=='context').length * 9) : 58, reasons: ['One or more risk indicators need analyst review'] };
  const threatResults = providerResults.filter(x => ['VirusTotal','Google Safe Browsing','URLhaus'].includes(x.source));
  const completedProvider = threatResults.length > 0 && threatResults.every(x => x.status === 'no_match');
  if (!failed && browser?.status === 'complete' && completedProvider) return { verdict: 'Clean', confidence: 50, reasons: ['No indicators found in the checks completed at scan time'] };
  return { verdict: 'Unknown', confidence: 0, reasons: [failed ? 'One or more evidence checks did not complete' : 'Evidence is incomplete; a negative result is not available'] };
}
async function createPinnedProxy() {
  const proxy = http.createServer(async (req, res) => {
    try {
      const u = new URL(req.url);
      if (u.protocol !== 'http:' || (u.port && u.port !== '80')) throw new Error('Proxy allows public HTTP on port 80 only');
      const checked = await validateTarget(u.href); const ip = checked.addresses[0];
      const upstream = http.request({ host: ip, family: net.isIP(ip), port: 80, method: req.method, path: u.pathname + u.search, headers: { ...req.headers, host: u.host }, agent: false }, response => {
        res.writeHead(response.statusCode || 502, response.headers); let bytes=0; response.on('data',chunk=>{bytes+=chunk.length;if(bytes>MAX_RESPONSE_BYTES){upstream.destroy();res.destroy()}}); response.pipe(res);
      });
      upstream.on('error', () => { if (!res.headersSent) res.writeHead(502); res.end(); });
      req.pipe(upstream);
    } catch { res.writeHead(403, { 'content-type':'text/plain' }); res.end('Destination blocked by Latch egress policy.'); }
  });
  proxy.on('connect', async (req, client, head) => {
    let upstream;
    try {
      const authority = new URL(`https://${req.url}`); const host = authority.hostname.replace(/^\[|\]$/g,''); const port = Number(authority.port || 443);
      if (![443,80].includes(port)) throw new Error('Destination port blocked');
      const checked = await validateTarget(`${port===443?'https':'http'}://${host.includes(':')?`[${host}]`:host}:${port}/`);
      const ip = checked.addresses[0]; upstream = net.connect({ host: ip, family: net.isIP(ip), port });
      upstream.once('connect', () => { client.write('HTTP/1.1 200 Connection Established\r\n\r\n'); let transferred=0; const cap=stream=>stream.on('data',chunk=>{transferred+=chunk.length;if(transferred>25*1024*1024){client.destroy();upstream.destroy()}}); cap(client);cap(upstream); if (head?.length) upstream.write(head); upstream.pipe(client); client.pipe(upstream); });
      upstream.on('error', () => client.destroy());
    } catch { client.end('HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n'); upstream?.destroy(); }
  });
  await new Promise((resolve,reject) => { proxy.once('error',reject); proxy.listen(EGRESS_PROXY_PORT, '127.0.0.1', resolve); });
  return proxy;
}
const egressProxy = await createPinnedProxy();
async function browserEvidence(item,scanId,timeoutSeconds){return collectBrowserEvidence(item,scanId,timeoutSeconds,{evidenceDir:EVIDENCE,validateTarget});}
async function runItem(job, item) {
  const deadline=Date.now()+job.settings.timeoutSeconds*1000;
  item.status = 'checking'; item.observedAt = new Date().toISOString(); job.updatedAt = item.observedAt; await save();
  try {
    const checked = await validateTarget(item.original);
    item.host = checked.host; item.dnsAnswers=checked.addresses; item.signals = localSignals(checked.url, checked.host);
    item.providerResults = await passiveChecks(item.original, deadline);
    item.status = 'rendering'; await save();
    const confirmedPositive=item.providerResults.some(x=>(x.source==='Google Safe Browsing'||x.source==='URLhaus')&&x.status==='match')||item.providerResults.some(x=>x.source==='VirusTotal'&&x.status==='match'&&x.malicious>=3);
    const remainingSeconds=Math.floor((deadline-Date.now())/1000);
    item.browser = remainingSeconds<1 ? {status:'failed',error:'Per-URL time limit reached before browser rendering.',redirects:[],screenshots:[]} : await browserEvidence(item, job.id, remainingSeconds);
    item.domainIntelligence=domainIntel(item,parseDomain(checked.host).domain||checked.host);
    item.codeAnalysis=job.settings.depth==='standard' && !(confirmedPositive&&!job.settings.continueAfterThreat) && deadline>Date.now() ? await collectCode(item.browser.finalUrl||item.original,validateTarget,Math.min(7000,deadline-Date.now())) : {status:'skipped',indicators:[],sources:[],summary:'Code collection was skipped by scan policy or the per-URL time limit.',gaps:[]};
    if(job.settings.dnstwistConsent && deadline>Date.now()) item.domainIntelligence.lookalikes=await analyzeLookalikes(item.domainIntelligence.registrableDomain||checked.host,Math.min(7000,deadline-Date.now()));
    else if(job.settings.dnstwistSkippedReason) item.domainIntelligence.lookalikes={status:'skipped',engine:'dnstwist',observedAt:new Date().toISOString(),generated:0,checked:0,found:[],gaps:[job.settings.dnstwistSkippedReason]};
    else if(!dnstwistAvailable) item.domainIntelligence.lookalikes={status:'unavailable',engine:'dnstwist',observedAt:new Date().toISOString(),generated:0,checked:0,found:[],gaps:['Python 3 and dnstwist are not installed; the rest of the scan continued normally.']};
    const sensitiveFields=(item.browser.formFields||[]).filter(f=>['password','email','tel','number'].includes((f.type||'').toLowerCase())||/pass(word)?|e-?mail|sign.?in|log.?in|card|payment|account|mfa|verification/i.test(`${f.label} ${f.name}`));
    if (sensitiveFields.length > 0) item.signals.push(['Credential/payment fields present', `${item.browser.forms||0} form(s) and ${sensitiveFields.length} potentially sensitive fields observed. No forms were submitted.`, 'Browser evidence']);
    const pageHost = item.browser.finalUrl ? new URL(item.browser.finalUrl).hostname : checked.host;
    if (pageHost !== checked.host) item.signals.push(['Redirect to a different host', `Navigation ended on ${pageHost}; review the full redirect trail.`, 'Browser evidence']);
    if((item.codeAnalysis.indicators||[]).some(x=>x.id==='dynamic-eval')) item.signals.push(['Dynamic code execution expression','Static source contains eval or Function construction. This is a review lead; execution and malicious intent are not established.','Static code analyzer']);
    const failed = item.browser.status !== 'complete' || !item.browser.screenshots?.length || (job.settings.depth==='standard' && item.codeAnalysis.status!=='complete') || item.providerResults.some(x => x.status === 'error');
    const assessment = scanVerdict(item.signals, item.providerResults, item.browser, failed);
    Object.assign(item, assessment, { status: failed ? 'partial' : 'complete', finalUrl: item.browser.finalUrl || null, redirects: item.browser.redirects || [], screenshots: item.browser.screenshots || [] });
    if(job.settings.aiConsent && process.env.OPENAI_API_KEY && !job.cancelled){
      const scanStatus=item.status;item.status='summarizing';await save();
      try{const image=job.settings.aiScreenshotConsent && item.screenshots[0] ? await fs.readFile(path.join(DATA,item.screenshots[0])):null;item.aiSummary=await synthesize(item,{key:process.env.OPENAI_API_KEY,model:AI_MODEL,image});}
      catch(e){item.aiSummary={status:'error',error:String(e.message).slice(0,200)}}
      item.status=scanStatus;
    }
  } catch (e) {
    item.status = 'failed'; item.verdict = 'Unknown'; item.confidence = 0; item.error = String(e.message).slice(0,200); item.signals = item.signals || []; item.providerResults = item.providerResults || [];
  }
  item.updatedAt = new Date().toISOString(); job.completed = job.items.filter(x => ['complete','partial','failed','cancelled'].includes(x.status)).length; job.updatedAt = item.updatedAt;
  if (job.completed >= job.total) job.status = job.cancelled ? 'cancelled' : 'complete';
  await save();
  if(job.cancelled&&!scans.some(s=>s.id===job.id)) await fs.rm(path.join(EVIDENCE,job.id),{recursive:true,force:true}).catch(()=>{});
}
function queueDomain(item) {
  try { const host=new URL(item.original).hostname.replace(/^\[|\]$/g,''); return parseDomain(host).domain||host; } catch { return `invalid:${item.id}`; }
}
function pump() {
  while (running < concurrencyLimit && queue.length) {
    const index=queue.findIndex(entry=>!activeDomains.has(queueDomain(entry.item)));
    if(index<0)break;
    const [next]=queue.splice(index,1); const domain=queueDomain(next.item);
    if (next.job.cancelled) { next.item.status = 'cancelled'; next.job.completed++; continue; }
    activeDomains.add(domain); running++;
    runItem(next.job, next.item).catch(() => {}).finally(() => { running--; activeDomains.delete(domain); pump(); });
  }
}
async function prune() {
  const cutoff = Date.now() - RETENTION_DAYS * 86400000;
  const keep = scans.filter(s => new Date(s.createdAt).getTime() >= cutoff);
  const removed = scans.filter(s => !keep.includes(s)); scans = keep;
  for (const s of removed) await fs.rm(path.join(EVIDENCE, s.id), { recursive: true, force: true }).catch(() => {});
  await save();
}
function serveFile(res, pathname) {
  const decoded = decodeURIComponent(pathname);
  const files = { '/':'index.html', '/index.html':'index.html', '/favicon.svg':'assets/latch-mark.svg', '/assets/latch-mark.svg':'assets/latch-mark.svg' };
  if (!Object.hasOwn(files, decoded)) return json(res, 404, { error: 'Not found' });
  const file = path.join(ROOT, files[decoded]);
  const mime = { '.html':'text/html; charset=utf-8', '.css':'text/css; charset=utf-8', '.js':'text/javascript; charset=utf-8', '.json':'application/json; charset=utf-8', '.jpg':'image/jpeg', '.jpeg':'image/jpeg', '.svg':'image/svg+xml' }[path.extname(file)] || 'application/octet-stream';
  fs.readFile(file).then(data => { res.writeHead(200, { 'content-type': mime, 'x-content-type-options':'nosniff', 'cache-control':'no-store', 'content-security-policy':"default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'" }); res.end(data); }).catch(() => json(res,404,{error:'Not found'}));
}
const server = http.createServer(async (req,res) => {
  const url = new URL(req.url, `http://${req.headers.host || '127.0.0.1'}`);
  try {
    if (req.method === 'GET' && url.pathname === '/api/config') { const browser=await firefoxHealth(); return json(res,200,{ providers, aiAvailable:Boolean(process.env.OPENAI_API_KEY), aiModel:AI_MODEL, dnstwistAvailable, browserAvailable:browser.available, browserEngine:browser.engine, retentionDays:RETENTION_DAYS, maxBatch:MAX_URLS, maxConcurrency:4, localOnly:HOST==='127.0.0.1'||HOST==='localhost' }); }
    if (url.pathname === '/api/scans' && req.method === 'GET') return json(res,200,{ scans:scans.map(publicJob) });
    if (url.pathname === '/api/scans' && req.method === 'DELETE') { requireSameOrigin(req); for(const job of scans){job.cancelled=true;job.status='cancelled';for(const item of job.items)if(item.status==='queued')item.status='cancelled'} scans=[]; queue=[]; await fs.rm(EVIDENCE,{recursive:true,force:true}); await fs.mkdir(EVIDENCE,{recursive:true,mode:0o700}); await save(); return json(res,200,{ok:true}); }
    if (url.pathname === '/api/scans' && req.method === 'POST') {
      requireSameOrigin(req); const b = await bodyJson(req);
      if (!Array.isArray(b.urls) || !b.urls.length || b.urls.length > MAX_URLS) return json(res,400,{error:`Provide 1–${MAX_URLS} URLs.`});
      const unique = [...new Set(b.urls.map(x => String(x).trim()).filter(Boolean))];
      if (!unique.length || unique.length !== b.urls.length) return json(res,400,{error:'Send only non-empty exact-unique URLs; validate and deduplicate in the UI.'});
      const consent = true;
      const id = crypto.randomUUID(); const now = new Date().toISOString();
      const dnstwistConsent=dnstwistAvailable&&unique.length<=25;
      const job = { id, status:'queued', createdAt:now, updatedAt:now, total:unique.length, completed:0, cancelled:false, settings:{ depth:'standard', timeoutSeconds:20, concurrency:2, externalLookupConsent:consent, dnstwistConsent, dnstwistSkippedReason:dnstwistAvailable&&unique.length>25?'DNSTwist is capped at 25 URLs per scan. This batch exceeded the cap; other analysis completed normally.':null, continueAfterThreat:true, aiConsent:Boolean(process.env.OPENAI_API_KEY), aiScreenshotConsent:Boolean(process.env.OPENAI_API_KEY) }, items:unique.map((original,index)=>({ id:crypto.randomUUID(), index, key:original, original, host:null, status:'queued', verdict:'Unknown', confidence:0, signals:[], providerResults:[], browser:null, redirects:[], screenshots:[] })) };
      scans.unshift(job); await save();
      for (const item of job.items) queue.push({job,item});
      concurrencyLimit = Math.max(1, Math.min(4, job.settings.concurrency)); job.status='running'; pump();
      return json(res,202,{scan:publicJob(job)});
    }
    const itemDelete=url.pathname.match(/^\/api\/scans\/([0-9a-f-]+)\/items\/([0-9a-f-]+)$/);
    if(itemDelete&&req.method==='DELETE'){
      requireSameOrigin(req);const job=scans.find(s=>s.id===itemDelete[1]);if(!job)return json(res,404,{error:'Scan not found'});
      const index=job.items.findIndex(x=>x.id===itemDelete[2]);if(index<0)return json(res,404,{error:'URL report not found'});
      const item=job.items[index];if(['queued','checking','rendering','summarizing'].includes(item.status))return json(res,409,{error:'Cancel the active scan before deleting this URL report.'});
      job.items.splice(index,1);job.total=job.items.length;job.completed=job.items.length;job.status='complete';job.updatedAt=new Date().toISOString();
      await fs.rm(path.join(EVIDENCE,job.id,item.id),{recursive:true,force:true});await save();return json(res,200,{scan:publicJob(job)});
    }
    const scanMatch = url.pathname.match(/^\/api\/scans\/([0-9a-f-]+)$/);
    if (scanMatch) {
      const job = scans.find(s => s.id === scanMatch[1]); if (!job) return json(res,404,{error:'Scan not found'});
      if (req.method === 'GET') return json(res,200,{scan:publicJob(job)});
      if (req.method === 'DELETE') { requireSameOrigin(req); job.cancelled=true; job.status='cancelled'; for (const x of queue.filter(q=>q.job.id===job.id)) x.item.status='cancelled'; queue=queue.filter(q=>q.job.id!==job.id); job.completed=job.items.filter(x=>['complete','partial','failed','cancelled'].includes(x.status)).length; job.updatedAt=new Date().toISOString(); await save(); return json(res,200,{scan:publicJob(job)}); }
      return json(res,405,{error:'Method not allowed'});
    }
    const evidence = url.pathname.match(/^\/evidence\/([0-9a-f-]+)\/([0-9a-f-]+)\/(landing|final)\.(jpg|png)$/);
    if (req.method === 'GET' && evidence) {
      const scan = scans.find(s=>s.id===evidence[1]); const item=scan?.items.find(x=>x.id===evidence[2]); const extension=evidence[4];
      if(!item || !item.screenshots?.some(p=>p.endsWith(`${evidence[3]}.${extension}`))) return json(res,404,{error:'Evidence unavailable'});
      const file=path.join(DATA,'evidence',evidence[1],evidence[2],`${evidence[3]}.${extension}`);
      try { const data=await fs.readFile(file); res.writeHead(200,{'content-type':extension==='png'?'image/png':'image/jpeg','cache-control':'private, max-age=300','x-content-type-options':'nosniff'}); return res.end(data); } catch { return json(res,404,{error:'Evidence unavailable'}); }
    }
    if (req.method==='GET' && !url.pathname.startsWith('/api/')) return serveFile(res,url.pathname);
    return json(res,404,{error:'Not found'});
  } catch(e) { return json(res,400,{error:String(e.message).slice(0,250)}); }
});
server.listen(PORT, HOST, () => console.log(`Latch listening at http://${HOST}:${PORT} · Playwright Firefox · pinned egress proxy 127.0.0.1:${EGRESS_PROXY_PORT} · ${os.hostname()}`));

for (const signal of ['SIGINT','SIGTERM']) process.once(signal,()=>{closeFirefox().finally(()=>{server.close(()=>process.exit(0));setTimeout(()=>process.exit(0),2500).unref()})});
