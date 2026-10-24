// Network-free pure negative controls. Import never invokes the capture entry.
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {spawnSync} from 'node:child_process';
import {SOURCE_SHA,SOURCES,sourceFor,curlArguments,parseCurlMetadata,sanitizeHeaders,assessCapture,MAX_BODY_BYTES} from './capture-nm-tx-source-only.mjs';
let checks=0;const check=fn=>{fn();checks++;};
check(()=>{assert.equal(SOURCE_SHA,'46b5b5f7a75cb251ea2cabb587af95f5eda34bca');assert.equal(SOURCES.length,2);assert.equal(sourceFor('anything-else'),undefined);});
const body=Buffer.from('<html><body><main>'+('Ordinary publisher material. '.repeat(30))+'</main></body></html>');
const raw=Buffer.from(`HTTP/2 200\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: ${body.length}\r\nSet-Cookie: PRIVATE_COOKIE_VALUE\r\nAuthorization: PRIVATE_AUTH_VALUE\r\nX-Private-Trace: PRIVATE_TRACE_VALUE\r\n\r\n`);
const projection=sanitizeHeaders(raw);
check(()=>{const text=JSON.stringify(projection);for(const forbidden of ['PRIVATE_COOKIE_VALUE','PRIVATE_AUTH_VALUE','PRIVATE_TRACE_VALUE','X-Private-Trace','Set-Cookie'])assert.ok(!text.includes(forbidden));assert.equal(projection.rawHeadersRetained,false);assert.equal(projection.sensitiveHeaderValuesOmitted,true);});
const sourceUrl=SOURCES[0].url;
const base={body,headers:projection,processStatus:0,processSignal:null,processError:null,metadata:{httpStatus:200,finalUrl:sourceUrl,redirectCount:0,contentTypeIsHtml:true,downloadedBytes:body.length},sourceUrl,streamLimitHit:false};
check(()=>assert.deepEqual(assessCapture(base),{captureEligibleForSeparateReview:true,failures:[]}));
for(const status of [202,206,301,302,403,404,500,null])check(()=>assert.equal(assessCapture({...base,metadata:{...base.metadata,httpStatus:status}}).captureEligibleForSeparateReview,false));
for(const changed of [
 {...base,processStatus:28},{...base,processSignal:'SIGTERM'},{...base,processError:'PARENT_TIMEOUT'},
 {...base,streamLimitHit:true},{...base,metadata:{...base.metadata,finalUrl:'https://example.invalid/'}},
 {...base,metadata:{...base.metadata,redirectCount:1}},{...base,metadata:{...base.metadata,contentTypeIsHtml:false}},
 {...base,metadata:{...base.metadata,downloadedBytes:body.length-1}},
 {...base,body:Buffer.alloc(0)},{...base,body:Buffer.alloc(MAX_BODY_BYTES+1)},
 {...base,headers:{...projection,observedRawHeadersTruncated:true}},
 {...base,headers:{...projection,headerTerminationComplete:false}},
 {...base,headers:{...projection,headerBlockCount:2}},
 {...base,headers:{...projection,contentRangePresent:true}},
 {...base,headers:{...projection,contentLengthValid:false}},
 {...base,headers:{...projection,contentLength:body.length+1}},
 {...base,headers:{...projection,contentTypeIsHtml:false}},
 {...base,headers:{...projection,identityEncoding:false}},
 {...base,headers:{...projection,locationPresent:true}},
 {...base,headers:{...projection,challengeHeaderPresent:true}},
 {...base,body:Buffer.from(body.toString().replace('Ordinary publisher material.','Access Denied'))}
])check(()=>assert.equal(assessCapture(changed).captureEligibleForSeparateReview,false));
// Observed October24 TWC robot/JavaScript wording must remain a rejected capture,
// even if a challenge is served with HTTP200 and a substantial HTML shell.
// These are synthetic negative fixtures, not claimed raw publisher body bytes.
for(const phrase of ['JavaScript is disabled', "we need to verify that you're not a robot", 'Enable JavaScript and then reload the page'])check(()=>assert.equal(assessCapture({...base,body:Buffer.from(body.toString().replace('Ordinary publisher material.',phrase))}).captureEligibleForSeparateReview,false));
check(()=>{const challenge=Buffer.from(`<html><body><h1>JavaScript is disabled</h1><p>In order to continue, we need to verify that you're not a robot. This requires JavaScript. Enable JavaScript and then reload the page.</p><script>${'/* padding */'.repeat(50)}</script></body></html>`);const headers=sanitizeHeaders(Buffer.from(`HTTP/2 200\r\nContent-Type: text/html\r\nContent-Length: ${challenge.length}\r\n\r\n`));assert.equal(assessCapture({...base,body:challenge,headers,metadata:{...base.metadata,downloadedBytes:challenge.length}}).captureEligibleForSeparateReview,false);});
for(const rawHeader of [
 'HTTP/2 200\r\nContent-Type: text/html\r\nContent-Type: text/html\r\n\r\n',
 'HTTP/2 200\r\nContent-Type: text/html\r\nContent-Length: not-a-length\r\n\r\n',
 'HTTP/2 200\r\nContent-Type: text/html\r\nContent-Encoding: gzip\r\n\r\n',
 'HTTP/2 200\r\nContent-Type: text/html\r\nLocation: https://example.invalid/?PRIVATE_QUERY\r\n\r\n',
 'HTTP/2 200\r\nContent-Type: text/html\r\nContent-Range: bytes 0-50/200\r\n\r\n'
])check(()=>{const headers=sanitizeHeaders(Buffer.from(rawHeader));assert.equal(assessCapture({...base,headers}).captureEligibleForSeparateReview,false);assert.ok(!JSON.stringify(headers).includes('PRIVATE_QUERY'));});
for(const source of SOURCES)check(()=>{const args=curlArguments(source.url,'/tmp/owned-test-body');assert.equal(args[0],'-q');assert.equal(args.at(-1),source.url);for(const prohibited of ['-L','--location','--range','-r','--proxy','--cookie','--netrc','--insecure','-k'])assert.ok(!args.includes(prohibited));assert.equal(args[args.indexOf('--retry')+1],'0');assert.equal(args[args.indexOf('--max-redirs')+1],'0');assert.equal(args[args.indexOf('--dump-header')+1],'-');assert.ok(args[args.indexOf('--write-out')+1].startsWith('%{stderr}\nPAYDECODE_CAPTURE_RESULT_V1\t'));});
check(()=>assert.throws(()=>curlArguments('https://example.invalid/','/tmp/owned-test-body')));
check(()=>{const result=parseCurlMetadata(Buffer.from(`diagnostic not retained\nPAYDECODE_CAPTURE_RESULT_V1\t200\t${sourceUrl}\t0\ttext/html; charset=utf-8\t${body.length}\n`),sourceUrl);assert.deepEqual(result,{httpStatus:200,finalUrl:sourceUrl,reportedFinalUrlMatchedSource:true,redirectCount:0,contentTypeIsHtml:true,downloadedBytes:body.length});});
check(()=>assert.equal(parseCurlMetadata(Buffer.from('no marker'),sourceUrl).httpStatus,null));
// Exercise real inherited stdout/stderr plumbing without any network request,
// body file or raw header/diagnostic logging. curl's file source is /dev/null.
check(()=>{const result=spawnSync('/usr/bin/curl',['-q','--silent','--show-error','--dump-header','-','--output','/dev/null','--write-out','%{stderr}\nPAYDECODE_CAPTURE_RESULT_V1\t%{http_code}\t%{url_effective}\t%{num_redirects}\t%{content_type}\t%{size_download}\n','file:///dev/null'],{env:{PATH:process.env.PATH,LANG:'C',LC_ALL:'C'},encoding:'buffer',timeout:5000,maxBuffer:65536});assert.equal(result.error,undefined);assert.equal(result.signal,null);assert.equal(result.status,0);assert.ok(result.stderr.includes(Buffer.from('\nPAYDECODE_CAPTURE_RESULT_V1\t')));assert.ok(!result.stdout.includes(Buffer.from('PAYDECODE_CAPTURE_RESULT_V1')));assert.equal(parseCurlMetadata(result.stderr,'file:///dev/null').downloadedBytes,0);});
const toolPath=new URL('./capture-nm-tx-source-only.mjs',import.meta.url).pathname;
const guardEnv={PATH:process.env.PATH,GITHUB_ACTIONS:'true',GITHUB_REPOSITORY:'abuhasnatruhu/paydecode-source-health',GITHUB_REF:'refs/heads/main',GITHUB_WORKFLOW_REF:'abuhasnatruhu/paydecode-source-health/.github/workflows/nm-tx-source-capture-only.yml@refs/heads/main',GITHUB_SHA:'a'.repeat(40),GITHUB_RUN_ID:'1',GITHUB_RUN_ATTEMPT:'1',PAYDECODE_SOURCE_SHA:SOURCE_SHA};
for(const [args,env]of [
 [[toolPath,'/not-used','unknown-source'],guardEnv],
 [[toolPath,'/not-used','nm-wage-hour','https://example.invalid/'],guardEnv],
 [[toolPath,'/not-used','nm-wage-hour'],{...guardEnv,GITHUB_REF:'refs/heads/not-main'}],
 [[toolPath,'/not-used','nm-wage-hour'],{...guardEnv,PAYDECODE_SOURCE_SHA:'b'.repeat(40)}]
])check(()=>{const result=spawnSync(process.execPath,args,{env,encoding:'utf8',timeout:5000,maxBuffer:65536});assert.equal(result.error,undefined);assert.equal(result.signal,null);assert.equal(result.status,5);const message=JSON.parse(result.stderr.trim());assert.equal(message.phase,'invocation-validation');assert.equal(message.rawMessageOmitted,true);assert.equal(message.originalFilesPreserved,true);assert.equal(result.stdout,'');});
const tool=readFileSync(new URL('./capture-nm-tx-source-only.mjs',import.meta.url),'utf8');
check(()=>{assert.ok(!/\b(?:unlinkSync|rmSync|renameSync)\s*\(/u.test(tool));assert.ok(!/PAYDECODE_RECEIPT_SIGNING_KEY|PAYDECODE_SOURCE_TOKEN1/u.test(tool));assert.ok(tool.includes("const localEnv={PATH:process.env.PATH,LANG:'C',LC_ALL:'C'}"));assert.ok(tool.includes("stdio:['ignore','pipe','pipe']"));});
console.log(`PASS: ${checks} network-free fixed-scope, header-redaction, transport-failure and negative controls. No publisher GET, signing, admission or deployment performed.`);
