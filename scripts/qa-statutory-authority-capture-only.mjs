// Network-free pure negative controls. Import never invokes the capture entry.
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {spawnSync} from 'node:child_process';
import {SOURCE_SHA,SOURCES,sourceFor,curlArguments,parseCurlMetadata,sanitizeHeaders,assessTransport,assessCapture,assessPdfExtraction,runBoundedProcess,MAX_BODY_BYTES} from './capture-statutory-authority-only.mjs';
let checks=0;const check=fn=>{fn();checks++;};
check(()=>{assert.equal(SOURCE_SHA,'a53eedb0ce508918f21e5958e78a61d07cd4c542');assert.equal(SOURCES.length,3);assert.equal(sourceFor('anything-else'),undefined);});
const body=Buffer.from('<html><body><main>TITLE 11 LABOR AND WORKERS COMPENSATION PART 4 WAGE AND HOUR AND EMPLOYMENT OF CHILDREN 11.1.4.1 '+('Ordinary publisher material. '.repeat(30))+'</main></body></html>');
const raw=Buffer.from(`HTTP/2 200\r\nContent-Type: text/html; charset=windows-1252\r\nContent-Length: ${body.length}\r\nSet-Cookie: PRIVATE_COOKIE_VALUE\r\nAuthorization: PRIVATE_AUTH_VALUE\r\nX-Private-Trace: PRIVATE_TRACE_VALUE\r\n\r\n`);
const projection=sanitizeHeaders(raw);
check(()=>{const text=JSON.stringify(projection);for(const forbidden of ['PRIVATE_COOKIE_VALUE','PRIVATE_AUTH_VALUE','PRIVATE_TRACE_VALUE','X-Private-Trace','Set-Cookie'])assert.ok(!text.includes(forbidden));assert.equal(projection.rawHeadersRetained,false);assert.equal(projection.sensitiveHeaderValuesOmitted,true);});
const sourceUrl=SOURCES[0].url;
const base={body,headers:projection,processStatus:0,processSignal:null,processError:null,metadata:{httpStatus:200,finalUrl:sourceUrl,redirectCount:0,contentTypeIsHtml:true,contentTypeIsPdf:false,downloadedBytes:body.length},sourceUrl,streamLimitHit:false};
check(()=>assert.deepEqual(assessTransport(base),{captureEligibleForSeparateReview:true,failures:[]}));
for(const status of [202,206,301,302,403,404,500,null])check(()=>assert.equal(assessTransport({...base,metadata:{...base.metadata,httpStatus:status}}).captureEligibleForSeparateReview,false));
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
])check(()=>assert.equal(assessTransport(changed).captureEligibleForSeparateReview,false));
// Observed October24 TWC robot/JavaScript wording must remain a rejected capture,
// even if a challenge is served with HTTP200 and a substantial HTML shell.
// These are synthetic negative fixtures, not claimed raw publisher body bytes.
for(const phrase of ['JavaScript is disabled', "we need to verify that you're not a robot", 'Enable JavaScript and then reload the page'])check(()=>assert.equal(assessTransport({...base,body:Buffer.from(body.toString().replace('Ordinary publisher material.',phrase))}).captureEligibleForSeparateReview,false));
check(()=>{const challenge=Buffer.from(`<html><body><h1>JavaScript is disabled</h1><p>In order to continue, we need to verify that you're not a robot. This requires JavaScript. Enable JavaScript and then reload the page.</p><script>${'/* padding */'.repeat(50)}</script></body></html>`);const headers=sanitizeHeaders(Buffer.from(`HTTP/2 200\r\nContent-Type: text/html\r\nContent-Length: ${challenge.length}\r\n\r\n`));assert.equal(assessTransport({...base,body:challenge,headers,metadata:{...base.metadata,downloadedBytes:challenge.length}}).captureEligibleForSeparateReview,false);});
for(const rawHeader of [
 'HTTP/2 200\r\nContent-Type: text/html\r\nContent-Type: text/html\r\n\r\n',
 'HTTP/2 200\r\nContent-Type: text/html\r\nContent-Length: not-a-length\r\n\r\n',
 'HTTP/2 200\r\nContent-Type: text/html\r\nContent-Encoding: gzip\r\n\r\n',
 'HTTP/2 200\r\nContent-Type: text/html\r\nLocation: https://example.invalid/?PRIVATE_QUERY\r\n\r\n',
 'HTTP/2 200\r\nContent-Type: text/html\r\nContent-Range: bytes 0-50/200\r\n\r\n'
])check(()=>{const headers=sanitizeHeaders(Buffer.from(rawHeader));assert.equal(assessTransport({...base,headers}).captureEligibleForSeparateReview,false);assert.ok(!JSON.stringify(headers).includes('PRIVATE_QUERY'));});
for(const source of SOURCES)check(()=>{const args=curlArguments(source.url,'/tmp/owned-test-body');assert.equal(args[0],'-q');assert.equal(args.at(-1),source.url);for(const prohibited of ['-L','--location','--range','-r','--proxy','--cookie','--netrc','--insecure','-k'])assert.ok(!args.includes(prohibited));assert.equal(args[args.indexOf('--retry')+1],'0');assert.equal(args[args.indexOf('--max-redirs')+1],'0');assert.equal(args[args.indexOf('--dump-header')+1],'-');assert.ok(args[args.indexOf('--write-out')+1].startsWith('%{stderr}\nPAYDECODE_CAPTURE_RESULT_V1\t'));});
check(()=>assert.throws(()=>curlArguments('https://example.invalid/','/tmp/owned-test-body')));
check(()=>{const result=parseCurlMetadata(Buffer.from(`diagnostic not retained\nPAYDECODE_CAPTURE_RESULT_V1\t200\t${sourceUrl}\t0\ttext/html; charset=windows-1252\t${body.length}\n`),sourceUrl);assert.deepEqual(result,{httpStatus:200,finalUrl:sourceUrl,reportedFinalUrlMatchedSource:true,redirectCount:0,contentTypeIsHtml:true,contentTypeIsPdf:false,downloadedBytes:body.length});});
check(()=>assert.equal(parseCurlMetadata(Buffer.from('no marker'),sourceUrl).httpStatus,null));
// Exercise real inherited stdout/stderr plumbing without any network request,
// body file or raw header/diagnostic logging. curl's file source is /dev/null.
check(()=>{const result=spawnSync('/usr/bin/curl',['-q','--silent','--show-error','--dump-header','-','--output','/dev/null','--write-out','%{stderr}\nPAYDECODE_CAPTURE_RESULT_V1\t%{http_code}\t%{url_effective}\t%{num_redirects}\t%{content_type}\t%{size_download}\n','file:///dev/null'],{env:{PATH:process.env.PATH,LANG:'C',LC_ALL:'C'},encoding:'buffer',timeout:5000,maxBuffer:65536});assert.equal(result.error,undefined);assert.equal(result.signal,null);assert.equal(result.status,0);assert.ok(result.stderr.includes(Buffer.from('\nPAYDECODE_CAPTURE_RESULT_V1\t')));assert.ok(!result.stdout.includes(Buffer.from('PAYDECODE_CAPTURE_RESULT_V1')));assert.equal(parseCurlMetadata(result.stderr,'file:///dev/null').downloadedBytes,0);});
const toolPath=new URL('./capture-statutory-authority-only.mjs',import.meta.url).pathname;
const guardEnv={PATH:process.env.PATH,GITHUB_ACTIONS:'true',GITHUB_REPOSITORY:'abuhasnatruhu/paydecode-source-health',GITHUB_REF:'refs/heads/main',GITHUB_WORKFLOW_REF:'abuhasnatruhu/paydecode-source-health/.github/workflows/statutory-authority-capture-only.yml@refs/heads/main',GITHUB_SHA:'a'.repeat(40),GITHUB_RUN_ID:'1',GITHUB_RUN_ATTEMPT:'1',PAYDECODE_SOURCE_SHA:SOURCE_SHA};
for(const [args,env]of [
 [[toolPath,'/not-used','unknown-source'],guardEnv],
 [[toolPath,'/not-used','nm-nmac-11-1-4','https://example.invalid/'],guardEnv],
 [[toolPath,'/not-used','nm-nmac-11-1-4'],{...guardEnv,GITHUB_REF:'refs/heads/not-main'}],
 [[toolPath,'/not-used','nm-nmac-11-1-4'],{...guardEnv,PAYDECODE_SOURCE_SHA:'b'.repeat(40)}]
])check(()=>{const result=spawnSync(process.execPath,args,{env,encoding:'utf8',timeout:5000,maxBuffer:65536});assert.equal(result.error,undefined);assert.equal(result.signal,null);assert.equal(result.status,5);const message=JSON.parse(result.stderr.trim());assert.equal(message.phase,'invocation-validation');assert.equal(message.rawMessageOmitted,true);assert.equal(message.originalFilesPreserved,true);assert.equal(result.stdout,'');});
const tool=readFileSync(new URL('./capture-statutory-authority-only.mjs',import.meta.url),'utf8');
check(()=>{assert.ok(!/\b(?:unlinkSync|rmSync|renameSync)\s*\(/u.test(tool));assert.ok(!/PAYDECODE_RECEIPT_SIGNING_KEY|PAYDECODE_SOURCE_TOKEN1/u.test(tool));assert.ok(tool.includes("const localEnv={PATH:process.env.PATH,LANG:'C',LC_ALL:'C'}"));assert.ok(tool.includes("stdio:['ignore','pipe','pipe']"));});


const expectedPolicies=[
 ['nm-nmac-11-1-4','https://www.srca.nm.gov/parts/title11/11.001.0004.html','html','windows-1252',95051,'da060f4b597011d5f3f549f5f5e98550863434a60220c6605c68613a14c2cb3c'],
 ['nm-nmsa-chapter50','https://nmonesource.com/nmos/nmsa/en/4420/1/document.do','pdf','binary',1014563,'e863a245c6db622d2a98e3124b164f2fe53840ac686e54c6275d6d1654b8e4e1'],
 ['tx-labor62','https://tcss.legis.texas.gov/resources/LA/htm/LA.62.htm','html','utf-8',33742,'22d2af1a00c952f74d69a2861e9a2437d14e395e2490bebdb33cbb3522dfb792']
];
check(()=>assert.deepEqual(SOURCES.map(s=>[s.id,s.url,s.kind,s.encoding,s.expectedBytes,s.expectedSha256]),expectedPolicies));
check(()=>{assert.ok(Object.isFrozen(SOURCES));for(const s of SOURCES){assert.ok(Object.isFrozen(s));assert.ok(Object.isFrozen(s.requiredText));assert.throws(()=>{s.expectedSha256='a'.repeat(64);},TypeError);}});
const fixture=(source,bytes,type)=>({body:bytes,headers:sanitizeHeaders(Buffer.from(`HTTP/2 200\r\nContent-Type: ${type}\r\nContent-Length: ${bytes.length}\r\n\r\n`)),processStatus:0,processSignal:null,processError:null,metadata:{httpStatus:200,finalUrl:source.url,redirectCount:0,contentTypeIsHtml:source.kind==='html',contentTypeIsPdf:source.kind==='pdf',downloadedBytes:bytes.length},sourceUrl:source.url,streamLimitHit:false});
const pdfBody=Buffer.from('%PDF-1.5\n'+('SYNTHETIC FORMAT FIXTURE ONLY\n'.repeat(40))+'%%EOF\n');
const pdfFixture=fixture(SOURCES[1],pdfBody,'application/pdf');
const txBody=Buffer.from('<html><body>LABOR CODE CHAPTER 62. MINIMUM WAGE Sec. 62.051. Sec. 62.151. '+('Synthetic material. '.repeat(40))+'</body></html>');
const txFixture=fixture(SOURCES[2],txBody,'text/html');
for(const f of [base,pdfFixture,txFixture]){
 check(()=>assert.equal(assessTransport(f).captureEligibleForSeparateReview,true));
 // Synthetic format fixtures MUST NEVER become signature-eligible reviewed captures.
 check(()=>{const a=assessCapture(f);assert.equal(a.captureEligibleForSeparateReview,false);assert.ok(a.failures.includes('reviewed-body-sha256-pin-mismatch'));assert.ok(a.failures.includes('reviewed-body-length-pin-mismatch'));});
}
for(const f of [
 {...base,headers:{...base.headers,charset:'utf-8'}},
 {...txFixture,headers:{...txFixture.headers,charset:'windows-1252'}},
 {...txFixture,body:Buffer.from('<html><body>'+('Wrong chapter material. '.repeat(40))+'</body></html>')},
 {...pdfFixture,body:Buffer.from('<html><body>'+('Access Denied '.repeat(100))+'</body></html>')},
 {...pdfFixture,body:pdfBody.subarray(0,pdfBody.length-8)},
 {...pdfFixture,headers:{...pdfFixture.headers,contentTypeIsPdf:false}},
 {...pdfFixture,metadata:{...pdfFixture.metadata,contentTypeIsPdf:false}},
 {...pdfFixture,metadata:{...pdfFixture.metadata,httpStatus:206}},
 {...pdfFixture,headers:{...pdfFixture.headers,contentRangePresent:true}},
 {...base,sourceUrl:'https://www.srca.nm.gov/parts/title11/11.001.0004.html?different=1'},
 {...txFixture,body:Buffer.concat([txBody,Buffer.from([0xff])])}
])check(()=>assert.equal(assessTransport(f).captureEligibleForSeparateReview,false));
check(()=>{const good=parseCurlMetadata(Buffer.from(`\nPAYDECODE_CAPTURE_RESULT_V1\t200\t${SOURCES[1].url}\t0\tapplication/pdf\t1014563\n`),SOURCES[1].url);assert.equal(good.contentTypeIsPdf,true);assert.equal(good.contentTypeIsHtml,false);});
check(()=>{const p=sanitizeHeaders(Buffer.from('HTTP/2 200\r\nContent-Type: application/pdf\r\n\r\n'));assert.equal(p.contentTypeIsPdf,true);assert.equal(p.contentTypeIsHtml,false);assert.equal(p.charset,null);});
const complete={status:0,signal:null,errorCode:null,limitHit:false};
const textFixture=Buffer.from(('Synthetic page text for transport extraction control. '.repeat(10)+'\f').repeat(175));
const extractFixture={info:Buffer.from('Pages:          175\nEncrypted:      no\n'),text:textFixture,infoOutcome:complete,textOutcome:complete};
check(()=>assert.deepEqual(assessPdfExtraction(extractFixture),{completeExtraction:true,failures:[],pagesExpected:175,formFeedCount:175,legalReviewAdmitted:false}));
for(const f of [
 {...extractFixture,info:Buffer.from('Pages: 174\nEncrypted: no\n')},
 {...extractFixture,info:Buffer.from('Pages: 175\nEncrypted: yes\n')},
 {...extractFixture,text:Buffer.alloc(0)},
 {...extractFixture,text:Buffer.alloc(4*1024*1024+1)},
 {...extractFixture,text:Buffer.from(textFixture.toString().replace(/\f$/u,''))},
 {...extractFixture,text:Buffer.concat([textFixture,Buffer.from([0xff])])},
 {...extractFixture,infoOutcome:{...complete,status:1}},
 {...extractFixture,textOutcome:{...complete,signal:'SIGTERM'}},
 {...extractFixture,textOutcome:{...complete,errorCode:'PROCESS_TIMEOUT'}},
 {...extractFixture,textOutcome:{...complete,limitHit:true}}
])check(()=>assert.equal(assessPdfExtraction(f).completeExtraction,false));
for(const [channel,code]of [['stdout','process.stdout.write("x".repeat(1024))'],['stderr','process.stderr.write("x".repeat(1024))']]){
 const outcome=await runBoundedProcess(process.execPath,['-e',code],{env:{PATH:process.env.PATH},stdoutLimit:64,stderrLimit:64,timeoutMs:2000});
 check(()=>{assert.equal(outcome.limitHit,true);assert.equal(outcome[channel].length,64);assert.ok(outcome[channel+'ObservedBytes']>64);});
}
const timed=await runBoundedProcess(process.execPath,['-e','setTimeout(()=>{},5000)'],{env:{PATH:process.env.PATH},timeoutMs:50});
check(()=>assert.equal(timed.errorCode,'PROCESS_TIMEOUT'));
for(const env of [
 {...guardEnv,GITHUB_REPOSITORY:'example/other'},
 {...guardEnv,GITHUB_WORKFLOW_REF:'abuhasnatruhu/paydecode-source-health/.github/workflows/old.yml@refs/heads/main'},
 {...guardEnv,GITHUB_RUN_ID:'0'},
 {...guardEnv,GITHUB_RUN_ATTEMPT:'0'}
])check(()=>{const r=spawnSync(process.execPath,[toolPath,'/not-used','nm-nmac-11-1-4'],{env,encoding:'utf8',timeout:5000,maxBuffer:65536});assert.equal(r.status,5);assert.equal(JSON.parse(r.stderr.trim()).phase,'invocation-validation');assert.equal(r.stdout,'');});
check(()=>{const r=spawnSync(process.execPath,[toolPath,'--extract-pdf','/not-used','../bad'],{env:{PATH:process.env.PATH},encoding:'utf8',timeout:5000,maxBuffer:65536});assert.equal(r.status,7);assert.equal(JSON.parse(r.stderr.trim()).phase,'pdf-invocation-validation');assert.equal(r.stdout,'');});
const workflow=readFileSync(new URL('../.github/workflows/statutory-authority-capture-only.yml',import.meta.url),'utf8');
check(()=>{assert.ok(workflow.includes('workflow_dispatch:'));for(const x of ['inputs:','pull_request:','schedule:','workflow_call:','contents: write','id-token: write'])assert.ok(!workflow.includes(x));assert.ok(workflow.includes('contents: read'));assert.ok(workflow.includes('source_id: [nm-nmac-11-1-4, nm-nmsa-chapter50, tx-labor62]'));});
check(()=>{assert.deepEqual([...new Set([...workflow.matchAll(/secrets\.([A-Z0-9_]+)/gu)].map(m=>m[1]))].sort(),['PAYDECODE_RECEIPT_SIGNING_KEY','PAYDECODE_SOURCE_TOKEN1']);assert.ok(workflow.includes('PAYDECODE_SOURCE_SHA: '+SOURCE_SHA));for(const use of workflow.matchAll(/uses:\s*(\S+)/gu))assert.match(use[1],/^actions\/(?:checkout|setup-node|upload-artifact)@[0-9a-f]{40}$/u);});
check(()=>{for(const pin of ['2e84076661a2382b2c277ba76c2dcd262d28972760804594339fe9b5441f2df5','f66c56b4744a762fe2ef75cacfe97fa8d5dbd7ffce48c55a1b9aafd7a142411a','3b63308793c627ae29a972dbd188708d43afbacc221e2dadd1e2bccf0ff719c9','8e5e7d259a5ed672c84a5281c97094345f480ba7eaa4d8c21755fa007bfd9ecb'])assert.ok(workflow.includes(pin));assert.ok(workflow.includes("steps.capture.outcome == 'success'"));assert.ok(workflow.includes("always() && steps.capture.outputs.capture_dir != ''"));assert.ok(workflow.includes("always() && steps.pdf.outputs.pdf_dir != ''"));});
check(()=>{for(const phrase of ['dpkg --verify poppler-utils','AllowInsecureRepositories=false','AllowDowngradeToInsecureRepositories=false','AllowUnauthenticated=false','--extract-pdf source "$CAPTURE_DIRECTORY"','overwrite: false'])assert.ok(workflow.includes(phrase));assert.ok(tool.includes("new TextDecoder(source.encoding,{fatal:true})"));assert.ok(tool.includes("if(digest(input.body)!==source.expectedSha256)"));assert.ok(tool.includes("stdoutLimit:4*1024*1024"));assert.ok(tool.includes("timeoutMs=20000"));assert.ok(!/\b(?:unlinkSync|rmSync|renameSync)\s*\(/u.test(tool));});
console.log(`PASS: ${checks} network-free fixed-target, reviewed-identity, HTML/PDF/encoding, privacy, bounded extraction and negative provenance controls. Synthetic fixtures are NOT signature-eligible; no publisher GET, signing, admission or deployment performed.`);

