// One fixed ordinary GET; no signing/admission or source mutation.
import assert from 'node:assert/strict';
import {spawn, spawnSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';

export const SOURCE_SHA='a53eedb0ce508918f21e5958e78a61d07cd4c542';
export const RUNNER_REPOSITORY='abuhasnatruhu/paydecode-source-health';
export const WORKFLOW_PATH='.github/workflows/statutory-authority-capture-only.yml';
export const USER_AGENT='PayDecode source maintenance (contact: hello@paydecode.com)';
export const MAX_BODY_BYTES=2*1024*1024;
export const MAX_HEADER_BYTES=64*1024;
export const MAX_DIAGNOSTIC_BYTES=16*1024;
export const SOURCES=Object.freeze([
 Object.freeze({id:'nm-nmac-11-1-4',url:'https://www.srca.nm.gov/parts/title11/11.001.0004.html',kind:'html',encoding:'windows-1252',expectedBytes:95051,expectedSha256:'da060f4b597011d5f3f549f5f5e98550863434a60220c6605c68613a14c2cb3c',requiredText:Object.freeze(['TITLE 11 LABOR AND WORKERS COMPENSATION','PART 4 WAGE AND HOUR AND EMPLOYMENT OF CHILDREN','11.1.4.1'])}),
 Object.freeze({id:'nm-nmsa-chapter50',url:'https://nmonesource.com/nmos/nmsa/en/4420/1/document.do',kind:'pdf',encoding:'binary',expectedBytes:1014563,expectedSha256:'e863a245c6db622d2a98e3124b164f2fe53840ac686e54c6275d6d1654b8e4e1',requiredText:Object.freeze([])}),
 Object.freeze({id:'tx-labor62',url:'https://tcss.legis.texas.gov/resources/LA/htm/LA.62.htm',kind:'html',encoding:'utf-8',expectedBytes:33742,expectedSha256:'22d2af1a00c952f74d69a2861e9a2437d14e395e2490bebdb33cbb3522dfb792',requiredText:Object.freeze(['LABOR CODE CHAPTER 62. MINIMUM WAGE','Sec. 62.051.','Sec. 62.151.'])})
]);
export const sourceFor=id=>SOURCES.find(item=>item.id===id);
const digest=bytes=>createHash('sha256').update(bytes).digest('hex');
const encode=value=>Buffer.from(JSON.stringify(value,null,2)+'\n');
const safeCode=value=>typeof value==='string'&&/^[A-Z0-9_]{1,40}$/u.test(value)?value:null;

// Raw headers are processed only in bounded memory. No cookie, authentication,
// redirect target, IP, server ID, arbitrary header name/value or raw line leaks.
export function sanitizeHeaders(bytes,{truncated=false}={}){
 const text=bytes.toString('latin1');
 const blocks=text.trim().split(/\r?\n\r?\n+/u).filter(Boolean);
 const block=blocks.at(-1)??'';
 const lines=block.split(/\r?\n/u);
 const statusMatch=lines[0]?.match(/^HTTP\/(1\.0|1\.1|2|3) ([0-9]{3})(?:\s|$)/u);
 const values=name=>lines.slice(1).filter(line=>new RegExp(`^${name}:`,'iu').test(line)).map(line=>line.slice(line.indexOf(':')+1).trim());
 const types=values('content-type'),lengths=values('content-length'),encodings=values('content-encoding');
 const ranges=values('content-range');
 const lengthValid=lengths.length===0||(lengths.length===1&&/^[0-9]{1,16}$/u.test(lengths[0])&&Number.isSafeInteger(Number(lengths[0])));
 const typeIsHtml=types.length===1&&/^text\/html(?:;|$)/iu.test(types[0]);
 const typeIsPdf=types.length===1&&/^application\/pdf(?:;|$)/iu.test(types[0]);
 const charsetMatch=types.length===1?types[0].match(/;\s*charset\s*=\s*["']?([a-z0-9_-]+)["']?(?:\s*;|\s*$)/iu):null;
 const charsets=new Set(['windows-1252','utf-8','us-ascii','iso-8859-1']);
 const charset=charsetMatch?(charsets.has(charsetMatch[1].toLowerCase())?charsetMatch[1].toLowerCase():'other'):null;
 const identityEncoding=encodings.length===0||(encodings.length===1&&encodings[0].toLowerCase()==='identity');
 const observedLines=blocks.flatMap(item=>item.split(/\r?\n/u).slice(1));
 return {
  schemaVersion:'sanitized-response-headers.v1',
  rawHeadersRetained:false,rawHeadersLogged:false,
  observedRawHeaderSha256:digest(bytes),observedRawHeaderBytes:bytes.length,
  observedRawHeadersTruncated:truncated,
  headerTerminationComplete:/\r?\n\r?\n$/u.test(text),
  headerBlockCount:blocks.length,
  protocol:statusMatch?.[1]??null,status:statusMatch?Number(statusMatch[2]):null,
  contentTypeHeaderCount:types.length,contentTypeIsHtml:typeIsHtml,contentTypeIsPdf:typeIsPdf,charset,
  contentLengthHeaderCount:lengths.length,contentLengthValid:lengthValid,
  contentLength:lengths.length===1&&lengthValid?Number(lengths[0]):null,
  contentEncodingHeaderCount:encodings.length,identityEncoding,
  contentRangePresent:ranges.length>0,
  locationPresent:values('location').length>0,
  challengeHeaderPresent:values('cf-mitigated').some(value=>value.toLowerCase()==='challenge'),
  sensitiveHeaderValuesOmitted:observedLines.some(line=>/^(?:set-cookie|cookie|authorization|proxy-authorization|www-authenticate|proxy-authenticate):/iu.test(line)),
  omittedHeaderLineCount:observedLines.filter(line=>! /^(?:content-type|content-length|content-encoding|content-range|location|cf-mitigated):/iu.test(line)).length
 };
}

// Pure transport/format checks are separately testable with synthetic bodies.
// The production eligibility wrapper below ALWAYS uses the immutable fixed pins.
export function assessTransport({body,headers,processStatus,processSignal,processError,metadata,sourceUrl,streamLimitHit=false}){
 const failures=[],source=SOURCES.find(item=>item.url===sourceUrl);
 if(!source)return {captureEligibleForSeparateReview:false,failures:['unknown-fixed-source']};
 if(processStatus!==0||processSignal||processError)failures.push('curl-process-failed');
 if(streamLimitHit)failures.push('response-metadata-limit');
 if(metadata.httpStatus!==200)failures.push('not-http200');
 if(metadata.finalUrl!==sourceUrl||metadata.redirectCount!==0)failures.push('not-exact-no-redirect-url');
 const isHtml=source.kind==='html';
 if((isHtml?metadata.contentTypeIsHtml:metadata.contentTypeIsPdf)!==true)failures.push('wrong-content-type');
 if(body.length<500||body.length>MAX_BODY_BYTES)failures.push('empty-nonsubstantive-or-oversized-body');
 if(metadata.downloadedBytes!==body.length)failures.push('download-size-mismatch');
 if(headers.observedRawHeadersTruncated||headers.headerTerminationComplete!==true||headers.headerBlockCount!==1||headers.status!==200||headers.protocol===null)failures.push('unexpected-or-incomplete-response-headers');
 if(headers.contentRangePresent)failures.push('unexpected-content-range');
 if(!headers.contentLengthValid||(headers.contentLength!==null&&headers.contentLength!==body.length))failures.push('content-length-mismatch');
 if((isHtml?headers.contentTypeIsHtml:headers.contentTypeIsPdf)!==true)failures.push('raw-content-type-mismatch');
 if(!headers.identityEncoding)failures.push('unexpected-compressed-body');
 if(headers.locationPresent)failures.push('unexpected-redirect-location');
 if(isHtml&&source.encoding==='windows-1252'&&headers.charset!=='windows-1252')failures.push('wrong-publisher-charset');
 if(isHtml&&source.encoding==='utf-8'&&headers.charset!==null&&headers.charset!=='utf-8')failures.push('wrong-publisher-charset');
 let decoded='';
 if(isHtml){
  try{decoded=new TextDecoder(source.encoding,{fatal:true}).decode(body);}catch{failures.push('invalid-publisher-text-encoding');}
  if(!/<(?:html|body|main|article)(?:\s|>)/iu.test(decoded))failures.push('nonsubstantive-html');
  const normalized=decoded.replace(/<[^>]*>/gu,' ').replace(/\s+/gu,' ').trim();
  if(source.requiredText.some(text=>!normalized.includes(text)))failures.push('missing-target-html-markers');
 }else if(!body.subarray(0,8).toString('latin1').startsWith('%PDF-')||!/%%EOF\s*$/u.test(body.subarray(-1024).toString('latin1')))failures.push('incomplete-or-non-pdf-body');
 const challengeText=isHtml?decoded:body.subarray(0,16384).toString('latin1');
 if(headers.challengeHeaderPresent||/Just a moment\.\.\.|Verify you are human|Performing security verification|Due to aggressive automated scraping|Please enable JavaScript to view|Access Denied|The requested URL was rejected|One moment, please\.\.\.|JavaScript is disabled|not a robot|Enable JavaScript and then reload the page/iu.test(challengeText))failures.push('challenge-or-access-denial-body');
 return {captureEligibleForSeparateReview:failures.length===0,failures};
}

export function assessCapture(input){
 const transport=assessTransport(input),failures=[...transport.failures],source=SOURCES.find(item=>item.url===input.sourceUrl);
 if(!source) return transport;
 if(input.body.length!==source.expectedBytes)failures.push('reviewed-body-length-pin-mismatch');
 if(digest(input.body)!==source.expectedSha256)failures.push('reviewed-body-sha256-pin-mismatch');
 return {captureEligibleForSeparateReview:failures.length===0,failures};
}

export function curlArguments(sourceUrl,bodyPath){
 assert.ok(SOURCES.some(source=>source.url===sourceUrl),'Fixed source URL only');
 return ['-q','--silent','--show-error','--noproxy','*','--proto','=https','--request','GET',
  '--max-redirs','0','--retry','0','--connect-timeout','15','--max-time','20',
  '--max-filesize',String(MAX_BODY_BYTES),'--user-agent',USER_AGENT,
  '--header','Accept-Encoding: identity','--dump-header','-','--output',bodyPath,
  '--write-out','%{stderr}\nPAYDECODE_CAPTURE_RESULT_V1\t%{http_code}\t%{url_effective}\t%{num_redirects}\t%{content_type}\t%{size_download}\n',sourceUrl];
}

export function parseCurlMetadata(stderr,sourceUrl){
 const marker='\nPAYDECODE_CAPTURE_RESULT_V1\t',text=stderr.toString('utf8'),index=text.lastIndexOf(marker);
 const fields=index<0?[]:text.slice(index+marker.length).trim().split('\t');
 const [status,reportedFinalUrl,redirects,type,downloaded]=fields.length===5?fields:[];
 return {httpStatus:/^[0-9]{3}$/u.test(status??'')?Number(status):null,finalUrl:reportedFinalUrl===sourceUrl?sourceUrl:null,reportedFinalUrlMatchedSource:reportedFinalUrl===sourceUrl,redirectCount:/^[0-9]+$/u.test(redirects??'')?Number(redirects):null,contentTypeIsHtml:/^text\/html(?:;|$)/iu.test(type??''),contentTypeIsPdf:/^application\/pdf(?:;|$)/iu.test(type??''),downloadedBytes:/^[0-9]+$/u.test(downloaded??'')?Number(downloaded):null};
}

async function captureMain(){
 process.umask(0o077);
 let attemptDirectory,phase='invocation-validation';
 const writeNew=(file,bytes)=>fs.writeFileSync(file,bytes,{flag:'wx',mode:0o600});
 const localEnv={PATH:process.env.PATH,LANG:'C',LC_ALL:'C'};
 try{
  assert.equal(process.argv.length,4,'Only source-root and fixed source ID accepted');
  const source=sourceFor(process.argv[3]);assert.ok(source,'Only three reviewed fixed authority IDs accepted');
  assert.equal(process.versions.node,'24.14.0');
  assert.equal(process.env.GITHUB_ACTIONS,'true');assert.equal(process.env.GITHUB_REPOSITORY,RUNNER_REPOSITORY);assert.equal(process.env.GITHUB_REF,'refs/heads/main');
  assert.equal(process.env.GITHUB_WORKFLOW_REF,`${RUNNER_REPOSITORY}/${WORKFLOW_PATH}@refs/heads/main`);
  for(const key of ['GITHUB_SHA'])assert.match(process.env[key]??' ',/^[0-9a-f]{40}$/u);
  for(const key of ['GITHUB_RUN_ID','GITHUB_RUN_ATTEMPT'])assert.match(process.env[key]??' ',/^[1-9][0-9]*$/u);
  assert.equal(process.env.PAYDECODE_SOURCE_SHA,SOURCE_SHA);
  const sourceRoot=path.resolve(process.argv[2]);assert.equal(fs.realpathSync(sourceRoot),sourceRoot);
  const head=spawnSync('git',['--no-replace-objects','-C',sourceRoot,'rev-parse','HEAD'],{encoding:'utf8',env:localEnv,timeout:10000});
  assert.equal(head.status,0);assert.equal(head.stdout.trim(),SOURCE_SHA);
  const createdAt=new Date().toISOString();
  const relativeDirectory=`research/source-captures/${createdAt.slice(0,10)}-run${process.env.GITHUB_RUN_ID}/statutory-authority-${source.id}-attempt${process.env.GITHUB_RUN_ATTEMPT}`;
  let current=sourceRoot;
  const parts=relativeDirectory.split('/');
  for(const [index,part]of parts.entries()){
   current=path.join(current,part);
   let previous;try{previous=fs.lstatSync(current);}catch(error){if(error.code!=='ENOENT')throw error;}
   if(previous){assert.equal(previous.isSymbolicLink(),false);assert.equal(previous.isDirectory(),true);assert.ok(index<parts.length-1,'Never overwrite an existing attempt');}
   else fs.mkdirSync(current,{mode:0o700});
  }
  attemptDirectory=current;
  assert.ok(process.env.GITHUB_OUTPUT);fs.appendFileSync(process.env.GITHUB_OUTPUT,`capture_dir=${relativeDirectory}\n`);
  writeNew(path.join(current,'invocation.json'),encode({schemaVersion:1,createdAt,sourceId:source.id,sourceUrl:source.url,sourceSha:SOURCE_SHA,sourceRepository:'abuhasnatruhu/paydecode.com',runnerRepository:RUNNER_REPOSITORY,workflowPath:WORKFLOW_PATH,workflowSha:process.env.GITHUB_SHA,githubRunId:process.env.GITHUB_RUN_ID,githubRunAttempt:process.env.GITHUB_RUN_ATTEMPT,method:'GET',range:null,redirectsFollowed:0,retries:0,archiveRequests:0,cookiesOrCredentials:false,proxy:false,bodyLimitBytes:MAX_BODY_BYTES,headerLimitBytes:MAX_HEADER_BYTES,diagnosticLimitBytes:MAX_DIAGNOSTIC_BYTES,connectTimeoutSeconds:15,requestTimeoutSeconds:20,headersSanitized:true,rawHeadersRetained:false,rawHeadersLogged:false,signingPerformedByThisTool:false,sourceReviewAdmission:false,outputDirectory:relativeDirectory}));
  phase='curl-runtime-check';
  const curl='/usr/bin/curl',stat=fs.lstatSync(curl);assert.ok(stat.isFile()&&!stat.isSymbolicLink());assert.equal(stat.uid,0);
  const version=spawnSync(curl,['-q','--version'],{encoding:'utf8',env:localEnv,timeout:5000,maxBuffer:65536});
  const match=version.stdout?.match(/^curl ([0-9]+)\.([0-9]+)\.([0-9]+)/u);
  writeNew(path.join(current,'curl-runtime.json'),encode({exitCode:version.status,version:match?match.slice(1,4).map(Number).join('.'):null,stdoutSha256:digest(Buffer.from(version.stdout??'')),stderrSha256:digest(Buffer.from(version.stderr??'')),rawOutputRetained:false}));
  assert.equal(version.status,0);assert.ok(match&&(Number(match[1])>8||(Number(match[1])===8&&Number(match[2])>=4)),'curl>=8.4 required for unknown-length download bound');
  const rawBody=path.join(current,'body.raw');writeNew(rawBody,Buffer.alloc(0));
  const args=curlArguments(source.url,rawBody);writeNew(path.join(current,'curl-arguments.json'),encode(args));
  phase='one-ordinary-get';
  const startedAt=new Date().toISOString();
  const observed=await new Promise(resolve=>{
   const buffers={stdout:[],stderr:[]},sizes={stdout:0,stderr:0},caps={stdout:MAX_HEADER_BYTES,stderr:MAX_DIAGNOSTIC_BYTES};
   let child,errorCode=null,limitHit=false,killTimer;
   const terminate=()=>{if(!child)return;child.kill('SIGTERM');killTimer??=setTimeout(()=>child.kill('SIGKILL'),3000);};
   try{child=spawn(curl,args,{env:localEnv,stdio:['ignore','pipe','pipe']});}catch(error){resolve({status:null,signal:null,errorCode:safeCode(error.code)||'SPAWN_ERROR',streamLimitHit:false,stdout:Buffer.alloc(0),stderr:Buffer.alloc(0),headersTruncated:false});return;}
   const timeout=setTimeout(()=>{errorCode='PARENT_TIMEOUT';terminate();},25000);
   const accept=(channel,bytes)=>{const room=Math.max(0,caps[channel]-sizes[channel]);if(room)buffers[channel].push(bytes.subarray(0,room));sizes[channel]+=bytes.length;if(sizes[channel]>caps[channel]){limitHit=true;terminate();}};
   for(const [channel,stream]of [['stdout',child.stdout],['stderr',child.stderr]]){stream.on('data',bytes=>accept(channel,bytes));stream.on('error',()=>{errorCode='PIPE_ERROR';terminate();});}
   child.on('error',error=>{errorCode=safeCode(error.code)||'CHILD_ERROR';});
   child.on('close',(status,signal)=>{clearTimeout(timeout);if(killTimer)clearTimeout(killTimer);resolve({status,signal,errorCode,streamLimitHit:limitHit,stdout:Buffer.concat(buffers.stdout),stderr:Buffer.concat(buffers.stderr),headersTruncated:sizes.stdout>caps.stdout});});
  });
  const receivedAt=new Date().toISOString();
  phase='sanitize-and-retain';
  const metadata=parseCurlMetadata(observed.stderr,source.url);
  const body=fs.readFileSync(rawBody),headers=sanitizeHeaders(observed.stdout,{truncated:observed.headersTruncated});
  const retain=(bytes,kind,extension)=>{const sha256=digest(bytes),filename=`${source.id}-${kind}.${sha256}.${extension}`;writeNew(path.join(current,filename),bytes);return{retainedPath:`${relativeDirectory}/${filename}`,sha256,byteLength:bytes.length};};
  const bodyRef=retain(body,'body','bin'),headersRef=retain(encode(headers),'sanitized-headers','json');
  const diagnostics={processExitCode:observed.status,processSignal:observed.signal,processErrorCode:observed.errorCode,streamLimitHit:observed.streamLimitHit,rawStdoutRetained:false,rawStderrRetained:false,stdoutObservedBytes:observed.stdout.length,stdoutObservedSha256:digest(observed.stdout),stderrObservedBytes:observed.stderr.length,stderrObservedSha256:digest(observed.stderr),metadata};
  writeNew(path.join(current,'curl-process.json'),encode(diagnostics));
  const assessment=assessCapture({body,headers,processStatus:observed.status,processSignal:observed.signal,processError:observed.errorCode,metadata,sourceUrl:source.url,streamLimitHit:observed.streamLimitHit});
  const receipt={schemaVersion:1,evidenceType:'ordinary-direct-http-attempt',name:`statutory-authority-${source.id}`,sourceUrl:source.url,startedAt,receivedAt,curlExitCode:observed.status,httpStatus:metadata.httpStatus,finalUrl:metadata.finalUrl,redirectCount:metadata.redirectCount,contentType:metadata.contentTypeIsHtml?'text/html':metadata.contentTypeIsPdf?'application/pdf':null,bodyEncoding:source.encoding,reviewedBodyIdentity:{sha256:source.expectedSha256,byteLength:source.expectedBytes},body:bodyRef,headers:headersRef,headersAreSanitized:true,headerRepresentation:'sanitized-response-headers.v1',rawResponseHeadersRetained:false,rawStderrRetained:false,transportMethod:'Single credential-free ordinary full curl GET to one fixed URL. No Range, proxy, cookies, redirects, retries, archive or challenge handling. Original success/failure body bytes and a sanitized header projection are retained; raw response headers and raw diagnostic text are not retained or logged.',limitations:['Transport only, not legal/content/source-review admission or release approval.','The headers artifact is an explicit sanitized projection, not the original response-header bytes.','Failed, partial, redirected, challenged or oversized attempts remain failures; no fallback.','A separately produced runner signature authenticates the receipt and predecessor source SHA, not the source facts or current legal effect.']};
  const receiptBytes=encode(receipt),receiptFile=`statutory-authority-${source.id}-receipt.${digest(receiptBytes)}.json`;writeNew(path.join(current,receiptFile),receiptBytes);
  const result={schemaVersion:1,sourceId:source.id,sourceUrl:source.url,sourceSha:SOURCE_SHA,startedAt,receivedAt,httpStatus:metadata.httpStatus,receiptFile,receiptSha256:digest(receiptBytes),originalBodySha256:digest(body),originalBodyBytes:body.length,reviewedBodyIdentity:{sha256:source.expectedSha256,byteLength:source.expectedBytes},bodyEncoding:source.encoding,sanitizedHeaderArtifact:headersRef,...assessment,signedByThisTool:false,sourceReviewAdmitted:false,trustedSourceHealthRun:false,oldFilesRemovedOrOverwritten:false,alertDecision:'KEEP OPEN'};
  writeNew(path.join(current,'capture-result.json'),encode(result));
  // Never log response body, raw headers, raw curl text, key material or env.
  console.log(JSON.stringify({sourceId:source.id,httpStatus:metadata.httpStatus,captureEligibleForSeparateReview:assessment.captureEligibleForSeparateReview,failures:assessment.failures,bodyBytes:body.length,receiptSha256:digest(receiptBytes),captureDirectory:relativeDirectory,sourceReviewAdmitted:false}));
  process.exitCode=assessment.captureEligibleForSeparateReview?0:4;
 }catch(error){
  if(attemptDirectory){try{writeNew(path.join(attemptDirectory,'tool-failure.json'),encode({failedAt:new Date().toISOString(),phase,errorName:error.name,errorCode:safeCode(error.code),messageOmitted:true,originalFilesPreserved:true,attemptedAdmission:false}));}catch{}}
  console.error(JSON.stringify({captureFailed:true,phase,errorName:error.name,errorCode:safeCode(error.code),rawMessageOmitted:true,originalFilesPreserved:true}));process.exitCode=5;
 }
}
export async function runBoundedProcess(binary,args,{env,stdoutLimit=4*1024*1024,stderrLimit=16*1024,timeoutMs=20000}={}){
 const startedAt=new Date().toISOString();
 return await new Promise(resolve=>{
  const buffers={stdout:[],stderr:[]},sizes={stdout:0,stderr:0},caps={stdout:stdoutLimit,stderr:stderrLimit};
  let child,errorCode=null,limitHit=false,killTimer;
  const terminate=()=>{if(!child)return;child.kill('SIGTERM');killTimer??=setTimeout(()=>child.kill('SIGKILL'),1000);};
  try{child=spawn(binary,args,{env,stdio:['ignore','pipe','pipe']});}catch(error){resolve({startedAt,completedAt:new Date().toISOString(),status:null,signal:null,errorCode:safeCode(error.code)||'SPAWN_ERROR',limitHit:false,stdout:Buffer.alloc(0),stderr:Buffer.alloc(0),stdoutObservedBytes:0,stderrObservedBytes:0});return;}
  const timer=setTimeout(()=>{errorCode='PROCESS_TIMEOUT';terminate();},timeoutMs);
  const accept=(channel,bytes)=>{const room=Math.max(0,caps[channel]-sizes[channel]);if(room)buffers[channel].push(bytes.subarray(0,room));sizes[channel]+=bytes.length;if(sizes[channel]>caps[channel]){limitHit=true;terminate();}};
  for(const [channel,stream]of [['stdout',child.stdout],['stderr',child.stderr]]){stream.on('data',bytes=>accept(channel,bytes));stream.on('error',()=>{errorCode='PIPE_ERROR';terminate();});}
  child.on('error',error=>{errorCode=safeCode(error.code)||'CHILD_ERROR';});
  child.on('close',(status,signal)=>{clearTimeout(timer);if(killTimer)clearTimeout(killTimer);resolve({startedAt,completedAt:new Date().toISOString(),status,signal,errorCode,limitHit,stdout:Buffer.concat(buffers.stdout),stderr:Buffer.concat(buffers.stderr),stdoutObservedBytes:sizes.stdout,stderrObservedBytes:sizes.stderr});});
 });
}

export function assessPdfExtraction({info,text,infoOutcome,textOutcome}){
 const failures=[],complete=o=>o.status===0&&!o.signal&&!o.errorCode&&!o.limitHit;
 if(!complete(infoOutcome))failures.push('pdfinfo-process-incomplete');
 if(!complete(textOutcome))failures.push('pdftotext-process-incomplete');
 let infoText='',decoded='';
 try{infoText=new TextDecoder('utf-8',{fatal:true}).decode(info);decoded=new TextDecoder('utf-8',{fatal:true}).decode(text);}catch{failures.push('invalid-utf8-extraction');}
 if(!/^Pages:\s+175\s*$/mu.test(infoText))failures.push('pdf-page-count-not175');
 if(!/^Encrypted:\s+no\s*$/mu.test(infoText))failures.push('encrypted-or-unknown-pdf');
 if(text.length<10000||text.length>4*1024*1024)failures.push('empty-or-oversized-pdf-text');
 if((decoded.match(/\f/gu)??[]).length!==175)failures.push('incomplete-pdf-page-extraction');
 return {completeExtraction:failures.length===0,failures,pagesExpected:175,formFeedCount:(decoded.match(/\f/gu)??[]).length,legalReviewAdmitted:false};
}

async function extractPdfMain(){
 process.umask(0o077);
 let directory,phase='pdf-invocation-validation';
 const writeNew=(file,bytes)=>fs.writeFileSync(file,bytes,{flag:'wx',mode:0o600});
 const localEnv={PATH:process.env.PATH,LANG:'C',LC_ALL:'C'};
 try{
  assert.equal(process.argv.length,5);assert.equal(process.argv[2],'--extract-pdf');
  assert.equal(process.versions.node,'24.14.0');assert.equal(process.platform,'linux');
  assert.equal(process.env.GITHUB_ACTIONS,'true');assert.equal(process.env.GITHUB_REPOSITORY,RUNNER_REPOSITORY);assert.equal(process.env.GITHUB_REF,'refs/heads/main');
  assert.equal(process.env.GITHUB_WORKFLOW_REF,`${RUNNER_REPOSITORY}/${WORKFLOW_PATH}@refs/heads/main`);
  assert.match(process.env.GITHUB_SHA??'',/^[0-9a-f]{40}$/u);
  for(const key of ['GITHUB_RUN_ID','GITHUB_RUN_ATTEMPT'])assert.match(process.env[key]??'',/^[1-9][0-9]*$/u);
  assert.equal(process.env.PAYDECODE_SOURCE_SHA,SOURCE_SHA);
  const sourceRoot=path.resolve(process.argv[3]);assert.equal(fs.realpathSync(sourceRoot),sourceRoot);
  const head=spawnSync('git',['--no-replace-objects','-C',sourceRoot,'rev-parse','HEAD'],{encoding:'utf8',env:localEnv,timeout:10000});assert.equal(head.status,0);assert.equal(head.stdout.trim(),SOURCE_SHA);
  const source=sourceFor('nm-nmsa-chapter50'),relative=process.argv[4];
  assert.match(relative,new RegExp(`^research/source-captures/[0-9]{4}-[0-9]{2}-[0-9]{2}-run${process.env.GITHUB_RUN_ID}/statutory-authority-nm-nmsa-chapter50-attempt${process.env.GITHUB_RUN_ATTEMPT}$`,'u'));
  let cursor=sourceRoot;for(const part of relative.split('/')){cursor=path.join(cursor,part);const s=fs.lstatSync(cursor);assert.ok(s.isDirectory()&&!s.isSymbolicLink());}
  const result=JSON.parse(fs.readFileSync(path.join(cursor,'capture-result.json'),'utf8'));assert.equal(result.sourceId,source.id);assert.equal(result.sourceUrl,source.url);assert.equal(result.sourceSha,SOURCE_SHA);assert.equal(result.captureEligibleForSeparateReview,true);assert.equal(result.originalBodySha256,source.expectedSha256);assert.equal(result.originalBodyBytes,source.expectedBytes);
  const input=path.join(cursor,`${source.id}-body.${source.expectedSha256}.bin`),s=fs.lstatSync(input);assert.ok(s.isFile()&&!s.isSymbolicLink());
  const pdf=fs.readFileSync(input);assert.equal(pdf.length,source.expectedBytes);assert.equal(digest(pdf),source.expectedSha256);
  directory=path.join(cursor,'pdf-extraction');fs.mkdirSync(directory,{mode:0o700});
  assert.ok(process.env.GITHUB_OUTPUT);fs.appendFileSync(process.env.GITHUB_OUTPUT,`pdf_dir=${relative}/pdf-extraction\n`);
  const info='/usr/bin/pdfinfo',text='/usr/bin/pdftotext';
  for(const binary of [info,text]){const st=fs.lstatSync(binary);assert.ok(st.isFile()&&!st.isSymbolicLink());assert.equal(st.uid,0);assert.equal(st.gid,0);assert.equal(st.mode&0o777,0o755);}
  const boundary=(name,binary,args,o)=>{
   const complete=o.status===0&&!o.signal&&!o.errorCode&&!o.limitHit,stem=complete?'complete':'partial';
   const stdoutName=`${name}-${stem}-stdout.${digest(o.stdout)}.bin`,stderrName=`${name}-${stem}-stderr.${digest(o.stderr)}.bin`;
   writeNew(path.join(directory,stdoutName),o.stdout);writeNew(path.join(directory,stderrName),o.stderr);
   const b={binary,args,startedAt:o.startedAt,completedAt:o.completedAt,exitCode:o.status,signal:o.signal,errorCode:o.errorCode,limitHit:o.limitHit,processComplete:complete,stdoutObservedBytes:o.stdoutObservedBytes,stderrObservedBytes:o.stderrObservedBytes,stdoutRetainedBytes:o.stdout.length,stderrRetainedBytes:o.stderr.length,stdoutFile:stdoutName,stderrFile:stderrName,stdoutSha256:digest(o.stdout),stderrSha256:digest(o.stderr),timeoutMs:20000,stdoutLimitBytes:name==='pdftotext'?4*1024*1024:65536,stderrLimitBytes:16384,legalReviewAdmitted:false};
   writeNew(path.join(directory,`${name}-boundary.json`),encode(b));return b;
  };
  phase='pdf-tool-versions';
  const versions=[];
  for(const [name,binary]of [['pdfinfo',info],['pdftotext',text]]){
   const o=await runBoundedProcess(binary,['-v'],{env:localEnv,stdoutLimit:65536});
   versions.push(boundary(`${name}-version`,binary,['-v'],o));
   assert.equal(o.status,0);assert.equal(o.signal,null);assert.equal(o.errorCode,null);assert.equal(o.limitHit,false);
   assert.match(Buffer.concat([o.stdout,o.stderr]).toString('utf8'),new RegExp(`^${name} version [0-9]+(?:\\.[0-9]+){1,2}`,'mu'));
  }
  phase='pdfinfo-full';const infoArgs=['-enc','UTF-8',input],infoResult=await runBoundedProcess(info,infoArgs,{env:localEnv,stdoutLimit:65536});const infoBoundary=boundary('pdfinfo',info,infoArgs,infoResult);
  phase='pdftotext-full-layout';const textArgs=['-layout','-enc','UTF-8',input,'-'],textResult=await runBoundedProcess(text,textArgs,{env:localEnv,stdoutLimit:4*1024*1024});const textBoundary=boundary('pdftotext',text,textArgs,textResult);
  const assessment=assessPdfExtraction({info:infoResult.stdout,text:textResult.stdout,infoOutcome:infoResult,textOutcome:textResult});
  writeNew(path.join(directory,'pdf-extraction-result.json'),encode({schemaVersion:1,at:new Date().toISOString(),sourceId:source.id,sourceUrl:source.url,sourceSha:SOURCE_SHA,workflowSha:process.env.GITHUB_SHA,githubRunId:process.env.GITHUB_RUN_ID,githubRunAttempt:process.env.GITHUB_RUN_ATTEMPT,rawPdfSha256:source.expectedSha256,rawPdfBytes:source.expectedBytes,versions,infoBoundary,textBoundary,...assessment,normalizationPerformed:false,rawTransportReceiptChanged:false,sourceReviewAdmitted:false}));
  console.log(JSON.stringify({pdfExtractionComplete:assessment.completeExtraction,failures:assessment.failures,pagesExpected:175,textBytes:textResult.stdout.length,textSha256:digest(textResult.stdout),sourceReviewAdmitted:false}));process.exitCode=assessment.completeExtraction?0:6;
 }catch(error){
  if(directory){try{writeNew(path.join(directory,'extraction-failure.json'),encode({failedAt:new Date().toISOString(),phase,errorName:error.name,errorCode:safeCode(error.code),messageOmitted:true,originalFilesPreserved:true,legalReviewAdmitted:false}));}catch{}}
  console.error(JSON.stringify({pdfExtractionFailed:true,phase,errorName:error.name,errorCode:safeCode(error.code),rawMessageOmitted:true,originalFilesPreserved:true}));process.exitCode=7;
 }
}

if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 if(process.argv[2]==='--extract-pdf')await extractPdfMain();else await captureMain();
}

