// Actual CLI subprocess tests with a fake curl; no publisher request or signing.
// All new fixtures/attempts are preserved. A historical public PDF is only a fixture.
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {SOURCE_SHA,RUNNER_REPOSITORY,WORKFLOW_PATH,USER_AGENT,MAX_BYTES,SPECIAL_SOURCES,getSpecialCaptureSource} from './lib/special-source-capture-only.mjs';

const root=fileURLToPath(new URL('../',import.meta.url));
assert.ok(process.argv[2],'usage: node scripts/qa-special-source-capture-only.mjs /absolute/path/to/source-repository');
const sourceRepository=path.resolve(process.argv[2]);
const output=fs.mkdtempSync(path.join(path.dirname(root.slice(0,-1)),'special-source-cli-tests-'));
const fixtureSource=path.join(output,'source-checkout-metadata');
const clone=spawnSync('git',['clone','--shared','--no-checkout',sourceRepository,fixtureSource],{encoding:'utf8'});assert.equal(clone.status,0,clone.stderr);
const setHead=sha=>{const result=spawnSync('git',['-C',fixtureSource,'update-ref','--no-deref','HEAD',sha],{encoding:'utf8'});assert.equal(result.status,0,result.stderr);};
setHead(SOURCE_SHA);
const digest=bytes=>createHash('sha256').update(bytes).digest('hex');
const writeNew=(file,bytes,mode=0o600)=>fs.writeFileSync(file,bytes,{flag:'wx',mode});
const html='<!doctype html><html><head><title>Fixture only</title></head><body><main><h1>Official-source transport fixture only</h1>'+('<p>No source facts, review admission or actual publisher request in this local fixture.</p>'.repeat(15))+'</main></body></html>';
const historicalPdf=fs.readFileSync(path.join(sourceRepository,'research/source-captures/2026-10-11-run38122527353/pg-cb-088-body.1bbcdf55fc47b0e5231258868dc40dddf51e7fe00724f0cad731e1d48c0b7acd.pdf'));
assert.equal(digest(historicalPdf),'1bbcdf55fc47b0e5231258868dc40dddf51e7fe00724f0cad731e1d48c0b7acd');
const good={sourceId:'ne-archive',body:html,status:200,exitCode:0,redirects:0,stderr:'',curlVersion:'8.5.0'};
const cases=[
  ...SPECIAL_SOURCES.map(source=>[`complete200-${source.id}`,{sourceId:source.id},0]),
  ['http403',{status:403,body:'<html><body>Access Denied</body></html>'},4],
  ['challenge200',{body:html.replace('transport fixture','Verify you are human. transport fixture')},4],
  ['redirect301',{status:301,headersExtra:'Location: https://example.test/elsewhere\r\n'},4],
  ['timeoutPartial',{exitCode:28,body:'<html><body>partial',stderr:'curl: (28) timeout\n'},4],
  ['partial200',{exitCode:18,headersLength:Buffer.byteLength(html)+100,stderr:'curl: (18) missing bytes\n'},4],
  ['empty200',{body:''},4],
  ['writeFailure',{exitCode:23,body:'<html>retained partial',stderr:'curl: (23) write failed\n'},4],
  ['oversizeRejected',{body:'<html>'+'x'.repeat(MAX_BYTES),exitCode:63,stderr:'curl: (63) Maximum file size exceeded\n'},4],
  ['wrongContentType',{contentType:'application/json'},4],
  ['wrongDownloadSize',{downloadedSize:1},4],
  ['wrongFinalUrl',{finalUrl:'https://example.test/elsewhere'},4],
  ['unexpectedRedirectCount',{redirects:1},4],
  ['unexpectedEncoding',{headersExtra:'Content-Encoding: gzip\r\n'},4],
  ['partialContentRange200',{headersExtra:'Content-Range: bytes 0-99/1000\r\n'},4],
  ['http206',{status:206,headersExtra:'Content-Range: bytes 0-99/1000\r\n'},4],
  ['multipleHeaderBlocks',{headerPrefix:'HTTP/1.1 301 Moved Permanently\r\nLocation: https://example.test/elsewhere\r\n\r\n'},4],
  ['duplicateContentLength',{headersExtra:`Content-Length: ${Buffer.byteLength(html)}\r\n`},4],
  ['malformedContentLength',{headersLength:'not-an-integer'},4],
  ['rawContentTypeMismatch',{rawContentType:'application/json'},4],
  ['duplicateContentType',{headersExtra:'Content-Type: text/html\r\n'},4],
  ['pdfTypeIsActuallyHtml',{sourceId:'pg-cb-088',body:html,contentType:'application/pdf'},4],
  ['pdfReturnedAsHtml',{sourceId:'pg-cb-088',bodyBase64:historicalPdf.toString('base64'),contentType:'text/html'},4],
  ['pdfOnHtmlSource',{bodyBase64:historicalPdf.toString('base64'),contentType:'application/pdf'},4],
  ['pdfMissingEof',{sourceId:'pg-cb-088',bodyBase64:historicalPdf.subarray(0,-30).toString('base64')},4],
  ['pdfParserRejectsMalformed',{sourceId:'pg-cb-088',body:'%PDF-1.7\n'+'invalid object\n'.repeat(100)+'%%EOF\n'},4],
  ['pdfParserUnavailable',{sourceId:'pg-cb-088',fakePdfinfoExit:127},4],
  ['oldCurlRefused',{curlVersion:'8.3.0'},5],
  ['existingAttemptRefused',{setup:'existing-directory'},5],
  ['symlinkAttemptRefused',{setup:'symlink'},5],
  ['invalidRepositoryRefused',{environment:{GITHUB_REPOSITORY:'untrusted/repository'}},5],
  ['invalidSourceShaRefused',{environment:{PAYDECODE_SOURCE_SHA:'0'.repeat(40)}},5],
  ['invalidRunIdRefused',{environment:{GITHUB_RUN_ID:'../escape'}},5],
  ['invalidWorkflowRefRefused',{environment:{GITHUB_WORKFLOW_REF:'untrusted/workflow@main'}},5],
  ['invalidIdRefused',{sourceId:'https://example.test/any-url'},5],
  ['missingIdRefused',{omitId:true},5],
  ['extraArgumentRefused',{extraArgument:'https://example.test/any-url'},5],
  ['parentFileRefused',{setup:'parent-file'},5],
  ['wrongCheckoutHeadRefused',{setup:'wrong-head'},5],
];
const records=[];
for(const [index,[name,overrides,expectedExit]] of cases.entries()){
  const caseDirectory=path.join(output,name),bin=path.join(caseDirectory,'bin');fs.mkdirSync(bin,{recursive:true,mode:0o700});
  const fixture={...good,...overrides};const selected=getSpecialCaptureSource(fixture.sourceId)||getSpecialCaptureSource('ne-archive');
  fixture.expectedUrl=selected.url;fixture.finalUrl??=selected.url;fixture.contentType??=selected.kind==='pdf'?'application/pdf':'text/html; charset=utf-8';
  if(selected.kind==='pdf'&&!Object.hasOwn(overrides,'body')&&!Object.hasOwn(overrides,'bodyBase64'))fixture.bodyBase64=historicalPdf.toString('base64');
  const actualBody=fixture.bodyBase64?Buffer.from(fixture.bodyBase64,'base64'):Buffer.from(fixture.body);
  const runId=String(92000000000+index),day=new Date().toISOString().slice(0,10);
  const relativeAttempt=`research/source-captures/${day}-run${runId}/special-source-${selected.id}-attempt1`,absoluteAttempt=path.join(fixtureSource,relativeAttempt);
  const outputFile=path.join(caseDirectory,'github-output.txt');writeNew(outputFile,'');
  if(fixture.setup==='existing-directory'){fs.mkdirSync(absoluteAttempt,{recursive:true});writeNew(path.join(absoluteAttempt,'sentinel.txt'),'unchanged original');}
  if(fixture.setup==='symlink'){fs.mkdirSync(path.dirname(absoluteAttempt),{recursive:true});const target=path.join(caseDirectory,'original-target');fs.mkdirSync(target);writeNew(path.join(target,'sentinel.txt'),'unchanged original');fs.symlinkSync(target,absoluteAttempt);}
  if(fixture.setup==='parent-file')writeNew(path.dirname(absoluteAttempt),'preserved parent-file');
  if(fixture.setup==='wrong-head'){const parent=spawnSync('git',['-C',fixtureSource,'rev-parse',`${SOURCE_SHA}^`],{encoding:'utf8'});assert.equal(parent.status,0);setHead(parent.stdout.trim());}
  writeNew(path.join(bin,'fixture.json'),JSON.stringify(fixture)+'\n');
  const fakeCurl=`#!/usr/bin/env node
import fs from 'node:fs';import path from 'node:path';import {fileURLToPath} from 'node:url';
const base=path.dirname(fileURLToPath(import.meta.url)),fixture=JSON.parse(fs.readFileSync(path.join(base,'fixture.json'))),args=process.argv.slice(2);
fs.appendFileSync(path.join(base,'calls.jsonl'),JSON.stringify({args,environmentKeys:Object.keys(process.env).sort()})+'\\n');
if(args.length===2&&args[0]==='-q'&&args[1]==='--version'){console.log('curl '+fixture.curlVersion+' fixture');process.exit(0);}
if(args.at(-1)!==fixture.expectedUrl)throw Error('Unexpected URL: no real network fallback');
const body=fixture.bodyBase64?Buffer.from(fixture.bodyBase64,'base64'):Buffer.from(fixture.body),get=flag=>args[args.indexOf(flag)+1];
const headers=(fixture.headerPrefix||'')+'HTTP/2 '+fixture.status+'\\r\\nContent-Type: '+(fixture.rawContentType||fixture.contentType)+'\\r\\nContent-Length: '+(fixture.headersLength??body.length)+'\\r\\n'+(fixture.headersExtra||'')+'\\r\\n';
fs.writeFileSync(get('--dump-header'),headers);fs.writeFileSync(get('--output'),body);
process.stdout.write([String(fixture.status),fixture.finalUrl,String(fixture.redirects),fixture.contentType,String(fixture.downloadedSize??body.length)].join('\\t')+'\\n');process.stderr.write(fixture.stderr);process.exitCode=fixture.exitCode;
`;
  writeNew(path.join(bin,'curl'),fakeCurl,0o755);
  if(Object.hasOwn(fixture,'fakePdfinfoExit'))writeNew(path.join(bin,'pdfinfo'),`#!/usr/bin/env node\nprocess.exit(${fixture.fakePdfinfoExit});\n`,0o755);
  const environment={PATH:`${bin}${path.delimiter}${path.dirname(process.execPath)}${path.delimiter}${process.env.PATH}`,LANG:'C',LC_ALL:'C',GITHUB_ACTIONS:'true',GITHUB_REPOSITORY:RUNNER_REPOSITORY,GITHUB_REF:'refs/heads/main',GITHUB_WORKFLOW_REF:`${RUNNER_REPOSITORY}/${WORKFLOW_PATH}@refs/heads/main`,GITHUB_SHA:'5b08ca2a6c5a5aa992b5807877149830a091a3de',GITHUB_RUN_ID:runId,GITHUB_RUN_ATTEMPT:'1',GITHUB_OUTPUT:outputFile,PAYDECODE_SOURCE_SHA:SOURCE_SHA,PAYDECODE_SOURCE_TOKEN1:'fixture-read-token-must-not-reach-child',PAYDECODE_RECEIPT_SIGNING_KEY:'fixture-not-a-key-must-not-reach-child',HTTPS_PROXY:'fixture-not-used',CURL_HOME:'/fixture/not-used',...fixture.environment};
  const cliArgs=[path.join(root,'scripts/special-source-capture-only.mjs'),fixtureSource,...(fixture.omitId?[]:[fixture.sourceId]),...(fixture.extraArgument?[fixture.extraArgument]:[])];
  const run=spawnSync(process.execPath,cliArgs,{cwd:root,env:environment,encoding:'utf8',timeout:30000,maxBuffer:1048576});
  writeNew(path.join(caseDirectory,'cli.stdout.txt'),run.stdout||'');writeNew(path.join(caseDirectory,'cli.stderr.txt'),run.stderr||'');
  const callsFile=path.join(bin,'calls.jsonl'),calls=fs.existsSync(callsFile)?fs.readFileSync(callsFile,'utf8').trim().split('\n').filter(Boolean).map(JSON.parse):[];
  const requests=calls.filter(call=>!call.args.includes('--version'));
  const expectedRequests=fixture.setup||fixture.environment||fixture.omitId||fixture.extraArgument||name==='invalidIdRefused'||name==='oldCurlRefused'?0:1;
  const record={name,sourceId:fixture.sourceId,expectedExit,actualExit:run.status,signal:run.signal,error:run.error?.message||null,requestCalls:requests.length,versionCalls:calls.length-requests.length,relativeAttempt};records.push(record);writeNew(path.join(caseDirectory,'result.json'),JSON.stringify(record,null,2)+'\n');
  assert.equal(run.status,expectedExit,`${name}: ${run.stderr}`);assert.equal(requests.length,expectedRequests,`${name}: at most one GET; no retry/archive`);
  for(const call of calls)assert.equal(call.args[0],'-q','Every curl invocation must disable curlrc first');
  for(const request of requests){
    const args=request.args,get=flag=>args[args.indexOf(flag)+1];
    assert.equal(args.at(-1),selected.url);assert.equal(get('--retry'),'0');assert.equal(get('--max-redirs'),'0');assert.equal(get('--max-filesize'),String(MAX_BYTES));assert.equal(get('--noproxy'),'*');assert.equal(get('--user-agent'),USER_AGENT);assert.equal(get('--header'),'Accept-Encoding: identity');
    for(const forbidden of ['-L','--location','--fail','--cookie','--netrc','--insecure','-k','--range'])assert.equal(args.includes(forbidden),false);
    const allowed=['LANG','LC_ALL','PATH','PWD','SHLVL','_',...(process.platform==='darwin'?['__CF_USER_TEXT_ENCODING']:[])];assert.deepEqual(request.environmentKeys,allowed.filter(key=>request.environmentKeys.includes(key)).sort(),'Never pass read/signing token, proxy or curl config to child');
    assert.ok(fs.readFileSync(path.join(absoluteAttempt,'body.raw')).equals(actualBody));assert.equal(fs.readFileSync(path.join(absoluteAttempt,'curl.stderr.txt'),'utf8'),fixture.stderr);
    const result=JSON.parse(fs.readFileSync(path.join(absoluteAttempt,'capture-result.json'))),receiptBytes=fs.readFileSync(path.join(absoluteAttempt,result.receiptFile)),receipt=JSON.parse(receiptBytes);
    assert.equal(result.captureEligibleForSeparateReview,expectedExit===0);assert.equal(result.admittedSourceReview,false);assert.equal(result.signedByThisTool,false);
    assert.equal(receipt.sourceUrl,selected.url);assert.equal(receipt.body.sha256,digest(actualBody));assert.equal(receipt.body.byteLength,actualBody.length);assert.equal(result.receiptSha256,digest(receiptBytes));
    assert.equal(fs.existsSync(path.join(absoluteAttempt,result.receiptFile+'.sig.json')),false);assert.equal(fs.readFileSync(outputFile,'utf8').trim(),`capture_dir=${relativeAttempt}`);
    if(selected.kind==='pdf'&&expectedExit===0){const parsed=JSON.parse(fs.readFileSync(path.join(absoluteAttempt,'pdf-parser-result.json')));assert.equal(parsed.eligible,true);assert.ok(parsed.pages>0);}
  }
  if(fixture.setup==='existing-directory')assert.equal(fs.readFileSync(path.join(absoluteAttempt,'sentinel.txt'),'utf8'),'unchanged original');
  if(fixture.setup==='symlink')assert.equal(fs.readFileSync(path.join(caseDirectory,'original-target/sentinel.txt'),'utf8'),'unchanged original');
  if(fixture.setup==='parent-file')assert.equal(fs.readFileSync(path.dirname(absoluteAttempt),'utf8'),'preserved parent-file');
}
const workflow=fs.readFileSync(path.join(root,WORKFLOW_PATH),'utf8');
assert.match(workflow,/workflow_dispatch:\s*\n\s*permissions:/u);assert.match(workflow,/source_id: \[pg-cb-088, ne-archive, ne-lincoln, ne-omaha\]/u);assert.match(workflow,/fail-fast: false/u);
assert.match(workflow,/ref: \$\{\{ github\.sha \}\}/u);assert.match(workflow,/PAYDECODE_SOURCE_SHA: a013cf5e55985ece73d6720c1fc76ff9f9d18d72/u);assert.match(workflow,/always\(\) && steps\.capture\.outputs\.capture_dir != ''/u);assert.match(workflow,/overwrite: false/u);assert.match(workflow,/persist-credentials: false/u);
for(const forbidden of ['schedule:','pull_request:','push:','PAYDECODE_SOURCE_WRITE_TOKEN','GH_TOKEN','git push','gh pr','npm ci','capture-source-batch','capture-archive','contents: write','apt-get','pip install'])assert.equal(workflow.includes(forbidden),false,`No ${forbidden}`);
for(const file of ['scripts/special-source-capture-only.mjs','scripts/lib/special-source-capture-only.mjs',WORKFLOW_PATH])assert.doesNotMatch(fs.readFileSync(path.join(root,file),'utf8'),/\b(?:unlinkSync|rmSync|rmdirSync)\s*\(|\brm\s+-/u);
assert.deepEqual(SPECIAL_SOURCES.map(source=>source.id),['pg-cb-088','ne-archive','ne-lincoln','ne-omaha']);
const sourceContract=fs.readFileSync(path.join(sourceRepository,'scripts/lib/legal-watch-renewals-20261011.mjs'),'utf8');for(const source of SPECIAL_SOURCES)assert.ok(sourceContract.includes(`'${source.url}'`),'Exact URLs remain those of the original legal-watch contract');
const summary={schemaVersion:1,completedAt:new Date().toISOString(),status:'PASS-LOCAL-ONLY',casesPassed:records.length,cases:records,fixedSourceCount:4,realPublisherRequests:0,localSigningOperations:0,oldFilesDeleted:0,dependenciesInstalled:0,workflowStaticChecksPassed:true,limitations:['Fake curl subprocess tests with a retained historical PDF parser fixture; no remote workflow execution or fresh publisher evidence.','Only eligible full responses would be passed to the unchanged signer inside the runner. No local signing or source-review admission.']};writeNew(path.join(output,'test-summary.json'),JSON.stringify(summary,null,2)+'\n');console.log(JSON.stringify({output,casesPassed:records.length,realPublisherRequests:0,localSigningOperations:0,oldFilesDeleted:0},null,2));
