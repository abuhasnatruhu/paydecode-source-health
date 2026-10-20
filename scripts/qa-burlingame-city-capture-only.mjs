// Exercises the actual CLI with a fake curl executable: no publisher requests,
// no signing/private key, no old-file cleanup, and every new attempt retained.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../', import.meta.url));
const sourceRepository = path.resolve(process.argv[2] || '');
assert.ok(process.argv[2], 'usage: node scripts/qa-burlingame-city-capture-only.mjs /path/to/local/source-repository');
const SOURCE_SHA = 'a013cf5e55985ece73d6720c1fc76ff9f9d18d72';
const CITY_URL = 'https://burlingame.org/307/Minimum-Wage-Information';
const output = fs.mkdtempSync(path.join(path.dirname(root.slice(0, -1)), 'capture-only-cli-tests-'));
const fixtureSource = path.join(output, 'source-checkout-metadata');
const clone = spawnSync('git', ['clone', '--shared', '--no-checkout', sourceRepository, fixtureSource], { encoding: 'utf8' });
assert.equal(clone.status, 0, clone.stderr);
const setHead = (sha) => {
  const result = spawnSync('git', ['-C', fixtureSource, 'update-ref', '--no-deref', 'HEAD', sha], { encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr);
};
setHead(SOURCE_SHA);
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');
const writeNew = (file, bytes, mode = 0o600) => fs.writeFileSync(file, bytes, { flag: 'wx', mode });
const body = '<!doctype html><html><head><title>Minimum Wage Information</title></head><body><main><h1>Minimum Wage Information</h1><p>City source fixture, not actual publisher evidence.</p>' + '<p>Transport preservation fixture only. No legal review or source admission.</p>'.repeat(15) + '</main></body></html>';
const good = { body, status: 200, exitCode: 0, finalUrl: CITY_URL, redirects: 0, contentType: 'text/html; charset=utf-8', stderr: '', curlVersion: '8.5.0' };
const cases = [
  ['complete200', {}, 0],
  ['http403', { status: 403, body: '<html><body>Access Denied</body></html>' }, 4],
  ['challenge200', { body: body.replace('City source fixture', 'Verify you are human. City source fixture') }, 4],
  ['redirect301', { status: 301, headersExtra: 'Location: https://burlingame.org/elsewhere\r\n' }, 4],
  ['timeoutPartial', { exitCode: 28, body: '<html><body>partial', stderr: 'curl: (28) Operation timed out\n' }, 4],
  ['partial200', { exitCode: 18, headersLength: Buffer.byteLength(body) + 100, stderr: 'curl: (18) end of response with bytes missing\n' }, 4],
  ['empty200', { body: '' }, 4],
  ['writeFailure', { exitCode: 23, body: '<html>retained partial', stderr: 'curl: (23) Failure writing output\n' }, 4],
  ['oversizeRejected', { body: '<html>' + 'x'.repeat(2097152), exitCode: 63, stderr: 'curl: (63) Maximum file size exceeded\n' }, 4],
  ['wrongContentType', { contentType: 'application/json' }, 4],
  ['wrongDownloadSize', { downloadedSize: 1 }, 4],
  ['wrongFinalUrl', { finalUrl: 'https://burlingame.org/elsewhere' }, 4],
  ['unexpectedEncoding', { headersExtra: 'Content-Encoding: gzip\r\n' }, 4],
  ['multipleHeaderBlocks', { headerPrefix: 'HTTP/1.1 301 Moved Permanently\r\nLocation: https://burlingame.org/elsewhere\r\n\r\n' }, 4],
  ['oldCurlRefused', { curlVersion: '8.3.0' }, 5],
  ['existingAttemptRefused', { setup: 'existing-directory' }, 5],
  ['symlinkAttemptRefused', { setup: 'symlink' }, 5],
  ['invalidRepositoryRefused', { environment: { GITHUB_REPOSITORY: 'untrusted/repository' } }, 5],
  ['invalidSourceShaRefused', { environment: { PAYDECODE_SOURCE_SHA: '0'.repeat(40) } }, 5],
  ['invalidRunIdRefused', { environment: { GITHUB_RUN_ID: '../escape' } }, 5],
  ['extraArgumentRefused', { extraArgument: 'https://example.com/' }, 5],
  ['parentFileRefused', { setup: 'parent-file' }, 5],
  ['wrongCheckoutHeadRefused', { setup: 'wrong-head' }, 5]
];
const records = [];
let index = 0;
for (const [name, overrides, expectedExit] of cases) {
  index += 1;
  const caseDirectory = path.join(output, name);
  const bin = path.join(caseDirectory, 'bin');
  fs.mkdirSync(bin, { recursive: true, mode: 0o700 });
  const fixture = { ...good, ...overrides };
  const runId = String(91000000000 + index);
  const day = new Date().toISOString().slice(0, 10);
  const relativeAttempt = `research/source-captures/${day}-run${runId}/burlingame-city-attempt1`;
  const absoluteAttempt = path.join(fixtureSource, relativeAttempt);
  const outputFile = path.join(caseDirectory, 'github-output.txt');
  writeNew(outputFile, '');
  if (fixture.setup === 'existing-directory') {
    fs.mkdirSync(absoluteAttempt, { recursive: true });
    writeNew(path.join(absoluteAttempt, 'sentinel.txt'), 'must remain byte-identical');
  } else if (fixture.setup === 'symlink') {
    fs.mkdirSync(path.dirname(absoluteAttempt), { recursive: true });
    const target = path.join(caseDirectory, 'original-target');
    fs.mkdirSync(target);
    writeNew(path.join(target, 'sentinel.txt'), 'must remain byte-identical');
    fs.symlinkSync(target, absoluteAttempt);
  } else if (fixture.setup === 'parent-file') {
    writeNew(path.dirname(absoluteAttempt), 'parent is an existing file; preserve it');
  } else if (fixture.setup === 'wrong-head') {
    const parent = spawnSync('git', ['-C', fixtureSource, 'rev-parse', `${SOURCE_SHA}^`], { encoding: 'utf8' });
    assert.equal(parent.status, 0);
    setHead(parent.stdout.trim());
  }
  writeNew(path.join(bin, 'fixture.json'), `${JSON.stringify(fixture)}\n`);
  const fakeCurl = `#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
const base=path.dirname(fileURLToPath(import.meta.url));
const fixture=JSON.parse(fs.readFileSync(path.join(base,'fixture.json'),'utf8'));
const args=process.argv.slice(2);
fs.appendFileSync(path.join(base,'calls.jsonl'),JSON.stringify({args,environmentKeys:Object.keys(process.env).sort()})+'\\n');
if(args.length===2&&args[0]==='-q'&&args[1]==='--version'){console.log('curl '+fixture.curlVersion+' fixture');process.exit(0);}
if(args.at(-1)!==${JSON.stringify(CITY_URL)}) throw new Error('Unexpected URL: never call a real network client');
const get=(flag)=>args[args.indexOf(flag)+1];
const headers=(fixture.headerPrefix||'')+'HTTP/2 '+fixture.status+'\\r\\nContent-Type: '+fixture.contentType+'\\r\\nContent-Length: '+(fixture.headersLength??Buffer.byteLength(fixture.body))+'\\r\\n'+(fixture.headersExtra||'')+'\\r\\n';
fs.writeFileSync(get('--dump-header'),headers);
fs.writeFileSync(get('--output'),fixture.body);
process.stdout.write([String(fixture.status),fixture.finalUrl,String(fixture.redirects),fixture.contentType,String(fixture.downloadedSize??Buffer.byteLength(fixture.body))].join('\\t')+'\\n');
process.stderr.write(fixture.stderr);
process.exitCode=fixture.exitCode;
`;
  writeNew(path.join(bin, 'curl'), fakeCurl, 0o755);
  // The extensionless fake executable is classified as ESM by Node24; no real
  // curl executable or arbitrary network fallback is invoked by these tests.
  const environment = {
    PATH: `${bin}${path.delimiter}${path.dirname(process.execPath)}${path.delimiter}${process.env.PATH}`,
    LANG: 'C', LC_ALL: 'C', GITHUB_ACTIONS: 'true',
    GITHUB_REPOSITORY: 'abuhasnatruhu/paydecode-source-health',
    GITHUB_REF: 'refs/heads/main',
    GITHUB_WORKFLOW_REF: 'abuhasnatruhu/paydecode-source-health/.github/workflows/burlingame-city-capture-only.yml@refs/heads/main',
    GITHUB_SHA: '4fc47b5d9651a33350bfa3122e3da3bd5f0eebdc',
    GITHUB_RUN_ID: runId, GITHUB_RUN_ATTEMPT: '1', GITHUB_OUTPUT: outputFile,
    PAYDECODE_SOURCE_SHA: SOURCE_SHA, ...fixture.environment
  };
  const startedAt = new Date().toISOString();
  const cliArgs = [path.join(root, 'scripts/capture-burlingame-city-only.mjs'), fixtureSource, ...(fixture.extraArgument ? [fixture.extraArgument] : [])];
  const run = spawnSync(process.execPath, cliArgs, { cwd: root, env: environment, encoding: 'utf8', timeout: 15000, maxBuffer: 1048576 });
  writeNew(path.join(caseDirectory, 'cli.stdout.txt'), run.stdout || '');
  writeNew(path.join(caseDirectory, 'cli.stderr.txt'), run.stderr || '');
  const callsFile = path.join(bin, 'calls.jsonl');
  const calls = fs.existsSync(callsFile) ? fs.readFileSync(callsFile, 'utf8').trim().split('\n').map(JSON.parse) : [];
  const requests = calls.filter(({ args }) => !args.includes('--version'));
  const expectedRequests = fixture.setup || fixture.environment || fixture.extraArgument || name === 'oldCurlRefused' ? 0 : 1;
  const record = { name, startedAt, completedAt: new Date().toISOString(), expectedExit, actualExit: run.status, signal: run.signal, error: run.error?.message || null, versionCalls: calls.length - requests.length, requestCalls: requests.length, relativeAttempt, stdoutPath: path.relative(output, path.join(caseDirectory, 'cli.stdout.txt')), stderrPath: path.relative(output, path.join(caseDirectory, 'cli.stderr.txt')) };
  records.push(record);
  writeNew(path.join(caseDirectory, 'result.json'), `${JSON.stringify(record, null, 2)}\n`);
  assert.equal(run.status, expectedExit, `${name}: ${run.stderr}`);
  assert.equal(requests.length, expectedRequests, `${name}: one GET at most; never retry or archive`);
  for (const call of calls) assert.equal(call.args[0], '-q', `${name}: every curl invocation, including the version probe, must disable curlrc first`);
  for (const request of requests) {
    assert.equal(request.args[0], '-q');
    assert.equal(request.args.at(-1), CITY_URL);
    assert.equal(request.args[request.args.indexOf('--retry') + 1], '0');
    assert.equal(request.args[request.args.indexOf('--max-redirs') + 1], '0');
    assert.equal(request.args[request.args.indexOf('--max-filesize') + 1], '2097152');
    assert.equal(request.args.includes('-L'), false);
    assert.equal(request.args.includes('--location'), false);
    assert.equal(request.args.includes('--fail'), false, 'A failure body must not be discarded');
    const allowedChildEnvironment = ['LANG', 'LC_ALL', 'PATH', 'PWD', 'SHLVL', '_', ...(process.platform === 'darwin' ? ['__CF_USER_TEXT_ENCODING'] : [])];
    assert.deepEqual(request.environmentKeys, allowedChildEnvironment.filter((key) => request.environmentKeys.includes(key)).sort(), 'No GitHub token or signing secret may reach the curl child');
    assert.deepEqual(fs.readFileSync(path.join(absoluteAttempt, 'body.raw')), Buffer.from(fixture.body), `${name}: preserve all original body bytes, including failure/partial/empty`);
    assert.equal(fs.readFileSync(path.join(absoluteAttempt, 'curl.stderr.txt'), 'utf8'), fixture.stderr);
    const summary = JSON.parse(fs.readFileSync(path.join(absoluteAttempt, 'capture-result.json'), 'utf8'));
    const receipt = JSON.parse(fs.readFileSync(path.join(absoluteAttempt, summary.receiptFile), 'utf8'));
    assert.equal(receipt.evidenceType, 'ordinary-direct-http-attempt');
    assert.equal(receipt.sourceUrl, CITY_URL);
    assert.equal(receipt.body.sha256, sha256(Buffer.from(fixture.body)));
    assert.equal(receipt.body.byteLength, Buffer.byteLength(fixture.body));
    assert.equal(receipt.body.retainedPath.startsWith(relativeAttempt + '/'), true);
    assert.equal(summary.captureEligibleForSeparateReview, expectedExit === 0);
    assert.equal(summary.admittedSourceReview, false);
    assert.equal(summary.signedByThisTool, false);
    assert.equal(fs.existsSync(path.join(absoluteAttempt, summary.receiptFile + '.sig.json')), false);
    assert.equal(fs.readFileSync(outputFile, 'utf8').trim(), `capture_dir=${relativeAttempt}`);
  }
  if (fixture.setup === 'existing-directory') assert.equal(fs.readFileSync(path.join(absoluteAttempt, 'sentinel.txt'), 'utf8'), 'must remain byte-identical');
  if (fixture.setup === 'symlink') assert.equal(fs.readFileSync(path.join(caseDirectory, 'original-target/sentinel.txt'), 'utf8'), 'must remain byte-identical');
  if (fixture.setup === 'parent-file') assert.equal(fs.readFileSync(path.dirname(absoluteAttempt), 'utf8'), 'parent is an existing file; preserve it');
}
const workflow = fs.readFileSync(path.join(root, '.github/workflows/burlingame-city-capture-only.yml'), 'utf8');
assert.match(workflow, /workflow_dispatch:\s*\n\s*permissions:/, 'Manual-only workflow has no free source or URL input');
for (const forbidden of ['schedule:', 'pull_request:', 'push:', 'PAYDECODE_SOURCE_WRITE_TOKEN', 'GH_TOKEN', 'git push', 'gh pr', 'npm ci', 'capture-source-batch', 'capture-archive', 'contents: write']) assert.equal(workflow.includes(forbidden), false, `Workflow must exclude ${forbidden}`);
assert.match(workflow, /ref: \$\{\{ github\.sha \}\}/);
assert.match(workflow, /PAYDECODE_SOURCE_SHA: a013cf5e55985ece73d6720c1fc76ff9f9d18d72/);
assert.match(workflow, /always\(\) && steps\.capture\.outputs\.capture_dir != ''/);
assert.match(workflow, /overwrite: false/);
assert.match(workflow, /persist-credentials: false/);
for (const file of ['scripts/capture-burlingame-city-only.mjs', '.github/workflows/burlingame-city-capture-only.yml']) {
  const source = fs.readFileSync(path.join(root, file), 'utf8');
  assert.doesNotMatch(source, /\b(?:unlinkSync|rmSync|rmdirSync)\s*\(|\brm\s+-/);
}
const summary = { schemaVersion: 1, createdAt: new Date().toISOString(), realPublisherRequests: 0, localSigningOperations: 0, oldFilesDeleted: 0, captureCaseCount: records.length, cases: records, workflowStaticSafetyChecksPassed: true, limits: ['Local subprocess/fake-curl and static workflow checks, not a GitHub Actions run or source admission.'] };
writeNew(path.join(output, 'test-summary.json'), `${JSON.stringify(summary, null, 2)}\n`);
console.log(JSON.stringify({ output, casesPassed: records.length, realPublisherRequests: 0, localSigningOperations: 0, oldFilesDeleted: 0 }, null, 2));
