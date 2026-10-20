// One of four fixed ordinary legal-watch GETs. This tool never signs, follows a redirect,
// retries, visits an archive, changes reviews, deletes or overwrites evidence.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

import {SOURCE_SHA,RUNNER_REPOSITORY,WORKFLOW_PATH,USER_AGENT,MAX_BYTES,getSpecialCaptureSource} from './lib/special-source-capture-only.mjs';
const source = getSpecialCaptureSource(process.argv[3]);
const SOURCE_URL = source?.url;
const NAME = `special-source-${source?.id || 'invalid'}`;
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');
const writeNew = (file, bytes) => fs.writeFileSync(file, bytes, { flag: 'wx', mode: 0o600 });
const localEnv = { PATH: process.env.PATH, LANG: 'C', LC_ALL: 'C' };
let attemptDirectory;
try {
  assert.equal(process.argv.length, 4, 'Only source-root and one fixed source ID are accepted; URL and SHA are fixed');
  assert.ok(source, 'Unknown source ID; only the four reviewed legal-watch sources are permitted');
  assert.equal(process.env.GITHUB_ACTIONS, 'true', 'Run only in the approved GitHub Actions workflow');
  assert.equal(process.env.GITHUB_REPOSITORY, RUNNER_REPOSITORY);
  assert.equal(process.env.GITHUB_REF, 'refs/heads/main');
  assert.equal(process.env.GITHUB_WORKFLOW_REF, `${RUNNER_REPOSITORY}/${WORKFLOW_PATH}@refs/heads/main`);
  assert.match(process.env.GITHUB_SHA || '', /^[0-9a-f]{40}$/);
  assert.match(process.env.GITHUB_RUN_ID || '', /^[1-9][0-9]*$/);
  assert.match(process.env.GITHUB_RUN_ATTEMPT || '', /^[1-9][0-9]*$/);
  assert.equal(process.env.PAYDECODE_SOURCE_SHA, SOURCE_SHA);
  const sourceRoot = path.resolve(process.argv[2]);
  assert.equal(fs.realpathSync(sourceRoot), sourceRoot, 'Source checkout path cannot traverse a symlink');
  const head = spawnSync('git', ['-C', sourceRoot, 'rev-parse', 'HEAD'], { encoding: 'utf8', env: localEnv, timeout: 10000 });
  assert.equal(head.status, 0, 'Source checkout must be a Git repository');
  assert.equal(head.stdout.trim(), SOURCE_SHA, 'Never execute or sign against an unreviewed source commit');
  const createdAt = new Date().toISOString();
  const relativeDirectory = `research/source-captures/${createdAt.slice(0, 10)}-run${process.env.GITHUB_RUN_ID}/special-source-${source.id}-attempt${process.env.GITHUB_RUN_ATTEMPT}`;
  const parts = relativeDirectory.split('/');
  let current = sourceRoot;
  for (const [index, part] of parts.entries()) {
    current = path.join(current, part);
    let previous;
    try { previous = fs.lstatSync(current); } catch (error) { if (error.code !== 'ENOENT') throw error; }
    if (previous) {
      assert.equal(previous.isSymbolicLink(), false, 'Evidence path cannot traverse a symlink');
      assert.equal(previous.isDirectory(), true, 'Evidence parents must be directories');
      assert.ok(index < parts.length - 1, 'Attempt path already exists: preserve it and refuse to overwrite');
    } else fs.mkdirSync(current, { mode: 0o700 });
  }
  attemptDirectory = current;
  if (process.env.GITHUB_OUTPUT) fs.appendFileSync(process.env.GITHUB_OUTPUT, `capture_dir=${relativeDirectory}\n`);
  const invocation = {
    schemaVersion: 1, createdAt, sourceRepository: 'abuhasnatruhu/paydecode.com', sourceSha: SOURCE_SHA,
    runnerRepository: RUNNER_REPOSITORY, workflowPath: WORKFLOW_PATH,
    workflowSha: process.env.GITHUB_SHA, githubRunId: process.env.GITHUB_RUN_ID,
    githubRunAttempt: process.env.GITHUB_RUN_ATTEMPT, sourceUrl: SOURCE_URL,
    sourceId: source.id, expectedBodyKind: source.kind,
    method: 'GET', redirectPolicy: 'no-follow', retries: 0, archiveRequests: 0,
    maxBytes: MAX_BYTES, maxTimeSeconds: 20, connectTimeoutSeconds: 15,
    userAgent: USER_AGENT, cookieOrCredentialInput: false,
    sourceOrReviewAdmission: false, outputDirectory: relativeDirectory
  };
  writeNew(path.join(current, 'invocation.json'), `${JSON.stringify(invocation, null, 2)}\n`);
  const version = spawnSync('curl', ['-q', '--version'], { encoding: 'utf8', env: localEnv, timeout: 5000, maxBuffer: 65536 });
  writeNew(path.join(current, 'curl-version.stdout.txt'), version.stdout || '');
  writeNew(path.join(current, 'curl-version.stderr.txt'), version.stderr || '');
  assert.equal(version.status, 0, 'curl version must be inspectable');
  const parsedVersion = /^curl (\d+)\.(\d+)\.(\d+)/.exec(version.stdout || '');
  assert.ok(parsedVersion && (Number(parsedVersion[1]) > 8 || (Number(parsedVersion[1]) === 8 && Number(parsedVersion[2]) >= 4)), 'curl >=8.4 is required to cap an unknown-length body without deleting it');
  const rawBody = path.join(current, 'body.raw');
  const rawHeaders = path.join(current, 'headers.raw');
  writeNew(rawBody, Buffer.alloc(0));
  writeNew(rawHeaders, Buffer.alloc(0));
  const args = ['-q', '--silent', '--show-error', '--noproxy', '*', '--proto', '=https',
    '--max-redirs', '0', '--retry', '0', '--connect-timeout', '15', '--max-time', '20',
    '--max-filesize', String(MAX_BYTES), '--user-agent', USER_AGENT,
    '--header', 'Accept-Encoding: identity', '--dump-header', rawHeaders, '--output', rawBody,
    '--write-out', '%{http_code}\t%{url_effective}\t%{num_redirects}\t%{content_type}\t%{size_download}\n', SOURCE_URL];
  writeNew(path.join(current, 'curl-arguments.json'), `${JSON.stringify(args, null, 2)}\n`);
  const startedAt = new Date().toISOString();
  const stdoutPath = path.join(current, 'curl.stdout.txt');
  const stderrPath = path.join(current, 'curl.stderr.txt');
  const stdoutFd = fs.openSync(stdoutPath, 'wx', 0o600);
  const stderrFd = fs.openSync(stderrPath, 'wx', 0o600);
  // No signing/read token or ambient proxy/CURL configuration reaches curl.
  let result;
  try {
    result = spawnSync('curl', args, { env: localEnv, timeout: 25000, stdio: ['ignore', stdoutFd, stderrFd] });
  } finally {
    fs.closeSync(stdoutFd);
    fs.closeSync(stderrFd);
  }
  const receivedAt = new Date().toISOString();
  const stdout = fs.readFileSync(stdoutPath, 'utf8');
  const stderr = fs.readFileSync(stderrPath, 'utf8');
  const [status, finalUrl, redirects, contentType, downloadedSize] = stdout.trim().split('\t');
  const body = fs.readFileSync(rawBody);
  const headers = fs.readFileSync(rawHeaders);
  const retain = (bytes, kind, extension) => {
    const digest = sha256(bytes);
    const filename = `${NAME}-${kind}.${digest}.${extension}`;
    writeNew(path.join(current, filename), bytes);
    return { retainedPath: `${relativeDirectory}/${filename}`, sha256: digest, byteLength: bytes.length };
  };
  const bodyRef = retain(body, 'body', /^application\/pdf(?:;|$)/i.test(contentType || '') ? 'pdf' : /html/i.test(contentType || '') ? 'html' : 'bin');
  const headersRef = retain(headers, 'headers', 'txt');
  const receipt = {
    schemaVersion: 1, evidenceType: 'ordinary-direct-http-attempt', name: NAME,
    sourceUrl: SOURCE_URL, startedAt, receivedAt, curlExitCode: result.status,
    httpStatus: /^\d{3}$/.test(status || '') ? Number(status) : null,
    finalUrl: finalUrl || null, redirectCount: /^\d+$/.test(redirects || '') ? Number(redirects) : null,
    contentType: contentType || null, stderr: stderr.trim(), body: bodyRef, headers: headersRef,
    transportMethod: 'Single ordinary credential-free curl GET with the existing PayDecode maintenance user agent; curlrc disabled; no proxy, redirect follow, retry, cookies, archive or challenge handling. All original success/failure bytes retained. A signature, when separately produced by the existing runner signer, authenticates this receipt, not source facts or review admission.',
    limitations: ['Transport capture only; no content/legal/source-review renewal, gate waiver or release approval.', 'Non-200, redirected, partial, challenge, oversized and failed attempts remain failures even when their original bytes are retained.']
  };
  const receiptBytes = Buffer.from(`${JSON.stringify(receipt, null, 2)}\n`);
  const receiptFile = `${NAME}-receipt.${sha256(receiptBytes)}.json`;
  writeNew(path.join(current, receiptFile), receiptBytes);
  const failures = [];
  if (result.status !== 0 || result.error || result.signal) failures.push('curl-process-failed');
  if (receipt.httpStatus !== 200) failures.push('not-http200');
  if (receipt.finalUrl !== SOURCE_URL || receipt.redirectCount !== 0) failures.push('not-exact-no-redirect-url');
  const expectedType = source.kind === 'pdf' ? /^application\/pdf(?:;|$)/i : /^text\/html(?:;|$)/i;
  if (!expectedType.test(receipt.contentType || '')) failures.push('wrong-content-type');
  if (body.length < 500 || body.length > MAX_BYTES) failures.push('empty-nonsubstantive-or-oversized-body');
  if (source.kind === 'html' && !/<(?:html|body|main|article)(?:\s|>)/i.test(body.toString('utf8'))) failures.push('not-html-body');
  if (source.kind === 'pdf') {
    const prefix = body.subarray(0, 5).toString('ascii') === '%PDF-';
    const eof = /%%EOF\s*$/.test(body.subarray(-2048).toString('latin1'));
    if (!prefix || !eof) failures.push('incomplete-or-not-pdf-body');
    let parser = { attempted: false, eligible: false, reason: 'not-complete200-pdf-candidate' };
    if (prefix && eof && receipt.httpStatus === 200 && result.status === 0 && body.length <= MAX_BYTES) {
      const info = spawnSync('pdfinfo', [rawBody], { encoding: 'utf8', env: localEnv, timeout: 10000, maxBuffer: 1048576 });
      const text = spawnSync('pdftotext', ['-layout', rawBody, '-'], { encoding: 'buffer', env: localEnv, timeout: 10000, maxBuffer: 4194304 });
      writeNew(path.join(current, 'pdfinfo.stdout.txt'), info.stdout || '');
      writeNew(path.join(current, 'pdfinfo.stderr.txt'), info.stderr || '');
      writeNew(path.join(current, 'pdftotext.stdout.txt'), text.stdout || Buffer.alloc(0));
      writeNew(path.join(current, 'pdftotext.stderr.txt'), text.stderr || Buffer.alloc(0));
      const pages = Number((info.stdout || '').match(/^Pages:\s+(\d+)\s*$/m)?.[1]);
      parser = { attempted: true, pdfinfoExit: info.status, pdfinfoSignal: info.signal, pdfinfoError: info.error?.message || null, pdftotextExit: text.status, pdftotextSignal: text.signal, pdftotextError: text.error?.message || null, pages: Number.isInteger(pages) ? pages : null, textByteLength: text.stdout?.length || 0, eligible: info.status === 0 && !info.error && !info.signal && text.status === 0 && !text.error && !text.signal && Number.isInteger(pages) && pages > 0 && pages <= 1000 && (text.stdout?.length || 0) >= 100 };
    }
    writeNew(path.join(current, 'pdf-parser-result.json'), `${JSON.stringify(parser, null, 2)}\n`);
    if (!parser.eligible) failures.push('pdf-parser-unavailable-or-incomplete');
  }
  if (!Number.isFinite(Number(downloadedSize)) || Number(downloadedSize) !== body.length) failures.push('download-size-mismatch');
  const headerBlocks = headers.toString('utf8').trim().split(/\r?\n\r?\n+/);
  if (headerBlocks.length !== 1 || !/^HTTP\/(?:1\.0|1\.1|2|3) 200(?:\s|$)/.test(headerBlocks[0])) failures.push('unexpected-or-incomplete-response-headers');
  if (/^content-range:/im.test(headers.toString('utf8'))) failures.push('unexpected-content-range');
  const headerValues = name => [...headers.toString('utf8').matchAll(new RegExp(`^${name}:([^\\r\\n]*)`, 'gim'))].map(match => match[1].trim());
  const lengthHeaders = headerValues('content-length');
  if (lengthHeaders.length > 1 || (lengthHeaders.length === 1 && (!/^\d+$/.test(lengthHeaders[0]) || Number(lengthHeaders[0]) !== body.length))) failures.push('content-length-mismatch');
  const typeHeaders = headerValues('content-type');
  if (typeHeaders.length !== 1 || !expectedType.test(typeHeaders[0])) failures.push('raw-content-type-mismatch');
  const encodingHeaders = headerValues('content-encoding');
  if (encodingHeaders.length > 1 || (encodingHeaders.length === 1 && encodingHeaders[0].toLowerCase() !== 'identity')) failures.push('unexpected-compressed-body');
  if (/Just a moment\.\.\.|Verify you are human|Performing security verification|Due to aggressive automated scraping|Please enable JavaScript to view|Access Denied|The requested URL was rejected|One moment, please\.\.\./i.test(body.toString('utf8'))) failures.push('challenge-or-access-denial-body');
  const summary = {
    schemaVersion: 1, sourceId: source.id, expectedBodyKind: source.kind, sourceUrl: SOURCE_URL, startedAt, receivedAt,
    curlExitCode: result.status, curlSignal: result.signal, processError: result.error?.message || null,
    receiptFile, receiptSha256: sha256(receiptBytes), httpStatus: receipt.httpStatus,
    originalRawBodySha256: sha256(body), originalRawHeadersSha256: sha256(headers),
    captureEligibleForSeparateReview: failures.length === 0, failures,
    signedByThisTool: false, admittedSourceReview: false, trustedSourceHealthRun: false,
    oldFilesRemovedOrOverwritten: false
  };
  writeNew(path.join(current, 'capture-result.json'), `${JSON.stringify(summary, null, 2)}\n`);
  console.log(JSON.stringify({ directory: relativeDirectory, ...summary }));
  process.exitCode = failures.length ? 4 : 0;
} catch (error) {
  if (attemptDirectory) {
    try { writeNew(path.join(attemptDirectory, 'tool-failure.json'), `${JSON.stringify({ failedAt: new Date().toISOString(), message: error.message, originalFilesPreserved: true, attemptedAdmission: false }, null, 2)}\n`); } catch {}
  }
  console.error(`Capture refused or failed; existing evidence preserved: ${error.message}`);
  process.exitCode = 5;
}
