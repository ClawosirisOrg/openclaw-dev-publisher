import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { closeSync, constants, createWriteStream, mkdtempSync, openSync,
  rmdirSync, unlinkSync } from 'node:fs';
import { once } from 'node:events';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Writable } from 'node:stream';
import { fileURLToPath } from 'node:url';
import { admitCandidate } from '../src/context-contract.mjs';
import { createClaimFrameIssuer, decodeClaimFrame } from '../src/claim-frame.mjs';

const fixture = fileURLToPath(new URL('../broker/tests/worker/frame_reader_fixture.py', import.meta.url));
const root = fileURLToPath(new URL('..', import.meta.url));

function issuer(privatePipe, overrides = {}, afterAdmission = () => {}) {
  const context = {
    agentId: 'dev-syn', sandboxed: true,
    activeModel: { modelRef: 'provider/host-model' },
    assertInvocationCurrent() {},
  };
  const admitted = admitCandidate(context, {
    commitSha: 'a'.repeat(40), branch: 'dev-syn/topic', thinking: 'medium',
  });
  afterAdmission(context);
  return createClaimFrameIssuer({
    privatePipe,
    trustedHost: {
      repository: 'fixture/repository', ref: 'refs/heads/main', base: 'b'.repeat(40),
      candidate: admitted.candidate, assertCurrent: admitted.assertCurrent,
      ...overrides,
    },
  });
}

// The Python fixture imports read_frame directly, with an independent synthetic
// DeploymentPin. fd 3 is a FIFO read descriptor, inherited by Python. Only
// the Node writer opens its private temporary pathname; argv has no frame.
async function readInPython(write) {
  const directory = mkdtempSync(join(tmpdir(), 'claim-frame-'));
  const fifo = join(directory, 'private-pipe');
  const made = spawnSync('mkfifo', ['-m', '600', fifo]);
  if (made.status !== 0) throw new Error('mkfifo failed');
  const readFd = openSync(fifo, constants.O_RDONLY | constants.O_NONBLOCK);
  const pipe = createWriteStream(fifo);
  // Establish the writer before Python can select the nonblocking read fd:
  // otherwise an early read sees EOF rather than waiting for Node's open.
  await once(pipe, 'open');
  const child = spawn('python3', ['-B', fixture], {
    cwd: root,
    env: { ...process.env, PYTHONDONTWRITEBYTECODE: '1' },
    stdio: ['ignore', 'pipe', 'pipe', readFd],
  });
  closeSync(readFd);
  const done = new Promise((resolve, reject) => {
    let stdout = '';
    let stderr = '';
    const timeout = setTimeout(() => child.kill(), 8000);
    child.stdout.setEncoding('utf8');
    child.stderr.setEncoding('utf8');
    child.stdout.on('data', chunk => { stdout += chunk; });
    child.stderr.on('data', chunk => { stderr += chunk; });
    child.on('error', reject);
    child.on('close', (code, signal) => {
      clearTimeout(timeout);
      if (signal || stderr || !stdout.endsWith('\n')) {
        reject(new Error('reader failed: code=' + code + ' signal=' + signal + ' stderr=' + stderr));
      } else {
        try { resolve({ code, body: JSON.parse(stdout) }); }
        catch (error) { reject(error); }
      }
    });
  });
  try {
    await write(pipe);
    if (!pipe.writableEnded) pipe.end();
    return await done;
  } finally {
    pipe.destroy();
    if (child.exitCode === null) child.kill();
    unlinkSync(fifo);
    rmdirSync(directory);
  }
}

async function issuedBytes(overrides) {
  let frame;
  const sink = new Writable({
    write(chunk, _encoding, callback) {
      assert.equal(frame, undefined);
      frame = Buffer.from(chunk);
      callback();
    },
  });
  await issuer(sink, overrides).emit();
  assert.ok(frame);
  return frame;
}

function reframe(body) {
  const raw = Buffer.from(JSON.stringify(body), 'utf8');
  const frame = Buffer.alloc(4 + raw.length);
  frame.writeUInt32BE(raw.length, 0);
  raw.copy(frame, 4);
  return frame;
}

test('real Node issuer feeds Python read_frame over private fd 3', async () => {
  const result = await readInPython(pipe => issuer(pipe).emit());
  assert.deepEqual(result, {
    code: 0,
    body: { ok: true, same_id: true, repository: 'fixture/repository',
      ref: 'refs/heads/main', model: 'provider/host-model', thinking: 'medium' },
  });
});

test('Python rejects tampered, mismatched, truncated and trailing Node-issued bytes', async () => {
  const frame = await issuedBytes();
  const body = JSON.parse(frame.subarray(4).toString('utf8'));
  assert.match(body.transactionId, /^[0-9a-f]{32}$/);
  assert.equal(body.claimId, body.transactionId);
  assert.equal(frame.readUInt32BE(0), frame.length - 4);
  const mismatchedId = reframe({ ...body, claimId: 'f' === body.claimId[0]
    ? '0' + body.claimId.slice(1) : 'f' + body.claimId.slice(1) });
  // Both endpoints reject a claim ID that differs from the transaction ID.
  assert.throws(() => decodeClaimFrame(mismatchedId), /claim_frame_invalid/);

  for (const [label, bytes, error] of [
    ['extra field', reframe({ ...body, extra: 'not-authority' }), 'invalid claim schema'],
    ['ID mismatch', mismatchedId, 'invalid claim context'],
    ['repository pin mismatch', reframe({ ...body, repository: 'fixture/other' }), 'invalid claim context'],
    ['wrong ref', reframe({ ...body, ref: 'refs/heads/other' }), 'invalid claim context'],
    ['short header', frame.subarray(0, 3), 'truncated claim frame'],
    ['short body', frame.subarray(0, -1), 'truncated claim frame'],
    ['extra bytes', Buffer.concat([frame, Buffer.from([0])]), 'trailing claim frame bytes'],
    ['noncanonical JSON', reframe(Object.fromEntries(Object.entries(body).reverse())), 'invalid claim schema'],
  ]) {
    const result = await readInPython(pipe => { pipe.end(bytes); });
    assert.deepEqual(result, { code: 2, body: { ok: false, error } }, label);
  }
});

test('stale live guard emits no bytes to the Python pipe', async () => {
  const result = await readInPython(async pipe => {
    const claim = issuer(pipe, {}, context => {
      context.activeModel.modelRef = 'provider/changed';
    });
    await assert.rejects(claim.emit(), /stale_invocation/);
    await assert.rejects(claim.emit(), /claim_frame_already_emitted/);
  });
  assert.deepEqual(result, { code: 2, body: { ok: false, error: 'truncated claim frame' } });
});

test('Gateway denies equal base and sha before sending bytes', async () => {
  const pipe = new Writable({ write(_chunk, _encoding, callback) { callback(); } });
  assert.throws(() => issuer(pipe, { base: 'a'.repeat(40) }), /claim_frame_invalid/);
});
