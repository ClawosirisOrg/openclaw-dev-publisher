import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { spawn, spawnSync } from 'node:child_process';
import { closeSync, constants, createWriteStream, mkdtempSync,
  openSync, rmSync } from 'node:fs';
import { once } from 'node:events';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { decodeClaimFrame, MAX_CLAIM_FRAME_BODY_BYTES } from '../src/claim-frame.mjs';
import { createDisabledHandoffFixture } from '../src/disabled-handoff.mjs';

const request = Object.freeze({ commitSha: 'a'.repeat(40),
  branch: 'dev-syn/topic', thinking: 'medium' });
const base = 'b'.repeat(40);
function context() {
  let live = true;
  const host = { agentId: 'dev-syn', sandboxed: true,
    activeModel: { modelRef: 'provider/host-model' },
    assertInvocationCurrent() { return live; } };
  return { host, abort() { live = false; } };
}
class FakePipe extends EventEmitter {
  frames = [];
  closed = false;
  callback = null;
  write(bytes, callback) {
    this.frames.push(Buffer.from(bytes));
    this.callback = callback;
    return true;
  }
  complete(error, count) { this.callback(error, count); }
  destroy() { this.closed = true; }
}
function fixture(overrides = {}) {
  const pipe = new FakePipe();
  const calls = { base: 0, pipe: 0 };
  const pins = { repository: 'fixture/repository', ref: 'refs/heads/main',
    async lookupFixedBaseForTest(...args) {
      calls.base++;
      assert.equal(args.length, 0);
      return base;
    },
    async openPrivatePipeForTest(...args) {
      calls.pipe++;
      assert.equal(args.length, 0);
      return pipe;
    },
    ...overrides };
  return { handoff: createDisabledHandoffFixture(pins), pins, pipe, calls };
}
const tick = () => new Promise(resolve => setImmediate(resolve));

test('one bounded frame from fixed pins, then disabled; replay and forged metadata denied', async () => {
  const { host } = context();
  const { handoff, pipe, calls, pins } = fixture();
  const pending = handoff.run(host, request);
  await assert.rejects(handoff.run(host, request), /handoff_replay_denied/);
  pins.repository = 'attacker/retargeted'; // caller config mutation has no effect
  await tick();
  assert.equal(pipe.frames.length, 1);
  const frame = pipe.frames[0];
  assert.ok(frame.length <= 4 + MAX_CLAIM_FRAME_BODY_BYTES);
  assert.equal(frame.readUInt32BE(0), frame.length - 4);
  const body = decodeClaimFrame(frame);
  assert.equal(body.repository, 'fixture/repository');
  assert.equal(body.ref, 'refs/heads/main');
  assert.equal(body.base, base);
  assert.equal(body.sha, request.commitSha);
  assert.equal(body.model, 'provider/host-model');
  assert.equal(body.thinkingSource, 'agent_attested');
  assert.equal(body.claimId, body.transactionId);
  assert.match(body.claimId, /^[0-9a-f]{32}$/);
  pipe.complete();
  await assert.rejects(pending, /^Error: publication_disabled$/);
  assert.equal(pipe.closed, true);
  assert.deepEqual(calls, { base: 1, pipe: 1 });
  await assert.rejects(handoff.run(host, request), /handoff_replay_denied/);
  assert.equal(pipe.frames.length, 1);
  const fresh = fixture();
  await assert.rejects(fresh.handoff.run(host, { ...request,
    model: 'attacker/model', token: 'fixture-secret', argv: ['fixture-secret'] }),
  /candidate_request_invalid/);
  assert.deepEqual(fresh.calls, { base: 0, pipe: 0 });
  assert.equal(fresh.pipe.frames.length, 0);
});

test('aborted, switched, or revoked context across each await writes nothing', async () => {
  for (const phase of ['base', 'pipe']) {
    for (const invalidate of [
      ({ host }) => { host.activeModel.modelRef = 'provider/switched'; },
      ({ abort }) => abort(),
      ({ host }) => { host.sandboxed = false; },
    ]) {
      const state = context();
      let release;
      const waiting = new Promise(resolve => { release = resolve; });
      const setup = fixture(phase === 'base'
        ? { lookupFixedBaseForTest: async () => { await waiting; return base; } }
        : { openPrivatePipeForTest: async () => { await waiting; return setup.pipe; } });
      const pending = setup.handoff.run(state.host, request);
      await tick();
      invalidate(state);
      release();
      await assert.rejects(pending, /stale_invocation|candidate_context_unavailable/);
      assert.equal(setup.pipe.frames.length, 0);
      assert.equal(setup.pipe.closed, phase === 'pipe');
      assert.equal(setup.calls.pipe, 0);
    }
  }
});

test('replacing the invocation assertion during either await cannot write a frame', async () => {
  for (const phase of ['base', 'pipe']) {
    const state = context();
    let originalCurrent = true;
    state.host.assertInvocationCurrent = () => originalCurrent;
    const setup = fixture(phase === 'base'
      ? { lookupFixedBaseForTest: async () => {
        originalCurrent = false;
        state.host.assertInvocationCurrent = () => true;
        return base;
      } }
      : { openPrivatePipeForTest: async () => {
        originalCurrent = false;
        state.host.assertInvocationCurrent = () => true;
        return setup.pipe;
      } });
    const rejection = assert.rejects(setup.handoff.run(state.host, request), /stale_invocation/);
    await tick();
    if (setup.pipe.callback) setup.pipe.complete(); // unexpected write must not hang the red test
    await rejection;
    assert.equal(setup.pipe.frames.length, 0);
  }
});

test('final synchronous issuer guard denies expiration without pipe writes', async () => {
  const { host } = context();
  let checks = 0;
  // admission, pre/post lookup, pre/post opener, then issuer write guard.
  host.assertInvocationCurrent = () => ++checks !== 6;
  const { handoff, pipe } = fixture();
  await assert.rejects(handoff.run(host, request), /stale_invocation/);
  assert.equal(checks, 6);
  assert.equal(pipe.frames.length, 0);
  assert.equal(pipe.closed, true);
});

test('invalid base, setup failure, and failed write never produce a receipt', async () => {
  for (const invalid of ['not-a-sha', request.commitSha, null]) {
    const setup = fixture({ lookupFixedBaseForTest: async () => invalid });
    await assert.rejects(setup.handoff.run(context().host, request), /trusted_base_unavailable/);
    assert.deepEqual(setup.calls, { base: 0, pipe: 0 });
    assert.equal(setup.pipe.frames.length, 0);
  }
  const lookup = fixture({ lookupFixedBaseForTest: async () => { throw Error('fixture-private-detail'); } });
  await assert.rejects(lookup.handoff.run(context().host, request), /^Error: trusted_base_unavailable$/);
  const opener = fixture({ openPrivatePipeForTest: async () => { throw Error('fixture-private-detail'); } });
  await assert.rejects(opener.handoff.run(context().host, request), /^Error: private_pipe_unavailable$/);
  const missing = fixture({ openPrivatePipeForTest: async () => null });
  await assert.rejects(missing.handoff.run(context().host, request), /private_pipe_unavailable/);
  const malformed = fixture({ openPrivatePipeForTest: async () => {
    malformed.pipe.write = undefined;
    return malformed.pipe;
  } });
  await assert.rejects(malformed.handoff.run(context().host, request), /trusted_claim_host_unavailable/);
  assert.equal(malformed.pipe.closed, true);
  assert.equal(malformed.pipe.frames.length, 0);
  const broken = fixture({ openPrivatePipeForTest: async () => {
    broken.pipe.write = () => { throw Error('fixture-private-detail'); };
    return broken.pipe;
  } });
  await assert.rejects(broken.handoff.run(context().host, request), /^Error: claim_pipe_error$/);
  assert.equal(broken.pipe.closed, true);
  assert.equal(broken.pipe.frames.length, 0);
  const short = fixture();
  const pending = short.handoff.run(context().host, request);
  await tick();
  short.pipe.complete(null, short.pipe.frames[0].length - 1);
  await assert.rejects(pending, /claim_pipe_short_write/);
  assert.equal(short.pipe.closed, true);
});

test('cleanup errors cannot replace the disabled result or leak private detail', async () => {
  for (const destroy of [
    () => { throw Error('fixture-private-destroy-detail'); },
    () => Promise.reject(Error('fixture-private-destroy-detail')),
  ]) {
    const setup = fixture();
    setup.pipe.destroy = destroy;
    const pending = setup.handoff.run(context().host, request);
    await tick();
    setup.pipe.complete();
    await assert.rejects(pending, /^Error: publication_disabled$/);
    assert.equal(setup.pipe.frames.length, 1);
  }
});

test('fixture pins and request cannot inject argv/env/log or retarget the pipe', async () => {
  for (const bad of [null, {}, { repository: 'fixture/repository', ref: 'refs/heads/other' },
    { repository: '../other', ref: 'refs/heads/main' }]) {
    assert.throws(() => createDisabledHandoffFixture(bad), /test_handoff_dependencies_unavailable/);
  }
  const state = context();
  const setup = fixture();
  const argv = [...process.argv];
  const oldLog = console.log;
  const logs = [];
  console.log = (...args) => logs.push(args);
  try {
    const pending = setup.handoff.run(state.host, request);
    await tick();
    setup.pipe.complete();
    await assert.rejects(pending, /publication_disabled/);
  } finally { console.log = oldLog; }
  assert.deepEqual(logs, []);
  assert.deepEqual(process.argv, argv);
  assert.equal(JSON.stringify(decodeClaimFrame(setup.pipe.frames[0])).includes('fixture-secret'), false);
  assert.equal(setup.pipe.closed, true);
});

test('disabled handoff frame decodes in independent Python FIFO reader', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'disabled-handoff-'));
  const fifo = join(dir, 'pipe');
  let reader;
  let writer;
  try {
    assert.equal(spawnSync('mkfifo', ['-m', '600', fifo]).status, 0);
    const fd = openSync(fifo, constants.O_RDONLY | constants.O_NONBLOCK);
    try {
      writer = createWriteStream(fifo);
      await once(writer, 'open');
      reader = spawn('python3', ['-B', fileURLToPath(new URL(
        '../broker/tests/worker/frame_reader_fixture.py', import.meta.url))], {
        cwd: fileURLToPath(new URL('..', import.meta.url)),
        env: { PYTHONDONTWRITEBYTECODE: '1' }, // no inherited credentials
        stdio: ['ignore', 'pipe', 'pipe', fd],
      });
    } finally { closeSync(fd); }
    const output = new Promise((resolve, reject) => {
      let stdout = '';
      let stderr = '';
      reader.stdout.on('data', chunk => { stdout += chunk; });
      reader.stderr.on('data', chunk => { stderr += chunk; });
      reader.on('error', reject);
      reader.on('close', code => {
        if (stderr) reject(new Error('offline reader failed'));
        else resolve({ code, body: JSON.parse(stdout) });
      });
    });
    const handoff = createDisabledHandoffFixture({
      repository: 'fixture/repository', ref: 'refs/heads/main',
      async lookupFixedBaseForTest() { return base; },
      async openPrivatePipeForTest() { return writer; },
    });
    await assert.rejects(handoff.run(context().host, request), /^Error: publication_disabled$/);
    assert.deepEqual(await output, { code: 0, body: { ok: true, same_id: true,
      repository: 'fixture/repository', ref: 'refs/heads/main',
      model: 'provider/host-model', thinking: 'medium' } });
  } finally {
    writer?.destroy();
    if (reader && reader.exitCode === null) reader.kill();
    rmSync(dir, { recursive: true, force: true });
  }
});
