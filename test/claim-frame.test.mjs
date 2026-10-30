import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { admitCandidate } from '../src/context-contract.mjs';
import { createClaimFrameIssuer, decodeClaimFrame,
  MAX_CLAIM_FRAME_BODY_BYTES } from '../src/claim-frame.mjs';

class FakePipe extends EventEmitter {
  constructor(accepted = true) {
    super();
    this.accepted = accepted;
    this.frames = [];
    this.callback = null;
  }
  write(buffer, callback) {
    this.frames.push(Buffer.from(buffer));
    this.callback = callback;
    return this.accepted;
  }
  complete(error, count) { this.callback(error, count); }
}

function host(overrides = {}) {
  const context = {
    agentId: 'dev-syn', sandboxed: true,
    activeModel: { modelRef: 'provider/host-model' },
    assertInvocationCurrent() {},
  };
  const admitted = admitCandidate(context, {
    commitSha: 'a'.repeat(40), branch: 'dev-syn/topic', thinking: 'medium',
  });
  return {
    repository: 'fixture/repository', ref: 'refs/heads/main', base: 'b'.repeat(40),
    candidate: admitted.candidate, context,
    assertCurrent: admitted.assertCurrent,
    ...overrides,
  };
}

function make(trustedHost = host(), pipe = new FakePipe()) {
  return { pipe, issuer: createClaimFrameIssuer({ trustedHost, privatePipe: pipe }) };
}

async function emitted() {
  const { issuer, pipe } = make();
  const pending = issuer.emit();
  pipe.complete();
  await pending;
  return pipe.frames[0];
}

function raw(body) {
  const bytes = Buffer.from(JSON.stringify(body));
  const frame = Buffer.alloc(4 + bytes.length);
  frame.writeUInt32BE(bytes.length);
  bytes.copy(frame, 4);
  return frame;
}

test('one length-prefixed canonical frame has CSPRNG ID, host model and attested thinking only', async () => {
  const pipe = new FakePipe();
  const trustedHost = host({ toolCallId: 'a'.repeat(32), claimId: 'caller-forged', token: 'bearer-DO-NOT-EMIT' });
  const issuer = createClaimFrameIssuer({ trustedHost, privatePipe: pipe });
  const pending = issuer.emit();
  assert.equal(pipe.frames.length, 1);
  await assert.rejects(issuer.emit(), /claim_frame_already_emitted/);
  assert.equal(pipe.frames.length, 1);
  pipe.complete();
  await pending;
  const frame = pipe.frames[0];
  assert.equal(frame.readUInt32BE(0), frame.length - 4);
  const body = decodeClaimFrame(frame);
  assert.deepEqual(Object.keys(body), ['version', 'transactionId', 'repository', 'ref',
    'base', 'sha', 'branch', 'model', 'thinking', 'thinkingSource', 'claimId']);
  assert.match(body.transactionId, /^[0-9a-f]{32}$/);
  assert.notEqual(body.transactionId, trustedHost.toolCallId);
  assert.equal(body.claimId, body.transactionId);
  assert.equal(body.model, 'provider/host-model');
  assert.equal(body.thinkingSource, 'agent_attested');
  assert.equal(body.thinking, 'medium');
  assert.equal(frame.includes(Buffer.from('bearer-DO-NOT-EMIT')), false);
  assert.equal(JSON.stringify(issuer).includes('assertCurrent'), false);
  assert.equal(pipe.frames.length, 1);
  await assert.rejects(issuer.emit(), /claim_frame_already_emitted/);
  const second = make();
  const pendingSecond = second.issuer.emit();
  second.pipe.complete();
  await pendingSecond;
  assert.notEqual(decodeClaimFrame(second.pipe.frames[0]).transactionId, body.transactionId);
});

test('truncated, oversized, trailing, noncanonical and malformed frames denied', async () => {
  const valid = await emitted();
  assert.throws(() => decodeClaimFrame(valid.subarray(0, 3)), /truncated/);
  assert.throws(() => decodeClaimFrame(valid.subarray(0, -1)), /truncated/);
  assert.throws(() => decodeClaimFrame(Buffer.concat([valid, Buffer.from('x')])), /truncated/);
  const oversized = Buffer.alloc(4);
  oversized.writeUInt32BE(MAX_CLAIM_FRAME_BODY_BYTES + 1);
  assert.throws(() => decodeClaimFrame(oversized), /oversized/);
  assert.throws(() => decodeClaimFrame(Buffer.alloc(4)), /oversized/);
  const body = decodeClaimFrame(valid);
  assert.throws(() => decodeClaimFrame(raw({ ...body, token: 'secret' })), /invalid/);
  assert.throws(() => decodeClaimFrame(raw(Object.fromEntries(
    Object.entries(body).reverse()))), /noncanonical/);
  assert.throws(() => decodeClaimFrame(raw({ ...body, thinking: 'forged' })), /invalid/);
  assert.throws(() => decodeClaimFrame(raw({ ...body, transactionId: 'x'.repeat(32) })), /invalid/);
  assert.throws(() => decodeClaimFrame(raw({ ...body, repository: '../repo' })), /invalid/);
  assert.throws(() => decodeClaimFrame(raw({ ...body, claimId: 'x\nsecret' })), /invalid/);
  assert.throws(() => decodeClaimFrame(raw({ ...body, ref: 'refs/heads/../wrong' })), /invalid/);
  assert.throws(() => decodeClaimFrame(raw({ ...body, ref: 'refs/heads/other' })), /invalid/);
  assert.throws(() => decodeClaimFrame(raw({ ...body, sha: body.base })), /invalid/);
  assert.throws(() => decodeClaimFrame(raw({ ...body, claimId: body.claimId[0] === 'f'
    ? '0' + body.claimId.slice(1) : 'f' + body.claimId.slice(1) })), /invalid/);
});

test('malformed host data and missing assertion fail before writing', () => {
  for (const invalid of [
    { base: 'not-sha' }, { ref: 'refs/heads/../wrong' }, { repository: 'token://bad' },
    { candidate: { ...host().candidate, model: '../bad' } },
    { candidate: { ...host().candidate, thinking_source: 'gateway_attested' } },
    { assertCurrent: undefined },
  ]) {
    const pipe = new FakePipe();
    assert.throws(() => make(host(invalid), pipe), /invalid|unavailable/);
    assert.equal(pipe.frames.length, 0);
  }
});

test('stale or throwing guard emits nothing and cannot retry', async () => {
  for (const guard of [() => false, () => { throw new Error('expired'); }]) {
    const { issuer, pipe } = make(host({ assertCurrent: guard }));
    await assert.rejects(issuer.emit(), /stale_invocation/);
    await assert.rejects(issuer.emit(), /already_emitted/);
    assert.equal(pipe.frames.length, 0);
  }
  let live = true;
  const candidateHost = host({ assertCurrent: () => live });
  const { issuer, pipe } = make(candidateHost);
  candidateHost.assertCurrent = () => true; // replacement cannot bypass retained closure
  live = false;
  await assert.rejects(issuer.emit(), /stale_invocation/);
  assert.equal(pipe.frames.length, 0);
  const switched = host();
  const otherPipe = new FakePipe();
  const otherIssuer = createClaimFrameIssuer({ trustedHost: switched, privatePipe: otherPipe });
  switched.context.activeModel.modelRef = 'provider/changed';
  await assert.rejects(otherIssuer.emit(), /stale_invocation/);
  assert.equal(otherPipe.frames.length, 0);
});

test('backpressure waits for callback and drain, and close/error/short writes fail closed', async () => {
  const pipe = new FakePipe(false);
  const { issuer } = make(host(), pipe);
  let settled = false;
  const pending = issuer.emit().then(() => { settled = true; });
  pipe.complete();
  await Promise.resolve();
  assert.equal(settled, false);
  pipe.emit('drain');
  await pending;
  assert.equal(settled, true);
  for (const [event, reason] of [['close', /closed/], ['error', /error/]]) {
    const broken = new FakePipe(false);
    const attempt = make(host(), broken).issuer.emit();
    broken.emit(event, event === 'error' ? new Error('private failure') : undefined);
    await assert.rejects(attempt, reason);
  }
  const callbackFailure = new FakePipe();
  const failed = make(host(), callbackFailure).issuer.emit();
  callbackFailure.complete(new Error('private detail'));
  await assert.rejects(failed, /^Error: claim_pipe_error$/);
  const throwing = new FakePipe();
  throwing.write = () => { throw new Error('private detail'); };
  await assert.rejects(make(host(), throwing).issuer.emit(), /^Error: claim_pipe_error$/);
  const short = new FakePipe();
  const attempt = make(host(), short).issuer.emit();
  short.complete(null, short.frames[0].length - 1);
  await assert.rejects(attempt, /short_write/);
  assert.equal(short.frames.length, 1);
  const closed = new FakePipe();
  closed.destroyed = true;
  await assert.rejects(make(host(), closed).issuer.emit(), /closed/);
  assert.equal(closed.frames.length, 0);
});
