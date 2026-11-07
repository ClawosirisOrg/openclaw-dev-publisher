import test from 'node:test';
import assert from 'node:assert/strict';
import { chmodSync, mkdtempSync, rmSync, symlinkSync } from 'node:fs';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { once } from 'node:events';
import { decodeClaimFrame } from '../src/claim-frame.mjs';
import { createPrivateHostChannel } from '../src/private-host-channel.mjs';

const request = Object.freeze({ commitSha: 'a'.repeat(40), branch: 'dev-syn/topic', thinking: 'medium' });
const base = 'b'.repeat(40);
function actor() {
  let current = true;
  const host = { agentId: 'dev-syn', sandboxed: true,
    activeModel: { modelRef: 'provider/model' }, assertInvocationCurrent() { return current; } };
  return { host, revoke() { current = false; } };
}
async function fixture(handler) {
  const directory = mkdtempSync(join(tmpdir(), 'claim-channel-'));
  chmodSync(directory, 0o700);
  const socketPath = join(directory, 'claim.sock');
  const connections = new Set();
  const server = createServer({ allowHalfOpen: true }, socket => {
    connections.add(socket);
    socket.on('close', () => connections.delete(socket));
    handler(socket);
    socket.resume(); // consume the claim even when a behavior only observes EOF
  });
  try {
    server.listen(socketPath);
    await once(server, 'listening');
    chmodSync(socketPath, 0o600);
  } catch (error) { server.close(); rmSync(directory, { recursive: true, force: true }); throw error; }
  const cleanup = async () => {
    for (const socket of connections) socket.destroy();
    await new Promise(resolve => server.close(resolve));
    rmSync(directory, { recursive: true, force: true });
  };
  const pins = { repository: 'fixture/repository', ref: 'refs/heads/main',
    socketPath, lookupFixedBaseForTest: async () => base, deadlineMs: 250 };
  return { pins, cleanup, directory };
}

test('fixed pins, one frame to EOF, fixed denial and no success permit', async () => {
  const observed = [];
  const setup = await fixture(socket => {
    const chunks = [];
    socket.on('data', chunk => chunks.push(chunk));
    socket.on('end', () => {
      observed.push(Buffer.concat(chunks));
      socket.end('publication_disabled');
    });
  });
  try {
    const channel = createPrivateHostChannel(setup.pins);
    setup.pins.repository = 'attacker/other';
    setup.pins.socketPath = '/tmp/other';
    await assert.rejects(channel.run(actor().host, request), /^Error: publication_disabled$/);
    assert.equal(observed.length, 1);
    const body = decodeClaimFrame(observed[0]);
    assert.equal(body.repository, 'fixture/repository');
    assert.equal(body.ref, 'refs/heads/main');
    assert.equal(body.base, base);
    assert.equal(body.sha, request.commitSha);
    assert.equal(body.model, 'provider/model');
    await assert.rejects(channel.run(actor().host, request), /handoff_replay_denied/);
  } finally { await setup.cleanup(); }
});

test('invalid tool input and socket path cannot reach server', async () => {
  let connections = 0;
  const setup = await fixture(socket => { connections++; socket.destroy(); });
  try {
    for (const requestOverride of [{ ...request, repository: 'attacker/repo' },
      { ...request, socketPath: setup.pins.socketPath }, { ...request, token: 'secret' }]) {
      await assert.rejects(createPrivateHostChannel(setup.pins).run(actor().host, requestOverride),
        /candidate_request_invalid/);
    }
    assert.equal(connections, 0);
    assert.throws(() => createPrivateHostChannel({ ...setup.pins, socketPath: 'relative' }),
      /private_host_config_unavailable/);
    const link = join(setup.directory, 'link');
    symlinkSync(setup.pins.socketPath, link);
    await assert.rejects(createPrivateHostChannel({ ...setup.pins, socketPath: link })
      .run(actor().host, request), /private_socket_unavailable/);
    chmodSync(setup.pins.socketPath, 0o666);
    await assert.rejects(createPrivateHostChannel(setup.pins).run(actor().host, request),
      /private_socket_unavailable/);
    assert.equal(connections, 0);
  } finally { await setup.cleanup(); }
});

test('changes across base lookup, socket check and response wait cannot permit', async () => {
  const setup = await fixture(socket => { socket.on('end', () => {}); });
  try {
    const a = actor();
    let release;
    const pendingBase = new Promise(resolve => { release = resolve; });
    const channel = createPrivateHostChannel({ ...setup.pins,
      lookupFixedBaseForTest: () => pendingBase });
    const result = channel.run(a.host, request);
    a.host.activeModel.modelRef = 'provider/changed';
    release(base);
    await assert.rejects(result, /candidate_context_unavailable/);

    const b = actor();
    const aborted = new AbortController();
    const waiting = createPrivateHostChannel(setup.pins).run(b.host, request, { signal: aborted.signal });
    await new Promise(resolve => setTimeout(resolve, 20));
    aborted.abort();
    await assert.rejects(waiting, /claim_cancelled/);

    const c = actor();
    const pending = createPrivateHostChannel({ ...setup.pins, deadlineMs: 40 }).run(c.host, request);
    await assert.rejects(pending, /claim_deadline_exceeded/);
  } finally { await setup.cleanup(); }
});

test('unknown, oversized, early-close and absent host responses are denied', async () => {
  for (const [name, behavior] of [
    ['unknown', socket => socket.on('end', () => socket.end('ok'))],
    ['oversized', socket => socket.on('end', () => socket.end('x'.repeat(65)))],
    ['early close', socket => socket.destroy()],
    ['empty', socket => socket.on('end', () => socket.end())],
  ]) {
    const setup = await fixture(behavior);
    try {
      await assert.rejects(createPrivateHostChannel(setup.pins).run(actor().host, request),
        /claim_response_invalid|claim_socket_closed|private_socket_unavailable|claim_pipe_closed/,
        name);
    } finally { await setup.cleanup(); }
  }
});

test('context switch on connect prevents even the first frame', async () => {
  const state = actor();
  let bytes = 0;
  const setup = await fixture(socket => {
    state.host.sandboxed = false;
    socket.on('data', chunk => { bytes += chunk.length; });
  });
  try {
    await assert.rejects(createPrivateHostChannel(setup.pins).run(state.host, request),
      /candidate_context_unavailable/);
    assert.equal(bytes, 0);
  } finally { await setup.cleanup(); }
});

test('retained assertion replacement and cancellation during base await deny IO', async () => {
  let connections = 0;
  const setup = await fixture(socket => { connections++; socket.destroy(); });
  try {
    for (const change of ['replace assertion', 'abort']) {
      const state = actor();
      let valid = true, release;
      state.host.assertInvocationCurrent = () => valid;
      const basePromise = new Promise(resolve => { release = resolve; });
      const signal = new AbortController();
      const channel = createPrivateHostChannel({ ...setup.pins,
        lookupFixedBaseForTest: () => basePromise });
      const pending = channel.run(state.host, request, { signal: signal.signal });
      if (change === 'replace assertion') {
        valid = false;
        state.host.assertInvocationCurrent = () => true;
      } else signal.abort();
      release(base);
      await assert.rejects(pending, change === 'abort' ? /claim_cancelled/ : /stale_invocation/);
    }
    assert.equal(connections, 0);
  } finally { await setup.cleanup(); }
});

test('parent mode and pre-aborted signal fail before connecting', async () => {
  let connections = 0;
  const setup = await fixture(socket => { connections++; socket.destroy(); });
  try {
    chmodSync(setup.directory, 0o755);
    await assert.rejects(createPrivateHostChannel(setup.pins).run(actor().host, request),
      /private_socket_unavailable/);
    chmodSync(setup.directory, 0o700);
    const signal = new AbortController();
    signal.abort();
    await assert.rejects(createPrivateHostChannel(setup.pins)
      .run(actor().host, request, { signal: signal.signal }), /claim_cancelled/);
    assert.equal(connections, 0);
  } finally { await setup.cleanup(); }
});
