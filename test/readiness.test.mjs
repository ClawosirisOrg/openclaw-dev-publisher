import test from 'node:test';
import assert from 'node:assert/strict';
import { createReadinessPolicy, ReadinessError, publishSignedCommit } from '../src/index.mjs';

const base = Object.freeze({
  containerId: '<container-id>',
  containerName: '<agent-name>',
  imageDigest: '<image-digest>',
  socketPath: '<socket-path>',
  signerFingerprint: '<signer-fingerprint>',
  knownContainerIds: ['<container-id>'],
  timeoutMs: 100,
});
const peer = Object.freeze({
  id: base.containerId, name: base.containerName,
  imageDigest: base.imageDigest, running: true,
});
const socket = Object.freeze({
  path: base.socketPath, containerId: base.containerId,
  signerFingerprint: base.signerFingerprint, ready: true,
});
function fixtures(container = peer, endpoint = socket) {
  return {
    containers: { async get() { return container; } },
    sockets: { async probe() { return endpoint; } },
  };
}

test('fresh checks precede every operation; lease cannot be reused', async () => {
  let checks = 0;
  let saved;
  const adapters = fixtures();
  adapters.containers.get = async () => { checks++; return peer; };
  const policy = createReadinessPolicy(base, adapters);
  assert.equal(await policy.withReadySigner(({ assertCurrent }) => {
    saved = assertCurrent;
    assertCurrent();
    return 'first';
  }), 'first');
  assert.throws(saved, { code: 'inactive_invocation' });
  assert.equal(await policy.withReadySigner(({ assertCurrent }) => {
    assertCurrent();
    return 'second';
  }), 'second');
  assert.equal(checks, 2);
});

test('unknown container denied without IO or callback', async () => {
  let touched = false;
  const policy = createReadinessPolicy({ ...base, knownContainerIds: [] }, {
    containers: { get: () => { touched = true; } },
    sockets: { probe: () => { touched = true; } },
  });
  await assert.rejects(policy.withReadySigner(() => { touched = true; }), { code: 'unknown_container' });
  assert.equal(touched, false);
});

for (const [label, container, endpoint, code] of [
  ['wrong id', { ...peer, id: '<different-id>' }, socket, 'container_identity_mismatch'],
  ['wrong name', { ...peer, name: '<different-name>' }, socket, 'container_identity_mismatch'],
  ['wrong image', { ...peer, imageDigest: '<different-digest>' }, socket, 'container_identity_mismatch'],
  ['stopped', { ...peer, running: false }, socket, 'container_identity_mismatch'],
  ['missing peer', null, socket, 'container_identity_mismatch'],
  ['wrong socket owner', peer, { ...socket, containerId: '<different-id>' }, 'socket_identity_mismatch'],
  ['wrong socket path', peer, { ...socket, path: '<different-path>' }, 'socket_identity_mismatch'],
  ['wrong signer fingerprint', peer, { ...socket, signerFingerprint: '<different-fingerprint>' }, 'socket_identity_mismatch'],
  ['socket unavailable', peer, { ...socket, ready: false }, 'socket_identity_mismatch'],
]) {
  test(label + ' fails closed', async () => {
    let invoked = false;
    await assert.rejects(
      createReadinessPolicy(base, fixtures(container, endpoint))
        .withReadySigner(() => { invoked = true; }),
      { code },
    );
    assert.equal(invoked, false);
  });
}

test('deadline bounds an unresponsive adapter', async () => {
  const adapters = fixtures();
  adapters.containers.get = () => new Promise(() => {});
  let invoked = false;
  await assert.rejects(
    createReadinessPolicy({ ...base, timeoutMs: 5 }, adapters)
      .withReadySigner(() => { invoked = true; }),
    { code: 'deadline_exceeded' },
  );
  assert.equal(invoked, false);
});

test('expired callback is not a reusable authority', async () => {
  let tick = 0;
  const policy = createReadinessPolicy({ ...base, timeoutMs: 10 }, fixtures(), {
    now: () => tick,
  });
  await assert.rejects(policy.withReadySigner(({ assertCurrent }) => {
    tick = 10;
    assertCurrent();
  }), { code: 'deadline_exceeded' });
});

test('malformed abort signal fails before adapter IO', async () => {
  let touched = false;
  const adapters = {
    containers: { get: () => { touched = true; } },
    sockets: { probe: () => { touched = true; } },
  };
  await assert.rejects(
    createReadinessPolicy(base, adapters).withReadySigner(
      () => { touched = true; }, { signal: { aborted: false } },
    ),
    { name: 'TypeError', message: 'signal must be an AbortSignal' },
  );
  assert.equal(touched, false);
});

test('abort denies work', async () => {
  const aborter = new AbortController();
  aborter.abort();
  await assert.rejects(
    createReadinessPolicy(base, fixtures())
      .withReadySigner(() => { throw Error('must not run'); }, { signal: aborter.signal }),
    { code: 'aborted' },
  );
});

test('late adapter result after abort cannot invoke operation', async () => {
  const aborter = new AbortController();
  let finishProbe;
  let invoked = false;
  const adapters = fixtures();
  adapters.containers.get = () => new Promise((resolve) => { finishProbe = resolve; });
  const pending = createReadinessPolicy(base, adapters)
    .withReadySigner(() => { invoked = true; }, { signal: aborter.signal });
  aborter.abort();
  await assert.rejects(pending, { code: 'aborted' });
  finishProbe(peer);
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(invoked, false);
});

test('invalid configuration and absent adapters cannot authorize', () => {
  assert.throws(() => createReadinessPolicy({ ...base, timeoutMs: Infinity }, fixtures()), TypeError);
  assert.throws(() => createReadinessPolicy(base, {}), TypeError);
  assert.ok(new ReadinessError('test') instanceof Error);
});

test('publication boundary is deliberately inert', async () => {
  await assert.rejects(publishSignedCommit(), /not implemented/);
});
