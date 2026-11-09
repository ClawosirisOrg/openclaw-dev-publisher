import test from 'node:test';
import assert from 'node:assert/strict';
import childProcess from 'node:child_process';
import { EventEmitter } from 'node:events';
import { PassThrough, Writable } from 'node:stream';
import { createProductionPublisher } from '../src/production-publisher.mjs';
import { createProductionPlugin } from '../src/production-plugin.mjs';

const config = Object.freeze({ pythonPath: '/fixture/python3', brokerRoot: '/fixture/install',
  configPath: '/fixture/private/deployment.json', deploymentId: 'fixture-publisher' });
const request = { commitSha: 'a'.repeat(40), branch: 'dev-syn/live-test', thinking: 'off' };
const phases = ['base', 'capture', 'reverify', 'mint', 'deliver', 'handoff', 'create'];
const context = () => ({ agentId: 'dev-syn', sandboxed: true,
  activeModel: { modelRef: 'fixture/effective-model' }, assertInvocationCurrent() {} });
const outcome = { sha: request.commitSha, branch: request.branch, base: 'b'.repeat(40),
  acknowledged: true, readback_checked: true, main_at_readback: 'b'.repeat(40), stale: false };

function fakeProcess(t, { beforePhase = () => {}, corruptPhase, result = outcome, expectedPhases = phases } = {}) {
  const observations = { inputs: [], killed: [], spawned: [] };
  t.mock.method(childProcess, 'spawn', (...args) => {
    observations.spawned.push(args);
    const child = new EventEmitter();
    child.stdout = new PassThrough();
    let index = 0, closed = false;
    const close = code => { if (!closed) { closed = true; child.stdout.end(); child.emit('close', code); } };
    child.kill = signal => { observations.killed.push(signal); queueMicrotask(() => close(1)); return true; };
    child.stdin = new Writable({ write(chunk, _enc, callback) {
      const input = JSON.parse(chunk.toString());
      observations.inputs.push(input);
      callback();
      queueMicrotask(() => {
        if (closed) return;
        if (index < expectedPhases.length) {
          const phase = expectedPhases[index++];
          beforePhase(phase);
          child.stdout.write(JSON.stringify({ guard: phase === corruptPhase ? 'invalid' : phase,
            nonce: 'c'.repeat(32) }) + '\n');
        } else {
          child.stdout.write(JSON.stringify({ result }) + '\n');
          queueMicrotask(() => close(0));
        }
      });
    } });
    return child;
  });
  return observations;
}

test('production bridge retains v2 identity and live guards through every effect', async t => {
  const io = fakeProcess(t);
  const result = await createProductionPublisher(config).run(context(), 'tool-fixture-1', request);
  assert.deepEqual(result, outcome);
  assert.deepEqual(io.inputs.slice(1).map(v => v.allow), phases);
  assert.equal(io.inputs[0].model, 'fixture/effective-model');
  assert.equal(io.inputs[0].thinking, 'off');
  assert.match(io.inputs[0].attempt, /^[0-9a-f]{32}$/);
  assert.equal(io.killed.length, 0);
  const [binary, args, options] = io.spawned[0];
  assert.equal(binary, config.pythonPath);
  assert.deepEqual(args, ['-B', '-m', 'broker.host.production', config.configPath]);
  assert.equal(options.cwd, config.brokerRoot);
  assert.equal(options.stdio[2], 'ignore');
  assert.equal(options.env.HOME, '/nonexistent');
  assert.equal(options.env.GITHUB_TOKEN, undefined);
  assert.equal(options.env.SSH_AUTH_SOCK, undefined);
});

test('correlation key is stable for the same trusted call and distinct for another', async t => {
  const io = fakeProcess(t);
  const publisher = createProductionPublisher(config);
  await publisher.run(context(), 'stable-call', request);
  await publisher.run(context(), 'stable-call', request);
  await publisher.run(context(), 'another-call', request);
  const keys = io.inputs.filter(v => v.attempt).map(v => v.attempt);
  assert.equal(keys[0], keys[1]);
  assert.notEqual(keys[0], keys[2]);
});

test('model substitution, abort or stale current assertion cannot get final permit', async t => {
  for (const reason of ['model', 'abort', 'current']) {
    const c = context(), controller = new AbortController();
    let current = true;
    c.assertInvocationCurrent = () => current;
    const io = fakeProcess(t, { beforePhase(phase) {
      if (phase === 'create') {
        if (reason === 'model') c.activeModel.modelRef = 'other/model';
        if (reason === 'abort') controller.abort();
        if (reason === 'current') current = false;
      }
    } });
    await assert.rejects(createProductionPublisher(config).run(c, 'call-' + reason, request,
      { signal: controller.signal }), /inspect_no_retry/);
    assert.equal(io.inputs.some(v => v.allow === 'create'), false);
    assert.deepEqual(io.killed, ['SIGTERM']);
    t.mock.restoreAll();
  }
});

test('out-of-order challenge and malformed readback fail sanitized without success', async t => {
  for (const options of [{ corruptPhase: 'mint' }, { result: { ...outcome, sha: 'd'.repeat(40) } }]) {
    const io = fakeProcess(t, options);
    await assert.rejects(createProductionPublisher(config).run(context(), 'bad-call', request),
      /^Error: publication_failed_or_uncertain_inspect_no_retry$/);
    assert.deepEqual(io.killed, ['SIGTERM']);
    t.mock.restoreAll();
  }
});

test('production permits accepted thinking attestation but never an agent model claim', async t => {
  const io = fakeProcess(t);
  const publisher = createProductionPublisher(config);
  await assert.rejects(publisher.run(context(), 'false-model', { ...request, model: 'claimed/model' }),
    /candidate_request_invalid/);
  assert.equal(io.spawned.length, 0);
  await publisher.run(context(), 'attested-thinking', { ...request, thinking: 'xhigh' });
  assert.equal(io.inputs[0].thinking, 'xhigh');
  assert.equal(io.inputs[0].model, 'fixture/effective-model');
});

test('production plugin is explicit, optional, dev-syn-only and contextVersion two', t => {
  const io = fakeProcess(t);
  let descriptor, options;
  createProductionPlugin(config).register({ registerTool(d, o) { descriptor = d; options = o; } });
  assert.equal(descriptor.contextVersion, 2);
  assert.equal(options.optional, true);
  assert.equal(descriptor.create({ ...context(), agentId: 'other' }), null);
  assert.equal(descriptor.create({ ...context(), sandboxed: false }), null);
  const tool = descriptor.create(context());
  assert.equal(tool.name, 'request_signed_publication');
  assert.deepEqual(tool.parameters.required, ['commitSha', 'branch', 'thinking']);
  assert.match(tool.parameters.properties.thinking.description, /not Gateway-authenticated/);
  assert.equal(io.spawned.length, 0);
  assert.throws(() => createProductionPublisher({ ...config }), /config_unavailable/);
});


test('guarded update forwards only explicit expected-old and retained runtime', async t => {
  const inspect = ['inspect-mint', 'inspect-deliver'];
  const expectedPhases = [...phases.slice(0, 3), ...inspect, ...phases.slice(3), ...inspect];
  const io = fakeProcess(t, { expectedPhases });
  await createProductionPublisher(config).run(context(), 'review-fix', {
    ...request, operation: 'update', expectedOldSha: 'b'.repeat(40),
  });
  assert.equal(io.inputs[0].operation, 'update');
  assert.equal(io.inputs[0].expectedOldSha, 'b'.repeat(40));
  assert.deepEqual(io.inputs.slice(1).map(v => v.allow), expectedPhases);
});

test('issue/PR and read-only reconciliation retain freshness fences and bounded URLs', async t => {
  for (const operation of ['issue', 'pr', 'reconcile']) {
    const expectedPhases = ['inspect-mint', 'inspect-deliver',
      ...(operation === 'reconcile' ? [] : ['api-mint', 'api-deliver', 'api-write'])];
    const result = { number: 12, url: 'https://github.com/fixture/repo/' +
      (operation === 'issue' ? 'issues' : 'pull') + '/12', head: request.commitSha, readback_checked: true };
    const io = fakeProcess(t, { expectedPhases, result });
    const artifact = operation === 'reconcile' ? {} : { title: 'Bounded title', body: 'Host validates attribution' };
    assert.deepEqual(await createProductionPublisher(config).run(context(), 'api-' + operation,
      { ...request, operation, ...artifact }), result);
    assert.equal(io.inputs[0].operation, operation);
    assert.deepEqual(io.inputs.slice(1).map(v => v.allow), expectedPhases);
    t.mock.restoreAll();
  }
});

test('stale original API invocation never permits artifact POST', async t => {
  let current = true;
  const c = context(); c.assertInvocationCurrent = () => current;
  const expectedPhases = ['inspect-mint', 'inspect-deliver', 'api-mint', 'api-deliver', 'api-write'];
  const io = fakeProcess(t, { expectedPhases, beforePhase(phase) {
    if (phase === 'api-write') { current = false; c.assertInvocationCurrent = () => true; }
  } });
  await assert.rejects(createProductionPublisher(config).run(c, 'api-expired', {
    ...request, operation: 'issue', title: 'Title', body: 'Body',
  }), /inspect_no_retry/);
  assert.equal(io.inputs.some(v => v.allow === 'api-write'), false);
});
