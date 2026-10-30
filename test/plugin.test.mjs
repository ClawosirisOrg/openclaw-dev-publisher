import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import plugin from '../src/plugin.mjs';

test('package declares a minimum host with the version-two tool guard', () => {
  const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
  assert.equal(pkg.openclaw.compat.pluginApi, '>=2026.10.3');
  assert.equal(pkg.openclaw.install.minHostVersion, '>=2026.10.3');
});

function registeredTool() {
  const registered = [];
  plugin.register({ registerTool(descriptor, options) { registered.push({ descriptor, options }); } });
  assert.equal(registered.length, 1);
  return registered[0];
}

function gatewayContext(overrides = {}) {
  return {
    agentId: 'dev-syn', sandboxed: true,
    activeModel: { modelRef: 'example/model-v1' },
    assertInvocationCurrent() {},
    ...overrides,
  };
}

const validRequest = Object.freeze({
  commitSha: 'a'.repeat(40), branch: 'dev-syn/change', thinking: 'off',
});

test('manual plugin registers only optional version-two disabled tool', async () => {
  const { descriptor, options } = registeredTool();
  assert.equal(descriptor.contextVersion, 2);
  assert.deepEqual(options, { name: 'request_signed_publication', optional: true });
  assert.equal(descriptor.create({ senderIsOwner: true, assertInvocationCurrent() {} }), null);
  assert.equal(descriptor.create(gatewayContext({ agentId: 'other' })), null);
  assert.equal(descriptor.create(gatewayContext({ sandboxed: false })), null);
  assert.equal(descriptor.create(gatewayContext({ assertInvocationCurrent: undefined })), null);
  let checks = 0;
  const tool = descriptor.create(gatewayContext({ assertInvocationCurrent() { checks++; } }));
  assert.equal(tool.name, options.name);
  assert.deepEqual(tool.parameters.required, ['commitSha', 'branch', 'thinking']);
  assert.equal(tool.parameters.additionalProperties, false);
  await assert.rejects(tool.execute('call-1', validRequest), /publication_disabled/);
  assert.equal(checks, 3); // creation, admission and final current check
});

test('stale or invalid host context is absent at create and rejected at execution', async () => {
  const { descriptor } = registeredTool();
  assert.equal(descriptor.create(gatewayContext({ activeModel: { modelRef: '' } })), null);
  assert.equal(descriptor.create(gatewayContext({ assertInvocationCurrent() { return false; } })), null);
  assert.equal(descriptor.create(gatewayContext({
    assertInvocationCurrent() { throw new Error('stale_invocation'); },
  })), null);
  let current = true;
  const context = gatewayContext({ assertInvocationCurrent() {
    if (!current) throw new Error('stale_invocation');
  } });
  const tool = descriptor.create(context);
  current = false;
  await assert.rejects(tool.execute('call-2', validRequest), /stale_invocation/);
  current = true;
  context.agentId = 'other';
  await assert.rejects(tool.execute('call-3', validRequest), /candidate_context_unavailable/);
});

test('every offered execution remains disabled without performing IO', async () => {
  const { descriptor } = registeredTool();
  const tool = descriptor.create(gatewayContext());
  for (const request of [validRequest, { ...validRequest, thinking: 'high' }]) {
    await assert.rejects(tool.execute('call', request), /publication_disabled/);
  }
  await assert.rejects(tool.execute('call', {
    ...validRequest, model: 'caller-selected/model',
  }), /candidate_request_invalid/);
});
