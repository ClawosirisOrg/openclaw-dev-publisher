import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import plugin from '../src/plugin.mjs';

test('package declares a minimum host with the version-two tool guard', () => {
  const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
  assert.equal(pkg.openclaw.compat.pluginApi, '>=2026.10.3');
  assert.equal(pkg.openclaw.install.minHostVersion, '>=2026.10.3');
});

test('manual plugin registers only optional version-two inert tool', async () => {
  const registered = [];
  plugin.register({ registerTool(descriptor, options) { registered.push({ descriptor, options }); } });
  assert.equal(registered.length, 1);
  const { descriptor, options } = registered[0];
  assert.equal(descriptor.contextVersion, 2);
  assert.deepEqual(options, { name: 'request_signed_publication', optional: true });
  assert.equal(descriptor.create({ senderIsOwner: false, assertInvocationCurrent() {} }), null);
  assert.equal(descriptor.create({ senderIsOwner: true }), null);
  let checks = 0;
  const tool = descriptor.create({ senderIsOwner: true, assertInvocationCurrent() { checks++; } });
  assert.equal(tool.name, options.name);
  await assert.rejects(tool.execute('call-1', {
    commitSha: 'a'.repeat(40), branch: 'agent/change',
  }), /publication_disabled/);
  assert.equal(checks, 1);
});

test('stale invocation rejects before the inert disabled result', async () => {
  let descriptor;
  plugin.register({ registerTool(tool) { descriptor = tool; } });
  const tool = descriptor.create({ senderIsOwner: true,
    assertInvocationCurrent() { throw new Error('stale_invocation'); } });
  await assert.rejects(tool.execute('call-2', {}), /stale_invocation/);
});
