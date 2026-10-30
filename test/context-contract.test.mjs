import test from 'node:test';
import assert from 'node:assert/strict';
import { admitCandidate, isEligibleGatewayContext } from '../src/context-contract.mjs';

const request = Object.freeze({
  commitSha: 'a'.repeat(40), branch: 'dev-syn/topic', thinking: 'medium',
});
function context(overrides = {}) {
  return {
    agentId: 'dev-syn', sandboxed: true,
    activeModel: { modelRef: 'provider/host-model' },
    assertInvocationCurrent() {},
    ...overrides,
  };
}

test('candidate selects host model and labels thinking as agent-attested, not authority', () => {
  const host = context();
  const result = admitCandidate(host, request);
  assert.deepEqual(result.candidate, {
    sha: request.commitSha, branch: request.branch,
    model: 'provider/host-model', thinking: 'medium',
    model_source: 'gateway_active_model', thinking_source: 'agent_attested',
  });
  assert.equal(Object.isFrozen(result), true);
  assert.equal(Object.isFrozen(result.candidate), true);
  result.assertCurrent();
  host.activeModel.modelRef = 'provider/another-model';
  assert.throws(result.assertCurrent, /candidate_context_unavailable/);
});

for (const [label, overrides] of [
  ['missing', null],
  ['wrong agent', { agentId: 'another-agent' }],
  ['not sandboxed', { sandboxed: false }],
  ['absent sandbox proof', { sandboxed: undefined }],
  ['missing assertion', { assertInvocationCurrent: undefined }],
  ['missing model', { activeModel: undefined }],
  ['invalid model', { activeModel: { modelRef: '../untrusted model' } }],
]) {
  test(label + ' host context denied', () => {
    const host = overrides === null ? null : context(overrides);
    assert.equal(isEligibleGatewayContext(host) === true, false);
    assert.throws(() => admitCandidate(host, request), /candidate_context_unavailable/);
  });
}

for (const [label, invalid] of [
  ['null', null],
  ['array', [request]],
  ['missing thinking', { commitSha: request.commitSha, branch: request.branch }],
  ['extra model', { ...request, model: 'forged/model' }],
  ['extra authority', { ...request, senderIsOwner: true }],
  ['uppercase SHA', { ...request, commitSha: 'A'.repeat(40) }],
  ['short SHA', { ...request, commitSha: 'a'.repeat(39) }],
  ['foreign branch', { ...request, branch: 'other/topic' }],
  ['unsafe branch', { ...request, branch: 'dev-syn/../topic' }],
  ['empty branch component', { ...request, branch: 'dev-syn/' }],
  ['long branch component', { ...request, branch: 'dev-syn/' + 'a'.repeat(64) }],
  ['unrecognized thinking', { ...request, thinking: 'unknown' }],
]) {
  test(label + ' request fails closed', () => {
    assert.throws(() => admitCandidate(context(), invalid), /candidate_request_invalid/);
  });
}

test('expiration after admission and revoked sandbox invalidate the closure', () => {
  let current = true;
  const host = context({ assertInvocationCurrent() { return current; } });
  const admitted = admitCandidate(host, request);
  current = false;
  assert.throws(admitted.assertCurrent, /stale_invocation/);
  assert.throws(() => admitCandidate(host, request), /stale_invocation/);
  current = true;
  host.sandboxed = false;
  assert.throws(admitted.assertCurrent, /candidate_context_unavailable/);
});
