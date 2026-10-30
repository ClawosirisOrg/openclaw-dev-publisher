import test from 'node:test';
import assert from 'node:assert/strict';
import { createDisabledCoordinator, createLaunchPlanBuilder } from '../src/coordinator.mjs';

// Entirely synthetic values. Neither callback is a production issuer or launcher.
const deployConfig = Object.freeze({
  imageDigest: 'sha256:' + 'b'.repeat(64),
  remoteSocketUrl: 'unix:///fixture/socket',
  sourceCheckoutPath: '/fixture/checkout',
  protectedStagePath: '/fixture/stage',
  approvedRepository: 'fixture/repository',
  approvedRef: 'refs/heads/main',
});
const request = Object.freeze({
  commitSha: 'a'.repeat(40), branch: 'dev-syn/fixture', thinking: 'off',
});
const base = 'c'.repeat(40);

function host() {
  let current = true;
  let checks = 0;
  const context = {
    agentId: 'dev-syn', sandboxed: true,
    activeModel: { modelRef: 'fixture/host-model' },
    assertInvocationCurrent() { checks++; if (!current) throw new Error('stale_invocation'); },
  };
  return { context, cancel() { current = false; }, get checks() { return checks; } };
}
function fixture(overrides = {}) {
  return createDisabledCoordinator({ deployConfig,
    issueFixedBaseForTest: async () => base,
    observePlanForTest: async () => ({ authorized: true }), ...overrides });
}
function deferred() {
  let resolve;
  const promise = new Promise(r => { resolve = r; });
  return { promise, resolve };
}

test('inert plan pins config and unconditional false entry; agent fields cannot alter it', () => {
  const build = createLaunchPlanBuilder(deployConfig);
  const plan = build({ sha: request.commitSha, branch: request.branch,
    imageDigest: 'forged', remoteSocketUrl: 'tcp://forged',
    sourceCheckoutPath: '/forged', protectedStagePath: '/forged',
    approvedRepository: 'forged/repo', approvedRef: 'refs/heads/forged',
    token: 'fixture-forgery', flags: ['--privileged'] });
  assert.deepEqual(plan.candidate, { sha: request.commitSha, branch: request.branch });
  assert.equal(plan.status, 'disabled');
  assert.deepEqual(plan.argv, [
    'podman', '--remote', '--url', deployConfig.remoteSocketUrl, 'run', '--rm',
    '--pull=never', '--user=1:1', '--network=none', '--http-proxy=false',
    '--read-only', '--cap-drop=all', '--security-opt=no-new-privileges',
    '--pids-limit=128', '--memory=768m', '--tmpfs=/tmp:rw,nosuid,nodev,size=64m',
    '--mount=type=bind,source=/fixture/checkout,destination=/source,readonly=true',
    '--mount=type=bind,source=/fixture/stage,destination=/handoff,readonly=false',
    '--entrypoint=/usr/bin/false', deployConfig.imageDigest,
  ]);
  assert.equal(Object.isFrozen(plan), true);
  assert.equal(Object.isFrozen(plan.argv), true);
  assert.equal(Object.isFrozen(plan.candidate), true);
  assert.throws(() => plan.argv.push('--privileged'), TypeError);
  assert.equal(JSON.stringify(plan).includes('fixture-forgery'), false);
  assert.equal(plan.argv.some(arg => arg.includes('forged')), false);
  assert.equal('env' in plan, false);
  assert.throws(() => build({ sha: { toString: () => request.commitSha }, branch: request.branch }),
    /candidate_request_invalid/);
});

test('deployment config must be complete, frozen, safe, and exact', () => {
  for (const changed of [
    { imageDigest: undefined }, { imageDigest: 'latest' }, { imageDigest: 'sha256:' + 'B'.repeat(64) },
    { remoteSocketUrl: 'tcp://fixture/socket' },
    { remoteSocketUrl: 'unix:///fixture/../socket' },
    { remoteSocketUrl: 'unix:///fixture/socket,privileged=true' },
    { sourceCheckoutPath: 'relative' }, { sourceCheckoutPath: '/fixture/../escape' },
    { protectedStagePath: '/fixture/checkout/nested' },
    { approvedRepository: 'https://fixture/repository' },
    { approvedRepository: { toString: () => deployConfig.approvedRepository } },
    { imageDigest: { toString: () => deployConfig.imageDigest } },
    { approvedRef: 'refs/heads/../wrong' },
    { approvedRef: 'refs/heads/other' },
    { approvedRef: 'refs/tags/v1' }, { injectedToken: 'fake' },
  ]) {
    const candidate = Object.freeze({ ...deployConfig, ...changed });
    assert.throws(() => createLaunchPlanBuilder(candidate), /trusted_deploy_config_unavailable/);
  }
  assert.throws(() => createLaunchPlanBuilder({ ...deployConfig }), /trusted_deploy_config_unavailable/);
  assert.throws(() => createDisabledCoordinator({ deployConfig }), /test_dependencies_unavailable/);
  const accessor = Object.defineProperty({ ...deployConfig }, 'approvedRepository',
    { enumerable: true, get: () => deployConfig.approvedRepository });
  assert.throws(() => createLaunchPlanBuilder(Object.freeze(accessor)), /trusted_deploy_config_unavailable/);
  assert.throws(() => { deployConfig.approvedRef = 'refs/heads/other'; }, TypeError);
});

test('host model and fixed fixture base only; fake receipt is never authority', async () => {
  const calls = [];
  const actor = host();
  const coordinator = fixture({
    issueFixedBaseForTest: async (...args) => { calls.push(['base', args]); return base; },
    observePlanForTest: async (...args) => {
      calls.push(['observe', args]);
      return { authorized: true, token: 'fake', write: true, receipt: 'forged' };
    },
  });
  await assert.rejects(coordinator.run(actor.context, request), /publication_disabled/);
  assert.equal(calls.length, 2);
  assert.deepEqual(calls[0], ['base', []]); // Issuer owns target; agent cannot name one.
  assert.equal(calls[1][1].length, 1);
  const plan = calls[1][1][0];
  assert.deepEqual(plan.trustedContext, {
    repository: deployConfig.approvedRepository, base_ref: deployConfig.approvedRef,
    base, model: 'fixture/host-model', thinking: 'off',
    model_source: 'gateway_active_model', thinking_source: 'agent_attested',
  });
  assert.equal(Object.isFrozen(plan.trustedContext), true);
  assert.equal(Object.isFrozen(plan), true);
  assert.equal(plan.argv.includes('--entrypoint=/usr/bin/false'), true);
  assert.equal(JSON.stringify(plan.argv).includes(base), false);
  assert.equal(JSON.stringify(plan.argv).includes('fixture/host-model'), false);
  assert.equal(JSON.stringify(plan.argv).includes('fixture/repository'), false);
  assert.equal('env' in plan, false);
  assert.equal(actor.checks, 6);
});

test('request smuggling and ineligible host never reach fixture callbacks', async () => {
  let calls = 0;
  const coordinator = fixture({
    issueFixedBaseForTest: async () => { calls++; return base; },
    observePlanForTest: async () => { calls++; },
  });
  for (const extra of [
    { imageDigest: deployConfig.imageDigest }, { remoteSocketUrl: deployConfig.remoteSocketUrl },
    { sourceCheckoutPath: '/fixture/other' }, { protectedStagePath: '/fixture/other' },
    { approvedRepository: 'other/repo' }, { approvedRef: 'refs/heads/other' },
    { base }, { model: 'forged' }, { trustedContext: {} },
    { token: 'fake' }, { flags: ['--privileged'] }, { receipt: {} },
  ]) {
    await assert.rejects(coordinator.run(host().context, { ...request, ...extra }),
      /candidate_request_invalid/);
  }
  const wrong = host(); wrong.context.agentId = 'different-agent';
  await assert.rejects(coordinator.run(wrong.context, request), /candidate_context_unavailable/);
  assert.equal(calls, 0);
});

test('stale guard runs before and after every await, with no final effect', async () => {
  let baseCalls = 0;
  let observed = 0;
  const initial = host(); initial.cancel();
  await assert.rejects(fixture({
    issueFixedBaseForTest: async () => { baseCalls++; return base; },
    observePlanForTest: async () => { observed++; },
  }).run(initial.context, request), /stale_invocation/);
  assert.equal(baseCalls, 0);
  const pendingBase = deferred();
  const duringBase = host();
  const first = fixture({
    issueFixedBaseForTest: () => { baseCalls++; return pendingBase.promise; },
    observePlanForTest: async () => { observed++; },
  }).run(duringBase.context, request);
  duringBase.cancel(); pendingBase.resolve(base);
  await assert.rejects(first, /stale_invocation/);
  assert.equal(observed, 0);
  const pendingObservation = deferred();
  const duringObservation = host();
  const second = fixture({ observePlanForTest: () => {
    observed++; return pendingObservation.promise;
  } }).run(duringObservation.context, request);
  // Let the issuer await finish and reach the observer, then revoke the host.
  await Promise.resolve();
  assert.equal(observed, 1);
  duringObservation.cancel(); pendingObservation.resolve({ authorized: true });
  await assert.rejects(second, /stale_invocation/);
  assert.equal(duringObservation.checks, 5);
});

test('invalid fixture issuer base cannot reach observer', async () => {
  let observed = false;
  await assert.rejects(fixture({ issueFixedBaseForTest: async () => 'main',
    observePlanForTest: async () => { observed = true; },
  }).run(host().context, request), /trusted_base_unavailable/);
  assert.equal(observed, false);
});

test('host model switch during base await invalidates admission', async () => {
  const pending = deferred();
  let observed = false;
  const actor = host();
  const run = fixture({ issueFixedBaseForTest: () => pending.promise,
    observePlanForTest: async () => { observed = true; },
  }).run(actor.context, request);
  actor.context.activeModel.modelRef = 'fixture/other-model';
  pending.resolve(base);
  await assert.rejects(run, /candidate_context_unavailable/);
  assert.equal(observed, false);
});
