/**
 * Inert Gateway-only coordination seam. Nothing in this module launches Podman,
 * issues credentials, signs, or writes to a repository. It is not a tool entry.
 * Only trusted Gateway construction may supply the frozen deployment config;
 * never derive it, an issuer, or a launcher from agent tool input.
 */
import { admitCandidate } from './context-contract.mjs';

const SHA = /^[0-9a-f]{40}$/;
const DIGEST = /^sha256:[0-9a-f]{64}$/;
const BRANCH = /^dev-syn\/[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const REPOSITORY = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}\/[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$/;
const BASE_REF = 'refs/heads/main';
const DEPLOY_KEYS = [
  'imageDigest', 'remoteSocketUrl', 'sourceCheckoutPath',
  'protectedStagePath', 'approvedRepository', 'approvedRef',
].sort().join(',');

function absoluteSafePath(path) {
  return typeof path === 'string' && /^\/[A-Za-z0-9_./-]+$/.test(path) &&
    path !== '/' && path.split('/').slice(1).every(part => part && part !== '.' && part !== '..');
}

function checkedConfig(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input) ||
      (Object.getPrototypeOf(input) !== Object.prototype && Object.getPrototypeOf(input) !== null) ||
      !Object.isFrozen(input) || Object.keys(input).sort().join(',') !== DEPLOY_KEYS ||
      Object.getOwnPropertySymbols(input).length !== 0 ||
      !Object.keys(input).every(key => Object.getOwnPropertyDescriptor(input, key)?.value !== undefined &&
        !Object.getOwnPropertyDescriptor(input, key)?.get) ||
      typeof input.imageDigest !== 'string' || !DIGEST.test(input.imageDigest) ||
      typeof input.remoteSocketUrl !== 'string' ||
      !input.remoteSocketUrl.startsWith('unix://') ||
      !absoluteSafePath(input.remoteSocketUrl.slice('unix://'.length)) ||
      !absoluteSafePath(input.sourceCheckoutPath) ||
      !absoluteSafePath(input.protectedStagePath) ||
      input.sourceCheckoutPath === input.protectedStagePath ||
      input.sourceCheckoutPath.startsWith(input.protectedStagePath + '/') ||
      input.protectedStagePath.startsWith(input.sourceCheckoutPath + '/') ||
      typeof input.approvedRepository !== 'string' || !REPOSITORY.test(input.approvedRepository) ||
      input.approvedRef !== BASE_REF) {
    throw new Error('trusted_deploy_config_unavailable');
  }
  // Copy own primitives, so even a hostile test fixture cannot retarget later.
  return Object.freeze(Object.fromEntries(DEPLOY_KEYS.split(',').map(key => [key, input[key]])));
}

function planBuilder(config) {
  return candidate => {
    if (!candidate || typeof candidate !== 'object' ||
        typeof candidate.sha !== 'string' || !SHA.test(candidate.sha) ||
        typeof candidate.branch !== 'string' || !BRANCH.test(candidate.branch)) {
      throw new Error('candidate_request_invalid');
    }
    const argv = Object.freeze([
      'podman', '--remote', '--url', config.remoteSocketUrl, 'run', '--rm',
      '--pull=never', '--user=1:1', '--network=none', '--http-proxy=false',
      '--read-only', '--cap-drop=all', '--security-opt=no-new-privileges',
      '--pids-limit=128', '--memory=768m', '--tmpfs=/tmp:rw,nosuid,nodev,size=64m',
      '--mount=type=bind,source=' + config.sourceCheckoutPath + ',destination=/source,readonly=true',
      '--mount=type=bind,source=' + config.protectedStagePath + ',destination=/handoff,readonly=false',
      // This entry remains unconditional. No verifier or publication entry exists.
      '--entrypoint=/usr/bin/false', config.imageDigest,
    ]);
    return Object.freeze({ status: 'disabled', argv,
      candidate: Object.freeze({ sha: candidate.sha, branch: candidate.branch }) });
  };
}

/** Pure, inert plan inspection. The returned argv is never executed here. */
export function createLaunchPlanBuilder(deployConfig) {
  return planBuilder(checkedConfig(deployConfig));
}

/**
 * Test-fixture orchestration only. issueFixedBaseForTest is an injectable fake,
 * NOT a production authenticated issuer or a security boundary. It must close
 * over its own fixed target and return an authenticated base in a real design;
 * this prototype cannot prove that. observePlanForTest is likewise NOT a
 * launcher. A receipt from it, however convincing, grants no authority.
 * Trusted context is a separate in-memory observation, never argv or env.
 */
export function createDisabledCoordinator({ deployConfig, issueFixedBaseForTest,
  observePlanForTest } = {}) {
  const config = checkedConfig(deployConfig);
  const buildPlan = planBuilder(config);
  if (typeof issueFixedBaseForTest !== 'function' ||
      typeof observePlanForTest !== 'function') {
    throw new Error('test_dependencies_unavailable');
  }
  return Object.freeze({
    async run(context, request) {
      const { candidate, assertCurrent } = admitCandidate(context, request);
      assertCurrent();
      const base = await issueFixedBaseForTest(); // No agent inputs or target overrides.
      assertCurrent();
      if (typeof base !== 'string' || !SHA.test(base)) throw new Error('trusted_base_unavailable');
      const trustedContext = Object.freeze({
        repository: config.approvedRepository,
        base_ref: config.approvedRef,
        base,
        model: candidate.model,
        thinking: candidate.thinking,
        model_source: candidate.model_source,
        thinking_source: candidate.thinking_source,
      });
      const plan = Object.freeze({ ...buildPlan(candidate), trustedContext });
      assertCurrent();
      const receipt = await observePlanForTest(plan);
      assertCurrent();
      void receipt; // No token, Git transport, signing, or final effect exists.
      assertCurrent();
      throw new Error('publication_disabled');
    },
  });
}
