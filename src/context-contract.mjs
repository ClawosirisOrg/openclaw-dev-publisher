/** Admission only. The Gateway supplies v2 context; tool input cannot supply it. */
const SHA = /^[0-9a-f]{40}$/;
const BRANCH = new RegExp('^dev-syn/[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$');
const MODEL = /^[A-Za-z0-9][A-Za-z0-9._/+:-]{0,127}$/;
const THINKING = new Set(['off', 'minimal', 'low', 'medium', 'high', 'xhigh']);

export function isEligibleGatewayContext(context) {
  return context?.agentId === 'dev-syn' && context.sandboxed === true &&
    typeof context.assertInvocationCurrent === 'function' &&
    typeof context.activeModel?.modelRef === 'string' &&
    MODEL.test(context.activeModel.modelRef);
}

/** No returned value is a permit to write, sign, or publish. */
export function admitCandidate(context, request) {
  if (!isEligibleGatewayContext(context)) throw new Error('candidate_context_unavailable');
  if (!request || typeof request !== 'object' || Array.isArray(request) ||
      Object.keys(request).sort().join(',') !== 'branch,commitSha,thinking') {
    throw new Error('candidate_request_invalid');
  }
  const { commitSha, branch, thinking } = request;
  if (typeof commitSha !== 'string' || !SHA.test(commitSha) ||
      typeof branch !== 'string' || !BRANCH.test(branch) ||
      typeof thinking !== 'string' || !THINKING.has(thinking)) {
    throw new Error('candidate_request_invalid');
  }
  if (context.assertInvocationCurrent() === false) throw new Error('stale_invocation');
  const model = context.activeModel.modelRef;
  if (!MODEL.test(model)) throw new Error('candidate_context_unavailable');
  const candidate = Object.freeze({
    sha: commitSha, branch, model, thinking,
    model_source: 'gateway_active_model',
    thinking_source: 'agent_attested',
  });
  const assertCurrent = () => {
    if (!isEligibleGatewayContext(context) || context.activeModel.modelRef !== model) {
      throw new Error('candidate_context_unavailable');
    }
    if (context.assertInvocationCurrent() === false) throw new Error('stale_invocation');
  };
  return Object.freeze({ candidate, assertCurrent });
}
