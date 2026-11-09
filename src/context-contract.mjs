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
  if (!request || typeof request !== 'object' || Array.isArray(request)) {
    throw new Error('candidate_request_invalid');
  }
  const operation = Object.hasOwn(request, 'operation') ? request.operation : 'create';
  if (!['create', 'update', 'issue', 'pr', 'reconcile'].includes(operation)) {
    throw new Error('candidate_request_invalid');
  }
  const expectedKeys = ['branch', 'commitSha', 'thinking'];
  if (Object.hasOwn(request, 'operation')) expectedKeys.push('operation');
  if (operation === 'update') expectedKeys.push('expectedOldSha');
  if (operation === 'issue' || operation === 'pr') expectedKeys.push('title', 'body');
  if (Object.keys(request).sort().join(',') !== expectedKeys.sort().join(',') ||
      (operation === 'update' && (typeof request.expectedOldSha !== 'string' ||
       !SHA.test(request.expectedOldSha) || request.expectedOldSha === request.commitSha)) ||
      (['issue', 'pr'].includes(operation) &&
       (typeof request.title !== 'string' || Buffer.byteLength(request.title, 'utf8') > 200 ||
        !request.title.length || typeof request.body !== 'string' ||
        !request.body.length || Buffer.byteLength(request.body, 'utf8') > 12000))) {
    throw new Error('candidate_request_invalid');
  }
  const { commitSha, branch, thinking } = request;
  if (typeof commitSha !== 'string' || !SHA.test(commitSha) ||
      typeof branch !== 'string' || !BRANCH.test(branch) ||
      typeof thinking !== 'string' || !THINKING.has(thinking)) {
    throw new Error('candidate_request_invalid');
  }
  // Retain the Gateway assertion selected at admission; a later context
  // property replacement must not substitute a new assertion after an await.
  const invocationAssertion = context.assertInvocationCurrent;
  if (invocationAssertion.call(context) === false) throw new Error('stale_invocation');
  const model = context.activeModel.modelRef;
  if (!MODEL.test(model)) throw new Error('candidate_context_unavailable');
  const candidate = Object.freeze({
    sha: commitSha, branch, model, thinking,
    model_source: 'gateway_active_model',
    thinking_source: 'agent_attested',
    ...(Object.hasOwn(request, 'operation') ? { operation } : {}),
    ...(operation === 'update' ? { expectedOldSha: request.expectedOldSha } : {}),
    ...(['issue', 'pr'].includes(operation) ? { title: request.title, body: request.body } : {}),
  });
  const assertCurrent = () => {
    if (!isEligibleGatewayContext(context) || context.activeModel.modelRef !== model) {
      throw new Error('candidate_context_unavailable');
    }
    if (invocationAssertion.call(context) === false) throw new Error('stale_invocation');
  };
  return Object.freeze({ candidate, assertCurrent });
}
