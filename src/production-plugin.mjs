/** Explicit opt-in factory for a PRIVATE reviewed host entry module.
 * The repository's default plugin remains disabled. Do not source deployment
 * config from tool input, an agent workspace or the public package metadata.
 */
import { isEligibleGatewayContext } from './context-contract.mjs';
import { createProductionPublisher } from './production-publisher.mjs';

export function createProductionPlugin(deployConfig) {
  const publisher = createProductionPublisher(deployConfig);
  return {
    id: 'openclaw-dev-publisher', name: 'Signed dev-agent publisher',
    register(api) {
      api.registerTool({ contextVersion: 2,
        create(context) {
          if (!isEligibleGatewayContext(context)) return null;
          try { if (context.assertInvocationCurrent() === false) return null; }
          catch { return null; }
          return {
            name: 'request_signed_publication',
            description: 'Publish one verified signed commit in the owned dev-syn namespace, guarded fast-forward review updates, or issue-first main PR; no merges/retries',
            parameters: { type: 'object', additionalProperties: false,
              required: ['commitSha', 'branch', 'thinking'], properties: {
                commitSha: { type: 'string', pattern: '^[0-9a-f]{40}$' },
                branch: { type: 'string', pattern: '^dev-syn/[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$' },
                operation: { type: 'string', enum: ['create', 'update', 'issue', 'pr', 'reconcile'], default: 'create' },
                expectedOldSha: { type: 'string', pattern: '^[0-9a-f]{40}$' },
                title: { type: 'string', minLength: 1, maxLength: 200 },
                body: { type: 'string', minLength: 1, maxLength: 12000,
                  description: 'Final exact runtime attribution required; UTF-8 byte bound enforced by host' },
                thinking: { type: 'string', enum: ['off', 'minimal', 'low', 'medium', 'high', 'xhigh'],
                  description: 'Temporarily owner-accepted agent attestation; not Gateway-authenticated' },
              }, allOf: [
                { if: { required: ['operation'], properties: { operation: { const: 'update' } } },
                  then: { required: ['expectedOldSha'] }, else: { not: { required: ['expectedOldSha'] } } },
                { if: { required: ['operation'], properties: { operation: { enum: ['issue', 'pr'] } } },
                  then: { required: ['title', 'body'] },
                  else: { not: { anyOf: [{ required: ['title'] }, { required: ['body'] }] } } },
              ] },
            async execute(callId, request, signal) {
              const outcome = await publisher.run(context, callId, request, { signal });
              return { content: [{ type: 'text', text: JSON.stringify(outcome) }], details: outcome };
            },
          };
        },
      }, { name: 'request_signed_publication', optional: true });
    },
  };
}
