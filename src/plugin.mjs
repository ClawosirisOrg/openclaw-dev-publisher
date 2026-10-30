/**
 * Disabled Gateway v2 admission entry. No issuer, transport, or write capability.
 */
import { admitCandidate, isEligibleGatewayContext } from './context-contract.mjs';

export const publisherPlugin = {
  id: 'openclaw-dev-publisher',
  name: 'Signed dev-agent publisher (disabled)',
  description: 'dev-syn admission only; publication is disabled',
  register(api) {
    api.registerTool({
      contextVersion: 2,
      create(context) {
        if (!isEligibleGatewayContext(context)) return null;
        try {
          if (context.assertInvocationCurrent() === false) return null;
        } catch {
          return null;
        }
        return {
          name: 'request_signed_publication',
          description: 'Disabled: no issuer, transport, or publication capability',
          parameters: {
            type: 'object', additionalProperties: false,
            required: ['commitSha', 'branch', 'thinking'],
            properties: {
              commitSha: { type: 'string', pattern: '^[0-9a-f]{40}$' },
              branch: { type: 'string', pattern: '^dev-syn/[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$' },
              thinking: { type: 'string', enum: ['off', 'minimal', 'low', 'medium', 'high', 'xhigh'],
                description: 'Agent-attested; not Gateway-authenticated' },
            },
          },
          async execute(_toolCallId, request) {
            const { assertCurrent } = admitCandidate(context, request);
            assertCurrent();
            throw new Error('publication_disabled');
          },
        };
      },
    }, { name: 'request_signed_publication', optional: true });
  },
};
export default publisherPlugin;
