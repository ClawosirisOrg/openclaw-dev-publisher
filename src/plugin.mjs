/**
 * Inert Gateway runtime entry. This package proves the versioned registration
 * shape; it contains no transport, credential issuer, or host-specific config.
 */
export const publisherPlugin = {
  id: 'openclaw-dev-publisher',
  name: 'Signed dev-agent publisher (inactive)',
  description: 'Inert versioned admission interface; no publication capability',
  register(api) {
    api.registerTool({
      contextVersion: 2,
      create(context) {
        if (context.senderIsOwner !== true ||
            typeof context.assertInvocationCurrent !== 'function') return null;
        return {
          name: 'request_signed_publication',
          description: 'Unavailable: publisher is not connected to a trusted issuer or transport',
          parameters: {
            type: 'object', additionalProperties: false,
            required: ['commitSha', 'branch'],
            properties: {
              commitSha: { type: 'string', pattern: '^[0-9a-f]{40}$' },
              branch: { type: 'string', minLength: 1, maxLength: 96 },
            },
          },
          async execute() {
            context.assertInvocationCurrent();
            throw new Error('publication_disabled');
          },
        };
      },
    }, { name: 'request_signed_publication', optional: true });
  },
};
export default publisherPlugin;
