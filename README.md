# Signed dev-agent publication: policy prototype

This is a small, **inert** Gateway-side design prototype, not a publisher,
installable OpenClaw plugin, or production deployment. It contains an
invocation-scoped signer-readiness gate and a publication function that always
throws. It neither signs commits nor acquires credentials nor writes to GitHub.
Node.js 20+ is required to run the tests.

## Trust boundaries and threat model

A development agent can request a signed publication but must not receive a
Gateway signing key or a standing repository credential. An unknown/stopped or
substituted container, socket peer, image, or signer must not be treated as the
approved agent. A prior successful readiness check must not authorize a later
invocation. Hanging probes must not make an unbounded authorization attempt.

The trusted Gateway supplies an exact allowlist of container IDs, expected
container name and image digest, socket path and signer fingerprint. Two
independently implemented, trusted adapters provide current container identity
and authenticated socket-peer readiness. No adapters are provided by this
repository; a path existence check or peer self-report is **not** an
authenticated probe. The signer fingerprint is a comparison field, not
cryptographic proof: a deployment must verify the actual signer key through a
trusted socket protocol before supplying that value.

## Component lifecycle

1. At Gateway startup, obtain approved configuration through a private,
   reviewed deployment mechanism; instantiate trusted container and socket
   adapters. Do not load policy values from the agent's writable checkout.
2. For **each** requested signing action, call `withReadySigner`. It
   starts a fresh bounded invocation; fails before IO if the container is not
   allowlisted; checks current container ID, name, image and running state;
   probes the exact socket, bound container and signer fingerprint; then invokes
   a callback. It exposes no reusable ready flag.
3. The callback must call `assertCurrent()` immediately before a side effect,
   use the provided abort signal, and avoid returning a capability or key. The
   callback's actual signing implementation is deliberately absent.
4. Separately, a future Gateway-owned publisher would validate the signed
   commit and its attribution, acquire a *fresh* repository-scoped credential
   per publish, use a one-operation transport, revoke/close it, and return only
   a sanitized result. `publishSignedCommit()` here always throws.

## Example with fake, non-secret adapters

```js
import { createReadinessPolicy } from './src/index.mjs';

const config = {
  containerId: '<container-id>',
  containerName: '<agent-name>',
  imageDigest: '<image-digest>',
  socketPath: '<socket-path>',
  signerFingerprint: '<signer-fingerprint>',
  knownContainerIds: ['<container-id>'],
  timeoutMs: 1000,
};
const adapters = {
  containers: { async get(id) {
    return { id, name: '<agent-name>', imageDigest: '<image-digest>', running: true };
  } },
  sockets: { async probe(path, { containerId }) {
    return { path, containerId, signerFingerprint: '<signer-fingerprint>', ready: true };
  } },
};
const policy = createReadinessPolicy(config, adapters);
await policy.withReadySigner(({ assertCurrent }) => {
  assertCurrent();
  // Fake callback only: no signing or publication occurs.
});
```

This example tests the shape of an integration, **not** socket authentication
or real signing. No GitHub action occurs. A real adapter must never trust a
container or socket object's identity just because that object claimed it.

## Per-publish transport boundary (design only)

Future interface, **not implemented**:

```text
publish(signedCommit, approvedRepository, invocationContext):
  validate commit, destination, current caller and authorization
  acquire one-use, short-lived credential from a Gateway-only provider
  perform exactly one credentialed transport operation
  revoke/close credential and transport in finally
  return sanitized outcome; never return credential material
```

The Gateway must keep credential issuance, transport and revocation on its
side of the boundary. A credential is short-lived, restricted to exactly the
approved repository and required operation; do not put it into an agent
container, environment inherited by a worker, command line, logs, checkout,
or persistent Git credential helper. Separate SSH commit signing from Git
transport and API authorization. Verify signed commit content and provenance
before publication, require exact allowlist and owner authorization, reject
replay, check remote state before write, and inspect the resulting remote
artifact. None of those controls is implemented here.

## Limitations and deployment notes

- The callback API is cooperative: a callback or adapter that ignores abort
  can continue running after timeout. The gate rejects the invocation but
  cannot undo external side effects. A real signer should enforce deadlines
  and identity **inside** its own service, with a request nonce, no reusable
  authority and one-operation semantics.
- These adapters are abstractions only. There is no container-runtime client,
  Unix socket protocol, cryptographic challenge, peer attestation, signature
  verification, privilege isolation or audit sink. Inject trusted monotonic
  time; prevent agent writes to Gateway configuration and socket.
- Failures of adapters reject the call; avoid exposing sensitive adapter
  errors in API responses. Revocation, rotation, concurrency, race-free
  container identity binding and replay protection need a separate review.
- OpenClaw **packer v2** packaging and plugin lifecycle are unsupported and
  unverified. There is no plugin manifest or registration, compatibility
  promise, installation command, active Gateway hook, or publisher service.
  Do not deploy this tree as an activated plugin or infer v2 compatibility.
- Treat the local tests as policy-unit tests using fakes, not an end-to-end
  security proof. Review the real adapter, signer, authorization and transport
  together before any deployment; keep keys and credentials outside this tree.

Run `npm test` to check the fake-IO policy tests. License: MIT.
