# Signed dev-agent publication: policy prototype

This is a **disabled** Gateway-side broker source repository, not an installed
publisher or production deployment. The version-2 optional tool is scoped to a
sandboxed development agent and always rejects publication. Its independent
source modules cover admission, a one-use claim frame, read-base issuance,
credential-free object verification, a dormant write-grant model, and one-shot
Git transport fixtures. They are **not composed into a live write path**.
No included entrypoint mints a write token or pushes to GitHub. Node.js 20+
and Python 3 are needed for the complete offline test suite.

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
artifact. Individual offline modules test parts of those controls; no composed
or deployed publisher implements them end-to-end.

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
- A manual `openclaw.plugin.json` and `src/plugin.mjs` now register an inert
  optional version-2 tool. Its invocation guard is unit-tested, but installed
  Gateway behavior is **not** verified. The authoring-only `openclaw plugins
  validate/pack` commands reject manual entries without `defineToolPlugin`
  metadata; switching to that helper would lose the version-2 guard. Installed
  OpenClaw documentation separately supports reviewed package installs via
  `npm pack` and `plugins install npm-pack:<archive>`. This package path has
  not been activated or proven in an isolated Gateway. Do not treat a local
  npm tarball as authorization to enable publication.
- Treat the local tests as policy-unit tests using fakes, not an end-to-end
  security proof. Review the real adapter, signer, authorization and transport
  together before any deployment; keep keys and credentials outside this tree.

## Source and packaging status

The public repository contains broker source under `src/`, `broker/issuer/`,
`broker/worker/`, and `broker/transport/`; a no-default, disabled worker image
recipe is under `containers/`. Offline tests are under `test/` and
`broker/tests/`. Run `npm run test:all` to check both Node and Python fixtures.
The current npm package allowlist includes only `src/` and plugin metadata;
putting source in Git is not an installed worker or a deployment. Keys, tokens,
actual App IDs, signer pins, image locks, and host paths belong only in a
separately reviewed private deployment configuration, never this repository.

Before any publication is enabled, complete and independently review the
Gateway-to-UID1 private claim delivery, protected stage ownership and replay
quarantine, separate object re-verification, final guarded write admission,
isolated scoped-token transport, immutable image identity, mount/FD/`/proc`
and egress probes, and remote readback with uncertain-outcome handling.
A valid offline receipt is not a permit to mint a token. The `main` preflight
is bounded but cannot atomically prevent stale branch creation. Plugin
installation/allowlisting and the first live branch probe require separate
owner review and authorization.

License: MIT.
