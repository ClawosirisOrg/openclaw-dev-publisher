# Signed dev-agent publication broker

This is source, **not an installed or live-verified deployment**. The default
version-2 optional plugin is disabled by default; explicit protected production
config enables the reviewed broker, never direct sandbox credentials.
A separate explicit production factory now composes live admission, durable
attempt reservation, isolated signed-object capture/reverification, selected
App write issuance, one-create transport and remote readback. It requires a
reviewed protected configuration and immutable worker image; the npm package
ships the Node entry and Python runtime, but production is not enabled by
default or any fixture flag. See
[PRODUCTION.md](PRODUCTION.md) for the integration interface and live-proof
requirements. Invoking that host entry with real credentials can write.
Node.js 20+ and Python 3 are needed for the offline test suite.

The following architecture notes describe the original disabled modules.
Production composition and its remaining deployment gates are documented
separately above; offline passing tests are never deployment authorization.

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

Original fixture boundary (operational composition: see PRODUCTION.md):

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
artifact. The separate production source composes these controls; no deployed publisher
has been verified end-to-end.

## Limitations and deployment notes

- The callback API is cooperative: a callback or adapter that ignores abort
  can continue running after timeout. The gate rejects the invocation but
  cannot undo external side effects. A real signer should enforce deadlines
  and identity **inside** its own service, with a request nonce, no reusable
  authority and one-operation semantics.
- These original readiness adapters are abstractions only. They contain no container-runtime client,
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
The npm allowlist includes Node entry/metadata and the explicit Python runtime
closure, excluding tests and private data. Putting source in Git or an archive
is not an installed worker or a live deployment. Keys, tokens,
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


## Namespace and review workflow extension

The operational candidate now supports host-bound dev-syn namespace creation,
durable publisher ownership and explicit-expected-old signed direct-child review
updates, plus a separate-lease issue-first PR path to fixed main. It never merges,
writes main, retargets, deletes, adopts other agents' branches or clears spent
legacy attempts. New API creates are journaled before effects; uncertain or
duplicate outcomes are read-only reconciled, never repeated. Cleanup/revocation
uncertainty still blocks success. See [PRODUCTION.md](PRODUCTION.md) for the exact
input/policy schemas, disjoint permission profiles, package entrypoints, ledger
migration, API limitations, actual-grant readiness worker, and BOTH agent/profile
and sandbox optional-tool admission. No deployment, live grant, image confinement
or external publication is established by these offline tests.
