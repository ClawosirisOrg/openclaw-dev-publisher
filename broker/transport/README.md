# Offline one-shot transport model and dormant Git adapter

This is **public-safe, unactivated transport code**, not a publisher.

- one_shot.py is an offline fixture protocol. Its fixed remote is a synthetic
  .invalid URL, not a deployable repository. Its main() refuses execution;
  injected callbacks are tests, not authority. A successful Git --porcelain
  acknowledgment must be exactly a To line naming the fixed remote, one
  created-ref status line, and Done, each LF-terminated; anything ambiguous
  after the push attempt remains uncertain.
- git_adapter.py is a **dormant** deployment-owned Git subprocess/HTTPS
  adapter, with a pinned GitHub host and validated owner/repository supplied
  only by a trusted deployer (none is supplied here). It limits operations to
  main/branch reads and one absent-target-lease create, disables helpers and
  redirects, bounds subprocess output/time, and passes a token over a private
  FD. askpass.py is the executable one-use FD prompt handler. Neither module
  authorizes a caller or supplies an issuer; both main() entrypoints refuse
  activation. The fixture's callback is not wired to this adapter.
- There is no live admission, issuer grant, credential, key, API client,
  deployment manifest, or enabled publication path. The inert container recipe
  copies one_shot.py, git_adapter.py, and executable askpass.py, but has
  /usr/bin/false as its entrypoint; a separately approved base image would
  also need the required Git/Python executables. Packaging these files does
  not make a publisher.

Offline tests (the local bare-Git case requires Git; no network is used):

    PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s broker/tests/transport

The fixture protocol checks a 40-character commit/base OID and constrained
create-only branch, calls a **separate injected authorization verifier** before
an injected issuer supplies one private FIFO/pipe FD, reads a bounded complete
printable token frame to EOF and closes the FD, and revokes the issuer lease
in finally even for invalid frames or failed commands. An in-memory fake Git
callback receives the token out of band; its Git arguments use the fixed
synthetic remote and contain no token. The separate, dormant adapter passes
only a private FD number through the environment; it never places the token in
Git argv, remote URL, environment values, or logs.

The fixture observes main, rejects an existing branch (even equal OID),
observes main again under a 10-second monotonic preflight bound, attempts one
absent-target lease push, checks the exact creation acknowledgment and ref
readback, then reports main-at-readback and stale. Main is **not** an atomic
compare-and-swap: drift after preflight can still create a stale branch.
Anything ambiguous after push invocation is UncertainPush; it never retries or
deletes. The separate inspection seam only observes and never grants an ack.

**Not publication authority:** All injected callbacks are test doubles and can
lie. In particular a caller-provided boolean is not authenticated admission;
a caller-provided Git callback could leak a secret or issue arbitrary commands.
Before deployment, a separate trusted implementation needs (1) owner-approved
admission, authenticated invocation/context, signed-object graph/attribution
verification and replay control *before* credential issuance; (2) a bounded,
repository-scoped, expiring issuer grant plus real revocation evidence and
handling for issuer failures; (3) approved deploy-selected HTTPS target and
integration/review of the dormant askpass/FD Git adapter's strict prompt,
redirect, credential-helper, process-output and deadline controls; (4)
distinct-UID staging and verified mount, /proc, egress, image and symlink/race
isolation; and (5) live remote
readback and uncertainty handling by a trusted operator. The private draft's
object-copy/receipt verifier is intentionally not imported or republished here.
No public CLI or composed publication path is enabled. The internal `git_adapter._run`
can perform a real HTTPS Git push if separately imported and supplied a trusted
deployment target and token FD; using it requires the authorization, isolation,
and review gates above.
