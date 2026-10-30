# Read-base issuer prototype (not deployed)

This module is a Gateway-side **read-only** GitHub App lookup of the commit SHA
at the approved repository's `main` ref. It has no publisher, Git transport,
write permission, agent-facing tool, executable CLI, default identity, or
standing credential. The only live entry point is `read_main_base(path)`; do
not call it during offline tests. A trusted Gateway deployment must supply
`path` to its own configuration file **outside this agent-writable repository**.
It must not accept the path, repository, App identity, or key from an agent
request. The module checks file ownership, owner-only permissions, final
symlinks, size, and resolved exclusion from this checkout; it does not prove
that a caller is the Gateway or that all parent directories are safe. Deploy
only under separately enforced process isolation and trusted path ownership.

The private JSON deployment file (not included here) has exactly four keys:
`app_id` (positive integer), `installation_id` (positive integer),
`repository` (approved `owner/name`), and `key_path` (absolute path to
private PEM outside the checkout). Both files must be Gateway-owned, unreadable
and unwritable by the agent, mode 0600 or stricter, with trusted, non-writable
parent directories. Pin and review the exact repository once in deployment
configuration; no per-call repository or branch parameter exists. No production
values, paths, key material, or tokens belong in this repository.

The issuer requests only that repository and `contents:read`, verifies the
returned selected-repository list contains exactly the approved repository,
checks that no additional permission except read-only metadata is present,
checks the 30–3700-second remaining token lifetime, reads exactly the `main`
commit ref, and revokes the installation token in `finally` before returning
only a 40-character lowercase SHA. If revocation fails, the lookup fails. An
invalid or unparseable token in an unsuccessful issuance response cannot be
revoked by this module; treat uncertain network outcomes as a deployment
incident, and rely on GitHub token expiry/revocation controls. Never log raw
HTTP responses, authorization headers, request exceptions, or bearer values.

The HTTP adapter uses a fixed GitHub API origin, an exact three-operation
allowlist, no process proxies or redirects, 15-second per-request timeout and
64 KiB response limit. The JWT signer passes the key by inherited fd to
OpenSSL; installation bearer tokens are only HTTP headers, never argv or
environment. The adapter and signer must run only in the trusted Gateway
process, which must keep the credential and return value out of untrusted
agent logs and mounts. TLS/CA trust, actual GitHub App installation grant,
OS/process isolation, protected config ancestry, revocation under network
failure, and integration with any caller remain **unverified**. Injectable
callbacks in `BaseIssuer` are test seams, not authentication, authorization, or
proof of a live repository grant.

Offline tests: `PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest discover -s broker/tests/issuer -p 'test_*.py' -v`
