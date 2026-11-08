# Installable production candidate — disabled by default

The npm package now ships its operational Node entry and the explicit Python
runtime import closure. No private executable wrapper, Python package install,
Gateway UID change or Gateway restart is required by this design. Source/tests
are not live deployment proof. No included default enables publication.

## Gateway plugin config

The normal package entry reads `api.pluginConfig`. Default/disabled mode retains
the original denial-only tool. Production requires exactly:

```json
{
  "mode": "production",
  "productionConfigPath": "/trusted/private/publisher.json"
}
```

The path is a reference, not a credential. The entry checks bounded regular-file
ownership, owner-only permissions, non-symlink ancestors, and exclusion from the
package/source checkout before loading. Runtime code comes from the installed
package, not a request-selected path. Python configuration is independently
validated again by the per-attempt host subprocess. No network, stage allocation,
key read or container start occurs at plugin registration. The installed
host also supports `python -B -m broker.host.production --check-config
<protected-json>`: it validates local config, current Gateway owner mapping
and existing protected parents without ledger writes, container starts, JWTs
or network. Its result explicitly proves local config/directories only. A malformed enabled
configuration fails closed; it does not silently fall back to a working tool.

## Private deployment JSON: exact fields

| Field | Host-owned value |
| --- | --- |
| python_path | Absolute Gateway Python 3 executable; separate from worker/askpass pin `/usr/local/bin/python3` |
| deployment_id | Stable lowercase correlation identifier |
| app_config | Separate private fixed-repository App issuer JSON path |
| runtime_socket | Existing trusted rootless Podman 5.8 Unix socket path |
| image_id | Full approved locally present 64-hex worker image ID, never a tag |
| source_host | Exact repository directory in the Podman host namespace, never workspace parent |
| source_device, source_inode | Trusted repository-root device/inode observed through the bind |
| stage_root | New dedicated protected Gateway-visible staging parent |
| stage_host_root | The same underlying directory in the Podman host namespace |
| ledger_root | Separate new dedicated durable Gateway-owned ledger parent |
| transport_network | Existing dedicated named network with separately verified egress policy |
| approved_branch | Exact separately approved new dev-syn branch |
| verifier | Exact verifier fields listed below |

The App config has exactly `app_id`, `installation_id`, `repository` and
`key_path`. Use the dedicated selected-repository publisher App, never the
main agent token. The App PEM/config remain Gateway-only and outside all agent
workspaces. Grant responses must prove exactly the configured repository,
contents permission and short lifetime; usable rejected grants are revoked.

Verifier fields: repository; base_ref (refs/heads/main); agent (exact-case
attribution name); bot_owner (without @); branch_prefix (dev-syn);
source_component (safe repository basename); signer_fingerprint;
signer_public_key (single-line pinned Ed25519 public key). Repository must match
the App config and the public-key fingerprint must agree. No identity, source,
path, executable, image, remote, model or permission override is accepted from
the agent request. Only commitSha, approved branch and thinking are tool inputs.

**Thinking is temporarily agent-attested by explicit owner decision**, not
Gateway-authenticated. Model is always taken from the Gateway v2 active model
and rechecked with the original current-invocation assertion. Signature/trailer
verification binds both labels to the exact commit. For the first live test,
record exact substantive author model/thinking from authoritative runtime
status evidence, not configured defaults or reasoning-visibility state. No
per-SHA hardcoded author record is required by the permanent architecture.

## Rootless user-namespace and storage model

Gateway keeps its existing non-root UID/GID. It validates that each maps to
ID 0 of its immediate rootless parent namespace. Production workers run as
container 1:1 using this supported Podman 5.8.7 specgen form:

```json
"userns": { "nsmode": "keep-id", "value": "uid=1,gid=1" }
```

Podman's rootless keep-id generator maps container UID/GID 1 to parent ID 0,
which is the rootless host owner. Gateway-created 0700 stages therefore appear
owned by worker 1 without a UID change, helper privilege, host filesystem mount,
or changing ownership of an old subordinate-UID stage. The deployment must use
**new** dedicated Gateway-owned 0700 stage/ledger parents outside every sandbox
mount; preserve existing ledgers, quarantines and old inaccessible stage roots.
No `:U`/chown mount option is used. The allocator touches only its exclusively
created per-publication directories.

This is **not distinct-host-UID isolation**: Gateway, worker and potentially the
agent can represent the same rootless host owner under different numeric IDs.
0700 alone does not isolate them. Security depends on exact mount visibility,
private PID/IPC/UTS/user namespaces, dropped capability/bounding sets, no-new-
privileges, read-only rootfs, and no Gateway PID/host-proc, key, socket, install,
config or other stage mount in a worker or sandbox. Never widen sandbox mounts
or tools to repair a failed proof. The private anonymous process/attach channels
avoid treating cross-namespace SO_PEERCRED PID values as stable identities.

Workers have one bounded 64 MiB nosuid/nodev/noexec memory tmpfs at /tmp for
Git/SSH scratch (signature verification requires temporary files); it is not a
host mount and disappears with the worker. No other writable rootfs scratch is
enabled. Libpod reports this in HostConfig.Tmpfs, separate from bind Mounts.

The host checks rootless API info and each worker's private namespace metadata,
owner UID/GID mapping, empty effective/bounding capabilities and exact mounts.
Podman inspect reports userns as private, not the original keep-id string; the
mapping is checked independently. Before accepting any input/token, the worker
checks its own UID/GID maps, PID 1/private proc root, zero effective/permitted/
bounding capabilities, NoNewPrivs and absence of inherited descriptors, then
sends a bounded credential-free readiness frame. A label or ready boolean
from an arbitrary agent process is never accepted as that channel.

SELinux remains enabled. Newly allocated per-attempt stage/store binds use
shared `z` relabelling so successive confined workers and Gateway can access
them. This relabels **only the new attempt's stage/store**, never an old stage
parent or source checkout. The exact repository bind is read-only and never
relabelled/chowned. Verify its existing label is compatible before production;
if not, stop for owner review rather than disabling SELinux or mutating sandbox
labels. Namespace visibility—not shared SELinux labels or UID arithmetic—is
the authority boundary.

## Per-publication sequence

1. Admit only sandboxed dev-syn Gateway v2 contexts. Retain the original live
   assertion and model observation across all asynchronous operations.
2. Host derives a durable repository/approved-branch publication key. Fsync
   allocated+attempted markers before one exclusive stage. Changing call ID,
   deployment_id, process, stage or candidate cannot retry a spent publication.
3. Obtain authenticated current main with a selected-repository contents:read
   App token, then revoke it. Candidate must be its exact direct child with one
   new commit, pinned SSH signature and exact attribution trailers.
4. Run a network-none capture container with exact repository RO plus its new
   stage RW only. Copy objects, never source config/hooks/refs/index. Remove it.
5. Run a new network-none container with stage only. Re-copy objects into a
   new sterile bare store and independently verify signature/graph/trailers.
   Remove it before any write token exists.
6. Obtain fresh Gateway mint/delivery guards, issue selected-repository
   contents:write, and launch a private ephemeral transport. It sees only its
   sterile store RO and approved network—no PEM/source/signer/runtime socket.
   A new live handoff guard is obtained after worker readiness, immediately
   before its token frame. Token travels over private attach stdin and inherited one-use Git askpass
   pipes, never argv, environment, URL, logs or persistent files.
7. Check main, target absence (equal SHA still denies), main again, then obtain
   a final fresh Gateway guard and attempt exactly one absent-ref-lease push.
   Require exact new-branch porcelain, exact branch readback and main readback.
   Main preflight is bounded, not atomic CAS; return if it became stale.
8. Revoke in finally, verify worker removal and quarantine the spent stage.
   Uncertain push, revocation or cleanup never returns success. Never retry,
   overwrite or automatically delete a branch; inspect separately.

## Owner-reviewed install and live proof

After diff/image/package review, the supported local archive route is
`openclaw plugins install npm-pack:<reviewed-absolute-tarball> --force
--accept-capabilities --no-enable`. This document is not authorization to run
it. The package's manifest already supports production config; no executable
wrapper or modified package entry is needed. Supply private JSON and **new**
0700 parents, apply the narrow optional-tool allow/config through validated
Gateway config control, then enable/reload through supported plugin lifecycle.
Do not install autonomously or restart the Gateway as a diagnostic.

Build a fresh immutable worker image from the reviewed minimal context in
`containers/README.md`; old inert image locks do not cover changed source.
Verify the actual keep-id mappings, stage/source inode equivalence, SELinux,
exact mounts, private proc/PID/IPC, denied PEM/socket/FD/install access, verifier
network-none behavior and transport egress before permitting the first token.
A named bridge is not by itself proof of GitHub-only firewall egress; inspect
its real policy. The fixed HTTPS Git adapter also refuses redirects/proxies
and alternative operations/remotes, but does not replace OS confinement.

Then use an owner-authorized exact new test branch and a freshly signed direct-
child commit from an actual dev-syn run. Save authoritative author-runtime
metadata and independently inspect remote signature, parent, trailers and ref.
Preserve private evidence without tokens. An uncertain outcome is reconciled
using durable ledger markers and predictable private worker names, not retry.

## Evidence and tests

`npm run test:all` includes real synthetic SSH/Git capture/reverification and
local bare-remote create/readback; mapping/capability/proc negative fixtures;
private config-path activation; and real offline npm pack/extract, complete
Python import closure, and operational entry loading from the extracted archive.
Container/API collaborators are fake. No local test proves live isolation.

Mapping/specgen references (Podman v5.8.7):
- pkg/specgen/namespaces.go: Namespace JSON nsmode/value; keep-id setup.
- pkg/namespaces/namespaces.go: keep-id uid/gid option parsing.
- pkg/util/utils.go: getRootlessKeepIDMapping maps target to parent 0:1.
- libpod/container_inspect_linux.go: private userns and IDMappings output.
- libpod/container_internal_common.go: bind z relabel handling, separate U chown.
- libpod/container_inspect.go: user bind Mounts versus HostConfig.Tmpfs and log driver.
All are under https://github.com/containers/podman/tree/v5.8.7 .
