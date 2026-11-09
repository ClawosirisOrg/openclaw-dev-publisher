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
| publication_policy | Exact host-owned actor/repo/namespace/signer/credential binding below |
| api_app_config | Separate protected API App config reference; same exact repository |
| verifier | Exact verifier fields listed below |

The App config has exactly `app_id`, `installation_id`, `repository` and
`key_path`. Use the dedicated selected-repository publisher App, never the
main agent token. The App PEM/config remain Gateway-only and outside all agent
workspaces. Grant responses must prove exactly the configured repository,
requested permission profile and short lifetime; usable rejected grants are revoked.
Contents writes, issue writes and PR writes use separate one-shot leases. No API
write lease also grants contents write, issues+PR write, administration, merge or
branch-protection bypass. The API App must actually possess the grants described
below; configuration does not invent or provision them.

Verifier fields: repository; base_ref (refs/heads/main); agent (exact-case
attribution name); bot_owner (without @); branch_prefix (dev-syn);
source_component (safe repository basename); signer_fingerprint;
signer_public_key (single-line pinned Ed25519 public key). Repository must match
the App config and the public-key fingerprint must agree. No identity, source,
path, executable, image, remote, model or permission override is accepted from
the agent request. The exact operation inputs are specified below. A namespace
policy is not a permission for any other actor or repository.

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
2. Hold a repository+branch cross-process flock for the entire operation.
   Persist an append-only actor/repository/branch intent with operation, exact
   expected-old/new and provenance before network, staging or effects. Any
   unresolved intent blocks later writes regardless of call ID, deployment,
   process or candidate. Old allocated/attempted/quarantined markers still deny
   their legacy repository/branch key. Allocate a separate one-shot stage for
   each operation; never remove or reset the legacy ledger.
3. Obtain authenticated current main with a selected-repository contents:read
   App token, then revoke it. Candidate must be its exact direct child with one
   new commit, pinned SSH signature and exact attribution trailers. For an
   update, the base for BOTH independent object checks is instead the explicit
   expectedOldSha, which must equal the last durable ownership receipt. Exactly
   one signed direct child is supported, not a chain or merge. The remote main
   snapshot remains separately authenticated for transport freshness.
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
7. Check main, target absence for create (equal SHA still denies) or exact
   expected-old for update, then main again. Obtain the final original Gateway
   guard and attempt one exact absent-ref or expected-old Git lease. The fixed
   adapter independently checks direct-child ancestry in the sterile store
   before an update. There is no plus refspec, unconditional force, rewind,
   merge, delete, tag, main write, alternate remote or agent-selected target.
   Require exact new-branch or fast-forward porcelain, exact branch readback and
   main readback. Main preflight is bounded, not atomic CAS; report stale main.
8. Revoke in finally, verify worker removal and quarantine the spent stage.
   Uncertain push, revocation or cleanup never returns success. Only then
   append the durable ownership completion. Never retry, overwrite or
   automatically delete a branch; inspect separately. Accept a receipt only
   with its exact matching completion-commit record, attempted after the receipt
   file and directory sync succeed. Final commit-record failure is a local
   acknowledgement ambiguity, with the distinct reopen contract below.

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

Then use an owner-authorized new safe branch in the deployed namespace and a freshly signed direct-
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


## Namespace policy and legacy migration (owner-reviewed, no automatic edits)

The namespace JSON has exactly the table fields above: replace
\`approved_branch\` with BOTH \`publication_policy\` and \`api_app_config\`.
The old exact-branch schema remains accepted **only** for old create behavior;
updates and API operations are denied in legacy mode. Mixed schemas deny.
The namespace policy has exactly:

| Policy field | Required constraint |
| --- | --- |
| actor | \`dev-syn\`; no other agent is deployed/admitted |
| repository | Exact App/verifier repository |
| namespace | \`dev-syn\` |
| signer_fingerprint | Exact verifier public-key fingerprint |
| credential_repository | Exact same repository as both private App configs |
| max_update_commits | Integer \`1\` (no chain mode) |
| api_author | Exact expected API bot login; readback must match |

The existing verifier fields continue to pin the signing key and attribution
name. No real repository identity, key, login or host path is supplied by this
public document. The actor need not equal the human-readable attribution name.
Both credential configs are protected host references, not request parameters;
they may identify the same reviewed App, but leases remain disjoint. Private
key bytes, bearer tokens, App config and the Podman socket never enter a sandbox.

Before migration, back up and inspect the protected config and **existing**
ledger. Preserve all old ledger inodes and stage quarantines; keep ledger_root
pointing to the same durable ledger. Do not switch to an empty ledger to gain
namespace admission. Legacy keys retain their existing case-folded repository +
branch derivation, and any allocated/attempted/quarantined key blocks adoption
or publication of that branch. Existing old remote branches are not silently
adopted as publisher-owned. Choosing a fresh unspent safe branch is supported;
reusing a spent branch needs separate owner reconciliation, never deletion of
markers. Stage root changes must preserve old inaccessible roots/quarantines.
Run the packaged protected-config check without minting or effects, then build
and review a fresh dedicated immutable worker image from the minimal context.
No config check, package test or image build proves a live deployment.

### Exact operational tool schema

The sole optional tool remains \`request_signed_publication\`, Gateway context
version 2. Every request requires \`commitSha\` (40 lowercase hex), \`branch\`
and \`thinking\` (off|minimal|low|medium|high|xhigh). Branch is exactly
\`dev-syn/<component>\`: component is 1–63 lowercase ASCII letters/digits/hyphens,
starts and ends alphanumeric. No slash, dot, underscore, colon or ref escape.
No model, actor, repository, base, signer, credential, endpoint or path input.

| operation | Additional request fields | Behavior |
| --- | --- | --- |
| omitted or create | none | Remote-absent signed main direct child; new ownership receipt |
| update | expectedOldSha (40 lowercase hex, differs from commitSha) | Proven own branch + explicit expected head; one signed direct-child FF |
| issue | title, body | Corresponding issue for proven own current head; issue-only write lease |
| pr | title, body | Previously completed corresponding issue, own head to fixed main; PR-only write lease |
| reconcile | none | Read-only issue/PR duplicate/uncertain-response reconciliation; never repeats POST |

Unknown/additional fields deny in Node admission and again at the host boundary.
Update fields on create, text on reconcile, or missing operation-specific fields
deny. Title is trimmed, nonempty, one line, at most 200 UTF-8 bytes. Body is
nonempty, at most 12000 UTF-8 bytes, LF-only (no control bytes except LF), and
ends with exactly one blank-line-separated four-line attribution block. The
Agent and Bot-Owner are host pins; Model is the original retained Gateway v2
active model; Thinking is still explicitly temporary **agent attestation**.
Duplicate or Unicode-confusable attribution labels deny. Attribution describes
the actual substantive author runtime, not the publisher's default or a reviewer.
The host inserts its correlation marker and, for PRs, the proven issue URL before
that final attribution block. Titles never contain attribution metadata.

Return for create/update: sha, branch, authenticated main base, acknowledged,
readback_checked, main_at_readback, stale. Return for issue/PR/reconcile: number,
url, head, readback_checked. Any failure/uncertainty suppresses success and must
be inspected; tool-call correlation is never an idempotent retry permit.

### Issue-first API effects and reconciliation

The trusted host holds the branch lock throughout read preflight, separate
credential mint/delivery, mutation, readback and revocation. It reserves the
exact issue/PR payload and actor/repo/branch/head before effects. Read leases
request only contents/read + issues/read + pull_requests/read. Issue writes
request only issues/write; PR writes only pull_requests/write (metadata/read
may accompany any profile). These selected-repository leases are short-lived,
validated against grant responses, immediately revoked in finally, and never
returned to the agent. API HTTPS uses a fixed origin, no proxies/redirects, and
an explicit path/method allowlist. No merge endpoint, auto-merge enablement,
retarget, comment/edit operation, branch-protection bypass or alternate repo is
implemented. PR creation fixes base=main and the receipt-bound own head/repo.

Read preflight checks exact remote head and bounded all-state duplicate scans
(up to ten pages of 100; exhaustion denies). The separately revoked read lease
precedes the write lease: no contents permission is smuggled into a write grant.
The preflight-to-POST interval is bounded to 30 seconds, and the original Gateway
assertion is checked immediately before the single POST. This is not an atomic
Git/API transaction; external actors can race remote observations. PR readback
must prove exact repository, main base, head branch/SHA, bot author, title/body,
open/unmerged state and absent auto_merge. Issue readback proves exact number,
URL, bot author and payload. Return only after both POST and independent GET
readback and confirmed revocation. Immediately before minting a later Git review-update write lease, read the
same recorded PR number and refuse repo/base/head/author/state/auto-merge drift;
repeat that check with the new exact head after Git revocation and cleanup. Thus
a retarget or metadata race suppresses success rather than silently blessing it;
no retarget or replacement PR is created.

A response loss or preexisting marker blocks new creates. Reconcile is GET-only
under a separate read lease; require exactly one marker match and exact payload,
author, repository/base/head bindings. Zero/multiple matches, closed/retargeted
artifacts or bounded-scan exhaustion remain blocked; never repeat POST. A
successful prior completion can also be read back after a lost caller response.
Pending API completion additionally requires its original durable cleanup proof:
confirmed remote existence does NOT erase an uncertain token mint/revocation.
Unknown bearer issuance, failed revocation, malformed/mismatched receipts, Git
write ambiguity or worker cleanup uncertainty require owner investigation; this tool
does not clear them, reset ledgers or restore write authority automatically.

### Receipt commit gate and final-acknowledgement ambiguity

The pre-effect durable intent is the unresolved state. A readable \`.complete\`
receipt alone is **not** completion. The host first creates the receipt and
requires both its file fsync and parent-directory fsync to return success; only
then does it attempt \`.complete.commit\`, containing the exact receipt's SHA-256
and record version. Reopen requires that matching commit record and the receipt's
exact intent binding. Failed receipt sync never attempts a commit gate, even if
the receipt is fully readable and all further writes fail. No best-effort
post-failure poison write is used to decide success.

The gate is attempted only after the remote effect, required readback,
revocation and worker cleanup are known complete. A failure while writing or
syncing the **commit record** is therefore classified as an ambiguous local final
acknowledgement, not permission to repeat the remote effect. It is deliberately
NOT a promise that every fsync-reported failure leaves no accepted record:

- If an exact matching commit record is readable on reopen, the journal may
  accept completion, even if the prior invocation reported commit-sync failure.
  Existing replay guards still forbid repeating that operation's Git/API effect;
  a later distinct update must satisfy the normal ownership/expected-old checks.
- If the record is absent, the original intent stays pending and ordinary writes
  stay blocked. API \`reconcile\` performs fresh GET-only evidence validation and
  requires the original committed cleanup proof. It may re-sync an identical
  existing receipt, then write its commit gate, without repeating POST. Git
  ambiguity still uses separate owner read-only inspection, not a tool retry.
- Malformed, partial or mismatched records are not repaired or overwritten by
  this path; they require owner inspection. Old receipt-only namespace records
  are uncommitted under this format, and existing uncertainty markers still deny.

Cleanup proofs use the same ordered \`.cleanup\` then \`.cleanup.commit\` gate:
a failed cleanup-receipt sync cannot establish cleanup merely because the proof
is readable and poison creation was impossible. A valid cleanup commit after a
reported final sync failure may be accepted on reopen, recording known **prior**
revocation; it never completes the repository operation by itself. An absent or
invalid cleanup commit cannot be replaced by finding the remote artifact.

Readability is not evidence of power-loss survival, and an fsync error cannot
prove whether a record persisted. A lost/missing gate after recovery remains
pending; no effect is automatically repeated. This protocol assumes protected
host-owned storage and does not promise durability on a broken filesystem or
against privileged mutation. No new database, privileged helper, marker deletion
or inferred storage guarantee is introduced.

### Actual permission readiness and independent tool-policy gates

The separate packaged read-only worker is:
\`python -B -m broker.issuer.api_readiness --config <protected-api-app-json>\`.
It uses App-authenticated installation evidence to check actual issues/write and
pull_requests/write grants, selected repository access, non-suspension and usable
repository features. It mints only the exact read profile, cross-checks repository
enumeration/metadata, and revokes before returning sanitized readiness evidence.
It does not provision permissions, mint write probes, create issues/PRs or prove
future authorization. Run only under separate operator permission; source tests
use fake HTTP and do not check the live installation.

For the coding profile, inspect and preserve existing arrays/denies, then admit
ONLY \`request_signed_publication\` at both independent layers when missing:
\`agents.entries.dev-syn.tools.alsoAllow\` and
\`agents.entries.dev-syn.tools.sandbox.tools.alsoAllow\`. Do not opt in other
agents, use group:plugins, enable direct GitHub sandbox credentials, disable
sandboxing or widen mounts. Installation, production activation, optional-tool
policy, sandbox policy and the actual dev-syn Gateway v2 context are separate
gates. Verify discovery and denial in a fresh actual agent run after the parent
reviews source/package/image/config; simulated tests are not that admission proof.
