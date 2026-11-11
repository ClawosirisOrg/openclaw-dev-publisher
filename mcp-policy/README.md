# Host-only issue/comment MCP policy adapter (not deployed)

This is a small newline-JSON-RPC stdio proxy around the **stock** GitHub MCP
server. It does not implement GitHub APIs, mint grants, alter the publisher, or
change an agent sandbox. The owner authorized issue create/update in one approved
repository, plus issue and PR conversation comments in that repository. Git,
PR body/state edits, PR reviews/approvals, merge, admin and other writes remain
unchanged.
No installation, activation, credential, or external write is performed here.

## Host construction

A protected host JSON file (not agent input) has exactly the four fields below.
Generic example only; replace every placeholder and never commit deployment JSON:

```json
{
  "binary": "/trusted-host/stock-github-mcp-server",
  "binary_sha256": "<64 lowercase hex characters measured from reviewed binary>",
  "repository": "ExampleOwner/ExampleRepo",
  "read_tools": ["issue_read", "read_01", "read_02", "read_03", "read_04",
    "read_05", "read_06", "read_07", "read_08", "read_09", "read_10",
    "read_11", "read_12", "read_13", "read_14", "read_15", "read_16", "read_17"]
}
```

These placeholder read names deliberately do **not** constitute a usable stock
inventory: use the actual reviewed 18 previously enabled read-only names from
this installation. `issue_read` is mandatory. Every listed read tool must
have stock `annotations.readOnlyHint: true`; stock `issue_write` and
`add_issue_comment` must each have `readOnlyHint: false`. The proxy starts only
the pinned child binary with
`stdio --tools <exact comma-separated 18 reads,issue_write,add_issue_comment>`.
No `--toolsets` or dynamic tool names. During child-facing initialize, it
removes only the `io.modelcontextprotocol/ui` client capability extension
without mutating the caller's request or other capabilities. The pinned stock
server otherwise defers `issue_write` to an MCP App form on UI-capable clients;
that form submission would bypass this adapter's canonical issue preflight.
The adapter continues denying any awaiting-form result, error, or uncertain
write and never retries a write. This change does not disable the host's UI
capability outside this child session. The proxy exposes exactly those 20 tools
even if the child lists additional tools; calls to anything else are denied.

The JSON file must be a regular owner-only (0600) same-Gateway-UID file outside
source/workspaces, with non-symlink safe ancestors. The binary must be a regular,
non-writable-by-group/other executable in protected host storage, with a
SHA-256 matching `binary_sha256`. Deployment should copy reviewed adapter
bytes into that protected host location and configure the existing MCP server
entry through supported MCP configuration controls, using a host Node process
invoked with `--config <protected-json-path>`. Do not edit stock
`node_modules`, replace the package/plugin, expose the config to a sandbox,
or add token arguments. The current host App authentication metadata is
configured as stock CLI flags, **not** environment variables. The adapter
launches the stock child with only `stdio --tools ...`, so an operator must
map the existing trusted host App metadata to the stock-supported host
environment variables `GITHUB_APP_ID`, `GITHUB_APP_INSTALLATION_ID`, and
`GITHUB_APP_PRIVATE_KEY_PATH` (a protected key-file path, **not** PEM bytes)
before activation. The stock binary resolves those variables through its
`GITHUB_` environment prefix and hyphen-to-underscore mapping. Keep the
credential and key path out of source, config examples, sandbox and logs; clear
ambient PAT/token variables from this child environment to prevent fallback
to a different identity. Do not rotate or mint credentials as part of this
source change. The host and child must remain outside agent mounts; verify
the installed stock binary hash/version, existing App installation grants,
repository metadata and an authenticated read-only integration before
activation. A binary hash check protects review identity, not a malicious
same-UID host that can replace the executable between check and exec.

## Policy and failure contract

Only `issue_write(method=create|update)` in the configured repository is
forwarded. Allowed normal issue fields are title, body, state/reason, labels,
assignees, milestone and type; create cannot provide `issue_number` and
update requires a positive integer. Parent/duplicate/field mutation or foreign
repository inputs are rejected rather than delegated. A host-only fresh
`issue_read(method=get)` preflight validates a structured minimal issue or
root JSON text with exact root issue number and canonical
`https://github.com/OWNER/REPO/issues/N`; any PR marker or `/pull/N` target
is rejected for **issue_write update**. The separately permitted
`add_issue_comment` accepts exactly owner, repo, positive issue_number and
nonempty bounded body. It uses the same fresh stock `issue_read get` and accepts
**either** canonical `/issues/N` or `/pull/N` for an issue or PR conversation
in the approved repository, never PR review/approval or body/state edit. A
contradictory marker, malformed/ambiguous/error result, foreign repo, or root
number mismatch is denied. Do not scan issue body/nested URLs for authority.
Actual stock issue_read was observed with `content[0].text` containing JSON
with root `number` and `html_url` and no `url`/pull_request marker; the other
fields (including untrusted body/labels/user) are not authority. If an actual
child output lacks the canonical fields, **stop for owner review** rather than
relax the gate. No PR number PATCH is authorized.

Read calls pass through stock unchanged after allowlist/annotation validation;
no issue-write permission is inferred from a tool name. Interactive MCP App form
metadata is removed from the advertised write tool and an awaiting-form result
is denied to avoid an unguarded deferred write. The proxy accepts only MCP
initialize, ping, tools/list, tools/call, and initialized/cancelled notifications;
no sampling, resources, prompts, arbitrary server request, merge or admin path
is auto-approved. Internal child request IDs are unique and serial, distinct
from caller IDs; duplicate caller IDs terminate the child. Input/output line
size is bounded to 1 MiB, the pending queue to 128 calls, retained caller
IDs to 65536, and each caller string ID to **256 UTF-8 bytes**. IDs beyond
that bound (or invalid numeric IDs) abort without reflecting the ID or sending
a child request; safe-integer numeric IDs remain supported. Each child request
has a 30-second timeout. A stream `write(false)` means that the frame was
accepted into a bounded buffer: the proxy waits for `drain` **without sending
it again**. Client responses are serialized while the output is blocked; a
child stdin or client stdout error, close, or drain timeout aborts fail-closed.
A cancellation naming an already successfully emitted initialize, ping,
tools/list, or allowlisted read response (including an SDK late abort) is
ignored. Those safe IDs are retained within the existing 65536 caller-ID cap;
ID type and the 256-byte UTF-8 bound still apply. Cancellation during output
drain, or naming an in-flight, queued, unknown, rejected, malformed, or write
request, aborts the child fail-closed. A cancellation may carry only a valid
requestId and an optional string reason of at most 256 UTF-8 bytes. Child
failure/cancel/timeout produces a sanitized error and process cleanup.
The proxy does not automatically retry either issue or comment writes. A lost
response **after** dispatch is uncertain and requires independent owner
reconciliation, not another call. This proxy has no durable cross-session
operation ledger and does not claim exactly-once
remote effects, atomic preflight/write or resistance to a separately privileged
writer. Credential attenuation and actual App grants are separate host checks.

The proxy cannot authenticate substantive model/thinking from generic MCP
context. Keep the existing agent pre-write attribution rule for issue bodies
**and comments** (four final lines: Agent, Model, Thinking, Bot-Owner), inspect
real final bodies, and do not treat a fixture trailer or proxy as runtime
evidence. The present dedicated host App credential and App installation grant
remain unchanged; metadata evidence shows repository selection and issues,
pull_requests, contents write grants, but does **not** prove an issues-only
backend token. The policy proxy constrains exposed operations; it does not
attenuate the existing host credential or rotate/mint any App token.

Tests use a fake stdio child and no GitHub traffic or real credentials:
`node --test test/mcp-issue-policy.test.mjs`, then `npm run test:all`.

## Version 2 Syn engineering capability candidate (source only; not activated)

The existing four-key policy remains version 1 with 20 tools. A separate,
protected host policy with exactly binary, binary_sha256, repository,
version: 2 and tool_groups selects from issues, pull_requests, actions,
repository and releases. Issue preflight is mandatory. This source candidate
includes 30 pinned stock v2.0.2 names (23 reads, seven writes), not all 91.
The additional three reads retain the production CodeQL/scanning surface.
The explicit registry and write preflights are in syn-tool-policy.mjs and
syn-write-policy.mjs; deployment must copy both beside issue-policy.mjs.
Review the protected version-two policy, Gateway toolFilter and session
admission separately. Copying source does not enlarge the active v1 catalog.
Version-two tools/list projects the stock input schemas through a small
static Syn contract: only admitted write fields/method values are advertised,
with unconditional required fields and conditional guards explained in tool
descriptions. Method-based reads likewise omit unsupported method values.
The stock child catalog and caller arguments remain unchanged; the adapter
still checks each request against its separate, fail-closed admission guards.
Version-one inventory behavior is unchanged. JSON Schema alone does not
encode canonical target proofs, attribution, status, or moving-head races.

Coverage: issues: canonical reads, issue create/update/comment and label
resource CRUD; pull_requests: read/diff/files/checks, body/state/draft update,
review create/submit, and head-SHA-pinned merge/squash with attributed merge
message (rebase rewrite is withheld). APPROVE/REQUEST_CHANGES review creation
requires the observed head commitID. Stock submit_pending ignores commitID;
that method is limited to attributed COMMENT, not an unpinned approval.
Actions: workflow/run/job/log read, dispatch and rerun/cancel after canonical
target GET. Repository:
branches/files/commits/tree reads, the three prior CodeQL/security readers,
and narrowly parsed exact-repo search;
releases: list/get only. Existing request_signed_publication remains the only
route for publishing exact locally SSH-signed Git commits, guarded branch
create/fast-forward update and issue-first PR creation. Stock push_files,
create_or_update_file, delete_file, unsigned PR branch updates, repository
admin, organization/global/user tools and arbitrary API URLs stay denied.

Every exposed read now checks owner/repo or an exact-prefix, simple-token
repo:owner/repo query before child dispatch, including version 1. Traversal,
encoded query operators, foreign heads, unknown fields/methods and nested
object arguments fail closed. Stock readOnlyHint is cross-checked, not trusted
alone. Existing canonical issue/PR preflights and form denial remain; new
writes demand canonical label, PR or Actions target proof and bounded fields.
Stock get_label has name/id/color/description but no URL; the requested
repository/name is pinned before the read and its returned name/stable ID
are checked. Canonical Syn PRs may have a well-formed fork head, but must
retain their Syn base and canonical PR URL. Actions resource IDs are positive
safe integers represented as canonical decimal strings for stock resource_id;
workflow_id stays a stock string (decimal ID or filename). GitHub normalizes
repository case in Actions URLs, so the preflight compares only owner/repo
case-insensitively while pinning host, path, and ID exactly. Stock workflow
GET includes an API URL; stock run GET omits API URL/repository, so rerun and
cancel preflight instead anchors the exact scoped html_url and run ID.
A supplied PR head SHA is compared with a fresh canonical GET and passed to
GitHub's expectedHeadSha merge parameter. That GET is not an atomic CAS for
other operations; GitHub branch protections and checks remain authoritative.
Write failures are uncertain and never retried. New issue/PR/comment/review
bodies must end in the four attribution lines: the adapter validates their
shape, but cannot authenticate effective model/thinking, which the author
must verify from the runtime. No human text is rewritten. Syn's separate
product MVP forbidden-write ceiling is unchanged.

Gaps requiring separately reviewed Syn-only typed routes: milestone resource
creation/update (issue_write can attach an existing ID); PR creation is via
the signed issue-first publisher, not stock create_pull_request; inline review
comments, thread resolution and comment replies/edit/delete require canonical
review/comment ownership and parent-PR proofs; auto-merge needs a typed route.
Actions log deletion is deliberately excluded. Pinned stock exposes release
reads but no release write, and no general check/status mutation endpoint.
Do not claim full coverage until those routes are reviewed. Administration
permission is absent from the App and would need an explicit owner grant if
truly required; no product-Syn mutation authority is implied.
