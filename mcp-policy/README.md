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
No `--toolsets` or dynamic tool names. It exposes exactly those 20 tools even if
the child lists additional tools; calls to anything else are denied.

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
Child failure/cancel/timeout produces a sanitized error and process cleanup.
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
