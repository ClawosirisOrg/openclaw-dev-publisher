# Repository contribution rules

This public prototype is not an operational publisher. Do not add credentials,
private configuration, real container IDs, internal hostnames, or signing keys
to source, tests, documentation, commits, or issue/PR content. Tests should
remain fake-IO and offline. Publication requires separate owner review.

For agent-authored GitHub issue bodies, PR bodies, comments and reviews, end
the body with the following attribution, using the runtime that authored the
substantive content (do not infer defaults):

```text
Agent: <exact agent name>
Model: <exact effective runtime model>
Thinking: <exact effective runtime thinking level>
Bot-Owner: @llunved
```

Agent-created commits must carry the same four lines as Git trailers, after a
blank line. Inspect the final body/commit before submission. For upstream
contributions, file a corresponding issue first and link it in the PR. If
effective model or thinking cannot be established, stop rather than guess.
