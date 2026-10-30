# Offline worker prototype (disabled)

Both main() functions reject invocation. The fixture-only handoff.capture() accepts a source root, protected empty handoff root, immutable deployment configuration, and an invocation expectation for offline testing; none is authenticated by this module. Do not route agent-controlled values or paths directly to it.

A future separately reviewed coordinator must authenticate invocation and remote base, supply trusted runtime/model provenance, load and pin deployment config and public signer key, lock image/UID/mounts, prove exclusive ownership of the private handoff inode, and discard the entire handoff on any failure. A caller-provided SHA, branch, model, thinking label, or repository is not proof of origin. No candidate-supplied expected tree is accepted. This is object-only inspection, not a clean-worktree or source ownership check.

The handoff copies bounded loose/packed Git objects using nofollow FD-relative reads into a private sterile store; it rejects alternates and other object metadata. The verifier checks strict object closure, exact direct parent, one-new-commit relation, pinned SSH signature, exact final trailers without duplicate/confusable attribution lines, and derives the tree from verified objects. It emits non-publishable facts only. There is no token, network transport, signer operation, Podman call, GitHub write or publication operation in this module. Tests generate disposable synthetic fixture keys and local Git objects offline.

Run: PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s broker/tests/worker -p test_*.py
