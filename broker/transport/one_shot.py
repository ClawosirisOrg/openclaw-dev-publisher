"""Inert, offline one-shot Git transport protocol model.

No Git subprocess, network adapter, issuer, authorization verifier or live
entrypoint exists here. Every injectable callback is a TEST FIXTURE, not an
authority boundary. A trusted deployment must select and pin its own remote;
this synthetic remote cannot be replaced by candidate/request data.
"""

from dataclasses import dataclass
import os
import re
import select
import stat
import time

REMOTE = "https://git.example.invalid/fixture/repo.git"
MAIN = "refs/heads/main"
PREFLIGHT_LIMIT = 10.0
TOKEN_LIMIT = 4096
OID = re.compile(r"[0-9a-f]{40}\Z")
BRANCH = re.compile(r"dev-syn/[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")


class UncertainPush(RuntimeError):
    """The push was attempted; do not retry, delete or assert creation."""


@dataclass(frozen=True)
class Outcome:
    sha: str
    branch: str
    base: str
    acknowledged: bool
    readback_checked: bool
    main_at_readback: str
    stale: bool


def _request(sha, branch, base):
    if not all(type(value) is str and OID.fullmatch(value) for value in (sha, base)):
        raise ValueError("invalid object ID")
    if (type(branch) is not str or not BRANCH.fullmatch(branch)
            or ".." in branch or branch.endswith((".", ".lock"))
            or "//" in branch):
        raise ValueError("invalid branch")


def read_token_fd(fd, *, timeout=10.0):
    """Read one complete FIFO frame to EOF, bounded by size and deadline; close FD."""
    try:
        if type(fd) is not int or fd < 0 or not stat.S_ISFIFO(os.fstat(fd).st_mode):
            raise ValueError("invalid token pipe")
        deadline = time.monotonic() + timeout
        parts = []
        size = 0
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select([fd], [], [], remaining)[0]:
                raise ValueError("token pipe timeout")
            chunk = os.read(fd, TOKEN_LIMIT + 1 - size)
            if not chunk:
                break
            size += len(chunk)
            if size > TOKEN_LIMIT:
                raise ValueError("invalid token")
            parts.append(chunk)
        token = b"".join(parts)
        if not token or not re.fullmatch(rb"[!-~]+", token):
            raise ValueError("invalid token")
        return token
    finally:
        if type(fd) is int and fd >= 0:
            os.close(fd)


def _main(call):
    raw = call("ls-remote", "--exit-code", REMOTE, MAIN)
    if type(raw) is not bytes or not re.fullmatch(
            rb"[0-9a-f]{40}\trefs/heads/main\n", raw):
        raise ValueError("invalid main observation")
    return raw[:40].decode("ascii")


def _branch(call, ref):
    raw = call("ls-remote", REMOTE, ref)
    if type(raw) is not bytes or (raw and not re.fullmatch(
            rb"[0-9a-f]{40}\t" + re.escape(ref.encode()) + rb"\n", raw)):
        raise ValueError("invalid branch observation")
    return raw[:40].decode("ascii") if raw else None


def _create_once(call, sha, branch, base, clock):
    """One absent-ref lease. Final main check is bounded but NOT an atomic CAS."""
    _request(sha, branch, base)
    ref = "refs/heads/" + branch
    if _main(call) != base:
        raise ValueError("main drift")
    if _branch(call, ref) is not None:  # equal OID also means existing
        raise ValueError("branch exists")
    started = clock()
    if _main(call) != base:
        raise ValueError("main drift")
    elapsed = clock() - started
    if not 0 <= elapsed <= PREFLIGHT_LIMIT:
        raise ValueError("main preflight expired")
    # No main lease exists. The absent-target lease prevents overwriting even
    # if another writer creates the same SHA between observation and push.
    try:
        response = call("push", "--porcelain", "--no-verify", "--no-follow-tags",
                        "--force-with-lease=" + ref + ":", REMOTE, sha + ":" + ref)
        expected = b"*\t" + sha.encode() + b":" + ref.encode() + b"\t[new branch]"
        # Git --porcelain emits a remote header, one status line, and Done.
        # Match the fixed remote and the sole created ref byte-for-byte.
        acknowledged = (b"To " + REMOTE.encode("ascii") + b"\n"
                        + expected + b"\nDone\n")
        if type(response) is not bytes or response != acknowledged:
            raise ValueError("unacknowledged create")
        if _branch(call, ref) != sha:
            raise ValueError("create readback mismatch")
        observed_main = _main(call)
    except Exception:
        raise UncertainPush("push attempted; inspect separately, never retry") from None
    return Outcome(sha, branch, base, True, True, observed_main, observed_main != base)


def exercise_fixture(sha, branch, base, *, verify_authorization, issue_fd,
                     git_call, revoke, clock=time.monotonic):
    """Offline fixture seam, never a callable live publisher.

    Verification is separate and precedes issuance. The caller supplies all
    fake callbacks: their honesty, trust, isolation and one-use nature cannot
    be established here. No token is accepted as an argument or returned.
    """
    _request(sha, branch, base)
    if verify_authorization() is not True:
        raise ValueError("authorization denied")
    try:
        fd = issue_fd()  # issuer callback must be distinct from verification
        token = read_token_fd(fd)  # closes even on invalid/timeout
        def call(*args):
            if args[0] not in ("ls-remote", "push") or REMOTE not in args:
                raise ValueError("unsupported fixture Git operation")
            # Memory-only fixture token; no argv, URL, env, file or log adapter.
            try:
                return git_call(token, *args)
            except Exception:
                raise ValueError("fixture Git operation failed") from None
        return _create_once(call, sha, branch, base, clock)
    finally:
        revoke()  # issuer revokes its lease even for invalid frames and failed pushes


def inspect_uncertain_fixture(sha, branch, base, *, read_only_call):
    """Separate read-only inspection; never upgrades uncertainty to an ack."""
    _request(sha, branch, base)
    ref = "refs/heads/" + branch
    try:
        observed = _branch(read_only_call, ref)
    except ValueError:
        observed = "invalid"
    main = _main(read_only_call)
    return {"acknowledged": False,
            "ref_state": "absent" if observed is None else
                         "exact" if observed == sha else "different_or_invalid",
            "main_at_readback": main, "stale": main != base}


def main(*_args, **_kwargs):
    raise RuntimeError("transport CLI and live publication are disabled")


if __name__ == "__main__":
    main()
