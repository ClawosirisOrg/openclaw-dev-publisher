"""Offline, public-safe one-use worker claim. No live entrypoint or authority to publish.

The context JSON and random IDs are NOT authentication. The issuer must be a
trusted Gateway holding a private one-way pipe and a live final invocation
assertion; deployment pins must be supplied independently of candidate input.
A separate final guard is required before any effect. This module has none.
"""
from dataclasses import dataclass
import json
import os
import re
import select
import stat
import time

MAX_BODY = 1024
TIMEOUT = 5.0
DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
CREATE_FLAGS = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
KEYS = ("version", "transactionId", "repository", "ref", "base", "sha",
        "branch", "model", "thinking", "thinkingSource", "claimId")
SHA = re.compile(r"[0-9a-f]{40}\Z")
ID = re.compile(r"[0-9a-f]{32}\Z")
BRANCH = re.compile(r"dev-syn/[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
MODEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/+:-]{0,127}\Z")
PART = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,99}\Z")
BASE_REF = "refs/heads/main"
THINKING = frozenset(("off", "minimal", "low", "medium", "high", "xhigh"))
MARKER = ".claim"


@dataclass(frozen=True)
class DeploymentPin:
    """Deploy-only inputs; never construct from the pipe or agent request."""
    stage_path: str
    stage_dev: int
    stage_ino: int
    stage_mnt_id: int
    worker_uid: int
    repository: str
    ref: str


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate claim field")
        result[key] = value
    return result


def _valid_ref(ref):
    return type(ref) is str and ref == BASE_REF


def _valid_repo(repository):
    if type(repository) is not str:
        return False
    parts = repository.split("/")
    return len(parts) == 2 and all(PART.fullmatch(p) and p not in (".", "..") for p in parts)


def _validate(body, pin):
    if type(body) is not dict or tuple(body) != KEYS:
        raise ValueError("invalid claim schema")
    if (type(body["version"]) is not int or body["version"] != 1 or
            not all(type(body[k]) is str for k in KEYS[1:]) or
            not ID.fullmatch(body["transactionId"]) or
            not ID.fullmatch(body["claimId"]) or
            body["claimId"] != body["transactionId"] or
            not _valid_repo(body["repository"]) or not _valid_ref(body["ref"]) or
            body["repository"] != pin.repository or body["ref"] != pin.ref or
            not SHA.fullmatch(body["base"]) or not SHA.fullmatch(body["sha"]) or
            body["base"] == body["sha"] or
            not BRANCH.fullmatch(body["branch"]) or
            not MODEL.fullmatch(body["model"]) or
            body["thinking"] not in THINKING or
            body["thinkingSource"] != "agent_attested"):
        raise ValueError("invalid claim context")


def _read_exact(fd, count, deadline):
    parts = []
    while count:
        remaining = deadline - time.monotonic()
        if remaining <= 0 or not select.select([fd], [], [], remaining)[0]:
            raise ValueError("claim pipe timeout")
        block = os.read(fd, count)
        if not block:
            raise ValueError("truncated claim frame")
        parts.append(block)
        count -= len(block)
    return b"".join(parts)


def read_frame(fd, pin):
    """Consume exactly one bounded FIFO frame to EOF; always close the descriptor."""
    try:
        if type(fd) is not int or fd < 0 or not stat.S_ISFIFO(os.fstat(fd).st_mode):
            raise ValueError("private pipe required")
        deadline = time.monotonic() + TIMEOUT
        size = int.from_bytes(_read_exact(fd, 4, deadline), "big")
        if not 0 < size <= MAX_BODY:
            raise ValueError("oversized claim frame")
        raw = _read_exact(fd, size, deadline)
        remaining = deadline - time.monotonic()
        if remaining <= 0 or not select.select([fd], [], [], remaining)[0]:
            raise ValueError("claim pipe timeout")
        if os.read(fd, 1):
            raise ValueError("trailing claim frame bytes")
        try:
            body = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs,
                              parse_constant=lambda _: (_ for _ in ()).throw(ValueError("invalid constant")))
            _validate(body, pin)
            canonical = json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            if raw != canonical:
                raise ValueError("noncanonical claim frame")
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise ValueError("invalid claim frame") from exc
        return body
    finally:
        if type(fd) is int and fd >= 0:
            os.close(fd)


def _mount_id(fd):
    # Linux fdinfo identifies the mount, including bind mounts with the same st_dev.
    with open(f"/proc/self/fdinfo/{fd}", "r", encoding="ascii") as info:
        matches = [line[7:].strip() for line in info if line.startswith("mnt_id:")]
    if len(matches) != 1 or not matches[0].isdigit():
        raise ValueError("stage mount identity unavailable")
    return int(matches[0])


def _check_stage(fd, pin):
    current = os.fstat(fd)
    if (not stat.S_ISDIR(current.st_mode) or current.st_uid != pin.worker_uid or
            stat.S_IMODE(current.st_mode) != 0o700 or
            (current.st_dev, current.st_ino, _mount_id(fd)) !=
            (pin.stage_dev, pin.stage_ino, pin.stage_mnt_id)):
        raise ValueError("stage pin mismatch")


def _open_stage(pin):
    path = pin.stage_path
    if (type(path) is not str or not path.startswith("/") or path == "/" or
            any(part in ("", ".", "..") for part in path.split("/")[1:])):
        raise ValueError("invalid deploy stage path")
    fd = os.open("/", DIR_FLAGS)
    try:
        for part in path.split("/")[1:]:
            child = os.open(part, DIR_FLAGS, dir_fd=fd)
            os.close(fd)
            fd = child
        _check_stage(fd, pin)
        return fd
    except BaseException:
        os.close(fd)
        raise


def _write_all(fd, content):
    view = memoryview(content)
    while view:
        count = os.write(fd, view)
        if count <= 0:
            raise OSError("short claim marker write")
        view = view[count:]


def claim_once(context_fd, deploy):
    """Fixture-callable claim; marker is never removed, including on failure.

    An exclusive, initially empty, protected stage must be dedicated to one
    invocation. The host must quarantine that stage on any ambiguous crash,
    especially before directory fsync can make the marker durable; it must
    never allocate a fresh stage for a retry of the same invocation. A same-UID
    actor able to delete the marker is outside this module's trust boundary.
    Success is a non-authorizing receipt, not a publication permit.
    """
    if type(deploy) is not DeploymentPin or type(deploy.worker_uid) is not int or \
            deploy.worker_uid < 0 or deploy.worker_uid != os.geteuid() or \
            any(type(v) is not int or v < 0 for v in
                (deploy.stage_dev, deploy.stage_ino, deploy.stage_mnt_id)) or \
            not _valid_repo(deploy.repository) or not _valid_ref(deploy.ref):
        # Own the read FD even when trusted deployment setup is invalid.
        if type(context_fd) is int and context_fd >= 0:
            os.close(context_fd)
        raise ValueError("invalid deployment pin or worker EUID")
    body = read_frame(context_fd, deploy)
    stage = _open_stage(deploy)
    try:
        with os.scandir(stage) as scan:
            if next(scan, None) is not None:
                raise ValueError("stage not empty or claim replay")
        # Fixed name, not the claim ID: any attempt consumes the entire stage.
        marker = os.open(MARKER, CREATE_FLAGS, 0o600, dir_fd=stage)
        try:
            _write_all(marker, (body["claimId"] + "\n" + body["transactionId"] + "\n").encode("ascii"))
            os.fsync(marker)
        finally:
            os.close(marker)
        os.fsync(stage)
        # A pathname replacement cannot turn the old pinned inode into a permit.
        reopened = _open_stage(deploy)
        try:
            if os.fstat(reopened).st_ino != os.fstat(stage).st_ino:
                raise ValueError("stage changed")
        finally:
            os.close(reopened)
        return {"claimed": True, "claimId": body["claimId"], "transactionId": body["transactionId"],
                "repository": body["repository"], "ref": body["ref"],
                "sha": body["sha"], "base": body["base"], "branch": body["branch"],
                "model": body["model"], "thinking": body["thinking"],
                "thinking_source": body["thinkingSource"], "publishable": False}
    finally:
        os.close(stage)


def main(*_args, **_kwargs):
    raise RuntimeError("claim entrypoint disabled: private Gateway pipe and final guard unproven")


if __name__ == "__main__":
    main()
