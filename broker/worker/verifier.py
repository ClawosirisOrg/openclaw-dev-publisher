"""Offline verification of a private object copy; never authorizes publication.

DeployConfig and Invocation MUST be supplied by a separately trusted coordinator.
Validation here is syntactic/cryptographic, not authentication of that channel,
model, thinking level, remote base, mount ownership or image provenance.
No agent-supplied expected tree is accepted. All object results are facts only.
"""
import base64
from dataclasses import dataclass
import hashlib
import os
import re
import stat
import subprocess
import select
import time
import unicodedata

OID = re.compile(r"[0-9a-f]{40}\Z")
NAME = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
REPO = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")
MODEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/+:-]{0,127}\Z")
FINGERPRINT = re.compile(r"SHA256:[A-Za-z0-9+/]{43}\Z")
THINKING = frozenset(("off", "minimal", "low", "medium", "high", "xhigh"))
ATTRIBUTION = re.compile(r"^\s*(?:agent|model|thinking|bot-owner)\s*:", re.I)
MAX_OUTPUT = 1024 * 1024
ENV = {"PATH": "/usr/bin:/bin", "HOME": "/nonexistent", "XDG_CONFIG_HOME": "/nonexistent",
       "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
       "GIT_CONFIG_SYSTEM": "/dev/null", "GIT_CONFIG_COUNT": "0",
       "GIT_TERMINAL_PROMPT": "0", "GIT_ALLOW_PROTOCOL": "file",
       "GIT_PROTOCOL_FROM_USER": "0", "GIT_NO_REPLACE_OBJECTS": "1",
       "GIT_OPTIONAL_LOCKS": "0", "GIT_LFS_SKIP_SMUDGE": "1"}


def match(value, pattern, label):
    if type(value) is not str or not pattern.fullmatch(value):
        raise ValueError("invalid " + label)
    return value


@dataclass(frozen=True)
class DeployConfig:
    """Immutable trusted deployment inputs; no public identity or key is baked in."""
    repository: str
    base_ref: str
    agent: str
    bot_owner: str
    branch_prefix: str
    source_component: str
    signer_fingerprint: str
    signer_public_key: bytes

    def __post_init__(self):
        match(self.repository, REPO, "repository")
        if self.base_ref != "refs/heads/main":
            raise ValueError("base ref")
        match(self.agent, NAME, "agent")
        match(self.bot_owner, NAME, "bot owner")
        match(self.branch_prefix, NAME, "branch prefix")
        match(self.source_component, NAME, "source component")
        match(self.signer_fingerprint, FINGERPRINT, "signer fingerprint")
        key = self.signer_public_key
        if type(key) is not bytes or not 32 < len(key) < 4096 or b"\n" in key.strip(b"\n"):
            raise ValueError("signer key")
        fields = key.strip().split()
        if len(fields) not in (2, 3) or fields[0] != b"ssh-ed25519":
            raise ValueError("signer key format")
        try:
            raw = base64.b64decode(fields[1], validate=True)
        except (ValueError, base64.binascii.Error) as exc:
            raise ValueError("signer key encoding") from exc
        if (len(raw) != 51 or raw[:15] != b"\x00\x00\x00\x0bssh-ed25519" or
                raw[15:19] != b"\x00\x00\x00\x20"):
            raise ValueError("signer key structure")
        fingerprint = "SHA256:" + base64.b64encode(hashlib.sha256(raw).digest()).decode().rstrip("=")
        if fingerprint != self.signer_fingerprint:
            raise ValueError("signer pin mismatch")
        if len(fields) == 3 and (not fields[2].isascii() or len(fields[2]) > 128):
            raise ValueError("signer comment")


@dataclass(frozen=True)
class Invocation:
    """Expected identity and runtime labels, NOT proof of their provenance."""
    sha: str
    branch: str
    base: str
    model: str
    thinking: str

    def validate(self, config):
        match(self.sha, OID, "candidate sha")
        match(self.base, OID, "base sha")
        if self.sha == self.base:
            raise ValueError("candidate equals base")
        if (type(self.branch) is not str or
                not self.branch.startswith(config.branch_prefix + "/") or
                not NAME.fullmatch(self.branch[len(config.branch_prefix) + 1:])):
            raise ValueError("branch")
        match(self.model, MODEL, "model")
        if type(self.thinking) is not str or self.thinking not in THINKING:
            raise ValueError("thinking")


def command(args, limit=MAX_OUTPUT):
    """Bound stdout and time even for hostile object input; never inherit Git env."""
    with subprocess.Popen(args, env=ENV, stdin=subprocess.DEVNULL,
                          stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                          close_fds=True) as process:
        output = bytearray()
        deadline = time.monotonic() + 30
        try:
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not select.select([process.stdout], [], [], remaining)[0]:
                    raise ValueError("offline git timeout")
                chunk = os.read(process.stdout.fileno(), min(65536, limit + 1 - len(output)))
                if not chunk:
                    break
                output.extend(chunk)
                if len(output) > limit:
                    raise ValueError("oversize git output")
            process.wait(timeout=max(0.001, deadline - time.monotonic()))
        except BaseException:
            process.kill()
            process.communicate(timeout=5)
            raise
        if process.returncode:
            raise ValueError("offline git check failed")
        return bytes(output)


def git(store, *args, limit=MAX_OUTPUT):
    return command(["git", "-c", "core.hooksPath=/dev/null",
                    "-c", "core.fsmonitor=false", "-c", "credential.helper=",
                    "--git-dir=" + str(store), *args], limit)


def object_id(store, spec):
    return match(git(store, "rev-parse", "--verify", spec, limit=100).decode("ascii").strip(), OID, "object")


def _attribution(line):
    normalized = unicodedata.normalize("NFKC", line).casefold()
    normalized = "".join(c for c in normalized if unicodedata.category(c) != "Cf")
    return bool(ATTRIBUTION.match(normalized))


def verify_graph(store, invocation, config, scratch_fd):
    """Return verified tree OID, independently derived from copied Git objects."""
    config.__post_init__()
    invocation.validate(config)
    sha, base = invocation.sha, invocation.base
    # The store contains only copied object files, fixed config and empty refs.
    if object_id(store, sha + "^{commit}") != sha or object_id(store, base + "^{commit}") != base:
        raise ValueError("commit identity")
    raw = git(store, "cat-file", "commit", sha)
    if b"\n\n" not in raw:
        raise ValueError("commit message")
    headers, message = raw.split(b"\n\n", 1)
    parents = [line[7:].decode("ascii") for line in headers.split(b"\n")
               if line.startswith(b"parent ")]
    if parents != [base]:
        raise ValueError("direct parent")
    if git(store, "rev-list", base + ".." + sha, limit=100).strip() != sha.encode():
        raise ValueError("not exactly one new commit")
    git(store, "fsck", "--strict", "--no-reflogs", "--no-progress", limit=4096)
    # Allowed-signers is created exclusively in the protected handoff, never read
    # from source. Strict O_EXCL also prevents accepting a preexisting injection.
    signers = b"candidate " + config.signer_public_key.strip() + b"\n"
    fd = os.open("allowed_signers", os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                 os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=scratch_fd)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ValueError("signers file")
        offset = 0
        while offset < len(signers):
            offset += os.write(fd, signers[offset:])
        os.fsync(fd)
    finally:
        os.close(fd)
    # The procfd path pins the handoff directory even if its path is renamed.
    signers_path = f"/proc/{os.getpid()}/fd/{scratch_fd}/allowed_signers"
    git(store, "-c", "gpg.format=ssh", "-c", "gpg.ssh.program=/usr/bin/ssh-keygen",
        "-c", "gpg.ssh.allowedSignersFile=" + signers_path,
        "-c", "gpg.ssh.revocationFile=/dev/null", "verify-commit", sha, limit=4096)
    try:
        lines = message.decode("utf-8", "strict").rstrip("\n").split("\n")
    except UnicodeDecodeError as exc:
        raise ValueError("commit message encoding") from exc
    expected = ["Agent: " + config.agent, "Model: " + invocation.model,
                "Thinking: " + invocation.thinking, "Bot-Owner: @" + config.bot_owner]
    if (len(lines) < 6 or lines[-5] != "" or lines[-4:] != expected or
            sum(_attribution(line) for line in lines) != 4):
        raise ValueError("attribution")
    return object_id(store, sha + "^{tree}")


def main(*_args):
    raise RuntimeError("worker entrypoint disabled: authenticated invocation and isolation unproven")


if __name__ == "__main__":
    main()
