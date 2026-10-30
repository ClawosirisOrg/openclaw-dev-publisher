"""Dormant deployment-owned Git adapter. No CLI, issuer, or agent activation."""
from dataclasses import dataclass
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import time
from broker.transport.one_shot import read_token_fd

_HOST = "github.com"  # pinned public HTTPS host; no checked-in repository identity
_ROOT = Path(__file__).resolve().parents[2]
_ASKPASS = Path(__file__).with_name("askpass.py")
_PART = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,99}\Z")
_SHA = re.compile(r"[0-9a-f]{40}\Z")
_BRANCH = re.compile(r"dev-syn/[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")


class GitAdapterError(RuntimeError):
    """Never carries Git output, environment, or bearer data."""


@dataclass(frozen=True)
class _DeployTarget:
    """Trusted deploy-only data, never parsed from a candidate or agent request."""
    owner: str
    name: str
    store: str

    def __post_init__(self):
        if (type(self.owner) is not str or type(self.name) is not str
                or not all(_PART.fullmatch(x) and x not in (".", "..")
                            and not x.endswith(".lock") for x in (self.owner, self.name))):
            raise GitAdapterError("invalid deployment target")
        if type(self.store) is not str or not Path(self.store).is_absolute():
            raise GitAdapterError("invalid deployment store")
        path = Path(self.store)
        try:
            if path == _ROOT or _ROOT in path.parents:
                raise GitAdapterError("invalid deployment store")
            current = Path("/")
            for part in path.parts[1:]:
                current /= part
                if stat.S_ISLNK(current.lstat().st_mode):
                    raise GitAdapterError("invalid deployment store")
            if not path.is_dir():
                raise GitAdapterError("invalid deployment store")
        except (OSError, ValueError):
            raise GitAdapterError("invalid deployment store") from None

    @property
    def remote(self):
        return f"https://{_HOST}/{self.owner}/{self.name}.git"


def _argv(target, operation, ref, sha=None):
    if type(target) is not _DeployTarget:
        raise GitAdapterError("invalid deployment target")
    if operation == "main" and ref == "refs/heads/main" and sha is None:
        command = ["ls-remote", "--exit-code", target.remote, ref]
    elif (type(ref) is str and ref.startswith("refs/heads/")
          and _BRANCH.fullmatch(ref[len("refs/heads/"):])
          and ".." not in ref and not ref.endswith((".", ".lock"))):
        if operation == "branch" and sha is None:
            command = ["ls-remote", target.remote, ref]
        elif operation == "create" and type(sha) is str and _SHA.fullmatch(sha):
            command = ["push", "--porcelain", "--no-verify", "--no-follow-tags",
                       "--force-with-lease=" + ref + ":", target.remote, sha + ":" + ref]
        else:
            raise GitAdapterError("invalid Git operation")
    else:
        raise GitAdapterError("invalid Git operation")
    return ["/usr/bin/git", "-c", "core.hooksPath=/dev/null",
            "-c", "credential.helper=", "-c", "credential.useHttpPath=false",
            "-c", "http.followRedirects=false", "-c", "http.proxy=",
            "-c", "protocol.allow=never", "-c", "protocol.https.allow=always",
            "--git-dir=" + target.store, *command]


def _collect(process, deadline):
    """Hard bounds on time, stdout and stderr, even for a streaming child."""
    output = bytearray()
    errors = 0
    with selectors.DefaultSelector() as selector:
        for stream in (process.stdout, process.stderr):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ)
        while selector.get_map():
            left = deadline - time.monotonic()
            if left <= 0:
                raise GitAdapterError("Git command failed")
            for key, _ in selector.select(left):
                data = os.read(key.fileobj.fileno(), 4096)
                if not data:
                    selector.unregister(key.fileobj)
                elif key.fileobj is process.stdout:
                    output.extend(data)
                    if len(output) > 8192:
                        raise GitAdapterError("Git command failed")
                else:
                    errors += len(data)
                    if errors > 2048:
                        raise GitAdapterError("Git command failed")
    left = deadline - time.monotonic()
    if left <= 0 or process.wait(timeout=left) != 0:
        raise GitAdapterError("Git command failed")
    return bytes(output)


def _run(target, operation, ref, token_fd, *, sha=None):
    """Internal one-command seam; caller supplies a fresh private pipe per call.

    Deployer must authorize before issuing and revoke in finally. This module
    cannot authenticate the caller or guarantee a protected process boundary.
    """
    try:
        argv = _argv(target, operation, ref, sha)
    except GitAdapterError:
        if type(token_fd) is int and token_fd >= 0:
            os.close(token_fd)
        raise
    env = {"PATH": "/usr/bin:/bin", "HOME": "/nonexistent",
           "XDG_CONFIG_HOME": "/nonexistent", "LC_ALL": "C",
           "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
           "GIT_TERMINAL_PROMPT": "0", "GIT_ALLOW_PROTOCOL": "https",
           "GIT_ASKPASS": str(_ASKPASS), "BROKER_GIT_PROMPT_URL": target.remote}
    token = bytearray()
    reader = writer = process = None
    succeeded = False
    try:
        token.extend(read_token_fd(token_fd))  # reads to EOF, closes source FD
        reader, writer = os.pipe2(os.O_CLOEXEC)
        offset = 0
        while offset < len(token):
            offset += os.write(writer, token[offset:])
        os.close(writer)
        writer = None
        env["BROKER_GIT_TOKEN_FD"] = str(reader)  # descriptor number, not token
        process = subprocess.Popen(argv, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   env=env, close_fds=True, pass_fds=(reader,),
                                   start_new_session=True)
        result = _collect(process, time.monotonic() + 90.0)
        succeeded = True
        return result
    except (OSError, ValueError, subprocess.SubprocessError, GitAdapterError):
        raise GitAdapterError("Git command failed") from None
    finally:
        for i in range(len(token)):
            token[i] = 0
        if writer is not None:
            os.close(writer)
        if reader is not None:
            os.close(reader)
        if process is not None:
            if not succeeded:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            if process.poll() is None:
                process.wait()
            process.stdout.close()
            process.stderr.close()


def main(*_args, **_kwargs):
    raise RuntimeError("Git transport CLI disabled")


if __name__ == "__main__":
    main()
