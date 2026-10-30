#!/usr/bin/python3
"""Private Git askpass child: strict prompts, one-use FD, no CLI credential API."""
import os
import re
import select
import stat
import sys
import time

_REMOTE = re.compile(r"https://github\.com/[A-Za-z0-9][A-Za-z0-9_.-]{0,99}/[A-Za-z0-9][A-Za-z0-9_.-]{0,99}\.git\Z")
_FD = re.compile(r"[0-9]{1,8}\Z")


def _answer(prompt, env, read=os.read, write=os.write):
    """Return only for the two exact Git prompt forms; fail closed otherwise."""
    remote = env.get("BROKER_GIT_PROMPT_URL", "")
    if not _REMOTE.fullmatch(remote) or type(prompt) is not str:
        return False
    if prompt == "Username for 'https://github.com': ":
        write(1, b"x-access-token\n")
        return True
    if prompt != "Password for 'https://x-access-token@github.com': ":
        return False
    raw_fd = env.get("BROKER_GIT_TOKEN_FD", "")
    if not _FD.fullmatch(raw_fd):
        return False
    fd = int(raw_fd)
    try:
        if not stat.S_ISFIFO(os.fstat(fd).st_mode):
            return False
        deadline = time.monotonic() + 10.0
        data = bytearray()
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select([fd], [], [], remaining)[0]:
                return False
            chunk = read(fd, 4097 - len(data))
            if not chunk:
                break
            data.extend(chunk)
            if len(data) > 4096:
                return False
        if not data or any(b < 33 or b > 126 for b in data):
            return False
        write(1, data + b"\n")
        return True
    except (OSError, ValueError):
        return False
    finally:
        try:
            os.close(fd)
        except OSError:
            pass


def main(argv=None, env=None):
    argv = sys.argv if argv is None else argv
    env = os.environ if env is None else env
    if len(argv) != 2 or not _answer(argv[1], env):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
