"""Fixture-callable, disabled-by-default, fact-only object handoff.

An external coordinator must authenticate invocation and base, pin image/UID/mounts,
ensure an empty protected exclusive handoff, and discard it on ANY failure.
This component copies no source config, refs, hooks or index. No token, signer
initiation, network or publication operation exists here.
"""
import hashlib
import os
import re
import stat
from . import verifier

MAX_BYTES = 512 * 1024 * 1024
MAX_ENTRIES = 100_000
DIR = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
FILE = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
CREATE = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
FANOUT = re.compile(r"[0-9a-f]{2}\Z")
LOOSE = re.compile(r"[0-9a-f]{38}\Z")
PACK = re.compile(r"pack-[0-9a-f]{40}\.(?:idx|pack)\Z")


def main(*_args):
    raise RuntimeError("handoff entrypoint disabled: authenticated coordinator and isolation unproven")


def directory(parent, name):
    fd = os.open(name, DIR, dir_fd=parent)
    if not stat.S_ISDIR(os.fstat(fd).st_mode):
        os.close(fd)
        raise ValueError("unsafe directory")
    return fd


def names(fd, budget):
    entries = []
    with os.scandir(fd) as scan:
        for entry in scan:
            budget[1] += 1
            if budget[1] > MAX_ENTRIES:
                raise ValueError("object entry count")
            entries.append(entry.name)
    return sorted(entries)


def new_file(fd, name, data):
    output = os.open(name, CREATE, 0o600, dir_fd=fd)
    try:
        offset = 0
        while offset < len(data):
            written = os.write(output, data[offset:])
            if written <= 0:
                raise OSError("short metadata write")
            offset += written
        os.fsync(output)
    finally:
        os.close(output)


def copy_file(source, target, name, budget):
    inp = os.open(name, FILE, dir_fd=source)
    try:
        before = os.fstat(inp)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise ValueError("special or hardlinked object")
        if before.st_size > MAX_BYTES - budget[0]:
            raise ValueError("oversize objects")
        out = os.open(name, CREATE, 0o600, dir_fd=target)
        digest = hashlib.sha256()
        length = 0
        try:
            while True:
                block = os.read(inp, min(65536, MAX_BYTES - budget[0] + 1))
                if not block:
                    break
                budget[0] += len(block)
                length += len(block)
                if budget[0] > MAX_BYTES:
                    raise ValueError("oversize objects")
                digest.update(block)
                view = memoryview(block)
                while view:
                    written = os.write(out, view)
                    if written <= 0:
                        raise OSError("short object write")
                    view = view[written:]
            os.fsync(out)
        finally:
            os.close(out)
        after = os.fstat(inp)
        stable = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        if stable(before) != stable(after) or length != before.st_size:
            raise ValueError("source object changed during copy")
        return length, digest.digest()
    finally:
        os.close(inp)


def copy_objects(source, target):
    budget = [0, 0]
    manifest = hashlib.sha256()
    for name in names(source, budget):
        if name not in ("pack", "info") and not FANOUT.fullmatch(name):
            raise ValueError("object directory shape")
        child = directory(source, name)
        try:
            os.mkdir(name, 0o700, dir_fd=target)
            dest = directory(target, name)
            try:
                for item in names(child, budget):
                    if name == "info" or not (PACK.fullmatch(item) if name == "pack" else LOOSE.fullmatch(item)):
                        raise ValueError("object metadata or name forbidden")
                    length, digest = copy_file(child, dest, item, budget)
                    path = (name + "/" + item).encode("ascii")
                    manifest.update(len(path).to_bytes(2, "big") + path +
                                    length.to_bytes(8, "big") + digest)
            finally:
                os.close(dest)
        finally:
            os.close(child)
    return budget[0], budget[1], manifest.hexdigest()


def capture(source_root, handoff_root, invocation, config, *, verify=verifier.verify_graph):
    """Offline fixture seam only; neither path nor invocation is authenticated here.

    No expected_tree parameter: the tree comes solely from verified copied objects.
    Failure leaves a PARTIAL handoff, which must be discarded by the caller.
    """
    config.__post_init__()
    invocation.validate(config)
    source = os.open(source_root, DIR)
    try:
        output = os.open(handoff_root, DIR)
        try:
            mode = os.fstat(output)
            with os.scandir(output) as scan:
                empty = next(scan, None) is None
            if (not stat.S_ISDIR(mode.st_mode) or mode.st_uid != os.geteuid() or
                    stat.S_IMODE(mode.st_mode) != 0o700 or not empty):
                raise ValueError("handoff must be private, owned and empty")
            checkout = directory(source, config.source_component)
            try:
                dotgit = directory(checkout, ".git")
                try:
                    objects = directory(dotgit, "objects")
                    try:
                        os.mkdir("store.git", 0o700, dir_fd=output)
                        store = directory(output, "store.git")
                        try:
                            new_file(store, "HEAD", b"ref: refs/heads/main\n")
                            new_file(store, "config", b"[core]\n\tbare = true\n")
                            os.mkdir("refs", 0o700, dir_fd=store)
                            os.mkdir("objects", 0o700, dir_fd=store)
                            destination = directory(store, "objects")
                            try:
                                size, count, digest = copy_objects(objects, destination)
                            finally:
                                os.close(destination)
                            # Verify by pinned descriptor path, not the mutable handoff pathname.
                            path = f"/proc/{os.getpid()}/fd/{store}"
                            tree = verify(path, invocation, config, output)
                        finally:
                            os.close(store)
                    finally:
                        os.close(objects)
                finally:
                    os.close(dotgit)
            finally:
                os.close(checkout)
            # Facts only; not a credential or authorization to publish.
            return {"sha": invocation.sha, "branch": invocation.branch,
                    "base": invocation.base, "tree": tree,
                    "fingerprint": config.signer_fingerprint,
                    "object_bytes": size, "object_entries": count,
                    "objects_sha256": digest, "publishable": False,
                    "provenance_authenticated": False}
        finally:
            os.close(output)
    finally:
        os.close(source)


if __name__ == "__main__":
    main()
