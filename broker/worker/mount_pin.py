"""Import-only, nonauthorizing worker-side measurement of a host-pinned stage.

The caller must independently trust the host's device/inode, fixed worker
identity, repository, and ref. A namespace-local mount ID is not host mount
provenance. This does not transfer an FD or a namespace, authenticate a host,
or grant publication or credential access.
"""
from contextlib import ExitStack
import os
import re
import stat

from broker.worker import claim

STAGE_PATH = "/stage"
STAGE_MODE = 0o700
DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_MOUNT_LINE = re.compile(r"mnt_id:[ \t]*([1-9][0-9]{0,19})\Z", re.ASCII)


class MountPinError(ValueError):
    """The stage could not be matched to independent deployment inputs."""


def _mount_id(fd):
    # Read fdinfo for the *open* descriptor, not mountinfo for a pathname.
    with open(f"/proc/self/fdinfo/{fd}", encoding="ascii") as info:
        data = info.read(16385)
    if len(data) > 16384:
        raise MountPinError("mount identity unavailable")
    values = [_MOUNT_LINE.fullmatch(line) for line in data.splitlines()
              if line.startswith("mnt_id:")]
    if len(values) != 1 or values[0] is None:
        raise MountPinError("mount identity unavailable")
    return int(values[0].group(1))


def _stage(stack):
    # Never resolve a whole pathname: both components are opened as directories
    # with nofollow; ExitStack retains and closes every descriptor on failure.
    root = os.open("/", DIR_FLAGS)
    stack.callback(os.close, root)
    fd = os.open("stage", DIR_FLAGS, dir_fd=root)
    stack.callback(os.close, fd)
    return fd


def _identity(fd, dev, ino, uid, gid):
    info = os.fstat(fd)
    if (not stat.S_ISDIR(info.st_mode) or
            (info.st_dev, info.st_ino, info.st_uid, info.st_gid,
             stat.S_IMODE(info.st_mode)) != (dev, ino, uid, gid, STAGE_MODE)):
        raise MountPinError("stage identity mismatch")
    mount_id = _mount_id(fd)
    if type(mount_id) is not int or mount_id <= 0:
        raise MountPinError("mount identity unavailable")
    return mount_id


def build_mount_pin(stage_dev, stage_ino, *, worker_uid, worker_gid, repository, ref):
    """Measure /stage against trusted host inputs; return only a claim pin.

    Inputs must come from a trusted deployment channel, never an agent frame or
    receipt. The returned pin remains nonauthorizing; the caller still needs
    separate FD/namespace provenance and a final effect guard.
    """
    if (any(type(v) is not int or v < 0 for v in
            (stage_dev, stage_ino, worker_uid, worker_gid)) or
            worker_uid != os.geteuid() or worker_gid != os.getegid() or
            not claim._valid_repo(repository) or not claim._valid_ref(ref)):
        raise MountPinError("invalid trusted deployment inputs")
    try:
        with ExitStack() as stack:
            first = _stage(stack)
            mount_id = _identity(first, stage_dev, stage_ino, worker_uid, worker_gid)
            second = _stage(stack)
            if (_identity(second, stage_dev, stage_ino, worker_uid, worker_gid) != mount_id or
                    _identity(first, stage_dev, stage_ino, worker_uid, worker_gid) != mount_id or
                    _identity(second, stage_dev, stage_ino, worker_uid, worker_gid) != mount_id):
                raise MountPinError("stage mount changed")
        return claim.DeploymentPin(STAGE_PATH, stage_dev, stage_ino, mount_id,
                                   worker_uid, repository, ref)
    except (OSError, UnicodeError) as exc:
        raise MountPinError("stage measurement unavailable") from exc


def main(*_args, **_kwargs):
    raise RuntimeError("mount pin CLI disabled")


if __name__ == "__main__":
    main()
