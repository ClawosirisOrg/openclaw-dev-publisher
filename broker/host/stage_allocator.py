"""Disabled host-side stage seam: no paths, credentials, containers, or activation.

The parent dirfd and AttemptLedger are supplied by trusted host code. A failed
invocation is never retried; no failure removes a directory. This assumes the
service does not change its process umask concurrently with allocation; the
preflight reads Linux /proc without changing the process-wide umask. This
cannot guard against a privileged/same-UID mutator or dishonest filesystem fsync.
"""
import ctypes
import os
import re
import stat
from dataclasses import dataclass, field

from broker.host.attempt_ledger import AttemptLedger, LedgerError

_KEY = re.compile(r'[0-9a-f]{32}\Z', re.ASCII)
_LABEL = re.compile(r'[A-Za-z0-9_-]{1,64}\Z', re.ASCII)


class StageError(RuntimeError):
    """Fail closed; never retry the same invocation key."""


@dataclass(frozen=True)
class StageAllocation:
    key: str
    label: str
    device: int
    inode: int
    _issuer: object = field(repr=False, compare=False)


def _rename_noreplace(parent_fd, source, target):
    """Linux renameat2, without os.rename's overwrite race; fail if absent."""
    libc = ctypes.CDLL(None, use_errno=True)
    rename = libc.renameat2
    rename.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int,
                       ctypes.c_char_p, ctypes.c_uint)
    rename.restype = ctypes.c_int
    if rename(parent_fd, source.encode('ascii'), parent_fd,
              target.encode('ascii'), 1) != 0:  # RENAME_NOREPLACE
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code))


class StageAllocator:
    """Disabled one-process model; the protected parent fd is borrowed."""

    def __init__(self, parent_fd, ledger, *, expected_uid, expected_gid):
        if (type(parent_fd) is not int or parent_fd < 0
                or not isinstance(ledger, AttemptLedger)
                or type(expected_uid) is not int or expected_uid < 0
                or type(expected_gid) is not int or expected_gid < 0):
            raise StageError('invalid trusted boundary')
        self._fd = parent_fd
        self._ledger = ledger
        self._uid = expected_uid
        self._gid = expected_gid
        self._identity = None
        self._pid = os.getpid()
        self._used = set()
        self._allocations = {}
        self._quarantine_started = set()
        self._parent()

    def _parent(self):
        try:
            info = os.fstat(self._fd)
        except OSError as exc:
            raise StageError('invalid parent descriptor') from exc
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != self._uid
                or stat.S_IMODE(info.st_mode) != 0o700 or info.st_nlink < 2):
            raise StageError('unprotected stage parent')
        identity = (info.st_dev, info.st_ino)
        if self._identity is not None and identity != self._identity:
            raise StageError('stage parent inode changed')
        self._identity = identity
        return info

    @staticmethod
    def _check_umask():
        # mkdir(0700) must be reopenable before we spend a marker. Reading
        # proc avoids temporarily altering the process-wide umask in threads.
        try:
            with open('/proc/self/status', encoding='ascii') as status:
                for line in status:
                    if line.startswith('Umask:'):
                        mask = int(line.split(':', 1)[1].strip(), 8)
                        if mask < 0 or mask > 0o777 or mask & 0o700:
                            break
                        return
        except (OSError, ValueError) as exc:
            raise StageError('cannot verify service umask') from exc
        raise StageError('unsafe or unavailable service umask')

    @staticmethod
    def _names(key, label):
        if type(key) is not str or _KEY.fullmatch(key) is None:
            raise StageError('invalid host invocation key')
        if (type(label) is not str or _LABEL.fullmatch(label) is None
                or (label.startswith('q-') and _KEY.fullmatch(label[2:]))):
            raise StageError('invalid or reserved stage label')

    def _child(self, label, expected=None, *, require_empty=True):
        fd = os.open(label, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW |
                     os.O_CLOEXEC, dir_fd=self._fd)
        try:
            info = os.fstat(fd)
            named = os.stat(label, dir_fd=self._fd, follow_symlinks=False)
            identity = (info.st_dev, info.st_ino)
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid != self._uid
                    or info.st_gid != self._gid or stat.S_IMODE(info.st_mode) != 0o700
                    or info.st_dev != self._identity[0]
                    or (named.st_dev, named.st_ino) != identity
                    or (expected is not None and identity != expected)
                    or (require_empty and (info.st_nlink != 2 or os.listdir(fd)))):
                raise StageError('stage directory identity or protection mismatch')
            return identity
        finally:
            os.close(fd)

    def allocate(self, key, label):
        """Reserve and sync allocated+attempted markers before exclusive mkdirat."""
        self._names(key, label)
        if os.getpid() != self._pid or key in self._used:
            raise StageError('invocation cannot be retried or inherited')
        self._parent()
        self._check_umask()  # no key or external directory consumed yet
        self._used.add(key)
        try:
            self._ledger.reserve(key, label)
            self._ledger.mark_attempted(key, label)
            self._parent()
            # mkdirat is inherently exclusive (EEXIST); O_EXCL is not a
            # mkdir flag. Never unlink, including on an ambiguous error.
            os.mkdir(label, 0o700, dir_fd=self._fd)
            fd = os.open(label, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW |
                         os.O_CLOEXEC, dir_fd=self._fd)
            try:
                created = os.fstat(fd)
                named = os.stat(label, dir_fd=self._fd, follow_symlinks=False)
                if (not stat.S_ISDIR(created.st_mode) or
                        (created.st_dev, created.st_ino) != (named.st_dev, named.st_ino)
                        or created.st_dev != self._identity[0]):
                    raise StageError('created stage inode changed')
                os.fchown(fd, self._uid, self._gid)
                os.fchmod(fd, 0o700)
                identity = self._child(label, (created.st_dev, created.st_ino))
                os.fsync(fd)
                os.fsync(self._fd)
                self._parent()
                self._child(label, identity)
            finally:
                os.close(fd)
            allocation = StageAllocation(key, label, *identity, self)
            self._allocations[key] = allocation
            return allocation
        except (OSError, LedgerError, StageError) as exc:
            raise StageError('stage allocation failed; key consumed, preserve any stage') from exc

    def quarantine(self, allocation, *, worker_terminated):
        """Caller asserts termination/detachment; durable marker before rename."""
        if type(worker_terminated) is not bool or not worker_terminated:
            raise StageError('trusted caller must assert worker terminated or detached')
        if (not isinstance(allocation, StageAllocation) or allocation._issuer is not self
                or self._allocations.get(allocation.key) is not allocation
                or os.getpid() != self._pid or allocation.key in self._quarantine_started):
            raise StageError('not an active local allocation')
        self._quarantine_started.add(allocation.key)
        try:
            self._parent()
            self._ledger.quarantine(allocation.key, allocation.label)
            self._parent()
            identity = (allocation.device, allocation.inode)
            self._child(allocation.label, identity, require_empty=False)
            terminal = 'q-' + allocation.key
            _rename_noreplace(self._fd, allocation.label, terminal)
            # Sync even if later verification fails; never attempt rollback.
            os.fsync(self._fd)
            self._parent()
            self._child(terminal, identity, require_empty=False)
            try:
                os.stat(allocation.label, dir_fd=self._fd, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise StageError('source label still present after rename')
            return terminal
        except (OSError, AttributeError, LedgerError, StageError) as exc:
            raise StageError('quarantine uncertain; preserve stage and marker') from exc


def main(*_args, **_kwargs):
    raise RuntimeError('host stage allocator CLI disabled')


if __name__ == '__main__':
    main()
