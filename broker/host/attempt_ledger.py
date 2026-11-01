"""Disabled, offline host-side attempt ledger model.

The supplied directory descriptor is the authority boundary: it must refer to
an owner-only directory, opened by trusted host code. No path, credential,
container operation or worker identity is accepted. A reservation must be
fully synced BEFORE any external stage creation. Neither a receipt nor the
stored stage label grants permission to perform an external operation.

Markers only accumulate; they are never removed. Existence, not their contents,
prevents reuse. A caller must treat any exception as a permanent denial. This
model cannot detect a privileged actor deleting markers, storage that lies about
fsync, or a crash before the first reservation becomes durable. In that last
case no stage operation may have begun.
"""

import contextlib
import fcntl
import os
import re
import stat


_KEY = re.compile(r'[0-9a-f]{32}\Z', re.ASCII)
_STAGE = re.compile(r'[A-Za-z0-9_-]{1,64}\Z', re.ASCII)
_FLAGS = os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK


class LedgerError(RuntimeError):
    """Fail-closed ledger denial; never retry a failed operation."""


class AttemptLedger:
    """Host-only model; all names are relative to a pinned protected dirfd."""

    def __init__(self, directory_fd, *, expected_uid):
        if type(directory_fd) is not int or directory_fd < 0 or type(expected_uid) is not int or expected_uid < 0:
            raise LedgerError('invalid boundary')
        self._fd = directory_fd  # borrowed, never closed by this object
        self._uid = expected_uid
        self._identity = None
        self._pid = os.getpid()
        self._pending = {}  # process-local one-shot continuation; never restored
        self._check_directory()

    def _check_directory(self):
        try:
            info = os.fstat(self._fd)
        except OSError as exc:
            raise LedgerError('invalid directory descriptor') from exc
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != self._uid
                or stat.S_IMODE(info.st_mode) != 0o700 or info.st_nlink < 2):
            raise LedgerError('unprotected directory')
        identity = (info.st_dev, info.st_ino)
        if self._identity is not None and identity != self._identity:
            raise LedgerError('directory inode changed')
        self._identity = identity

    def _check_file(self, fd):
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != self._uid
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
            raise LedgerError('unprotected marker')
        return info

    def _open_marker(self, name):
        try:
            fd = os.open(name, os.O_RDONLY | _FLAGS, dir_fd=self._fd)
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise LedgerError('unsafe marker') from exc
        try:
            info = self._check_file(fd)
            # Check that the name still denotes this regular inode, not a
            # replaced symlink or a separately opened marker.
            named = os.stat(name, dir_fd=self._fd, follow_symlinks=False)
            if (named.st_dev, named.st_ino) != (info.st_dev, info.st_ino):
                raise LedgerError('marker inode changed')
            return fd
        except BaseException:
            os.close(fd)
            raise

    def _exists(self, name):
        fd = self._open_marker(name)
        if fd is None:
            return False
        os.close(fd)
        return True

    def _sync_file(self, fd):
        os.fsync(fd)

    def _sync_directory(self):
        os.fsync(self._fd)

    def _create(self, name, data=b''):
        # O_EXCL is the linearization point; no unlink on ANY failure.
        try:
            fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _FLAGS,
                         0o600, dir_fd=self._fd)
        except OSError as exc:
            raise LedgerError('reservation already used or marker creation failed') from exc
        try:
            os.fchmod(fd, 0o600)
            self._check_file(fd)
            if data:
                offset = 0
                while offset < len(data):
                    written = os.write(fd, data[offset:])
                    if written <= 0:
                        raise LedgerError('short marker write')
                    offset += written
            self._sync_file(fd)
            self._sync_directory()
            self._check_directory()
        except BaseException as exc:
            raise LedgerError('uncertain marker durability; deny invocation') from exc
        finally:
            os.close(fd)

    @contextlib.contextmanager
    def _locked(self):
        self._check_directory()
        try:
            # Only the exclusive creator may repair the umask-restricted mode.
            # An existing malformed lock is never normalized or replaced.
            try:
                fd = os.open('.lock', os.O_RDWR | os.O_CREAT | os.O_EXCL | _FLAGS,
                             0o600, dir_fd=self._fd)
                created = True
            except FileExistsError:
                fd = os.open('.lock', os.O_RDWR | _FLAGS, dir_fd=self._fd)
                created = False
        except OSError as exc:
            raise LedgerError('unsafe lock') from exc
        try:
            if created:
                info = os.fstat(fd)
                named = os.stat('.lock', dir_fd=self._fd, follow_symlinks=False)
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != self._uid
                        or info.st_nlink != 1
                        or (named.st_dev, named.st_ino) != (info.st_dev, info.st_ino)):
                    raise LedgerError('unsafe new lock inode')
                os.fchmod(fd, 0o600)
            self._check_file(fd)
            fcntl.flock(fd, fcntl.LOCK_EX)
            info = self._check_file(fd)
            named = os.stat('.lock', dir_fd=self._fd, follow_symlinks=False)
            if (named.st_dev, named.st_ino) != (info.st_dev, info.st_ino):
                raise LedgerError('lock inode changed')
            # The lock is durable before any marker mutation; another opener
            # cannot proceed until this process completes the sync.
            self._sync_file(fd)
            self._sync_directory()
            self._check_directory()
            yield
            self._check_directory()
        except OSError as exc:
            raise LedgerError('ledger IO failure') from exc
        finally:
            os.close(fd)  # releases flock; never unlink the lock inode

    @staticmethod
    def _key(key):
        if type(key) is not str or _KEY.fullmatch(key) is None:
            raise LedgerError('invalid host invocation key')
        return key

    @staticmethod
    def _stage(stage_identity):
        if type(stage_identity) is not str or _STAGE.fullmatch(stage_identity) is None:
            raise LedgerError('invalid stage label')
        return stage_identity

    def _status(self, key):
        allocated = self._exists(key + '.allocated')
        attempted = self._exists(key + '.attempted')
        quarantined = self._exists(key + '.quarantined')
        if quarantined or (attempted and not allocated):
            return 'quarantined'
        if attempted:
            return 'attempted'
        if allocated:
            return 'allocated'
        return None

    def state(self, key):
        """Reconstruct conservative state solely from protected marker inodes."""
        key = self._key(key)
        with self._locked():
            return self._status(key)

    def reserve(self, key, stage_identity):
        """Permanently consume key before external stage creation is allowed."""
        key, stage_identity = self._key(key), self._stage(stage_identity)
        # A duplicate reservation call poisons any still-live continuation.
        if self._pending.pop(key, None) is not None:
            raise LedgerError('invocation already reserved')
        with self._locked():
            if self._status(key) is not None:
                raise LedgerError('invocation already reserved')
            # Label is audit-only, never an authorization receipt.
            self._create(key + '.allocated', stage_identity.encode('ascii'))
        self._pending[key] = stage_identity
        return 'allocated'

    def _same_stage(self, key, stage_identity):
        fd = self._open_marker(key + '.allocated')
        if fd is None:
            raise LedgerError('missing reservation')
        try:
            info = os.fstat(fd)
            if info.st_size > 64 or os.read(fd, 65) != stage_identity.encode('ascii'):
                raise LedgerError('stage label mismatch')
        finally:
            os.close(fd)

    def mark_attempted(self, key, stage_identity):
        """Sync attempted marker BEFORE any external operation may be attempted."""
        key, stage_identity = self._key(key), self._stage(stage_identity)
        # A disk reservation is a tombstone, NOT a resumable permit. Even a
        # fully synced allocated state cannot be resumed after process death,
        # fork, failed transition, or another AttemptLedger instance.
        if os.getpid() != self._pid or self._pending.pop(key, None) != stage_identity:
            raise LedgerError('reserved attempt cannot be resumed or retried')
        with self._locked():
            if self._status(key) != 'allocated':
                raise LedgerError('invocation is not solely allocated')
            self._same_stage(key, stage_identity)
            self._create(key + '.attempted')
        return 'attempted'

    def quarantine(self, key, stage_identity):
        """Terminally mark a reserved stage unusable, including after failure."""
        key, stage_identity = self._key(key), self._stage(stage_identity)
        # Even a failed quarantine is terminal for this process's continuation.
        self._pending.pop(key, None)
        with self._locked():
            state = self._status(key)
            if state not in ('allocated', 'attempted'):
                raise LedgerError('invocation not eligible for quarantine')
            self._same_stage(key, stage_identity)
            self._create(key + '.quarantined')
        return 'quarantined'


def main(*_args, **_kwargs):
    raise RuntimeError('host attempt ledger CLI disabled')


if __name__ == '__main__':
    main()
