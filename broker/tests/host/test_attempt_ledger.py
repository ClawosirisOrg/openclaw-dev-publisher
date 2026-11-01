"""Offline fake-stage tests of protected-dirfd, one-use attempt markers."""

import concurrent.futures
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from broker.host import attempt_ledger as mod


KEY = '0123456789abcdef0123456789abcdef'
STAGE = 'fake-stage-a'


class AttemptLedgerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)
        self.path = self.root / 'protected'
        self.path.mkdir(mode=0o700)
        self.fd = os.open(self.path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        self.addCleanup(os.close, self.fd)
        self.ledger = self.restart()

    def restart(self):
        return mod.AttemptLedger(self.fd, expected_uid=os.getuid())

    def test_reserve_attempt_and_reconstruct_after_restart(self):
        self.assertIsNone(self.ledger.state(KEY))
        self.assertEqual(self.ledger.reserve(KEY, STAGE), 'allocated')
        self.assertEqual(self.restart().state(KEY), 'allocated')
        for stage in (STAGE, 'fake-stage-b'):
            with self.assertRaises(mod.LedgerError):
                self.restart().reserve(KEY, stage)
        with self.assertRaises(mod.LedgerError):
            self.restart().mark_attempted(KEY, STAGE)  # restart cannot resume
        self.assertEqual(self.ledger.mark_attempted(KEY, STAGE), 'attempted')
        self.assertEqual(self.restart().state(KEY), 'attempted')
        with self.assertRaises(mod.LedgerError):
            self.restart().mark_attempted(KEY, STAGE)
        self.assertEqual(self.restart().quarantine(KEY, STAGE), 'quarantined')
        self.assertEqual(self.restart().state(KEY), 'quarantined')
        for operation in (lambda: self.restart().reserve(KEY, 'fresh-stage'),
                          lambda: self.restart().mark_attempted(KEY, STAGE),
                          lambda: self.restart().quarantine(KEY, STAGE)):
            with self.assertRaises(mod.LedgerError):
                operation()

    def test_quarantine_unattempted_stage_prevents_fresh_stage_retry(self):
        self.ledger.reserve(KEY, STAGE)
        self.ledger.quarantine(KEY, STAGE)
        self.assertEqual(self.restart().state(KEY), 'quarantined')
        with self.assertRaises(mod.LedgerError):
            self.restart().mark_attempted(KEY, STAGE)
        with self.assertRaises(mod.LedgerError):
            self.restart().reserve(KEY, 'fresh-stage')

    def test_duplicate_reservation_and_failed_quarantine_poison_continuation(self):
        self.ledger.reserve(KEY, STAGE)
        with self.assertRaises(mod.LedgerError):
            self.ledger.reserve(KEY, 'fresh-stage')
        with self.assertRaises(mod.LedgerError):
            self.ledger.mark_attempted(KEY, STAGE)
        self.assertEqual(self.restart().state(KEY), 'allocated')
        with self.assertRaises(mod.LedgerError):
            self.ledger.quarantine(KEY, 'wrong-stage')
        self.assertEqual(self.restart().state(KEY), 'allocated')
        self.assertEqual(self.restart().quarantine(KEY, STAGE), 'quarantined')

    def test_parallel_reservation_one_winner(self):
        def reserve(_):
            try:
                self.restart().reserve(KEY, STAGE)
                return True
            except mod.LedgerError:
                return False
        with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
            outcomes = list(pool.map(reserve, range(32)))
        self.assertEqual(sum(outcomes), 1)
        self.assertEqual(self.restart().state(KEY), 'allocated')

    def test_restrictive_umask_creates_usable_lock_without_normalizing_existing(self):
        script = '''
import os
import pathlib
import stat
import sys
from broker.host.attempt_ledger import AttemptLedger, LedgerError

path = pathlib.Path(sys.argv[1])
fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
try:
    os.umask(0o777)
    ledger = AttemptLedger(fd, expected_uid=os.getuid())
    assert ledger.state(sys.argv[2]) is None
    assert stat.S_IMODE((path / ".lock").stat().st_mode) == 0o600
    assert ledger.reserve(sys.argv[2], sys.argv[3]) == "allocated"
    assert ledger.state(sys.argv[2]) == "allocated"
    assert stat.S_IMODE((path / (sys.argv[2] + ".allocated")).stat().st_mode) == 0o600
    (path / ".lock").chmod(0)
    try:
        ledger.state(sys.argv[2])
    except LedgerError:
        pass
    else:
        raise AssertionError("malformed existing lock accepted")
    assert stat.S_IMODE((path / ".lock").stat().st_mode) == 0
finally:
    os.close(fd)
'''
        result = subprocess.run([sys.executable, '-B', '-c', script,
                                 str(self.path), KEY, STAGE],
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_crash_before_marker_fsync_denies_replay_when_inode_survives(self):
        original = self.ledger._sync_file
        count = 0
        def fail_marker(fd):
            nonlocal count
            count += 1
            if count == 2:  # first call synced the lock inode
                raise OSError('simulated crash before marker fsync')
            return original(fd)
        with mock.patch.object(self.ledger, '_sync_file', side_effect=fail_marker):
            with self.assertRaises(mod.LedgerError):
                self.ledger.reserve(KEY, STAGE)
        self.assertEqual(self.restart().state(KEY), 'allocated')
        with self.assertRaises(mod.LedgerError):
            self.restart().reserve(KEY, 'fresh-stage')

    def test_zero_progress_marker_write_denies_without_retry(self):
        with mock.patch.object(mod.os, 'write', return_value=0):
            with self.assertRaises(mod.LedgerError):
                self.ledger.reserve(KEY, STAGE)
        self.assertEqual(self.restart().state(KEY), 'allocated')
        with self.assertRaises(mod.LedgerError):
            self.restart().reserve(KEY, 'fresh-stage')

    def test_crash_after_marker_fsync_before_directory_fsync(self):
        original = self.ledger._sync_directory
        count = 0
        def fail_second():
            nonlocal count
            count += 1
            if count == 2:
                raise OSError('simulated crash after file fsync')
            return original()
        with mock.patch.object(self.ledger, '_sync_directory', side_effect=fail_second):
            with self.assertRaises(mod.LedgerError):
                self.ledger.reserve(KEY, STAGE)
        self.assertEqual(self.restart().state(KEY), 'allocated')
        with self.assertRaises(mod.LedgerError):
            self.restart().reserve(KEY, STAGE)

    def test_sync_order_and_transition_failure_remain_nonretryable(self):
        calls = []
        real_sync_file = self.ledger._sync_file
        real_sync_dir = self.ledger._sync_directory
        def file_sync(fd):
            calls.append('file')
            real_sync_file(fd)
        def dir_sync():
            calls.append('directory')
            real_sync_dir()
        with (mock.patch.object(self.ledger, '_sync_file', side_effect=file_sync),
              mock.patch.object(self.ledger, '_sync_directory', side_effect=dir_sync)):
            self.ledger.reserve(KEY, STAGE)
        self.assertEqual(calls, ['file', 'directory', 'file', 'directory'])
        with mock.patch.object(self.ledger, '_sync_directory', side_effect=[None, OSError('disk failure')]):
            with self.assertRaises(mod.LedgerError):
                self.ledger.mark_attempted(KEY, STAGE)
        self.assertEqual(self.restart().state(KEY), 'attempted')
        with self.assertRaises(mod.LedgerError):
            self.restart().mark_attempted(KEY, STAGE)
        with self.assertRaises(mod.LedgerError):
            self.restart().reserve(KEY, 'fresh-stage')

    def test_marker_symlink_hardlink_and_path_swap(self):
        outside = self.root / 'unrelated'
        outside.write_text('not a marker')
        (self.path / (KEY + '.allocated')).symlink_to(outside)
        with self.assertRaises(mod.LedgerError):
            self.ledger.state(KEY)
        with self.assertRaises(mod.LedgerError):
            self.ledger.reserve(KEY, STAGE)
        (self.path / (KEY + '.allocated')).unlink()
        os.chmod(outside, 0o600)
        os.link(outside, self.path / (KEY + '.allocated'))
        with self.assertRaises(mod.LedgerError):
            self.ledger.state(KEY)
        (self.path / (KEY + '.allocated')).unlink()
        self.ledger.reserve(KEY, STAGE)
        moved = self.root / 'pinned-original'
        self.path.rename(moved)
        self.path.mkdir(mode=0o700)
        self.assertEqual(self.ledger.state(KEY), 'allocated')  # pinned inode, not swapped pathname
        fresh_fd = os.open(self.path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            self.assertIsNone(mod.AttemptLedger(fresh_fd, expected_uid=os.getuid()).state(KEY))
        finally:
            os.close(fresh_fd)

    def test_wrong_owner_mode_and_invalid_names(self):
        with self.assertRaises(mod.LedgerError):
            mod.AttemptLedger(self.fd, expected_uid=os.getuid() + 1)
        os.chmod(self.path, 0o750)
        with self.assertRaises(mod.LedgerError):
            self.restart()
        with self.assertRaises(mod.LedgerError):
            self.ledger.reserve(KEY, STAGE)
        os.chmod(self.path, 0o700)
        for key in ('../' + KEY, KEY.upper(), KEY + '/escape', 'x' * 32):
            with self.assertRaises(mod.LedgerError):
                self.ledger.reserve(key, STAGE)
        for label in ('../stage', '', 'a/b'):
            with self.assertRaises(mod.LedgerError):
                self.ledger.reserve(KEY, label)
        self.ledger.reserve(KEY, STAGE)
        os.chmod(self.path / (KEY + '.allocated'), 0o644)
        with self.assertRaises(mod.LedgerError):
            self.ledger.state(KEY)
        with self.assertRaises(mod.LedgerError):
            self.ledger.mark_attempted(KEY, STAGE)

    def test_stage_mismatch_and_receipt_cannot_grant_authority(self):
        (self.path / 'receipt.json').write_text('{"state":"attempted"}')
        with self.assertRaises(mod.LedgerError):
            self.ledger.mark_attempted(KEY, STAGE)
        self.ledger.reserve(KEY, STAGE)
        with self.assertRaises(mod.LedgerError):
            self.ledger.mark_attempted(KEY, 'fresh-stage')
        self.assertEqual(self.restart().state(KEY), 'allocated')
        with self.assertRaises(mod.LedgerError):
            self.ledger.mark_attempted(KEY, STAGE)  # wrong-stage failure consumed permit
        self.assertEqual(self.restart().quarantine(KEY, STAGE), 'quarantined')

    def test_cli_unconditionally_disabled(self):
        with self.assertRaisesRegex(RuntimeError, 'disabled'):
            mod.main()
        result = subprocess.run([sys.executable, '-B', str(pathlib.Path(mod.__file__))],
                                capture_output=True, text=True, timeout=10)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('CLI disabled', result.stderr)


if __name__ == '__main__':
    unittest.main()
