"""Offline tempdir and fault-injection tests; never touch a protected host stage."""
import concurrent.futures
import os
import pathlib
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from broker.host.attempt_ledger import AttemptLedger
from broker.host import stage_allocator as mod

KEY = '0123456789abcdef0123456789abcdef'
LABEL = 'host-stage-a'


class StageAllocatorTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = pathlib.Path(temp.name)
        self.parent = self.root / 'stages'
        self.ledger_dir = self.root / 'ledger'
        self.parent.mkdir(mode=0o700)
        self.ledger_dir.mkdir(mode=0o700)
        self.fd = os.open(self.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        self.ledger_fd = os.open(self.ledger_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        self.addCleanup(os.close, self.ledger_fd)
        self.addCleanup(os.close, self.fd)
        self.ledger = AttemptLedger(self.ledger_fd, expected_uid=os.getuid())
        self.allocator = self.new_allocator()

    def new_allocator(self):
        return mod.StageAllocator(self.fd, self.ledger, expected_uid=os.getuid(),
                                  expected_gid=os.getgid())

    def test_sync_before_mkdir_and_quarantine_marker_before_rename(self):
        events = []
        real_mkdir = mod.os.mkdir
        real_rename = mod._rename_noreplace
        real_fsync = mod.os.fsync
        real_reserve = self.ledger.reserve
        real_attempt = self.ledger.mark_attempted
        real_quarantine = self.ledger.quarantine
        def reserve(*args):
            result = real_reserve(*args)
            events.append('reserve')
            return result
        def attempt(*args):
            result = real_attempt(*args)
            events.append('attempt')
            return result
        def mkdir(*args, **kwargs):
            events.append('mkdir')
            return real_mkdir(*args, **kwargs)
        def fsync(fd):
            if fd == self.fd:
                events.append('parent-fsync')
            return real_fsync(fd)
        def quarantine(*args):
            result = real_quarantine(*args)
            events.append('marker')
            return result
        def rename(*args):
            events.append('rename')
            return real_rename(*args)
        with (mock.patch.object(self.ledger, 'reserve', side_effect=reserve),
              mock.patch.object(self.ledger, 'mark_attempted', side_effect=attempt),
              mock.patch.object(self.ledger, 'quarantine', side_effect=quarantine),
              mock.patch.object(mod.os, 'mkdir', side_effect=mkdir),
              mock.patch.object(mod.os, 'fsync', side_effect=fsync),
              mock.patch.object(mod, '_rename_noreplace', side_effect=rename)):
            stage = self.allocator.allocate(KEY, LABEL)
            self.assertEqual(self.allocator.quarantine(stage, worker_terminated=True), 'q-' + KEY)
        self.assertLess(events.index('reserve'), events.index('attempt'))
        self.assertLess(events.index('attempt'), events.index('mkdir'))
        self.assertLess(events.index('marker'), events.index('rename'))
        self.assertGreater(events.index('parent-fsync'), events.index('mkdir'))
        self.assertEqual(self.ledger.state(KEY), 'quarantined')
        self.assertFalse((self.parent / LABEL).exists())
        terminal = self.parent / ('q-' + KEY)
        self.assertEqual(terminal.stat().st_ino, stage.inode)
        self.assertEqual(stat.S_IMODE(terminal.stat().st_mode), 0o700)
        self.assertEqual(terminal.stat().st_uid, os.getuid())
        self.assertEqual(terminal.stat().st_gid, os.getgid())
        with self.assertRaises(mod.StageError):
            self.allocator.quarantine(stage, worker_terminated=True)

    def test_crash_before_mkdir_or_after_mkdir_never_retries(self):
        with mock.patch.object(mod.os, 'mkdir', side_effect=OSError('crash before mkdir')):
            with self.assertRaises(mod.StageError):
                self.allocator.allocate(KEY, LABEL)
        self.assertEqual(self.ledger.state(KEY), 'attempted')
        with self.assertRaises(mod.StageError):
            self.new_allocator().allocate(KEY, LABEL)
        key2 = 'f' * 32
        real_fsync = mod.os.fsync
        def fail_child(fd):
            if (stat.S_ISDIR(os.fstat(fd).st_mode)
                    and fd not in (self.fd, self.ledger_fd)):
                raise OSError('crash after mkdir')
            return real_fsync(fd)
        with mock.patch.object(mod.os, 'fsync', side_effect=fail_child):
            with self.assertRaises(mod.StageError):
                self.allocator.allocate(key2, 'stage-b')
        self.assertTrue((self.parent / 'stage-b').is_dir())
        self.assertEqual(self.ledger.state(key2), 'attempted')
        with self.assertRaises(mod.StageError):
            self.new_allocator().allocate(key2, 'stage-b')

    def test_mark_attempted_failure_forbids_mkdir(self):
        with (mock.patch.object(self.ledger, 'mark_attempted', side_effect=OSError('sync failed')),
              mock.patch.object(mod.os, 'mkdir') as mkdir):
            with self.assertRaises(mod.StageError):
                self.allocator.allocate(KEY, LABEL)
            mkdir.assert_not_called()
        self.assertEqual(self.ledger.state(KEY), 'allocated')

    def test_restrictive_umask_rejected_before_reservation_or_mkdir(self):
        script = '''
import os
import pathlib
import sys
from broker.host.attempt_ledger import AttemptLedger
from broker.host.stage_allocator import StageAllocator, StageError

parent, ledger_path = map(pathlib.Path, sys.argv[1:3])
key, label = sys.argv[3:5]
parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
ledger_fd = os.open(ledger_path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
try:
    ledger = AttemptLedger(ledger_fd, expected_uid=os.getuid())
    allocator = StageAllocator(parent_fd, ledger, expected_uid=os.getuid(),
                               expected_gid=os.getgid())
    old_umask = os.umask(0o777)
    try:
        try:
            allocator.allocate(key, label)
        except StageError:
            pass
        else:
            raise AssertionError("unsafe umask accepted")
        assert not (parent / label).exists()
        assert not list(ledger_path.iterdir()), "key consumed before umask rejection"
    finally:
        os.umask(old_umask)
    assert allocator.allocate(key, label).label == label
    assert ledger.state(key) == "attempted"
finally:
    os.close(ledger_fd)
    os.close(parent_fd)
'''
        result = subprocess.run([sys.executable, '-B', '-c', script,
                                 str(self.parent), str(self.ledger_dir), KEY, LABEL],
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_parent_owner_mode_identity_and_no_symlink(self):
        with self.assertRaises(mod.StageError):
            mod.StageAllocator(self.fd, self.ledger, expected_uid=os.getuid() + 1,
                               expected_gid=os.getgid())
        self.parent.chmod(0o750)
        with mock.patch.object(mod.os, 'mkdir') as mkdir:
            with self.assertRaises(mod.StageError):
                self.allocator.allocate(KEY, LABEL)
            mkdir.assert_not_called()
        self.parent.chmod(0o700)
        other = self.new_allocator()
        (self.parent / LABEL).symlink_to(self.root)
        with self.assertRaises(mod.StageError):
            other.allocate(KEY, LABEL)
        self.assertEqual(self.ledger.state(KEY), 'attempted')
        self.assertTrue((self.parent / LABEL).is_symlink())
        with self.assertRaises(mod.StageError):
            other.allocate(KEY, LABEL)

    def test_pinned_parent_not_replaced_path(self):
        moved = self.root / 'old-stages'
        self.parent.rename(moved)
        self.parent.mkdir(mode=0o700)
        self.allocator.allocate(KEY, LABEL)
        self.assertTrue((moved / LABEL).is_dir())
        self.assertFalse((self.parent / LABEL).exists())

    def test_child_fsync_failure_keeps_directory(self):
        real_fsync = mod.os.fsync
        def fail_stage(fd):
            if stat.S_ISDIR(os.fstat(fd).st_mode) and fd != self.fd and fd != self.ledger_fd:
                raise OSError('stage sync failed')
            return real_fsync(fd)
        with mock.patch.object(mod.os, 'fsync', side_effect=fail_stage):
            with self.assertRaises(mod.StageError):
                self.allocator.allocate(KEY, LABEL)
        self.assertTrue((self.parent / LABEL).is_dir())
        self.assertEqual(self.ledger.state(KEY), 'attempted')

    def test_quarantine_requires_assertion_and_preserves_ambiguous_rename(self):
        stage = self.allocator.allocate(KEY, LABEL)
        with self.assertRaises(mod.StageError):
            self.allocator.quarantine(stage, worker_terminated=False)
        with mock.patch.object(mod, '_rename_noreplace', side_effect=OSError('uncertain rename')):
            with self.assertRaises(mod.StageError):
                self.allocator.quarantine(stage, worker_terminated=True)
        self.assertTrue((self.parent / LABEL).is_dir())
        self.assertEqual(self.ledger.state(KEY), 'quarantined')
        with self.assertRaises(mod.StageError):
            self.allocator.quarantine(stage, worker_terminated=True)

    def test_populated_stage_quarantines_without_deletion(self):
        stage = self.allocator.allocate(KEY, LABEL)
        (self.parent / LABEL / 'worker-output').write_text('retained')
        (self.parent / LABEL / 'subdir').mkdir()
        terminal = self.allocator.quarantine(stage, worker_terminated=True)
        self.assertEqual((self.parent / terminal / 'worker-output').read_text(), 'retained')
        self.assertTrue((self.parent / terminal / 'subdir').is_dir())

    def test_quarantine_parent_fsync_failure_preserves_rename(self):
        stage = self.allocator.allocate(KEY, LABEL)
        real_fsync = mod.os.fsync
        def fail_parent(fd):
            if fd == self.fd:
                raise OSError('uncertain rename durability')
            return real_fsync(fd)
        with mock.patch.object(mod.os, 'fsync', side_effect=fail_parent):
            with self.assertRaises(mod.StageError):
                self.allocator.quarantine(stage, worker_terminated=True)
        self.assertEqual(self.ledger.state(KEY), 'quarantined')
        self.assertTrue((self.parent / ('q-' + KEY)).is_dir())
        with self.assertRaises(mod.StageError):
            self.allocator.quarantine(stage, worker_terminated=True)

    def test_quarantine_detects_swapped_inode_and_existing_destination(self):
        stage = self.allocator.allocate(KEY, LABEL)
        (self.parent / LABEL).rename(self.parent / 'moved')
        (self.parent / LABEL).mkdir(mode=0o700)
        with self.assertRaises(mod.StageError):
            self.allocator.quarantine(stage, worker_terminated=True)
        self.assertEqual(self.ledger.state(KEY), 'quarantined')
        self.assertTrue((self.parent / LABEL).is_dir())
        self.assertTrue((self.parent / 'moved').is_dir())
        key2 = 'a' * 32
        stage2 = self.allocator.allocate(key2, 'stage-b')
        (self.parent / ('q-' + key2)).mkdir(mode=0o700)
        with self.assertRaises(mod.StageError):
            self.allocator.quarantine(stage2, worker_terminated=True)
        self.assertTrue((self.parent / 'stage-b').is_dir())
        self.assertTrue((self.parent / ('q-' + key2)).is_dir())

    def test_post_mkdir_symlink_race_preserves_original(self):
        real_mkdir = mod.os.mkdir
        def swap(name, mode, *, dir_fd):
            real_mkdir(name, mode, dir_fd=dir_fd)
            os.rename(name, 'saved-stage', src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
            os.symlink('saved-stage', name, dir_fd=dir_fd)
        with mock.patch.object(mod.os, 'mkdir', side_effect=swap):
            with self.assertRaises(mod.StageError):
                self.allocator.allocate(KEY, LABEL)
        self.assertTrue((self.parent / LABEL).is_symlink())
        self.assertTrue((self.parent / 'saved-stage').is_dir())
        self.assertEqual(self.ledger.state(KEY), 'attempted')

    def test_distinct_keys_same_label_consume_loser(self):
        self.allocator.allocate(KEY, LABEL)
        other_key = 'a' * 32
        with self.assertRaises(mod.StageError):
            self.new_allocator().allocate(other_key, LABEL)
        self.assertEqual(self.ledger.state(other_key), 'attempted')
        self.assertEqual(len(list(self.parent.iterdir())), 1)

    def test_parallel_duplicate_key_and_label_one_winner(self):
        def allocate(_):
            try:
                return self.new_allocator().allocate(KEY, LABEL)
            except mod.StageError:
                return None
        with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
            outcomes = list(pool.map(allocate, range(24)))
        self.assertEqual(sum(x is not None for x in outcomes), 1)
        self.assertEqual(self.ledger.state(KEY), 'attempted')
        self.assertEqual(len(list(self.parent.iterdir())), 1)

    def test_invalid_names_and_disabled_cli(self):
        for label in ('../escape', 'q-' + KEY, ''):
            with self.assertRaises(mod.StageError):
                self.allocator.allocate(KEY, label)
        with self.assertRaises(mod.StageError):
            self.allocator.allocate('../' + KEY, LABEL)
        self.assertIsNone(self.ledger.state(KEY))
        with self.assertRaisesRegex(RuntimeError, 'disabled'):
            mod.main()
        result = subprocess.run([sys.executable, '-B', '-m', 'broker.host.stage_allocator'],
                                capture_output=True, text=True, timeout=10)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('CLI disabled', result.stderr)


if __name__ == '__main__':
    unittest.main()
