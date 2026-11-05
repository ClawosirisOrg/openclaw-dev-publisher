"""Offline fake-I/O tests for the disabled, nonauthorizing stage pin."""
import io
import os
import stat
from types import SimpleNamespace
import unittest
from unittest import mock

from broker.worker import claim, mount_pin

REPO = "example.invalid/demo"
REF = "refs/heads/main"


def stage(*, dev=12, ino=34, uid=None, gid=None, mode=0o700):
    return SimpleNamespace(st_dev=dev, st_ino=ino,
                           st_uid=os.geteuid() if uid is None else uid,
                           st_gid=os.getegid() if gid is None else gid,
                           st_mode=stat.S_IFDIR | mode)


class FakeIO:
    def __init__(self):
        self.stages = {11: stage(), 13: stage()}
        self.mounts = {11: 47, 13: 47}
        self.opens = []
        self.closed = []
        self.fail_open = None

    def open(self, name, flags, *, dir_fd=None):
        expected = [("/", None, 10), ("stage", 10, 11),
                    ("/", None, 12), ("stage", 12, 13)]
        index = len(self.opens)
        assert flags == mount_pin.DIR_FLAGS
        assert (name, dir_fd) == expected[index][:2]
        self.opens.append((name, flags, dir_fd))
        if self.fail_open == index:
            raise OSError(40, "synthetic symlink or unavailable directory")
        return expected[index][2]

    def fstat(self, fd):
        return self.stages[fd]

    def close(self, fd):
        self.closed.append(fd)

    def mount_id(self, fd):
        value = self.mounts[fd]
        if isinstance(value, Exception):
            raise value
        return value

    def run(self):
        with mock.patch.object(mount_pin.os, "open", side_effect=self.open), \
             mock.patch.object(mount_pin.os, "fstat", side_effect=self.fstat), \
             mock.patch.object(mount_pin.os, "close", side_effect=self.close), \
             mock.patch.object(mount_pin, "_mount_id", side_effect=self.mount_id):
            return mount_pin.build_mount_pin(12, 34, worker_uid=os.geteuid(),
                                             worker_gid=os.getegid(),
                                             repository=REPO, ref=REF)


class MountPinTests(unittest.TestCase):
    def test_success_uses_only_trusted_inputs_and_local_mount_id(self):
        fake = FakeIO()
        result = fake.run()
        self.assertEqual(result, claim.DeploymentPin("/stage", 12, 34, 47,
                                                      os.geteuid(), REPO, REF))
        self.assertEqual(fake.closed, [13, 12, 11, 10])
        self.assertEqual([x[0] for x in fake.opens], ["/", "stage", "/", "stage"])
        with self.assertRaisesRegex(RuntimeError, "disabled"):
            mount_pin.main()

    def test_bad_trusted_inputs_fail_before_io(self):
        valid = dict(worker_uid=os.geteuid(), worker_gid=os.getegid(),
                     repository=REPO, ref=REF)
        variants = [(True, 34, valid), (-1, 34, valid), (12, "34", valid),
                    (12, 34, dict(valid, worker_uid=os.geteuid() + 1)),
                    (12, 34, dict(valid, worker_gid=os.getegid() + 1)),
                    (12, 34, dict(valid, repository="other/../repo")),
                    (12, 34, dict(valid, ref="refs/heads/other"))]
        for dev, ino, values in variants:
            with self.subTest(dev=dev, ino=ino, values=values):
                with mock.patch.object(mount_pin.os, "open", side_effect=AssertionError("I/O")):
                    with self.assertRaises(mount_pin.MountPinError):
                        mount_pin.build_mount_pin(dev, ino, **values)

    def test_symlink_and_open_error_close_prior_descriptors(self):
        for failed, closed in ((0, []), (1, [10]), (2, [11, 10]),
                               (3, [12, 11, 10])):
            fake = FakeIO()
            fake.fail_open = failed
            with self.subTest(failed=failed), self.assertRaises(mount_pin.MountPinError):
                fake.run()
            self.assertEqual(fake.closed, closed)

    def test_replacement_owner_mode_and_mount_swap(self):
        changes = (lambda f: f.stages.__setitem__(11, stage(dev=13)),
                   lambda f: f.stages.__setitem__(13, stage(ino=35)),
                   lambda f: f.stages.__setitem__(11, stage(uid=os.geteuid() + 1)),
                   lambda f: f.stages.__setitem__(13, stage(gid=os.getegid() + 1)),
                   lambda f: f.stages.__setitem__(13, stage(mode=0o755)),
                   lambda f: f.stages.__setitem__(13, SimpleNamespace(
                       st_dev=12, st_ino=34, st_uid=os.geteuid(),
                       st_gid=os.getegid(), st_mode=stat.S_IFREG | 0o700)),
                   lambda f: f.mounts.__setitem__(13, 48),
                   lambda f: f.mounts.__setitem__(11, 0),
                   lambda f: f.mounts.__setitem__(11, True),
                   lambda f: f.mounts.__setitem__(11, OSError(2, "fdinfo absent")))
        for change in changes:
            fake = FakeIO()
            change(fake)
            with self.subTest(change=change), self.assertRaises(mount_pin.MountPinError):
                fake.run()
            self.assertEqual(set(fake.closed), set((10, 11) if len(fake.opens) < 4 else (10, 11, 12, 13)))

    def test_mutation_after_first_measurement_is_detected(self):
        fake = FakeIO()
        original = fake.fstat
        count = 0
        def changing(fd):
            nonlocal count
            count += 1
            if count == 3:
                fake.stages[11] = stage(ino=99)
            return original(fd)
        fake.fstat = changing
        with self.assertRaises(mount_pin.MountPinError):
            fake.run()
        self.assertEqual(fake.closed, [13, 12, 11, 10])

    def test_fdinfo_missing_duplicate_malformed_or_unreadable(self):
        valid = "pos:\t0\nflags:\t0\nmnt_id:\t47\n"
        for content in ("", "mnt_id: 0\n", "mnt_id: -2\n",
                        "mnt_id: abc\n", "mnt_id: 47\nmnt_id: 47\n",
                        "mnt_id: 47 trailing\n", "mnt_id: " + "9" * 21 + "\n",
                        "x" * 16385):
            with self.subTest(content=content[:40]), \
                 mock.patch("builtins.open", return_value=io.StringIO(content)):
                with self.assertRaises(mount_pin.MountPinError):
                    mount_pin._mount_id(11)
        with mock.patch("builtins.open", return_value=io.StringIO(valid)) as opened:
            self.assertEqual(mount_pin._mount_id(11), 47)
            opened.assert_called_once_with("/proc/self/fdinfo/11", encoding="ascii")
        with mock.patch("builtins.open", side_effect=FileNotFoundError):
            fake = FakeIO()
            with mock.patch.object(mount_pin, "_mount_id", wraps=mount_pin._mount_id):
                fake.mount_id = mount_pin._mount_id
                with self.assertRaises(mount_pin.MountPinError):
                    fake.run()


if __name__ == "__main__":
    unittest.main()
