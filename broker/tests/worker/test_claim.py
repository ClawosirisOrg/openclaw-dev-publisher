"""Offline one-use claim fixtures; synthetic IDs only, no live entrypoint."""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from broker.worker import claim


BODY = {
    "version": 1, "transactionId": "1" * 32, "repository": "example.invalid/demo",
    "ref": "refs/heads/main", "base": "a" * 40, "sha": "b" * 40,
    "branch": "dev-syn/fixture", "model": "fixture/model", "thinking": "off",
    "thinkingSource": "agent_attested", "claimId": "1" * 32,
}


def frame(body=BODY):
    raw = json.dumps(body, separators=(",", ":")).encode()
    return len(raw).to_bytes(4, "big") + raw


def pipe(data):
    reader, writer = os.pipe()
    try:
        os.write(writer, data)
    finally:
        os.close(writer)
    return reader


class ClaimTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.stage = self.root / "stage"
        self.stage.mkdir(mode=0o700)
        fd = os.open(self.stage, claim.DIR_FLAGS)
        try:
            st = os.fstat(fd)
            self.pin = claim.DeploymentPin(str(self.stage), st.st_dev, st.st_ino,
                                           claim._mount_id(fd), os.geteuid(),
                                           BODY["repository"], BODY["ref"])
        finally:
            os.close(fd)

    def run_claim(self, data=None, pin=None):
        fd = pipe(frame() if data is None else data)
        return claim.claim_once(fd, self.pin if pin is None else pin)

    def test_one_use_and_concurrent_claims(self):
        with ThreadPoolExecutor(max_workers=2) as pool:
            outcomes = list(pool.map(lambda _: self._attempt(), range(2)))
        self.assertEqual(sorted(outcomes), ["claimed", "rejected"])
        marker = self.stage / claim.MARKER
        self.assertEqual(marker.read_text(), BODY["claimId"] + "\n" + BODY["transactionId"] + "\n")
        self.assertEqual(marker.stat().st_mode & 0o777, 0o600)
        changed = dict(BODY, claimId="e" * 32, transactionId="e" * 32)
        with self.assertRaisesRegex(ValueError, "replay"):
            self.run_claim(frame(changed))
        with self.assertRaisesRegex(RuntimeError, "disabled"):
            claim.main()

    def _attempt(self):
        try:
            receipt = self.run_claim()
            self.assertFalse(receipt["publishable"])
            self.assertEqual(receipt["sha"], BODY["sha"])
            self.assertEqual(receipt["base"], BODY["base"])
            self.assertEqual(receipt["model"], BODY["model"])
            self.assertEqual(receipt["thinking_source"], "agent_attested")
            return "claimed"
        except (ValueError, FileExistsError):
            return "rejected"

    def test_truncated_oversized_and_trailing(self):
        for data in (b"", b"\0\0", b"\0\0\0\x04ab", b"\0\0\x04\x01",
                     b"\0\0\0\0", frame() + b"x"):
            with self.subTest(data=data[:8]), self.assertRaises(ValueError):
                self.run_claim(data)
        self.assertEqual(list(self.stage.iterdir()), [])
        reader, writer = os.pipe()
        try:
            os.write(writer, frame()[:5])
            with mock.patch.object(claim, "TIMEOUT", 0.001):
                with self.assertRaisesRegex(ValueError, "timeout"):
                    claim.claim_once(reader, self.pin)
            with self.assertRaises(OSError):
                os.fstat(reader)
        finally:
            os.close(writer)
        with tempfile.TemporaryFile() as file:
            fd = os.dup(file.fileno())
            with self.assertRaisesRegex(ValueError, "pipe"):
                claim.claim_once(fd, self.pin)
            with self.assertRaises(OSError):
                os.fstat(fd)

    def test_exact_schema_and_canonical_encoding(self):
        variants = [dict(BODY, extra="anything"), {k: v for k, v in BODY.items() if k != "model"},
                    dict(BODY, claimId="chosen-by-agent"), dict(BODY, claimId="2" * 32),
                    dict(BODY, transactionId="bad"),
                    dict(BODY, repository="other/repo"), dict(BODY, ref="refs/heads/other"),
                    dict(BODY, thinkingSource="gateway"), dict(BODY, version=True),
                    dict(BODY, branch="dev-syn/../escape"), dict(BODY, sha=BODY["base"])]
        for body in variants:
            with self.subTest(body=body), self.assertRaises(ValueError):
                self.run_claim(frame(body))
        raw = frame()
        with self.assertRaises(ValueError):
            self.run_claim(raw[:4] + raw[4:].replace(b'"model":', b'"model":"duplicate","model":'))
        noncanonical = json.dumps(BODY, indent=1).encode()
        with self.assertRaisesRegex(ValueError, "noncanonical"):
            self.run_claim(len(noncanonical).to_bytes(4, "big") + noncanonical)
        self.assertEqual(list(self.stage.iterdir()), [])

    def test_symlink_and_stage_swap(self):
        original = self.stage
        moved = self.root / "moved"
        original.rename(moved)
        original.symlink_to(moved, target_is_directory=True)
        with self.assertRaises(OSError):
            self.run_claim()
        self.assertEqual(list(moved.iterdir()), [])
        original.unlink()
        moved.rename(original)
        opener = claim._open_stage
        calls = 0
        def swap(pin):
            nonlocal calls
            calls += 1
            if calls == 2:
                original.rename(moved)
                original.mkdir(mode=0o700)
            return opener(pin)
        with mock.patch.object(claim, "_open_stage", side_effect=swap):
            with self.assertRaises(ValueError):
                self.run_claim()
        self.assertEqual(calls, 2)
        self.assertTrue((moved / claim.MARKER).exists())
        self.assertEqual(list(original.iterdir()), [])
        with self.assertRaisesRegex(ValueError, "pin mismatch"):
            self.run_claim()

    def test_permissions_ownership_and_pins(self):
        self.stage.chmod(0o755)
        with self.assertRaisesRegex(ValueError, "pin mismatch"):
            self.run_claim()
        self.stage.chmod(0o700)
        for pin in (replace(self.pin, stage_dev=self.pin.stage_dev + 1),
                    replace(self.pin, stage_ino=self.pin.stage_ino + 1),
                    replace(self.pin, stage_mnt_id=self.pin.stage_mnt_id + 1),
                    replace(self.pin, worker_uid=os.geteuid() + 1)):
            with self.subTest(pin=pin), self.assertRaises(ValueError):
                self.run_claim(pin=pin)
        alien = replace(self.pin, worker_uid=os.geteuid() + 1)
        with mock.patch.object(claim.os, "geteuid", return_value=alien.worker_uid):
            with self.assertRaisesRegex(ValueError, "pin mismatch"):
                self.run_claim(pin=alien)
        self.assertEqual(list(self.stage.iterdir()), [])

    def test_preexisting_symlink_marker_is_not_followed(self):
        outside = self.root / "outside"
        outside.write_text("unchanged")
        self.stage.joinpath(claim.MARKER).symlink_to(outside)
        with self.assertRaisesRegex(ValueError, "replay"):
            self.run_claim()
        self.assertEqual(outside.read_text(), "unchanged")

    def test_failure_after_exclusive_create_never_unclaims(self):
        original = claim.os.fsync
        calls = 0
        def failure(fd):
            nonlocal calls
            calls += 1
            if calls == 1:
                raise OSError("synthetic fsync failure")
            return original(fd)
        with mock.patch.object(claim.os, "fsync", side_effect=failure):
            with self.assertRaisesRegex(OSError, "synthetic"):
                self.run_claim()
        self.assertTrue((self.stage / claim.MARKER).exists())
        with self.assertRaisesRegex(ValueError, "replay"):
            self.run_claim()


if __name__ == "__main__":
    unittest.main()
