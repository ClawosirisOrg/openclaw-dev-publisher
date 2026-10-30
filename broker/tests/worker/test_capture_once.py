"""Offline one-claim/one-object-copy orchestration fixtures; no network or tokens."""
from dataclasses import replace
import json
import os
import unittest
from unittest import mock

from broker.tests.worker import test_offline
from broker.worker import claim, handoff, capture_once, verifier


class CaptureTests(unittest.TestCase):
    commit = test_offline.Fixture.commit

    def setUp(self):
        test_offline.Fixture.setUp(self)
        self.stage = self.root / "stage"
        self.stage.mkdir(mode=0o700)
        fd = os.open(self.stage, claim.DIR_FLAGS)
        try:
            st = os.fstat(fd)
            self.deploy = claim.DeploymentPin(str(self.stage), st.st_dev, st.st_ino,
                                              claim._mount_id(fd), os.geteuid(),
                                              self.config.repository, self.config.base_ref)
        finally:
            os.close(fd)
        fd = os.open(self.src, claim.DIR_FLAGS)
        try:
            st = os.fstat(fd)
            self.bind = capture_once.SourceBind(str(self.src), st.st_dev, st.st_ino,
                                                claim._mount_id(fd))
        finally:
            os.close(fd)
        self.body = {"version": 1, "transactionId": "1" * 32,
                     "repository": self.config.repository, "ref": self.config.base_ref,
                     "base": self.base, "sha": self.invocation.sha,
                     "branch": "dev-syn/fixture", "model": self.invocation.model,
                     "thinking": self.invocation.thinking, "thinkingSource": "agent_attested",
                     "claimId": "1" * 32}
        # The trusted branch convention is deploy-only and must match the frame.
        self.config = replace(self.config, branch_prefix="dev-syn")

    def attempt(self, body=None, bind=None, config=None):
        raw = json.dumps(self.body if body is None else body, separators=(",", ":")).encode()
        read, write = os.pipe()
        try:
            os.write(write, len(raw).to_bytes(4, "big") + raw)
        finally:
            os.close(write)
        return capture_once.capture_once(read, self.deploy,
                                         self.bind if bind is None else bind,
                                         self.config if config is None else config)

    def test_one_claim_one_capture_replay_and_no_authority(self):
        real = handoff.capture
        with mock.patch.object(handoff, "capture", wraps=real) as copied:
            facts = self.attempt()
        self.assertEqual(copied.call_count, 1)
        invocation = copied.call_args.args[2]
        self.assertEqual(invocation, verifier.Invocation(self.body["sha"], self.body["branch"],
                                                         self.body["base"], self.body["model"],
                                                         self.body["thinking"]))
        self.assertEqual(facts["capture"]["tree"], test_offline.run("git", "rev-parse", "HEAD^{tree}", cwd=self.repo))
        self.assertFalse(facts["publishable"])
        self.assertFalse(facts["authorization_claimed"])
        self.assertFalse(facts["provenance_authenticated"])
        self.assertFalse(facts["claim"]["publishable"])
        self.assertFalse(facts["capture"]["publishable"])
        self.assertEqual(set(p.name for p in self.stage.iterdir()), {claim.MARKER, capture_once.CHILD})
        self.assertEqual(set(p.name for p in (self.stage / capture_once.CHILD).iterdir()),
                         {"store.git", "allowed_signers"})
        with mock.patch.object(handoff, "capture") as copied:
            with self.assertRaisesRegex(ValueError, "replay"):
                self.attempt()
        copied.assert_not_called()
        with self.assertRaisesRegex(RuntimeError, "disabled"):
            capture_once.main()

    def test_context_substitution_spends_claim_before_capture(self):
        # Claimed context is valid but cannot be silently replaced with the
        # trusted config's expected branch convention or a caller's guess.
        changed = dict(self.body, branch="dev-syn/substituted")
        with mock.patch.object(handoff, "capture", wraps=handoff.capture) as copied:
            with self.assertRaisesRegex(ValueError, "attribution"):
                self.attempt(dict(changed, model="other/model"))
        self.assertEqual(copied.call_count, 1)
        self.assertEqual(copied.call_args.args[2].model, "other/model")
        self.assertTrue((self.stage / claim.MARKER).exists())
        self.assertTrue((self.stage / capture_once.CHILD / "store.git").exists())
        with self.assertRaisesRegex(ValueError, "replay"):
            self.attempt()

    def test_deploy_mismatch_leaves_spent_stage(self):
        with mock.patch.object(handoff, "capture") as copied:
            with self.assertRaisesRegex(ValueError, "deployment mismatch"):
                self.attempt(config=replace(self.config, repository="example.invalid/other"))
        copied.assert_not_called()
        self.assertEqual(set(p.name for p in self.stage.iterdir()), {claim.MARKER})
        with self.assertRaisesRegex(ValueError, "replay"):
            self.attempt()

    def test_invalid_source_bind_spends_claim_and_does_not_copy(self):
        with mock.patch.object(handoff, "capture") as copied:
            with self.assertRaisesRegex(ValueError, "source bind pin mismatch"):
                self.attempt(bind=replace(self.bind, ino=self.bind.ino + 1))
        copied.assert_not_called()
        self.assertTrue((self.stage / claim.MARKER).exists())
        with self.assertRaisesRegex(ValueError, "replay"):
            self.attempt()

    def test_source_symlink_swap_after_claim_fails(self):
        original = capture_once._open_source
        moved = self.root / "moved-source"
        def swap(bind):
            self.src.rename(moved)
            self.src.symlink_to(moved, target_is_directory=True)
            return original(bind)
        with mock.patch.object(capture_once, "_open_source", side_effect=swap):
            with mock.patch.object(handoff, "capture") as copied:
                with self.assertRaises(OSError):
                    self.attempt()
        copied.assert_not_called()
        self.assertTrue((self.stage / claim.MARKER).exists())

    def test_stage_swap_after_claim_fails_closed(self):
        original = claim._open_stage
        moved = self.root / "moved-stage"
        calls = 0
        def swap(pin):
            nonlocal calls
            calls += 1
            if calls == 3:  # two openings in claim_once, then orchestration
                self.stage.rename(moved)
                self.stage.symlink_to(moved, target_is_directory=True)
            return original(pin)
        with mock.patch.object(claim, "_open_stage", side_effect=swap):
            with mock.patch.object(handoff, "capture") as copied:
                with self.assertRaises(OSError):
                    self.attempt()
        copied.assert_not_called()
        self.assertTrue((moved / claim.MARKER).exists())

    def test_bad_frame_never_captures(self):
        with mock.patch.object(handoff, "capture") as copied:
            with self.assertRaises(ValueError):
                self.attempt(dict(self.body, sha="not-an-object"))
        copied.assert_not_called()
        self.assertEqual(list(self.stage.iterdir()), [])

    def test_stage_child_swap_during_capture_never_returns_facts(self):
        real = handoff.capture
        moved = self.root / "moved-capture"
        def swapped(*args):
            self.stage.joinpath(capture_once.CHILD).rename(moved)
            self.stage.joinpath(capture_once.CHILD).symlink_to(moved, target_is_directory=True)
            return real(*args)
        with mock.patch.object(handoff, "capture", side_effect=swapped) as copied:
            with self.assertRaises(OSError):
                self.attempt()
        self.assertEqual(copied.call_count, 1)
        self.assertTrue((self.stage / claim.MARKER).exists())
        self.assertTrue((moved / "store.git").exists())

    def test_source_path_swap_during_capture_never_returns_facts(self):
        real = handoff.capture
        moved = self.root / "moved-source"
        def swapped(*args):
            self.src.rename(moved)
            self.src.symlink_to(moved, target_is_directory=True)
            return real(*args)
        with mock.patch.object(handoff, "capture", side_effect=swapped) as copied:
            with self.assertRaises(OSError):
                self.attempt()
        self.assertEqual(copied.call_count, 1)
        self.assertTrue((self.stage / claim.MARKER).exists())
        self.assertTrue((self.stage / capture_once.CHILD / "store.git").exists())


if __name__ == "__main__":
    unittest.main()
