"""Offline fake callbacks and disposable local Git; no network or credentials."""
import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[2] / "transport" / "one_shot.py"
spec = importlib.util.spec_from_file_location("fixture_one_shot", SOURCE)
t = importlib.util.module_from_spec(spec)
import sys
sys.modules[spec.name] = t
spec.loader.exec_module(t)
BASE, SHA = "a" * 40, "b" * 40
BRANCH = "dev-syn/fixture"
TOKEN = b"synthetic-test-token"


class Fixture:
    def __init__(self):
        self.events = []
        self.main = BASE
        self.branch = None
        self.pushes = 0
        self.fail_push = False
        self.drift_after_final_main = False
        self.main_reads = 0
        self.ack = True
        self.response_override = None
        self.readback_override = None

    def verify(self):
        self.events.append("verified")
        return True

    def issue(self, token=TOKEN):
        self.events.append("issued")
        reader, writer = os.pipe()
        os.write(writer, token)
        os.close(writer)
        self.fd = reader
        return reader

    def revoke(self):
        self.events.append("revoked")

    def call(self, token, *args):
        assert token == TOKEN
        assert TOKEN.decode() not in repr(args)
        assert args[-2] == t.REMOTE
        self.events.append(args[0])
        if args[0] == "ls-remote":
            ref = args[-1]
            if ref == t.MAIN:
                self.main_reads += 1
                value = self.main
                if self.drift_after_final_main and self.main_reads == 2:
                    self.main = SHA
                return (value + "\t" + ref + "\n").encode()
            value = self.readback_override if self.readback_override is not None else self.branch
            return (value + "\t" + ref + "\n").encode() if value else b""
        assert args[0] == "push"
        assert args[-3] == "--force-with-lease=refs/heads/" + BRANCH + ":"
        assert args[-1] == SHA + ":refs/heads/" + BRANCH
        self.pushes += 1
        if self.branch is not None:
            raise ValueError("absent-ref lease rejected")
        self.branch = SHA
        if self.fail_push:
            raise OSError("lost acknowledgment")
        if self.response_override is not None:
            return self.response_override
        if not self.ack:
            return b"unrecognized response\n"
        return ("To " + t.REMOTE + "\n*\t" + SHA + ":refs/heads/" + BRANCH
                + "\t[new branch]\nDone\n").encode()

    def run(self, **kw):
        args = dict(verify_authorization=self.verify, issue_fd=self.issue,
                    git_call=self.call, revoke=self.revoke,
                    clock=iter((1.0, 2.0)).__next__)
        args.update(kw)
        return t.exercise_fixture(SHA, BRANCH, BASE, **args)


class TransportTests(unittest.TestCase):
    def test_success_fixed_remote_and_order_and_readback(self):
        f = Fixture()
        result = f.run()
        self.assertTrue(result.acknowledged and result.readback_checked)
        self.assertFalse(result.stale)
        self.assertEqual(result.main_at_readback, BASE)
        self.assertEqual(f.events, ["verified", "issued", "ls-remote", "ls-remote",
                                    "ls-remote", "push", "ls-remote", "ls-remote", "revoked"])
        self.assertEqual(f.pushes, 1)
        with self.assertRaises(OSError):
            os.fstat(f.fd)

    def test_rejects_ambiguous_porcelain_after_one_push(self):
        status = ("*\t" + SHA + ":refs/heads/" + BRANCH + "\t[new branch]\n").encode()
        good = b"To " + t.REMOTE.encode() + b"\n" + status + b"Done\n"
        cases = {
            "missing header": status + b"Done\n",
            "wrong remote": good.replace(t.REMOTE.encode(), b"https://other.invalid/repo.git"),
            "extra header": good.replace(status, b"To " + t.REMOTE.encode() + b"\n" + status),
            "missing status": b"To " + t.REMOTE.encode() + b"\nDone\n",
            "duplicate status": good.replace(status, status + status),
            "other status": good.replace(b"[new branch]", b"[up to date]"),
            "other sha": good.replace(SHA.encode(), BASE.encode()),
            "other ref": good.replace(BRANCH.encode(), b"dev-syn/other"),
            "missing Done": good[:-5],
            "extra line": good + b"Done\n",
            "reordered": status + b"To " + t.REMOTE.encode() + b"\nDone\n",
            "CRLF": good.replace(b"\n", b"\r\n"),
            "string not bytes": good.decode(),
            "secret in output": good + TOKEN,
        }
        for name, response in cases.items():
            with self.subTest(name=name):
                f = Fixture()
                f.response_override = response
                with self.assertRaises(t.UncertainPush) as failure:
                    f.run()
                self.assertNotIn(TOKEN.decode(), str(failure.exception))
                self.assertEqual(f.pushes, 1)
                self.assertEqual(f.branch, SHA)
                self.assertEqual(f.events[-1], "revoked")
                self.assertEqual(f.events.count("ls-remote"), 3)  # no readback/cleanup

    def test_disposable_local_git_porcelain_is_acknowledged(self):
        # No network, bearer, adapter, or deployment: only a temporary file remote.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bare, local = root / "remote.git", root / "local"
            env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                   "HOME": directory, "GIT_CONFIG_NOSYSTEM": "1",
                   "GIT_CONFIG_GLOBAL": os.devnull, "GIT_ALLOW_PROTOCOL": "file"}
            def git(*args, cwd=None):
                return subprocess.run(("git", "-c", "protocol.file.allow=always", *args),
                                      cwd=cwd, env=env, stdout=subprocess.PIPE,
                                      stderr=subprocess.PIPE, check=True).stdout
            git("init", "--bare", str(bare))
            git("init", str(local))
            git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                "commit", "--allow-empty", "-m", "fixture", cwd=local)
            sha = git("rev-parse", "HEAD", cwd=local).decode().strip()
            git("push", str(bare), sha + ":refs/heads/main", cwd=local)
            responses = []
            def call(*args):
                self.assertEqual(args[-2], str(bare))
                result = git(*args, cwd=local)
                if args[0] == "push":
                    responses.append(result)
                return result
            with patch.object(t, "REMOTE", str(bare)):
                result = t._create_once(call, sha, BRANCH, sha, iter((1., 2.)).__next__)
            self.assertTrue(result.acknowledged and result.readback_checked)
            self.assertFalse(result.stale)
            self.assertEqual(len(responses), 1)
            self.assertEqual(responses[0], ("To " + str(bare) + "\n*\t" + sha + ":refs/heads/"
                                            + BRANCH + "\t[new branch]\nDone\n").encode())

    def test_denial_never_issues(self):
        f = Fixture()
        with self.assertRaisesRegex(ValueError, "authorization denied"):
            f.run(verify_authorization=lambda: False)
        self.assertEqual(f.events, [])
        with self.assertRaisesRegex(ValueError, "invalid branch"):
            t.exercise_fixture(SHA, "dev-syn/a..b", BASE,
                               verify_authorization=f.verify, issue_fd=f.issue,
                               git_call=f.call, revoke=f.revoke)
        self.assertEqual(f.events, [])
        for branch in ("dev-syn/a_b", "dev-syn/a.b", "dev-syn/a-", "dev-syn/" + "a" * 65):
            with self.subTest(branch=branch), self.assertRaisesRegex(ValueError, "invalid branch"):
                t._request(SHA, branch, BASE)
        with self.assertRaisesRegex(RuntimeError, "disabled"):
            t.main("publish")

    def test_existing_equal_and_main_drift_fail_before_push(self):
        for branch, main in ((SHA, BASE), (None, SHA)):
            f = Fixture()
            f.branch, f.main = branch, main
            with self.assertRaisesRegex(ValueError, "branch exists|main drift"):
                f.run()
            self.assertEqual(f.pushes, 0)
            self.assertEqual(f.events[-1], "revoked")

    def test_final_preflight_deadline_before_push(self):
        for ticks in ((1, 11.001), (1, 0), (1, float("nan"))):
            f = Fixture()
            with self.assertRaisesRegex(ValueError, "preflight expired"):
                f.run(clock=iter(ticks).__next__)
            self.assertEqual(f.pushes, 0)
            self.assertEqual(f.events[-1], "revoked")

    def test_late_main_drift_is_reported_not_atomic(self):
        f = Fixture()
        f.drift_after_final_main = True
        result = f.run()
        self.assertTrue(result.stale)
        self.assertEqual(result.main_at_readback, SHA)
        self.assertEqual(f.pushes, 1)

    def test_uncertain_push_never_retried_or_cleaned_up(self):
        for flag in ("fail_push", "ack"):
            f = Fixture()
            setattr(f, flag, True if flag == "fail_push" else False)
            with self.assertRaises(t.UncertainPush) as cm:
                f.run()
            self.assertNotIn(TOKEN.decode(), str(cm.exception))
            self.assertEqual(f.pushes, 1)
            self.assertEqual(f.events[-1], "revoked")
            inspect = t.inspect_uncertain_fixture(SHA, BRANCH, BASE,
                          read_only_call=lambda *args: f.call(TOKEN, *args))
            self.assertEqual(inspect["ref_state"], "exact")
            self.assertFalse(inspect["acknowledged"])
            self.assertEqual(f.pushes, 1)

    def test_readback_mismatch_is_uncertain(self):
        f = Fixture()
        original = f.call
        def tamper(token, *args):
            output = original(token, *args)
            if args[0] == "push":
                f.readback_override = BASE
            return output
        with self.assertRaises(t.UncertainPush):
            f.run(git_call=tamper)
        self.assertEqual(f.pushes, 1)
        self.assertEqual(f.events[-1], "revoked")

    def test_fifo_frame_complete_bounded_and_closed(self):
        for token, valid in ((TOKEN, True), (b"bad\nframe", False),
                             (b"x" * (t.TOKEN_LIMIT + 1), False), (b"", False)):
            f = Fixture()
            if valid:
                self.assertTrue(f.run(issue_fd=lambda: f.issue(token)).acknowledged)
            else:
                with self.assertRaisesRegex(ValueError, "invalid token"):
                    f.run(issue_fd=lambda: f.issue(token))
                self.assertEqual(f.pushes, 0)
            self.assertEqual(f.events[-1], "revoked")
            with self.assertRaises(OSError):
                os.fstat(f.fd)
        with tempfile.TemporaryFile() as file:
            f = Fixture()
            dup = os.dup(file.fileno())
            with self.assertRaisesRegex(ValueError, "invalid token pipe"):
                f.run(issue_fd=lambda: dup)
            self.assertEqual(f.events[-1], "revoked")
            with self.assertRaises(OSError):
                os.fstat(dup)

    def test_open_writer_timeout_closes_reader(self):
        reader, writer = os.pipe()
        try:
            os.write(writer, b"partial")
            with self.assertRaisesRegex(ValueError, "token pipe timeout"):
                t.read_token_fd(reader, timeout=0.001)
            with self.assertRaises(OSError):
                os.fstat(reader)
        finally:
            os.close(writer)

    def test_issuer_failure_still_revokes_without_git(self):
        f = Fixture()
        def fail():
            raise ValueError("fixture issuer failed")
        with self.assertRaisesRegex(ValueError, "fixture issuer failed"):
            f.run(issue_fd=fail)
        self.assertEqual(f.events, ["verified", "revoked"])

    def test_separate_inspection_states(self):
        f = Fixture()
        def inspect(*args):
            return f.call(TOKEN, *args)
        self.assertEqual(t.inspect_uncertain_fixture(SHA, BRANCH, BASE,
                         read_only_call=inspect)["ref_state"], "absent")
        f.branch = BASE
        self.assertEqual(t.inspect_uncertain_fixture(SHA, BRANCH, BASE,
                         read_only_call=inspect)["ref_state"], "different_or_invalid")
        f.main = SHA
        self.assertTrue(t.inspect_uncertain_fixture(SHA, BRANCH, BASE,
                        read_only_call=inspect)["stale"])
        self.assertEqual(f.pushes, 0)


if __name__ == "__main__":
    unittest.main()
