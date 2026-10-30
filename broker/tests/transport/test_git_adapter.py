"""Synthetic, offline Git/FD fixtures only; never spawn Git or contact a host."""
import io
import os
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from broker.transport import askpass, git_adapter as adapter

TOKEN = b"fixture-only-secret"
SHA = "b" * 40
REF = "refs/heads/dev-syn/fixture"


def pipe(data=TOKEN):
    reader, writer = os.pipe()
    os.write(writer, data)
    os.close(writer)
    return reader


class FakeProcess:
    def __init__(self):
        self.stdout = io.BytesIO()
        self.stderr = io.BytesIO()
        self.pid = 42
    def poll(self):
        return 0


class AdapterTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.target = adapter._DeployTarget("FixtureOwner", "fixture-repo", self.temp.name)

    def test_fixed_remote_exact_argv_and_rejected_operations(self):
        main = adapter._argv(self.target, "main", "refs/heads/main")
        branch = adapter._argv(self.target, "branch", REF)
        push = adapter._argv(self.target, "create", REF, SHA)
        self.assertEqual(main[-5:], ["--git-dir=" + self.temp.name, "ls-remote",
                                     "--exit-code", self.target.remote, "refs/heads/main"])
        self.assertEqual(main[-3:], ["--exit-code", self.target.remote, "refs/heads/main"])
        self.assertEqual(branch[-3:], ["ls-remote", self.target.remote, REF])
        self.assertEqual(push[-7:], ["push", "--porcelain", "--no-verify",
                                     "--no-follow-tags", "--force-with-lease=" + REF + ":",
                                     self.target.remote, SHA + ":" + REF])
        self.assertEqual(push[-3:], ["--force-with-lease=" + REF + ":",
                                     self.target.remote, SHA + ":" + REF])
        self.assertIn("credential.helper=", push)
        self.assertIn("http.followRedirects=false", push)
        for op, ref, sha in (("push", REF, None), ("create", REF, "c" * 39),
                             ("branch", "refs/heads/main", None),
                             ("branch", "refs/heads/dev-syn/a..b", None),
                             ("branch", "refs/heads/dev-syn/a.lock", None),
                             ("branch", "refs/heads/dev-syn/a_b", None),
                             ("branch", "refs/heads/dev-syn/a.b", None),
                             ("branch", "https://other.invalid/x", None),
                             ("main", REF, None)):
            with self.subTest(op=op, ref=ref), self.assertRaises(adapter.GitAdapterError):
                adapter._argv(self.target, op, ref, sha)
        with self.assertRaises(RuntimeError):
            adapter.main("publish")

    def test_target_not_candidate_url_and_outside_checkout(self):
        for owner, name in (("https://other.invalid", "repo"), ("..", "repo"),
                            ("owner", "repo/other"), ("owner", "name.lock")):
            with self.assertRaises(adapter.GitAdapterError):
                adapter._DeployTarget(owner, name, self.temp.name)
        with self.assertRaises(adapter.GitAdapterError):
            adapter._DeployTarget("owner", "name", str(adapter._ROOT))
        link = Path(self.temp.name) / "link"
        link.symlink_to(self.temp.name)
        with self.assertRaises(adapter.GitAdapterError):
            adapter._DeployTarget("owner", "name", str(link))

    def test_private_fd_sanitized_environment_single_command_and_cleanup(self):
        captured = []
        def fake_spawn(argv, **kwargs):
            self.assertEqual(kwargs["pass_fds"], (int(kwargs["env"]["BROKER_GIT_TOKEN_FD"]),))
            self.assertEqual(os.read(kwargs["pass_fds"][0], 4096), TOKEN)
            self.assertNotIn(TOKEN.decode(), repr((argv, kwargs)))
            self.assertNotIn("GIT_TRACE", kwargs["env"])
            self.assertNotIn("HTTPS_PROXY", kwargs["env"])
            self.assertEqual(kwargs["env"]["GIT_ALLOW_PROTOCOL"], "https")
            self.assertTrue(kwargs["close_fds"] and kwargs["start_new_session"])
            captured.append(argv)
            return FakeProcess()
        fd = pipe()
        with patch.dict(os.environ, {"GIT_TRACE": "1", "HTTPS_PROXY": "http://other.invalid"}), \
             patch.object(adapter.subprocess, "Popen", side_effect=fake_spawn), \
             patch.object(adapter, "_collect", return_value=b"fixture-output"):
            self.assertEqual(adapter._run(self.target, "branch", REF, fd), b"fixture-output")
        with self.assertRaises(OSError):
            os.fstat(fd)
        self.assertEqual(len(captured), 1)
        self.assertEqual(captured[0][-3:], ["ls-remote", self.target.remote, REF])

    def test_rejected_operation_closes_issuer_fd_before_spawn(self):
        fd = pipe()
        with patch.object(adapter.subprocess, "Popen") as spawn:
            with self.assertRaises(adapter.GitAdapterError):
                adapter._run(self.target, "arbitrary", REF, fd)
        spawn.assert_not_called()
        with self.assertRaises(OSError):
            os.fstat(fd)

    def test_failure_sanitized_no_retry(self):
        fd = pipe()
        with patch.object(adapter.subprocess, "Popen", side_effect=OSError(TOKEN.decode())) as spawn:
            with self.assertRaises(adapter.GitAdapterError) as failure:
                adapter._run(self.target, "create", REF, fd, sha=SHA)
        self.assertEqual(spawn.call_count, 1)
        self.assertNotIn(TOKEN.decode(), str(failure.exception))
        with self.assertRaises(OSError):
            os.fstat(fd)

    def test_bounded_pipe_collection_and_deadline(self):
        class Pipes:
            def __init__(self, stdout, stderr=b"", status=0):
                self.streams = []
                self.writers = []
                for data in (stdout, stderr):
                    reader, writer = os.pipe()
                    def feed(fd, payload):
                        try:
                            os.write(fd, payload)
                        except BrokenPipeError:
                            pass
                        finally:
                            os.close(fd)
                    thread = threading.Thread(target=feed, args=(writer, data))
                    thread.start()
                    self.writers.append(thread)
                    self.streams.append(os.fdopen(reader, "rb", buffering=0))
                self.stdout, self.stderr = self.streams
                self.status = status
            def wait(self, timeout):
                return self.status
            def close(self):
                for stream in self.streams:
                    stream.close()
                for thread in self.writers:
                    thread.join(timeout=1)
        for output, error, status, valid in ((b"ok", b"ignored", 0, True),
                                              (b"x" * 8193, b"", 0, False),
                                              (b"", b"x" * 2049, 0, False),
                                              (b"ok", b"", 1, False)):
            p = Pipes(output, error, status)
            try:
                if valid:
                    self.assertEqual(adapter._collect(p, time.monotonic() + 1), output)
                else:
                    with self.assertRaisesRegex(adapter.GitAdapterError, "Git command failed"):
                        adapter._collect(p, time.monotonic() + 1)
            finally:
                p.close()
        p = Pipes(b"pending")
        try:
            with self.assertRaises(adapter.GitAdapterError):
                adapter._collect(p, time.monotonic() - 1)
        finally:
            p.close()

    def test_askpass_exact_prompts_and_single_fd_consumption(self):
        env = {"BROKER_GIT_PROMPT_URL": self.target.remote}
        outputs = []
        write = lambda _, data: outputs.append(bytes(data))
        username = "Username for 'https://github.com': "
        password = "Password for 'https://x-access-token@github.com': "
        self.assertTrue(askpass._answer(username, env, write=write))
        self.assertEqual(outputs, [b"x-access-token\n"])
        for prompt in (username[:-1], username + " ", password[:-1],
                       "Password for 'https://other.invalid': ",
                       "Password for 'https://x-access-token@github.com/other': "):
            self.assertFalse(askpass._answer(prompt, env, write=write))
        fd = pipe()
        env["BROKER_GIT_TOKEN_FD"] = str(fd)
        self.assertTrue(askpass._answer(password, env, write=write))
        self.assertEqual(outputs[-1], TOKEN + b"\n")
        with self.assertRaises(OSError):
            os.fstat(fd)
        self.assertFalse(askpass._answer(password, env, write=write))
        self.assertEqual(len(outputs), 2)
        for data in (b"", b"bad\nvalue", b"x" * 4097):
            fd = pipe(data)
            env["BROKER_GIT_TOKEN_FD"] = str(fd)
            self.assertFalse(askpass._answer(password, env, write=write))
            with self.assertRaises(OSError):
                os.fstat(fd)
        self.assertEqual(len(outputs), 2)


if __name__ == "__main__":
    unittest.main()
