"""Synthetic local Git and SSH fixtures. No network, external signer or publication."""
import base64
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

from broker.worker import handoff, verifier


def run(*args, cwd=None):
    return subprocess.check_output(args, cwd=cwd, env=verifier.ENV,
                                   stderr=subprocess.DEVNULL).decode().strip()


class Fixture(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.src = self.root / "src"
        self.repo = self.src / "checkout"
        self.repo.mkdir(parents=True)
        self.handoff = self.root / "handoff"
        self.handoff.mkdir(mode=0o700)
        run("git", "init", "-q", str(self.repo))
        key = self.root / "synthetic_fixture_key"
        run("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key))
        pub = (self.root / "synthetic_fixture_key.pub").read_bytes()
        raw = base64.b64decode(pub.split()[1])
        fp = "SHA256:" + base64.b64encode(hashlib.sha256(raw).digest()).decode().rstrip("=")
        self.config = verifier.DeployConfig("example.invalid/demo", "refs/heads/main",
                                            "fixture", "testowner", "review", "checkout", fp, pub)
        for k, value in (("user.name", "Synthetic"), ("user.email", "synthetic@example.invalid"),
                         ("gpg.format", "ssh"), ("user.signingkey", str(key)),
                         ("commit.gpgsign", "true")):
            run("git", "config", k, value, cwd=self.repo)
        self.commit("base", signed=False)
        self.base = run("git", "rev-parse", "HEAD", cwd=self.repo)
        self.commit("candidate", signed=True)
        self.invocation = verifier.Invocation(run("git", "rev-parse", "HEAD", cwd=self.repo),
                                               "review/fixture", self.base, "fixture/model", "off")

    def commit(self, body, signed=True):
        (self.repo / "file").write_text(body)
        run("git", "add", "file", cwd=self.repo)
        message = body
        if signed:
            message += ("\n\nAgent: fixture\nModel: fixture/model\n"
                        "Thinking: off\nBot-Owner: @testowner")
        run("git", "-c", "commit.gpgsign=" + str(signed).lower(),
            "commit", "-qm", message, cwd=self.repo)

    def capture(self, **kwargs):
        return handoff.capture(self.src, self.handoff, self.invocation, self.config, **kwargs)

    def fresh(self):
        self.handoff = self.root / ("fresh-" + str(len(list(self.root.iterdir()))))
        self.handoff.mkdir(mode=0o700)

    def test_signed_graph_and_derived_tree(self):
        record = self.capture()
        self.assertEqual(record["tree"], run("git", "rev-parse", "HEAD^{tree}", cwd=self.repo))
        self.assertEqual(record["base"], self.base)
        self.assertFalse(record["publishable"])
        self.assertFalse(record["provenance_authenticated"])
        self.assertEqual(set(p.name for p in self.handoff.iterdir()), {"store.git", "allowed_signers"})
        self.assertFalse((self.handoff / "store.git" / "index").exists())
        self.assertFalse((self.handoff / "store.git" / "hooks").exists())
        self.assertEqual((self.handoff / "store.git" / "config").read_text(),
                         "[core]\n\tbare = true\n")
        with self.assertRaisesRegex(ValueError, "empty"):
            self.capture()
        with self.assertRaisesRegex(RuntimeError, "disabled"):
            handoff.main()
        with self.assertRaisesRegex(RuntimeError, "disabled"):
            verifier.main()

    def test_wrong_base_signer_unsigned_and_trailers(self):
        wrong = verifier.Invocation(self.invocation.sha, self.invocation.branch, "a" * 40,
                                    self.invocation.model, self.invocation.thinking)
        with self.assertRaises(ValueError):
            handoff.capture(self.src, self.handoff, wrong, self.config)
        self.fresh()
        altered = verifier.Invocation(self.invocation.sha, self.invocation.branch, self.base,
                                      "other/model", "off")
        with self.assertRaisesRegex(ValueError, "attribution"):
            handoff.capture(self.src, self.handoff, altered, self.config)
        self.fresh()
        other = self.root / "other"
        run("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(other))
        pub = Path(str(other) + ".pub").read_bytes()
        fp = "SHA256:" + base64.b64encode(hashlib.sha256(base64.b64decode(pub.split()[1])).digest()).decode().rstrip("=")
        other_config = verifier.DeployConfig("example.invalid/demo", "refs/heads/main", "fixture",
                                              "testowner", "review", "checkout", fp, pub)
        with self.assertRaises(ValueError):
            handoff.capture(self.src, self.handoff, self.invocation, other_config)
        self.fresh()
        self.commit("unsigned", signed=False)
        unsigned = verifier.Invocation(run("git", "rev-parse", "HEAD", cwd=self.repo),
                                        "review/fixture", self.invocation.sha, "fixture/model", "off")
        with self.assertRaises(ValueError):
            handoff.capture(self.src, self.handoff, unsigned, self.config)

    def test_extra_commit_duplicate_attribution_and_source_dotgit_symlink(self):
        self.commit("second", signed=True)
        sha = run("git", "rev-parse", "HEAD", cwd=self.repo)
        extra = verifier.Invocation(sha, "review/fixture", self.base, "fixture/model", "off")
        with self.assertRaisesRegex(ValueError, "direct parent"):
            handoff.capture(self.src, self.handoff, extra, self.config)
        self.fresh()
        # Sign a commit with an additional visually confusable trailer.
        run("git", "reset", "--hard", self.base, cwd=self.repo)
        (self.repo / "file").write_text("duplicated")
        run("git", "add", "file", cwd=self.repo)
        text = ("candidate\n\nＴｈｉｎｋｉｎｇ： low\n\nAgent: fixture\n"
                "Model: fixture/model\nThinking: off\nBot-Owner: @testowner")
        run("git", "commit", "-qm", text, cwd=self.repo)
        duplicate = verifier.Invocation(run("git", "rev-parse", "HEAD", cwd=self.repo),
                                        "review/fixture", self.base, "fixture/model", "off")
        with self.assertRaisesRegex(ValueError, "attribution"):
            handoff.capture(self.src, self.handoff, duplicate, self.config)
        self.fresh()
        dotgit = self.repo / ".git"
        dotgit.rename(self.repo / "saved-git")
        dotgit.symlink_to(self.repo / "saved-git", target_is_directory=True)
        with self.assertRaises(OSError):
            self.capture()

    def test_config_request_and_no_expected_tree(self):
        with self.assertRaisesRegex(ValueError, "pin"):
            verifier.DeployConfig("example.invalid/demo", "refs/heads/main", "fixture",
                                  "testowner", "review", "checkout", "SHA256:" + "A" * 43,
                                  self.config.signer_public_key)
        for branch in ("../../x", "review/../x", "--help", "review/valid/other"):
            with self.subTest(branch=branch), self.assertRaises(ValueError):
                handoff.capture(self.src, self.handoff,
                                verifier.Invocation(self.invocation.sha, branch, self.base,
                                                    "fixture/model", "off"), self.config)
        with self.assertRaises(TypeError):
            handoff.capture(self.src, self.handoff, self.invocation, self.config,
                            expected_tree="a" * 40)
        self.assertEqual(list(self.handoff.iterdir()), [])

    def test_hostile_paths_and_file_types(self):
        objects = self.repo / ".git" / "objects"
        external = self.root / "external"
        external.mkdir()
        for case in ("symlink_directory", "symlink_object", "hardlink", "fifo", "alternates"):
            with self.subTest(case=case):
                self.fresh()
                item = objects / "aa"
                item.mkdir(exist_ok=True)
                leaf = item / ("b" * 38)
                if case == "symlink_directory":
                    item.rmdir(); item.symlink_to(external, target_is_directory=True)
                elif case == "symlink_object":
                    leaf.symlink_to(self.repo / "file")
                elif case == "hardlink":
                    os.link(self.repo / "file", leaf)
                elif case == "fifo":
                    os.mkfifo(leaf)
                else:
                    (objects / "info" / "alternates").write_text(str(external))
                with self.assertRaises((ValueError, OSError)):
                    self.capture()
                if case != "alternates":
                    if case == "symlink_directory":
                        item.unlink()
                    else:
                        leaf.unlink(); item.rmdir()
                else:
                    (objects / "info" / "alternates").unlink()
        self.assertFalse(list(external.iterdir()))

    def test_bounds_and_mutable_source_config_not_copied(self):
        with mock.patch.object(handoff, "MAX_BYTES", 2):
            with self.assertRaisesRegex(ValueError, "oversize"):
                self.capture()
        self.fresh()
        with mock.patch.object(handoff, "MAX_ENTRIES", 1):
            with self.assertRaisesRegex(ValueError, "entry count"):
                self.capture()
        self.fresh()
        marker = self.root / "marker"
        payload = self.root / "payload"
        payload.write_text("#!/bin/sh\ntouch " + str(marker) + "\n")
        payload.chmod(0o755)
        cfg = self.repo / ".git" / "config"
        cfg.write_text(cfg.read_text() + "\n[core]\nfsmonitor = " + str(payload) + "\n")
        self.capture()
        self.assertFalse(marker.exists())

    def test_symlink_swap_at_open_and_private_empty_destination(self):
        path = self.repo / ".git" / "objects" / "aa"
        path.mkdir()
        target = self.root / "external"
        target.write_text("not an object")
        leaf = path / ("b" * 38)
        leaf.write_bytes(b"object")
        original = os.open
        swapped = [False]
        def swap(name, flags, *args, **kwargs):
            if name == "b" * 38 and kwargs.get("dir_fd") is not None and not swapped[0]:
                swapped[0] = True
                leaf.unlink(); leaf.symlink_to(target)
            return original(name, flags, *args, **kwargs)
        with mock.patch.object(handoff.os, "open", side_effect=swap):
            with self.assertRaises(OSError):
                self.capture()
        self.assertTrue(swapped[0])
        self.assertEqual(target.read_text(), "not an object")
        self.fresh()
        self.handoff.chmod(0o755)
        with self.assertRaisesRegex(ValueError, "private"):
            self.capture()


if __name__ == "__main__":
    unittest.main()
