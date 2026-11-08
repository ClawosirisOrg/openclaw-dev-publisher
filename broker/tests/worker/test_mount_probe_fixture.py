"""Offline framing and silent-denial tests for the nonauthorizing fixture."""
import ast
from contextlib import redirect_stderr, redirect_stdout
import io
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
from types import SimpleNamespace
import unittest
from unittest import mock

from broker.worker import mount_pin, mount_probe_fixture as fixture


BODY = {"stage_dev": 12, "stage_ino": 34,
        "repository": "example.invalid/demo", "ref": "refs/heads/main"}


def frame(body=BODY):
    raw = json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return len(raw).to_bytes(4, "big") + raw


def raw_frame(raw):
    return len(raw).to_bytes(4, "big") + raw


class ChunkedInput(io.BytesIO):
    def read(self, size=-1):
        return super().read(min(size, 2) if size >= 0 else size)


class MountProbeFixtureTests(unittest.TestCase):
    def run_main(self, payload, *, argv=("mount_probe_fixture.py",), failure=None):
        out, err = io.StringIO(), io.StringIO()
        input_stream = SimpleNamespace(buffer=ChunkedInput(payload))
        with mock.patch.object(fixture.sys, "stdin", input_stream), \
             mock.patch.object(fixture.sys, "argv", list(argv)), \
             mock.patch.object(fixture.os, "geteuid", return_value=1), \
             mock.patch.object(fixture.os, "getegid", return_value=1), \
             mock.patch.object(fixture.mount_pin, "build_mount_pin", side_effect=failure) as build, \
             redirect_stdout(out), redirect_stderr(err):
            code = fixture.main()
        return code, out.getvalue(), err.getvalue(), build

    def test_success_only_emits_fixed_token_with_local_identity(self):
        code, out, err, build = self.run_main(frame())
        self.assertEqual((code, out, err), (0, "MOUNT_PIN_OK", ""))
        build.assert_called_once_with(12, 34, worker_uid=1, worker_gid=1,
                                      repository=BODY["repository"], ref=BODY["ref"])

    def test_partial_reads_and_exact_limit(self):
        self.assertEqual(fixture.read_config(ChunkedInput(frame())), BODY)
        # A canonical valid object can reach the cap by extending a decimal integer.
        prefix = b'{"stage_dev":'
        suffix = b',"stage_ino":34,"repository":"example.invalid/demo","ref":"refs/heads/main"}'
        raw = prefix + b"1" * (fixture.MAX_BODY - len(prefix) - len(suffix)) + suffix
        self.assertEqual(len(raw), fixture.MAX_BODY)
        self.assertEqual(fixture.read_config(ChunkedInput(raw_frame(raw)))["stage_ino"], 34)

    def test_bad_frames_are_silent_and_do_not_measure(self):
        variants = [b"", b"\x00\x00", b"\x00\x00\x00\x00",
                    (1025).to_bytes(4, "big"), frame()[:-1], frame() + b"x",
                    frame() + frame(), raw_frame(b"{"), raw_frame(b"\xff"),
                    raw_frame(b"[1,2]"),
                    raw_frame(b'{"stage_dev":12,"stage_dev":12,"stage_ino":34,"repository":"example.invalid/demo","ref":"refs/heads/main"}'),
                    raw_frame(b'{"stage_dev":12,"stage_ino":34,"repository":"example.invalid/demo","ref":"refs/heads/main","extra":1}'),
                    raw_frame(b'{"stage_dev":12,"stage_ino":34,"repository":"example.invalid/demo"}'),
                    raw_frame(b'{"stage_ino":34,"stage_dev":12,"repository":"example.invalid/demo","ref":"refs/heads/main"}'),
                    raw_frame(json.dumps(BODY, indent=2).encode()),
                    raw_frame(frame()[4:].replace(b'"repository"', b'"\u0072epository"')),
                    frame({**BODY, "stage_dev": True}), frame({**BODY, "stage_ino": -1}),
                    frame({**BODY, "stage_dev": 1.0}),
                    frame({**BODY, "repository": 3}),
                    raw_frame(frame()[4:].replace(b'"stage_dev":12', b'"stage_dev":NaN'))]
        for payload in variants:
            with self.subTest(payload=payload[:50]):
                code, out, err, build = self.run_main(payload)
                self.assertNotEqual(code, 0)
                self.assertEqual((out, err), ("", ""))
                build.assert_not_called()

    def test_measurement_denial_and_argv_are_silent(self):
        code, out, err, build = self.run_main(
            frame(), failure=mount_pin.MountPinError("private /stage and pin 123"))
        self.assertEqual((code, out, err), (2, "", ""))
        build.assert_called_once()
        code, out, err, build = self.run_main(frame(), argv=("fixture", "private-path"))
        self.assertEqual((code, out, err), (2, "", ""))
        build.assert_not_called()

    def test_invalid_repository_and_ref_denied_by_real_mount_pin_without_stage_io(self):
        for body in ({**BODY, "repository": "../private"},
                     {**BODY, "ref": "refs/heads/other"}):
            out, err = io.StringIO(), io.StringIO()
            with self.subTest(body=body), \
                 mock.patch.object(fixture.sys, "stdin", SimpleNamespace(buffer=io.BytesIO(frame(body)))), \
                 mock.patch.object(fixture.sys, "argv", ["mount_probe_fixture.py"]), \
                 mock.patch.object(mount_pin.os, "open", side_effect=AssertionError("stage I/O")) as opened, \
                 redirect_stdout(out), redirect_stderr(err):
                code = fixture.main()
            self.assertEqual((code, out.getvalue(), err.getvalue()), (2, "", ""))
            opened.assert_not_called()

    def test_module_denies_without_input_and_image_stays_inert(self):
        repo = Path(__file__).resolve().parents[3]
        result = subprocess.run([sys.executable, "-m", "broker.worker.mount_probe_fixture"],
                                input=b"", capture_output=True, cwd=repo, check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((result.stdout, result.stderr), (b"", b""))
        containerfile = (repo / "containers/Containerfile").read_text()
        self.assertIn("broker/worker/mount_pin.py broker/worker/mount_probe_fixture.py", containerfile)
        self.assertIn("USER 1:1", containerfile)
        self.assertIn('ENTRYPOINT ["/usr/bin/false"]', containerfile)

    def test_isolated_context_matches_copy_sources_and_image_defaults(self):
        repo = Path(__file__).resolve().parents[3]
        recipe = (repo / "containers/Containerfile").read_text()
        readme = (repo / "containers/README.md").read_text()
        self.assertEqual(readme.count("paths = ("), 1)
        whitelist = ast.literal_eval("(" + readme.split("paths = (", 1)[1].split(")\nfor name in paths:", 1)[0] + ")")
        self.assertEqual(len(whitelist), len(set(whitelist)))
        self.assertIn("containers/Containerfile", whitelist)
        self.assertEqual(len(whitelist), 14)  # thirteen Python files and the recipe
        instructions = [line for line in recipe.splitlines()
                        if line and not line.lstrip().startswith("#")]
        copied = []
        for line in instructions:
            if line.startswith("COPY "):
                args = shlex.split(line)[1:]
                sources = [item for item in args[:-1] if not item.startswith("--")]
                self.assertTrue(args[-1].startswith("/opt/publisher/"))
                copied.extend(sources)
        self.assertEqual(len(copied), len(set(copied)))
        self.assertEqual(set(copied), set(whitelist) - {"containers/Containerfile"})
        self.assertEqual(instructions[-3:], ["WORKDIR /opt/publisher", "USER 1:1",
                                             'ENTRYPOINT ["/usr/bin/false"]'])
        self.assertEqual(sum(line.startswith("WORKDIR ") for line in instructions), 1)
        self.assertEqual(sum(line.startswith("ENTRYPOINT ") for line in instructions), 1)
        self.assertIn("/usr/local/bin/python3", readme)


if __name__ == "__main__":
    unittest.main()
