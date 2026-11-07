"""Offline Unix socketpair fixtures for disabled host peer admission."""
import json
import os
from pathlib import Path
import socket
import tempfile
import threading
import time
import unittest
from unittest import mock

from broker.host import attempt_ledger, peer_admission

KEY = '1' * 32
BODY = {
    'version': 1, 'transactionId': KEY, 'repository': 'example.invalid/demo',
    'ref': 'refs/heads/main', 'base': 'a' * 40, 'sha': 'b' * 40,
    'branch': 'dev-syn/fixture', 'model': 'fixture/model', 'thinking': 'off',
    'thinkingSource': 'agent_attested', 'claimId': KEY,
}


def frame(body=BODY):
    raw = json.dumps(body, ensure_ascii=False, separators=(',', ':')).encode()
    return len(raw).to_bytes(4, 'big') + raw


class PeerAdmissionTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.path = Path(tmp.name) / 'ledger'
        self.path.mkdir(mode=0o700)
        self.fd = os.open(self.path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        self.addCleanup(os.close, self.fd)

    def pair(self, **kwargs):
        host, peer = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        self.addCleanup(peer.close)
        admission = peer_admission.PeerAdmission(
            host, expected_pid=os.getpid(), expected_uid=os.geteuid(),
            expected_gid=os.getegid(), repository=BODY['repository'],
            ref=BODY['ref'], ledger_dirfd=self.fd,
            same_uid_isolated_socket=True, **kwargs)
        return admission, peer

    def exchange(self, data=None):
        admission, peer = self.pair()
        peer.sendall(frame() if data is None else data)
        peer.shutdown(socket.SHUT_WR)
        result = admission.run()
        peer.settimeout(0.5)
        try:
            response = peer.recv(2048)
        except ConnectionResetError:
            response = b''  # unread rejected input can cause ECONNRESET
        self.closed(peer)
        return result, response

    def closed(self, peer):
        try:
            self.assertEqual(peer.recv(1), b'')
        except ConnectionResetError:
            pass

    def state(self):
        return attempt_ledger.AttemptLedger(self.fd, expected_uid=os.geteuid()).state(KEY)

    def test_valid_frame_is_only_fixed_denial_with_durable_replay_key(self):
        with mock.patch('broker.host.stage_allocator.StageAllocator.allocate',
                        side_effect=AssertionError('stage used')):
            result, response = self.exchange()
        self.assertEqual((result, response), ('publication_disabled', b'publication_disabled'))
        self.assertEqual(self.state(), 'attempted')
        self.assertEqual((self.path / (KEY + '.attempted')).stat().st_mode & 0o777, 0o600)
        label = (self.path / (KEY + '.allocated')).read_text()
        self.assertRegex(label, r'^admit-[0-9a-f]{32}$')
        self.assertNotEqual(label, KEY)
        self.assertEqual(sorted(p.name for p in self.path.iterdir()),
                         ['.lock', KEY + '.allocated', KEY + '.attempted'])
        self.assertEqual(self.exchange(), (None, b''))
        self.assertEqual(self.state(), 'attempted')

    def test_denial_does_not_echo_claim_or_private_state(self):
        variant = dict(BODY, transactionId='e' * 32, claimId='e' * 32,
                       model='private-fixture/marker')
        result, response = self.exchange(frame(variant))
        self.assertEqual(result, 'publication_disabled')
        self.assertEqual(response, b'publication_disabled')
        self.assertNotIn(b'private-fixture', response)
        self.assertNotIn(b'e' * 32, response)
        label = (self.path / ('e' * 32 + '.allocated')).read_text()
        self.assertNotIn('private-fixture', label)
        self.assertNotIn('e' * 32, label)

    def test_kernel_peer_credentials_rejected_before_read(self):
        for field in ('_pid', '_uid', '_gid'):
            with self.subTest(field=field):
                admission, peer = self.pair()
                setattr(admission, field, getattr(admission, field) + 1)
                peer.sendall(frame())  # leave write half open; must not wait for EOF
                with mock.patch.object(peer_admission, '_read_exact',
                                       side_effect=AssertionError('read')) as reader:
                    self.assertIsNone(admission.run())
                reader.assert_not_called()
                self.closed(peer)
        self.assertEqual(list(self.path.iterdir()), [])

    def test_same_uid_needs_explicit_isolated_path_assertion(self):
        admission, peer = self.pair()
        admission._isolated = False
        peer.sendall(frame())
        self.assertIsNone(admission.run())
        self.closed(peer)
        self.assertEqual(list(self.path.iterdir()), [])

    def test_malformed_frames_never_reserve(self):
        raw = frame()
        duplicate = raw[4:].replace(b'"model":', b'"model":"other","model":')
        formatted = json.dumps(BODY, indent=2).encode()
        bad = (b'', b'\0\0', b'\0\0\0\0', (1025).to_bytes(4, 'big'),
               raw[:8], raw + b'x', raw + raw,
               len(duplicate).to_bytes(4, 'big') + duplicate,
               len(formatted).to_bytes(4, 'big') + formatted,
               frame(dict(BODY, repository='other/repo')),
               frame(dict(BODY, ref='refs/heads/other')),
               frame(dict(BODY, claimId='2' * 32)),
               frame(dict(BODY, extra='unsafe')))
        for data in bad:
            with self.subTest(data=data[:16]):
                self.assertEqual(self.exchange(data), (None, b''))
        self.assertEqual(list(self.path.iterdir()), [])

    def test_deadline_is_absolute_against_drip_and_missing_eof(self):
        with mock.patch.object(peer_admission, 'TIMEOUT', 0.07):
            admission, peer = self.pair()
            peer.sendall(frame())  # complete frame but no EOF
            start = time.monotonic()
            self.assertIsNone(admission.run())
            self.assertLess(time.monotonic() - start, 0.5)
            self.assertEqual(peer.recv(1), b'')
            admission, peer = self.pair()
            wire = frame()
            def drip():
                for byte in wire[:10]:
                    try:
                        peer.sendall(bytes((byte,)))
                    except (BrokenPipeError, OSError):
                        break
                    time.sleep(0.02)
            sender = threading.Thread(target=drip)
            sender.start()
            start = time.monotonic()
            self.assertIsNone(admission.run())
            self.assertLess(time.monotonic() - start, 0.5)
            sender.join(timeout=1)
            self.assertFalse(sender.is_alive())
        self.assertEqual(list(self.path.iterdir()), [])

    def test_abort_after_reserve_is_terminal_and_no_stage(self):
        admission, peer = self.pair()
        peer.sendall(frame())
        peer.shutdown(socket.SHUT_WR)
        with mock.patch.object(peer_admission.AttemptLedger, 'mark_attempted',
                               side_effect=RuntimeError('private abort marker')):
            self.assertIsNone(admission.run())
        self.assertEqual(peer.recv(1024), b'')  # no exception text disclosed
        self.assertEqual(self.state(), 'allocated')
        self.assertEqual(self.exchange(), (None, b''))
        self.assertEqual(self.state(), 'allocated')
        self.assertIsNone(admission.run())  # one-shot, cannot resume
        self.assertEqual(sorted(p.name for p in self.path.iterdir()),
                         ['.lock', KEY + '.allocated'])

    def test_trusted_boundary_and_disabled_cli(self):
        with mock.patch.object(peer_admission, 'TIMEOUT', 0.01):
            admission, peer = self.pair()
            peer.sendall(frame()[:5])
            peer.shutdown(socket.SHUT_WR)
            self.assertIsNone(admission.run())
        self.assertEqual(list(self.path.iterdir()), [])
        with self.assertRaisesRegex(RuntimeError, 'CLI disabled'):
            peer_admission.main()


if __name__ == '__main__':
    unittest.main()
