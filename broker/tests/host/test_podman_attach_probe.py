"""Offline Unix HTTP hijack tests; no real Podman access."""

import http.server
import json
import pathlib
import socket
import socketserver
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

from broker.host import podman_attach_probe as mod

IMAGE = 'a' * 64
CID = 'b' * 64
NAME = 'attach-probe-' + 'c' * 32
STAGE = '/private/stage/secret'
CONFIG = {'ref': 'main', 'repository': 'private-config',
          'stage_ino': 123, 'stage_dev': 456}
BASE = '/v5.8.0/libpod'
ATTACH = (BASE + '/containers/' + NAME + '/attach?stream=true&logs=false&'
          'stdin=true&stdout=true&stderr=false&detachKeys=')


def frame(stream, payload):
    return bytes([stream, 0, 0, 0]) + struct.pack('>I', len(payload)) + payload


class DripDeadlineTests(unittest.TestCase):
    """A peer can stay under the idle timeout while exceeding wall time."""

    class ConnectedSocket:
        def __init__(self, sock):
            self.sock = sock

        def connect(self, _path):
            pass  # socketpair is already connected

        def __getattr__(self, name):
            return getattr(self.sock, name)

    def peer(self, chunks):
        client, server = socket.socketpair()

        def drip():
            try:
                server.recv(4096)  # attach request
                for chunk in chunks:
                    time.sleep(0.015)
                    try:
                        server.sendall(chunk)
                    except (BrokenPipeError, ConnectionResetError):
                        break
            finally:
                server.close()

        thread = threading.Thread(target=drip, daemon=True)
        thread.start()
        self.addCleanup(lambda: (client.close(), thread.join(timeout=1)))
        return self.ConnectedSocket(client)

    def test_handshake_header_drip_honors_absolute_deadline(self):
        client = self.peer([b'H', b'T', b'T', b'P', b'/', b'1', b'.', b'1'])
        with (mock.patch.object(mod.socket, 'socket', return_value=client),
              mock.patch.object(mod, '_IO_TIMEOUT', 0.05)):
            begin = time.monotonic()
            with self.assertRaisesRegex(mod.ProbeError, '^attach handshake unavailable or invalid$'):
                mod._attach('/private/socket/path', NAME, begin + 0.055)
            self.assertLess(time.monotonic() - begin, 0.105)
        self.assertEqual(client.fileno(), -1)

    def test_frame_drip_honors_absolute_deadline(self):
        handshake = (b'HTTP/1.1 101 Switching Protocols\r\n'
                     b'Connection: Upgrade\r\nUpgrade: tcp\r\n\r\n')
        payload = frame(1, b'MOUNT_PIN_OK')
        client = self.peer([handshake + payload[:8],
                            *[bytes([b]) for b in payload[8:]]])
        with (mock.patch.object(mod.socket, 'socket', return_value=client),
              mock.patch.object(mod, '_IO_TIMEOUT', 0.05)):
            begin = time.monotonic()
            sock, reader = mod._attach('/private/socket/path', NAME, begin + 0.09)
            try:
                with self.assertRaises((TimeoutError, ValueError, OSError)):
                    mod._frames(reader)
                self.assertLess(time.monotonic() - begin, 0.14)
            finally:
                reader.close()
                sock.close()
        self.assertEqual(client.fileno(), -1)

    def test_handshake_read_ahead_keeps_output_frame(self):
        handshake = (b'HTTP/1.1 101 Switching Protocols\r\n'
                     b'Connection: Upgrade\r\nUpgrade: tcp\r\n\r\n')
        client = self.peer([handshake + frame(1, b'MOUNT_PIN_OK')])
        with mock.patch.object(mod.socket, 'socket', return_value=client):
            sock, reader = mod._attach('/private/socket/path', NAME,
                                       time.monotonic() + 0.3)
            try:
                self.assertGreater(len(reader.buffer), 0)
                mod._frames(reader)
            finally:
                reader.close()
                sock.close()
        self.assertEqual(client.fileno(), -1)

    def test_oversized_handshake_closes_without_exposing_path(self):
        client = self.peer([b'HTTP/1.1 101 Switching Protocols\r\n'
                            + b'X: ' + b'a' * 4096 + b'\r\n'])
        with mock.patch.object(mod.socket, 'socket', return_value=client):
            with self.assertRaisesRegex(mod.ProbeError, '^attach handshake unavailable or invalid$'):
                mod._attach('/private/socket/path', NAME, time.monotonic() + 0.3)
        self.assertEqual(client.fileno(), -1)


class UnixServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def log_message(self, *_args):
        pass

    def _serve(self):
        state = self.server.state
        body = self.rfile.read(int(self.headers.get('Content-Length', '0')))
        route = self.path
        state['requests'].append((self.command, route, body, dict(self.headers)))
        if route == ATTACH:
            if state['attach_status'] == 'timeout':
                time.sleep(0.2)
                return
            if state['attach_status'] == 101:
                self.send_response(101, state['attach_reason'])
                self.send_header('Connection', 'Upgrade')
                self.send_header('Upgrade', 'tcp')
                self.end_headers()
                self.wfile.flush()
                data = self.rfile.read(4)
                if len(data) == 4:
                    count = int.from_bytes(data, 'big')
                    state['stdin'] = data + self.rfile.read(count)
                    state['stdin_eof'] = self.rfile.read(1) == b''
                state['input_ready'].set()
                state['started_event'].wait(1)
                if state['attach_mode'] == 'timeout':
                    time.sleep(0.2)
                else:
                    try:
                        self.wfile.write(state['frames'])
                        self.wfile.flush()
                    except (BrokenPipeError, ConnectionResetError):
                        pass
                self.close_connection = True
                return
            status, data = state['attach_status'], b'private ' + STAGE.encode()
        elif route == BASE + '/images/' + IMAGE + '/exists':
            status, data = (204, b'') if state['image'] else (404, b'')
        elif route == BASE + '/containers/create':
            state['present'] = True
            status, data = 201, json.dumps({'Id': CID}).encode()
            if state['create_mode'] == 'bad':
                status, data = 500, b'private ' + STAGE.encode()
            if state['create_mode'] == 'timeout':
                time.sleep(0.2)
        elif route == BASE + '/containers/' + NAME + '/json':
            status, data = 404, b''
            if state['present']:
                item = {'Name': '/' + NAME, 'Id': CID, 'Image': IMAGE,
                        'Mounts': [{'Type': 'bind', 'Source': STAGE,
                                    'Destination': '/stage', 'RW': False}]}
                item.update(state['inspect_override'])
                status, data = 200, json.dumps(item).encode()
        elif route == BASE + '/containers/' + NAME + '/start':
            state['started'] += 1
            status, data = 204, b''
            if state['start_mode'] == 'bad':
                status, data = 500, b'private ' + STAGE.encode()
            if state['start_mode'] == 'timeout':
                time.sleep(0.2)
            state['started_event'].set()
        elif route == BASE + '/containers/' + NAME + '/wait?condition=exited':
            status, data = 200, state['wait'].encode()
        elif route == BASE + '/containers/' + NAME + '?force=true&volumes=false':
            state['deleted'] += 1
            state['present'] = state['delete_noop']
            status, data = 200, b'[{}]'
        else:
            status, data = 404, b''
        try:
            self.send_response(status)
            self.send_header('Content-Length', str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def handle(self):
        try:
            super().handle()
        except (BrokenPipeError, ConnectionResetError):
            pass

    do_GET = _serve
    do_POST = _serve
    do_DELETE = _serve


class AttachProbeTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.path = str(pathlib.Path(temp.name) / 'fake.sock')
        self.server = UnixServer(self.path, Handler)
        self.state = self.server.state = {
            'requests': [], 'present': False, 'image': True,
            'create_mode': 'ok', 'start_mode': 'ok', 'attach_mode': 'ok',
            'attach_status': 101, 'attach_reason': 'Switching Protocols',
            'frames': frame(1, b'MOUNT_PIN_OK'),
            'stdin': None, 'stdin_eof': False, 'input_ready': threading.Event(),
            'started_event': threading.Event(), 'started': 0, 'deleted': 0,
            'inspect_override': {}, 'wait': '0', 'delete_noop': False,
        }
        self.addCleanup(self.server.server_close)
        thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(lambda: (self.server.shutdown(), thread.join(timeout=2)))

    def run_probe(self):
        with mock.patch.object(mod.secrets, 'token_hex', return_value='c' * 32):
            return mod.probe_once(socket_path=self.path, image_id=IMAGE,
                                  stage_source=STAGE, config=CONFIG)

    def routes(self):
        return [route for _, route, _, _ in self.state['requests']]

    def denied(self):
        with self.assertRaises(mod.ProbeError) as caught:
            self.run_probe()
        self.assertNotIn(STAGE, str(caught.exception))
        self.assertNotIn('private-config', str(caught.exception))

    def test_success_spec_payload_order_and_cleanup(self):
        self.assertEqual(self.run_probe(), 0)
        self.assertEqual(self.routes(), [
            BASE + '/images/' + IMAGE + '/exists', BASE + '/containers/create',
            BASE + '/containers/' + NAME + '/json', ATTACH,
            BASE + '/containers/' + NAME + '/start',
            BASE + '/containers/' + NAME + '/wait?condition=exited',
            BASE + '/containers/' + NAME + '/json',
            BASE + '/containers/' + NAME + '?force=true&volumes=false',
            BASE + '/containers/' + NAME + '/json'])
        req = self.state['requests']
        spec = json.loads(req[1][2])
        self.assertEqual(spec, mod._spec(IMAGE, STAGE, NAME))
        self.assertEqual(spec['entrypoint'], ['/usr/local/bin/python3'])
        self.assertEqual(spec['command'], ['-m', 'broker.worker.mount_probe_fixture'])
        self.assertEqual(spec['user'], '1:1')
        self.assertEqual(spec['netns'], {'nsmode': 'none'})
        self.assertEqual(spec['cap_drop'], ['ALL'])
        self.assertEqual(len(spec['mounts']), 1)
        self.assertTrue(spec['stdin'])
        self.assertFalse(spec['terminal'])
        self.assertEqual(self.state['stdin'], mod._config_bytes(CONFIG))
        self.assertTrue(self.state['stdin_eof'])
        for i, (_, route, body, headers) in enumerate(req):
            self.assertNotIn(STAGE, route)
            self.assertNotIn(STAGE, str(headers))
            self.assertNotIn('private-config', route + str(headers))
            if i != 1:
                self.assertNotIn(STAGE.encode(), body)
                self.assertNotIn(b'private-config', body)
        self.assertFalse(self.state['present'])
        self.assertEqual(self.state['deleted'], 1)

    def test_invalid_inputs_and_image_never_create(self):
        for config in ([1], {**CONFIG, 'ref': 'x' * 1025},
                       {**CONFIG, 'stage_dev': float('nan')}, {'missing': 1}):
            with self.assertRaises(mod.ProbeError):
                mod.probe_once(socket_path=self.path, image_id=IMAGE,
                               stage_source=STAGE, config=config)
        for image, stage in [('latest', STAGE), (IMAGE, 'relative'),
                             (IMAGE, STAGE + '\x00')]:
            with self.assertRaises(mod.ProbeError):
                mod.probe_once(socket_path=self.path, image_id=image,
                               stage_source=stage, config=CONFIG)
        self.assertFalse(self.routes())
        self.state['image'] = False
        self.denied()
        self.assertEqual(len(self.routes()), 1)

    def test_invalid_handshake_and_timeout_no_start(self):
        for status in (200, 400, 500):
            with self.subTest(status=status):
                self.state['attach_status'] = status
                self.denied()
                self.assertEqual(self.state['started'], 0)
                self.assertFalse(self.state['present'])

    def test_handshake_timeout_and_explicit_create_start_errors(self):
        self.state['attach_status'] = 'timeout'
        with mock.patch.object(mod, '_IO_TIMEOUT', 0.05):
            self.denied()
        self.assertEqual(self.state['started'], 0)
        self.assertFalse(self.state['present'])
        self.state['attach_status'] = 101
        for phase in ('create', 'start'):
            with self.subTest(phase=phase):
                self.state['started_event'].clear()
                self.state[phase + '_mode'] = 'bad'
                self.denied()
                self.assertFalse(self.state['present'])
                self.state[phase + '_mode'] = 'ok'

    def test_podman_upgraded_reason_is_valid_101(self):
        self.state['attach_reason'] = 'UPGRADED'
        self.assertEqual(self.run_probe(), 0)

    def test_split_frames_accept_only_exact_combination(self):
        self.state['frames'] = frame(1, b'MOUNT_') + frame(1, b'PIN_OK')
        self.assertEqual(self.run_probe(), 0)

    def test_frames_fail_closed_and_no_wait(self):
        cases = [frame(1, b'MOUNT_PIN_O'), frame(1, b'MOUNT_PIN_OK') + b'X',
                 frame(2, b'private log'), frame(1, b'MOUNT_PIN_OK') + frame(2, b'x'),
                 frame(1, b'MOUNT_PIN_OK')[:-2],
                 b'\x01\x00\x00\x00' + struct.pack('>I', 1000),
                 frame(1, b'MOUNT_PIN_OK') + frame(1, b'X')]
        for payload in cases:
            with self.subTest(payload=payload):
                self.state['frames'] = payload
                self.state['started_event'].clear()
                self.state['requests'].clear()
                self.denied()
                self.assertNotIn(BASE + '/containers/' + NAME + '/wait?condition=exited',
                                 self.routes())
                self.assertFalse(self.state['present'])

    def test_attach_output_timeout_and_wait_nonzero(self):
        with mock.patch.object(mod, '_IO_TIMEOUT', 0.05):
            self.state['attach_mode'] = 'timeout'
            self.denied()
        self.assertFalse(self.state['present'])
        self.state['attach_mode'] = 'ok'
        self.state['wait'] = '7'
        self.state['started_event'].clear()
        self.denied()
        self.assertFalse(self.state['present'])

    def test_create_and_start_uncertainty_no_retry(self):
        for phase in ('create', 'start'):
            with self.subTest(phase=phase):
                self.state['requests'].clear()
                self.state['started_event'].clear()
                self.state[phase + '_mode'] = 'timeout'
                with mock.patch.object(mod._base, '_IO_TIMEOUT', 0.05):
                    self.denied()
                self.assertEqual(self.routes().count(BASE + '/containers/create'), 1)
                self.assertFalse(self.state['present'])
                self.state[phase + '_mode'] = 'ok'

    def test_identity_mismatch_blocks_delete_and_start(self):
        self.state['inspect_override'] = {'Image': 'f' * 64}
        self.denied()
        self.assertEqual(self.state['started'], 0)
        self.assertEqual(self.state['deleted'], 0)
        self.assertTrue(self.state['present'])

    def test_delete_ack_without_absence_uncertain(self):
        self.state['delete_noop'] = True
        self.denied()
        self.assertEqual(self.state['deleted'], 1)
        self.assertTrue(self.state['present'])

    def test_cli_disabled(self):
        with self.assertRaises(RuntimeError):
            mod.main()
        run = subprocess.run([sys.executable, '-B', '-m', 'broker.host.podman_attach_probe'],
                             capture_output=True, text=True, timeout=5)
        self.assertNotEqual(run.returncode, 0)
        self.assertIn('CLI disabled', run.stderr)


if __name__ == '__main__':
    unittest.main()
