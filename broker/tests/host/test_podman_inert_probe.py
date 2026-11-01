"""Offline fake Unix-HTTP tests; never contact a real Podman socket."""

import http.server
import json
import pathlib
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

from broker.host import podman_inert_probe as mod


IMAGE = 'a' * 64
CID = 'b' * 64
NAME = 'inert-probe-' + 'c' * 32
STAGE = '/private/host-stage/secret'
BASE = '/v5.8.0/libpod'


class UnixServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True
    allow_reuse_address = True


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def log_message(self, *_args):
        pass

    def _serve(self):
        body = self.rfile.read(int(self.headers.get('Content-Length', '0')))
        state = self.server.state
        state['requests'].append((self.command, self.path, body, dict(self.headers)))
        route = self.path
        status, data = 404, b'not found'
        if route == BASE + '/images/' + IMAGE + '/exists':
            status, data = (204, b'') if state['image'] else (404, b'private path ' + STAGE.encode())
        elif route == BASE + '/containers/create':
            state['name'] = json.loads(body)['name']
            state['present'] = True
            status, data = 201, json.dumps({'Id': CID}).encode()
            if state['create_mode'] == 'malformed':
                data = b'{"Id":'
            if state['create_mode'] == 'oversize':
                data = b'X' * (mod._MAX_REPLY + 1)
            if state['create_mode'] == 'timeout':
                time.sleep(0.2)
        elif route == BASE + '/containers/' + NAME + '/json':
            if state['present']:
                status = 200
                item = {'Name': '/' + NAME, 'Id': CID, 'Image': IMAGE,
                        'Mounts': [{'Type': 'bind', 'Source': STAGE,
                                    'Destination': '/stage', 'RW': False}]}
                item.update(state['inspect_override'])
                data = json.dumps(item).encode()
        elif route == BASE + '/containers/' + NAME + '/start':
            state['started'] += 1
            status, data = 204, b''
            if state['start_mode'] == 'malformed':
                status, data = 500, b'private path ' + STAGE.encode()
            if state['start_mode'] == 'timeout':
                time.sleep(0.2)
        elif route == BASE + '/containers/' + NAME + '/wait?condition=exited':
            state['waited'] += 1
            status, data = 200, state['wait_mode'].encode()
            if state['wait_mode'] == 'timeout':
                time.sleep(0.2)
        elif route == BASE + '/containers/' + NAME + '?force=true&volumes=false':
            state['deleted'] += 1
            state['present'] = state['delete_noop']
            status, data = 200, b'[{}]'
        try:
            self.send_response(status)
            self.send_header('Content-Length', str(len(data)))
            if state['response_close']:
                self.send_header('Connection', 'close')
            self.end_headers()
            self.wfile.write(data)
        except (BrokenPipeError, ConnectionResetError):
            pass

    do_GET = _serve
    do_POST = _serve
    do_DELETE = _serve


class PodmanProbeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = str(pathlib.Path(self.temp.name) / 'fake.sock')
        self.server = UnixServer(self.path, Handler)
        self.server.state = {'requests': [], 'present': False, 'image': True,
                             'name': None, 'started': 0, 'waited': 0, 'deleted': 0,
                             'create_mode': 'ok', 'start_mode': 'ok',
                             'wait_mode': '0', 'inspect_override': {}, 'delete_noop': False,
                             'response_close': False}
        self.addCleanup(self.server.server_close)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.stop_server)

    def stop_server(self):
        self.server.shutdown()
        self.thread.join(timeout=2)

    @property
    def state(self):
        return self.server.state

    def run_probe(self):
        with mock.patch.object(mod.secrets, 'token_hex', return_value='c' * 32):
            return mod.probe_once(socket_path=self.path, image_id=IMAGE, stage_source=STAGE)

    def operations(self):
        return [(method, route) for method, route, _, _ in self.state['requests']]

    def test_connection_close_204_empty_response(self):
        self.state['response_close'] = True
        status, data = mod._request(self.path, 'GET', BASE + '/images/' + IMAGE + '/exists',
                                    deadline=time.monotonic() + 1)
        self.assertEqual((status, data), (204, b''))

    def test_connection_close_200_nonempty_response(self):
        self.state['response_close'] = True
        status, data = mod._request(self.path, 'POST',
                                    BASE + '/containers/' + NAME + '/wait?condition=exited',
                                    deadline=time.monotonic() + 1)
        self.assertEqual((status, data), (200, b'0'))

    def test_connection_close_oversize_response_is_sanitized(self):
        self.state['response_close'] = True
        self.state['wait_mode'] = 'X' * (mod._MAX_REPLY + 1) + STAGE
        with self.assertRaises(mod.ProbeError) as caught:
            mod._request(self.path, 'POST',
                         BASE + '/containers/' + NAME + '/wait?condition=exited',
                         deadline=time.monotonic() + 1)
        self.assertNotIn(STAGE, str(caught.exception))

    def test_exact_spec_success_and_no_path_in_route_or_headers(self):
        self.assertEqual(self.run_probe(), 0)
        self.assertEqual(self.operations(), [
            ('GET', BASE + '/images/' + IMAGE + '/exists'),
            ('POST', BASE + '/containers/create'),
            ('GET', BASE + '/containers/' + NAME + '/json'),
            ('POST', BASE + '/containers/' + NAME + '/start'),
            ('POST', BASE + '/containers/' + NAME + '/wait?condition=exited'),
            ('GET', BASE + '/containers/' + NAME + '/json'),
            ('DELETE', BASE + '/containers/' + NAME + '?force=true&volumes=false'),
            ('GET', BASE + '/containers/' + NAME + '/json')])
        requests = self.state['requests']
        self.assertEqual([body for _, _, body, _ in requests if body], [requests[1][2]])
        self.assertEqual(json.loads(requests[1][2]), {
            'name': NAME, 'image': IMAGE, 'raw_image_name': IMAGE,
            'entrypoint': ['/usr/bin/stat'],
            'command': ['--format=%F', '--', '/stage'],
            'user': '1:1', 'netns': {'nsmode': 'none'},
            'mounts': [{'type': 'bind', 'source': STAGE, 'destination': '/stage',
                        'options': ['ro', 'rbind']}],
            'read_only_filesystem': True, 'read_write_tmpfs': False,
            'image_volume_mode': 'ignore', 'cap_drop': ['ALL'],
            'no_new_privileges': True, 'privileged': False,
            'restart_policy': 'no', 'remove': False,
            'env_host': False, 'httpproxy': False, 'unsetenvall': True,
            'terminal': False, 'stdin': False, 'timeout': 5,
            'log_configuration': {'driver': 'none'},
        })
        for method, route, body, headers in requests:
            self.assertNotIn(STAGE, route)
            self.assertNotIn(STAGE, str(headers))
            if route != BASE + '/containers/create':
                self.assertNotIn(STAGE.encode(), body)
        self.assertFalse(self.state['present'])
        self.assertEqual(self.state['deleted'], 1)

    def test_image_preflight_and_bad_inputs_do_not_create(self):
        self.state['image'] = False
        with self.assertRaises(mod.ProbeError) as caught:
            self.run_probe()
        self.assertNotIn(STAGE, str(caught.exception))
        self.assertEqual(len(self.operations()), 1)
        for image, stage in [('latest', STAGE), (IMAGE.upper(), STAGE),
                             (IMAGE, 'relative'), (IMAGE, STAGE + '\x00')]:
            with self.assertRaises(mod.ProbeError):
                mod.probe_once(socket_path=self.path, image_id=image, stage_source=stage)
        self.assertEqual(len(self.operations()), 1)

    def test_malformed_and_oversize_create_reconcile_without_start_or_retry(self):
        for mode in ('malformed', 'oversize'):
            with self.subTest(mode=mode):
                self.state['requests'].clear()
                self.state['create_mode'] = mode
                with self.assertRaises(mod.ProbeError) as caught:
                    self.run_probe()
                self.assertNotIn(STAGE, str(caught.exception))
                self.assertEqual(self.state['started'], 0)
                self.assertEqual(sum(route.endswith('/create') for _, route in self.operations()), 1)
                self.assertFalse(self.state['present'])

    def test_timeout_create_start_wait_do_not_retry_and_reconcile(self):
        with mock.patch.object(mod, '_IO_TIMEOUT', 0.05):
            for phase in ('create', 'start', 'wait'):
                with self.subTest(phase=phase):
                    self.state['requests'].clear()
                    self.state['create_mode'] = 'ok'
                    self.state['start_mode'] = 'ok'
                    self.state['wait_mode'] = '0'
                    self.state[phase + '_mode'] = 'timeout'
                    with self.assertRaises(mod.ProbeError) as caught:
                        self.run_probe()
                    self.assertNotIn(STAGE, str(caught.exception))
                    self.assertEqual(sum(route.endswith('/create') for _, route in self.operations()), 1)
                    self.assertFalse(self.state['present'])

    def test_nonzero_wait_and_start_error_cleanup(self):
        for phase in ('start', 'wait'):
            self.state['requests'].clear()
            self.state['start_mode'] = 'malformed' if phase == 'start' else 'ok'
            self.state['wait_mode'] = '37' if phase == 'wait' else '0'
            with self.assertRaises(mod.ProbeError):
                self.run_probe()
            self.assertFalse(self.state['present'])
            self.assertIn(('DELETE', BASE + '/containers/' + NAME + '?force=true&volumes=false'),
                          self.operations())

    def test_delete_ack_without_removal_is_uncertain(self):
        self.state['delete_noop'] = True
        with self.assertRaisesRegex(mod.ProbeError, 'cleanup'):
            self.run_probe()
        self.assertTrue(self.state['present'])
        self.assertEqual(self.state['deleted'], 1)  # no second delete

    def test_mismatched_inspect_blocks_start_and_delete(self):
        for altered in ({'Image': 'f' * 64}, {'Mounts': []}, {'Id': 'd' * 64},
                        {'Mounts': [{'Type': 'bind', 'Source': '/wrong',
                                     'Destination': '/stage', 'RW': False}]}):
            with self.subTest(altered=altered):
                self.state['requests'].clear()
                self.state['present'] = False
                self.state['inspect_override'] = altered
                with self.assertRaises(mod.ProbeError):
                    self.run_probe()
                self.assertTrue(self.state['present'])  # quarantine for operator
                self.assertNotIn(('DELETE', BASE + '/containers/' + NAME + '?force=true&volumes=false'),
                                 self.operations())
                self.assertNotIn(('POST', BASE + '/containers/' + NAME + '/start'),
                                 self.operations())

    def test_cli_refuses_and_no_real_socket(self):
        with self.assertRaisesRegex(RuntimeError, 'disabled'):
            mod.main()
        result = subprocess.run([sys.executable, '-B', str(pathlib.Path(mod.__file__))],
                                capture_output=True, text=True, timeout=5)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('CLI disabled', result.stderr)


if __name__ == '__main__':
    unittest.main()
