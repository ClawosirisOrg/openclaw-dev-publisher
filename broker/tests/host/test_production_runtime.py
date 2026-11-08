"""Fake Podman responses only: fixed worker specs and bounded attach lifecycle."""
import json
import unittest
from unittest import mock
from broker.host import production_runtime as runtime
from broker.worker.production import encode

IMAGE, ATTEMPT, CID = 'a' * 64, 'b' * 32, 'c' * 64
MOUNTS = [('/fixture/stage', '/stage', False)]


def inspect(session):
    return {'Name': session.name, 'Image': IMAGE, 'Id': CID,
        'Config': {'User': '1:1'}, 'HostConfig': {'Privileged': False,
            'ReadonlyRootfs': True, 'CapDrop': ['ALL'], 'SecurityOpt': ['no-new-privileges'],
            'NetworkMode': 'none', 'PidMode': 'private', 'IpcMode': 'private', 'UTSMode': 'private',
            'UsernsMode': 'private', 'Tmpfs': {'/tmp': 'rw,nosuid,nodev,noexec,size=67108864,mode=1777'},
            'LogConfig': {'Type': 'none'}, 'IDMappings': {'UidMap': ['0:1:1', '1:0:1', '2:2:65535'],
                                                  'GidMap': ['0:1:1', '1:0:1', '2:2:65535']}},
        'EffectiveCaps': None, 'BoundingCaps': None,
        'Mounts': [{'Type': 'bind', 'Source': a, 'Destination': b, 'RW': not c}
                   for a, b, c in session.mounts]}


class Sock:
    def __init__(self):
        self.sent = []
    def settimeout(self, _value): pass
    def sendall(self, data): self.sent.append(data)
    def shutdown(self, _value): pass
    def close(self): pass


class Reader:
    def __init__(self, output):
        self.data = bytearray(b'\x01\0\0\0' + len(output).to_bytes(4, 'big') + output)
    def take(self, size, *, eof_ok=False):
        if not self.data and eof_ok:
            return b''
        if len(self.data) < size:
            raise ValueError('fixture truncated')
        data = bytes(self.data[:size])
        del self.data[:size]
        return data
    def close(self): pass


class RuntimeTests(unittest.TestCase):
    def test_specs_have_no_host_authority_or_network_in_crypto_workers(self):
        for op in ('capture', 'reverify'):
            spec = runtime.specification(IMAGE, 'fixture', op, MOUNTS)
            self.assertEqual(spec['netns'], {'nsmode': 'none'})
            self.assertEqual(spec['user'], '1:1')
            self.assertEqual(spec['userns'], {'nsmode': 'keep-id', 'value': 'uid=1,gid=1'})
            self.assertFalse(spec['init'])
            self.assertIn('z', spec['mounts'][0]['options'])
            self.assertNotIn('U', spec['mounts'][0]['options'])
            self.assertEqual(spec['mounts'][-1]['type'], 'tmpfs')
            self.assertEqual(spec['mounts'][-1]['destination'], '/tmp')
            self.assertIn('size=67108864', spec['mounts'][-1]['options'])
            self.assertEqual(spec['log_configuration'], {'driver': 'none'})
            self.assertFalse(spec['env_host'])
            self.assertFalse(spec['httpproxy'])
            self.assertTrue(spec['read_only_filesystem'])
            self.assertEqual(spec['image_volume_mode'], 'ignore')
            self.assertNotIn('token', repr(spec))
        with self.assertRaises(runtime.RuntimeError_):
            runtime.specification(IMAGE, 'fixture', 'capture', MOUNTS, 'fixture-network')
        with self.assertRaises(runtime.RuntimeError_):
            runtime.specification(IMAGE, 'fixture', 'transport', MOUNTS)

    def test_real_session_protocol_and_verified_cleanup_with_fake_server(self):
        session = runtime.Session('/fixture/socket', IMAGE, 'capture', MOUNTS, attempt=ATTEMPT)
        self.assertEqual(session.name, 'publisher-' + ATTEMPT + '-capture')
        sock = Sock()
        deleted = False
        def request(method, suffix, **_kwargs):
            nonlocal deleted
            if method == 'GET' and suffix == '/info':
                return 200, b'{"host":{"security":{"rootless":true}}}'
            if method == 'GET' and suffix.startswith('/images/'):
                return 204, b''
            if method == 'POST' and suffix == '/containers/create':
                return 201, json.dumps({'Id': CID}).encode()
            if method == 'GET':
                return (404, b'') if deleted else (200, json.dumps(inspect(session)).encode())
            if method == 'DELETE':
                deleted = True
                return 200, b'[{}]'
            if 'wait?' in suffix:
                return 200, b'0'
            return 204, b''
        result = {'sha': 'd' * 40, 'tree': 'e' * 40}
        with mock.patch.object(session, 'request', side_effect=request), mock.patch.object(
                runtime.attach, '_attach', return_value=(sock, Reader(encode({'ready': 'capture', 'mapping': 'rootless-owner'}) + encode(result)))):
            with session:
                session.send({'fixture': True})
                self.assertEqual(session.receive(), result)
                session.finish()
        self.assertTrue(session.terminated)
        self.assertTrue(deleted)
        self.assertEqual(sock.sent, [encode({'fixture': True})])

    def test_unbounded_or_host_scratch_and_worker_logging_are_denied(self):
        session = runtime.Session('/fixture/socket', IMAGE, 'capture', MOUNTS, attempt=ATTEMPT)
        for scratch, driver in (({}, 'none'), ({'/tmp': 'rw,size=1g'}, 'none'),
                                ({'/tmp': 'rw,nosuid,nodev,noexec,size=64m'}, 'journald')):
            obj = inspect(session)
            obj['HostConfig']['Tmpfs'] = scratch
            obj['HostConfig']['LogConfig']['Type'] = driver
            with mock.patch.object(session, 'request', return_value=(200, json.dumps(obj).encode())):
                with self.assertRaises(runtime.RuntimeError_):
                    session.inspect()

    def test_source_mount_is_never_relabelled_or_chowned(self):
        spec = runtime.specification(IMAGE, 'fixture', 'capture',
            [('/fixture/stage', '/stage', False), ('/fixture/repo', '/source/repo', True)])
        self.assertIn('z', spec['mounts'][0]['options'])
        self.assertNotIn('z', spec['mounts'][1]['options'])
        self.assertNotIn('Z', spec['mounts'][1]['options'])
        self.assertTrue(all('U' not in mount['options'] for mount in spec['mounts']))

    def test_default_rootless_or_foreign_namespace_mapping_is_denied(self):
        session = runtime.Session('/fixture/socket', IMAGE, 'capture', MOUNTS, attempt=ATTEMPT)
        for rows in (['0:0:65537'], ['0:1:65536', '42:0:1'], ['1:0:2']):
            obj = inspect(session)
            obj['HostConfig']['IDMappings']['UidMap'] = rows
            with mock.patch.object(session, 'request', return_value=(200, json.dumps(obj).encode())):
                with self.assertRaises(runtime.RuntimeError_):
                    session.inspect()

    def test_extra_mount_or_network_refuses_cleanup_identity(self):
        session = runtime.Session('/fixture/socket', IMAGE, 'capture', MOUNTS, attempt=ATTEMPT)
        for mutation in ('mount', 'network'):
            obj = inspect(session)
            if mutation == 'mount':
                obj['Mounts'].append({'Type': 'bind', 'Source': '/fixture/private', 'Destination': '/key', 'RW': False})
            else:
                obj['HostConfig']['NetworkMode'] = 'host'
            with mock.patch.object(session, 'request', return_value=(200, json.dumps(obj).encode())):
                with self.assertRaises(runtime.RuntimeError_):
                    session.inspect()
