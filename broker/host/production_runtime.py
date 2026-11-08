"""Trusted Podman 5.8 runtime; no agent-callable endpoint or default socket.

Every session has an opaque host-generated name, immutable image ID, exact
mounts and UID, no logs, a bounded private attach channel, and verified cleanup.
Only this module's fixed operations are allowed. The broker must reserve its
attempt durably BEFORE constructing a session. Never retry an uncertain create.
"""
import json
import secrets
import socket
import time

from broker.host import podman_inert_probe as api, podman_attach_probe as attach
from broker.worker import production as protocol
from broker.worker.isolation import require_owner_mapping


class RuntimeError_(RuntimeError):
    pass


def specification(image, name, operation, mounts, network=None):
    if operation not in ('capture', 'reverify', 'transport'):
        raise RuntimeError_('invalid worker operation')
    transport = operation == 'transport'
    if transport != (network is not None):
        raise RuntimeError_('invalid worker network')
    spec = api._spec(image, '/unused', name)
    spec.update(entrypoint=['/usr/local/bin/python3'],
        command=['-B', '-m', 'broker.transport.production'] if transport else
                ['-B', '-m', 'broker.worker.production', operation],
        mounts=[{'type': 'bind', 'source': source, 'destination': destination,
                 'options': ['ro' if readonly else 'rw', 'rbind', 'nosuid', 'nodev'] +
                            (['z'] if destination in ('/stage', '/store') else [])}
                for source, destination, readonly in mounts] +
               [{'type': 'tmpfs', 'source': 'tmpfs', 'destination': '/tmp',
                 'options': ['rw', 'nosuid', 'nodev', 'noexec', 'size=67108864', 'mode=1777']}],
        stdin=True, init=False, timeout=180, work_dir='/opt/publisher',
        userns={'nsmode': 'keep-id', 'value': 'uid=1,gid=1'},
        pidns={'nsmode': 'private'}, ipcns={'nsmode': 'private'},
        utsns={'nsmode': 'private'}, cgroupns={'nsmode': 'private'},
        resource_limits={'pids': {'limit': 128}, 'memory': {'limit': 805306368}})
    if transport:
        spec.update(netns={'nsmode': 'bridge'}, networks={network: {}})
    return spec


class Session:
    """Host-owned one-shot container and private attach. No request overrides."""
    def __init__(self, socket_path, image, operation, mounts, *, network=None, attempt):
        self.socket_path, self.image, self.operation = socket_path, image, operation
        self.mounts, self.network = tuple(mounts), network
        if type(attempt) is not str or not protocol.claim.ID.fullmatch(attempt):
            raise RuntimeError_('invalid durable attempt key')
        self.name = 'publisher-' + attempt + '-' + operation
        self.identity = None
        self.sock = self.reader = None
        self.buffer = bytearray()
        self.output = 0
        self.deadline = time.monotonic() + 180.0
        self.terminated = False
        self.attempted = False

    def request(self, method, suffix, *, body=None, cleanup=False):
        return api._request(self.socket_path, method, api._API + suffix, body=body,
            deadline=time.monotonic() + 3.0 if cleanup else self.deadline)

    def inspect(self, *, cleanup=False):
        status, raw = self.request('GET', '/containers/' + self.name + '/json', cleanup=cleanup)
        if status == 404:
            return None
        if status != 200:
            raise RuntimeError_('worker reconciliation uncertain')
        obj = api._json(raw)
        host = obj.get('HostConfig', {})
        config = obj.get('Config', {})
        mounts = obj.get('Mounts')
        expected = {(a, b, not c) for a, b, c in self.mounts}
        if (obj.get('Name') not in (self.name, '/' + self.name) or
                obj.get('Image') != self.image or
                type(obj.get('Id')) is not str or not api._IMAGE_ID.fullmatch(obj['Id']) or
                (self.identity is not None and obj['Id'] != self.identity) or
                type(mounts) is not list or len(mounts) != len(expected) or
                any(type(m) is not dict or m.get('Type') != 'bind' or
                    (m.get('Source'), m.get('Destination'), m.get('RW')) not in expected
                    for m in mounts) or
                config.get('User') != '1:1' or host.get('Privileged') is not False or
                host.get('ReadonlyRootfs') is not True or
                any(field not in obj for field in ('EffectiveCaps', 'BoundingCaps')) or
                obj.get('EffectiveCaps') not in (None, []) or obj.get('BoundingCaps') not in (None, []) or
                host.get('CapAdd') not in (None, []) or host.get('UsernsMode') != 'private' or
                'no-new-privileges' not in host.get('SecurityOpt', []) or
                host.get('PidMode') != 'private' or host.get('IpcMode') != 'private' or
                host.get('UTSMode') != 'private'):
            raise RuntimeError_('worker isolation mismatch')
        # Git SSH signature verification needs private writable scratch.
        # Libpod excludes tmpfs from Mounts and reports it in HostConfig.Tmpfs.
        scratch = host.get('Tmpfs')
        if type(scratch) is not dict or set(scratch) != {'/tmp'} or type(scratch['/tmp']) is not str:
            raise RuntimeError_('private worker scratch unavailable')
        options = set(scratch['/tmp'].split(','))
        if not {'rw', 'nosuid', 'nodev', 'noexec'}.issubset(options) or 'ro' in options:
            raise RuntimeError_('private worker scratch mismatch')
        sizes = [option.split('=', 1)[1].lower() for option in options if option.startswith('size=')]
        if len(sizes) != 1 or sizes[0] not in ('67108864', '65536k', '64m'):
            raise RuntimeError_('private worker scratch unbounded')
        if host.get('LogConfig', {}).get('Type') != 'none':
            raise RuntimeError_('worker logging must be disabled')
        # Inspect reports keep-id as UsernsMode=private and IDMappings in the
        # rootless parent namespace, not a keep-id mode string (Podman 5.8.7).
        maps = host.get('IDMappings')
        if type(maps) is not dict or set(maps) != {'UidMap', 'GidMap'}:
            raise RuntimeError_('worker owner mapping unavailable')
        for kind in ('UidMap', 'GidMap'):
            if type(maps[kind]) is not list or any(type(row) is not str for row in maps[kind]):
                raise RuntimeError_('worker owner mapping unavailable')
            try:
                require_owner_mapping('\n'.join(maps[kind]), 1)
            except ValueError:
                raise RuntimeError_('worker owner mapping mismatch') from None
        if self.network is None:
            if host.get('NetworkMode') != 'none':
                raise RuntimeError_('worker network mismatch')
        elif (set(obj.get('NetworkSettings', {}).get('Networks', {})) != {self.network} or
              host.get('NetworkMode') == 'host'):
            raise RuntimeError_('worker network mismatch')
        return obj['Id']

    def __enter__(self):
        try:
            status, raw = self.request('GET', '/info')
            info = api._json(raw) if status == 200 else {}
            if info.get('host', {}).get('security', {}).get('rootless') is not True:
                raise RuntimeError_('rootless runtime unavailable')
            status, raw = self.request('GET', '/images/' + self.image + '/exists')
            if status != 204 or raw:
                raise RuntimeError_('pinned worker image unavailable')
            self.attempted = True
            status, raw = self.request('POST', '/containers/create', body=specification(
                self.image, self.name, self.operation, self.mounts, self.network))
            obj = api._json(raw)
            if status != 201 or type(obj.get('Id')) is not str or not api._IMAGE_ID.fullmatch(obj['Id']):
                raise RuntimeError_('worker create uncertain')
            self.identity = obj['Id']
            if self.inspect() is None:
                raise RuntimeError_('worker create uncertain')
            self.sock, self.reader = attach._attach(self.socket_path, self.name, self.deadline)
            status, raw = self.request('POST', '/containers/' + self.name + '/start')
            if status != 204 or raw:
                raise RuntimeError_('worker start uncertain')
            # Check the active namespace/network and mounts as well as config.
            if self.inspect() is None:
                raise RuntimeError_('worker start uncertain')
            if self.receive() != {'ready': self.operation, 'mapping': 'rootless-owner'}:
                raise RuntimeError_('worker namespace self-check failed')
            return self
        except BaseException:
            self.close()
            raise

    def send(self, body):
        attach._timeout(self.sock, self.deadline)
        self.sock.sendall(protocol.encode(body))

    def chunk(self):
        first = self.reader.take(1, eof_ok=True)
        if not first:
            return b''
        header = first + self.reader.take(7)
        if header[0] != 1 or header[1:4] != b'\0' * 3:
            raise RuntimeError_('invalid worker output')
        size = int.from_bytes(header[4:], 'big')
        self.output += size
        if not 0 < size <= 16384 or self.output > 32768:
            raise RuntimeError_('invalid worker output')
        return self.reader.take(size)

    def take(self, count):
        while len(self.buffer) < count:
            chunk = self.chunk()
            if not chunk:
                raise RuntimeError_('truncated worker output')
            self.buffer.extend(chunk)
        data = bytes(self.buffer[:count])
        del self.buffer[:count]
        return data

    def receive(self):
        size = int.from_bytes(self.take(4), 'big')
        if not 0 < size <= protocol.LIMIT:
            raise RuntimeError_('invalid worker frame')
        raw = self.take(size)
        try:
            body = json.loads(raw.decode('ascii'), object_pairs_hook=protocol.claim._pairs)
            if protocol.encode(body)[4:] != raw:
                raise ValueError()
        except (ValueError, UnicodeError):
            raise RuntimeError_('invalid worker frame') from None
        return body

    def finish(self):
        self.sock.shutdown(socket.SHUT_WR)
        if self.buffer or self.chunk():
            raise RuntimeError_('trailing worker output')
        status, raw = self.request('POST', '/containers/' + self.name + '/wait?condition=exited')
        if status != 200 or raw.strip() != b'0':
            raise RuntimeError_('worker failed or exit uncertain')

    def close(self):
        if self.reader is not None:
            self.reader.close()
        if self.sock is not None:
            self.sock.close()
        if not self.attempted:
            self.terminated = True
            return
        identity = self.inspect(cleanup=True)
        if identity is None:
            # With a lost create response, absence now cannot exclude a late
            # create. Keep the stage mounted path permanently quarantined.
            if self.identity is None:
                raise RuntimeError_('late worker create uncertain; inspect no retry')
            self.terminated = True
            return
        status, raw = self.request('DELETE', '/containers/' + self.name + '?force=true&volumes=false', cleanup=True)
        report = api._json(raw) if status == 200 else None
        if (type(report) is not list or len(report) != 1 or
                self.inspect(cleanup=True) is not None):
            raise RuntimeError_('worker cleanup uncertain; inspect no retry')
        self.terminated = True

    def __exit__(self, *_args):
        self.close()
