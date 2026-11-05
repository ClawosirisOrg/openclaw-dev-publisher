"""Dormant host-side Podman 5.8.x attach/stdin mount probe.

Only trusted host code may call probe_once with a pinned image and an already
protected stage. This is neither admission nor publication authority. A failed
or ambiguous invocation consumes the stage attempt: never retry it, even when
container cleanup was confirmed. Reconcile late creates separately by name.
"""

import json
import secrets
import select
import socket
import time

from broker.host import podman_inert_probe as _base


ProbeError = _base.ProbeError
_API = _base._API
_IO_TIMEOUT = _base._IO_TIMEOUT
_DEADLINE = _base._DEADLINE
_TOKEN = b'MOUNT_PIN_OK'
_MAX_STDOUT = 256
_MAX_HEADER = 4096
_CONFIG_KEYS = ('stage_dev', 'stage_ino', 'repository', 'ref')


def _spec(image_id, stage, name):
    spec = _base._spec(image_id, stage, name)
    spec.update(entrypoint=['/usr/local/bin/python3'],
                command=['-m', 'broker.worker.mount_probe_fixture'],
                stdin=True, terminal=False)
    return spec


def _timeout(sock, deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError()
    sock.settimeout(min(_IO_TIMEOUT, remaining))


class _Stream:
    """One bounded buffer for both HTTP headers and hijacked frames."""

    def __init__(self, sock, deadline):
        self.sock = sock
        self.deadline = deadline
        self.buffer = bytearray()

    def close(self):
        self.sock.close()

    def _recv(self, limit):
        while True:
            remaining = self.deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError()
            if not select.select([self.sock], [], [], min(_IO_TIMEOUT, remaining))[0]:
                raise TimeoutError()
            if time.monotonic() >= self.deadline:
                raise TimeoutError()
            try:
                return self.sock.recv(min(512, limit))
            except (BlockingIOError, InterruptedError):
                continue

    def line(self, limit):
        while True:
            if time.monotonic() >= self.deadline:
                raise TimeoutError()
            end = self.buffer.find(b'\n')
            if end >= 0:
                if end == 0 or self.buffer[end - 1] != 13 or end + 1 > limit:
                    raise ValueError()
                line = bytes(self.buffer[:end - 1])
                del self.buffer[:end + 1]
                return line
            if len(self.buffer) >= limit:
                raise ValueError()
            chunk = self._recv(limit - len(self.buffer))
            if not chunk:
                raise ValueError()
            self.buffer.extend(chunk)

    def take(self, size, *, eof_ok=False):
        while len(self.buffer) < size:
            if time.monotonic() >= self.deadline:
                raise TimeoutError()
            chunk = self._recv(size - len(self.buffer))
            if not chunk:
                if eof_ok and not self.buffer:
                    return b''
                raise ValueError()
            self.buffer.extend(chunk)
        if time.monotonic() >= self.deadline:
            raise TimeoutError()
        data = bytes(self.buffer[:size])
        del self.buffer[:size]
        return data


def _attach(socket_path, name, deadline):
    """Return a hijacked socket and shared header/frame stream after a strict 101.

    The caller owns and closes both resources.
    """
    sock = None
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        _timeout(sock, deadline)
        sock.connect(socket_path)
        route = (f'{_API}/containers/{name}/attach?stream=true&logs=false&'
                 'stdin=true&stdout=true&stderr=false&detachKeys=')
        request = (f'POST {route} HTTP/1.1\r\nHost: localhost\r\n'
                   'Connection: Upgrade\r\nUpgrade: tcp\r\n'
                   'Content-Length: 0\r\n\r\n').encode('ascii')
        _timeout(sock, deadline)
        sock.sendall(request)
        sock.setblocking(False)
        reader = _Stream(sock, deadline)
        remaining = _MAX_HEADER
        status = reader.line(remaining)
        remaining -= len(status) + 2
        parts = status.split(b' ', 2)
        if (len(parts) < 2 or parts[0] not in (b'HTTP/1.1', b'HTTP/1.0')
                or parts[1] != b'101' or
                (len(parts) == 3 and any(c < 32 or c > 126 for c in parts[2]))):
            raise ValueError()
        headers = {}
        while True:
            line = reader.line(remaining)
            remaining -= len(line) + 2
            if not line:
                break
            if b':' not in line:
                raise ValueError()
            key, value = line.split(b':', 1)
            key = key.strip().lower()
            if not key or key in headers or any(c < 33 or c > 126 for c in key):
                raise ValueError()
            headers[key] = value.strip().lower()
        if (b'upgrade' not in headers.get(b'connection', b'').split(b', ')
                or headers.get(b'upgrade') != b'tcp'
                or b'transfer-encoding' in headers or b'content-length' in headers):
            raise ValueError()
        return sock, reader
    except (OSError, TimeoutError, ValueError):
        if sock is not None:
            sock.close()
        raise ProbeError('attach handshake unavailable or invalid') from None


def _frames(reader):
    output = bytearray()
    while True:
        first = reader.take(1, eof_ok=True)
        if not first:
            break
        header = first + reader.take(7)
        if header[0] != 1 or header[1:4] != b'\x00' * 3:
            raise ValueError()
        length = int.from_bytes(header[4:], 'big')
        if length == 0 or length > _MAX_STDOUT - len(output):
            raise ValueError()
        output.extend(reader.take(length))
    if bytes(output) != _TOKEN:
        raise ValueError()


def _config_bytes(config):
    if (type(config) is not dict or set(config) != set(_CONFIG_KEYS)
            or any(type(config[k]) is not int or config[k] < 0 for k in _CONFIG_KEYS[:2])
            or any(type(config[k]) is not str for k in _CONFIG_KEYS[2:])):
        raise ProbeError('invalid trusted config')
    try:
        ordered = {key: config[key] for key in _CONFIG_KEYS}
        data = json.dumps(ordered, separators=(',', ':'),
                          ensure_ascii=False, allow_nan=False).encode('utf-8')
    except (TypeError, ValueError, UnicodeError, RecursionError):
        raise ProbeError('invalid trusted config') from None
    if len(data) > 1024:
        raise ProbeError('invalid trusted config')
    return len(data).to_bytes(4, 'big') + data


def probe_once(*, socket_path, image_id, stage_source, config):
    """Attempt exactly one attach probe, returning 0 only after verified cleanup.

    All inputs are trusted deployment inputs, never agent claims. The caller
    must consume its durable one-use stage permit BEFORE invoking this function.
    An exception after create may mean the worker ran; no retry is safe.
    """
    if (type(socket_path) is not str or not socket_path.startswith('/')
            or type(image_id) is not str or _base._IMAGE_ID.fullmatch(image_id) is None
            or type(stage_source) is not str or not stage_source.startswith('/')
            or '\x00' in socket_path or '\x00' in stage_source
            or len(socket_path) > 100 or len(stage_source) > 4096):
        raise ProbeError('invalid trusted probe parameters')
    payload = _config_bytes(config)
    name = 'attach-probe-' + secrets.token_hex(16)
    deadline = time.monotonic() + _DEADLINE
    status, data = _base._request(socket_path, 'GET',
                                  f'{_API}/images/{image_id}/exists', deadline=deadline)
    if status != 204 or data:
        raise ProbeError('pinned image unavailable')

    attempted = False
    created_id = None
    attach_sock = reader = None
    failure = None
    try:
        attempted = True
        status, data = _base._request(socket_path, 'POST', f'{_API}/containers/create',
                                      body=_spec(image_id, stage_source, name), deadline=deadline)
        if status != 201:
            raise ProbeError('container create uncertain')
        obj = _base._json(data)
        if (not isinstance(obj, dict) or type(obj.get('Id')) is not str
                or _base._IMAGE_ID.fullmatch(obj['Id']) is None):
            raise ProbeError('container create uncertain')
        created_id = obj['Id']
        if _base._inspect(socket_path, name, image_id, stage_source,
                          deadline, created_id) is None:
            raise ProbeError('container create uncertain')
        attach_sock, reader = _attach(socket_path, name, deadline)
        _timeout(attach_sock, deadline)
        attach_sock.sendall(payload)
        attach_sock.shutdown(socket.SHUT_WR)
        status, data = _base._request(socket_path, 'POST',
                                      f'{_API}/containers/{name}/start', deadline=deadline)
        if status != 204 or data:
            raise ProbeError('container start uncertain')
        try:
            _frames(reader)
        except (OSError, TimeoutError, ValueError):
            raise ProbeError('attach output unavailable or invalid') from None
        status, data = _base._request(socket_path, 'POST',
                                      f'{_API}/containers/{name}/wait?condition=exited',
                                      deadline=deadline)
        if status != 200 or data.strip() != b'0':
            raise ProbeError('container wait uncertain or probe failed')
    except ProbeError as exc:
        failure = exc
    except (OSError, TimeoutError):
        failure = ProbeError('attach input unavailable or invalid')
    finally:
        if reader is not None:
            reader.close()
        if attach_sock is not None:
            attach_sock.close()
        if attempted:
            try:
                identity = _base._inspect(socket_path, name, image_id, stage_source,
                                          time.monotonic() + _IO_TIMEOUT, created_id)
                if identity is not None:
                    status, data = _base._request(socket_path, 'DELETE',
                                                  f'{_API}/containers/{name}?force=true&volumes=false',
                                                  deadline=time.monotonic() + _IO_TIMEOUT)
                    report = _base._json(data) if status == 200 else None
                    if not isinstance(report, list) or len(report) != 1:
                        raise ProbeError('container cleanup uncertain')
                    if _base._inspect(socket_path, name, image_id, stage_source,
                                      time.monotonic() + _IO_TIMEOUT, identity) is not None:
                        raise ProbeError('container cleanup uncertain')
                elif failure is None:
                    raise ProbeError('container cleanup uncertain')
            except ProbeError:
                raise ProbeError('container cleanup or reconciliation uncertain') from None
    if failure is not None:
        raise failure
    return 0


def main(*_args, **_kwargs):
    raise RuntimeError('attach probe CLI disabled')


if __name__ == '__main__':
    main()
