"""Dormant host-only, single-use inert stage probe over a trusted Podman socket.

NOT admission, staging authority, or a publisher. Import explicitly from trusted
host code only; no CLI or default socket/image/stage is supplied. This models
Libpod 5.8.x specgen, not the Docker-compatible API or a remote Podman CLI.
The caller must separately establish socket identity, pinned image content,
stage ownership/symlink safety, and authorization before invoking this code.
No request may be retried after an ambiguous create/start/wait result. An
inspection is reconciliation, not evidence that an invocation succeeded.
"""

import http.client
import json
import re
import secrets
import socket
import time


_API = '/v5.8.0/libpod'  # Podman 5.8.x API version (server release is 5.8.7)
_IMAGE_ID = re.compile(r'[0-9a-f]{64}\Z', re.ASCII)
_MAX_REPLY = 65536
_DEADLINE = 12.0
_IO_TIMEOUT = 3.0
_MOUNT = '/stage'


class ProbeError(RuntimeError):
    """Sanitized denial; uncertain operations are never an authorization receipt."""


class _UnixHTTP(http.client.HTTPConnection):
    def __init__(self, path, timeout):
        super().__init__('localhost', timeout=timeout)
        self._socket_path = path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        try:
            self.sock.connect(self._socket_path)
        except BaseException:
            self.sock.close()
            raise


def _request(sock, method, route, *, body=None, deadline):
    """One bounded request/response; never surface transport or server text."""
    conn = None
    read_socket = None
    response = None
    try:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError()
        conn = _UnixHTTP(sock, min(_IO_TIMEOUT, remaining))
        payload = None if body is None else json.dumps(body, separators=(',', ':'),
                                                        ensure_ascii=True).encode('ascii')
        conn.request(method, route, body=payload,
                     headers={'Content-Type': 'application/json', 'Accept': 'application/json',
                              'Connection': 'close'})
        # getresponse() detaches conn.sock for a legitimate Connection: close.
        read_socket = conn.sock
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError()
        read_socket.settimeout(min(_IO_TIMEOUT, remaining))
        response = conn.getresponse()
        chunks = []
        total = 0
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError()
            # HTTPResponse may close its file (and socket) at Content-Length.
            if response.isclosed():
                break
            read_socket.settimeout(min(_IO_TIMEOUT, remaining))
            chunk = response.read(min(4096, _MAX_REPLY + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > _MAX_REPLY:
                raise ValueError()
        return response.status, b''.join(chunks)
    except (OSError, TimeoutError, ValueError, http.client.HTTPException):
        raise ProbeError('Podman response unavailable or invalid') from None
    finally:
        if response is not None:
            response.close()
        if conn is not None:
            conn.close()
        if read_socket is not None:
            read_socket.close()


def _json(data):
    try:
        return json.loads(data.decode('utf-8'))
    except (UnicodeError, ValueError):
        raise ProbeError('invalid Podman response') from None


def _spec(image_id, stage, name):
    # No user path in entrypoint, command, environment, URL, name or headers.
    # Image-declared volumes and writable tmpfs are explicitly disabled.
    return {
        'name': name, 'image': image_id, 'raw_image_name': image_id,
        'entrypoint': ['/usr/bin/stat'],
        'command': ['--format=%F', '--', _MOUNT],
        'user': '1:1', 'netns': {'nsmode': 'none'},
        'mounts': [{'type': 'bind', 'source': stage, 'destination': _MOUNT,
                    'options': ['ro', 'rbind']}],
        'read_only_filesystem': True, 'read_write_tmpfs': False,
        'image_volume_mode': 'ignore', 'cap_drop': ['ALL'],
        'no_new_privileges': True, 'privileged': False,
        'restart_policy': 'no', 'remove': False,
        'env_host': False, 'httpproxy': False, 'unsetenvall': True,
        'terminal': False, 'stdin': False, 'timeout': 5,
        'log_configuration': {'driver': 'none'},
    }


def _inspect(sock, name, image, stage, deadline, container_id=None):
    status, data = _request(sock, 'GET', f'{_API}/containers/{name}/json', deadline=deadline)
    if status == 404:
        return None
    if status != 200:
        raise ProbeError('container reconciliation failed')
    obj = _json(data)
    if not isinstance(obj, dict):
        raise ProbeError('container identity mismatch')
    mounts = obj.get('Mounts')
    if (obj.get('Name') not in (name, '/' + name)
            or obj.get('Image') != image
            or not _IMAGE_ID.fullmatch(obj.get('Id', '') if isinstance(obj.get('Id'), str) else '')
            or (container_id is not None and obj['Id'] != container_id)
            or not isinstance(mounts, list)
            or len(mounts) != 1
            or not isinstance(mounts[0], dict)
            or mounts[0].get('Type') != 'bind'
            or mounts[0].get('Source') != stage
            or mounts[0].get('Destination') != _MOUNT
            or mounts[0].get('RW') is not False):
        raise ProbeError('container identity mismatch')
    return obj['Id']


def probe_once(*, socket_path, image_id, stage_source):
    """Run ONE stat-only probe; return exit code 0, otherwise deny.

    Parameters are deployment-owned, never received from worker claims. An
    ambiguous create/start/wait remains uncertain even if cleanup succeeds.
    A create that completes server-side AFTER timed-out reconciliation can
    leave an orphan; deployment needs independent operator reconciliation.
    Failure to verify identity prevents deletion; it must be handled by a
    trusted operator, not a retry with a new name.
    """
    if (type(socket_path) is not str or not socket_path.startswith('/')
            or type(image_id) is not str or _IMAGE_ID.fullmatch(image_id) is None
            or type(stage_source) is not str or not stage_source.startswith('/')
            or '\x00' in socket_path or '\x00' in stage_source
            or len(socket_path) > 100 or len(stage_source) > 4096):
        raise ProbeError('invalid trusted probe parameters')
    name = 'inert-probe-' + secrets.token_hex(16)
    deadline = time.monotonic() + _DEADLINE
    status, data = _request(socket_path, 'GET',
                            f'{_API}/images/{image_id}/exists', deadline=deadline)
    if status != 204 or data:
        raise ProbeError('pinned image unavailable')

    attempted = False
    created_id = None
    failure = None
    try:
        attempted = True  # set BEFORE create; even a lost response may have created it
        status, data = _request(socket_path, 'POST', f'{_API}/containers/create',
                                body=_spec(image_id, stage_source, name), deadline=deadline)
        if status != 201:
            raise ProbeError('container create uncertain')
        obj = _json(data)
        if not isinstance(obj, dict) or not isinstance(obj.get('Id'), str) or not _IMAGE_ID.fullmatch(obj['Id']):
            raise ProbeError('container create uncertain')
        created_id = obj['Id']
        if _inspect(socket_path, name, image_id, stage_source, deadline, created_id) is None:
            raise ProbeError('container create uncertain')
        status, data = _request(socket_path, 'POST', f'{_API}/containers/{name}/start', deadline=deadline)
        if status != 204 or data:
            raise ProbeError('container start uncertain')
        status, data = _request(socket_path, 'POST',
                                f'{_API}/containers/{name}/wait?condition=exited', deadline=deadline)
        if status != 200 or data.strip() != b'0':
            raise ProbeError('container wait uncertain or probe failed')
    except ProbeError as exc:
        failure = exc
    finally:
        if attempted:
            try:
                # Reconcile by opaque name AND image + mount + ID before deletion.
                # No volume deletion, no force on an unverified container.
                identity = _inspect(socket_path, name, image_id, stage_source,
                                    time.monotonic() + _IO_TIMEOUT, created_id)
                if identity is not None:
                    status, data = _request(socket_path, 'DELETE',
                                            f'{_API}/containers/{name}?force=true&volumes=false',
                                            deadline=time.monotonic() + _IO_TIMEOUT)
                    # Libpod deletion returns 200 with a report; unlike the
                    # Docker-compatible route, its volume flag is 'volumes'.
                    report = _json(data) if status == 200 else None
                    if not isinstance(report, list) or len(report) != 1:
                        raise ProbeError('container cleanup uncertain')
                    if _inspect(socket_path, name, image_id, stage_source,
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
    raise RuntimeError('inert Podman probe CLI disabled')


if __name__ == '__main__':
    main()
