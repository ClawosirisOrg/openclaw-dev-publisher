"""Import-only, publication-disabled admission for one accepted Unix connection.

Trusted host code supplies an accepted socket from a private host-owned AF_UNIX
listener, expected peer PID/UID/GID, fixed repository/ref, and a protected host
ledger dirfd. Same-UID peers require an explicit isolated socket-path threat
model assertion. Neither listener provenance nor the Gateway route is proved.
The claim IDs are correlation/replay keys, never authority. No stage is created.
"""
import json
import os
import secrets
import select
import socket
import struct
import time
from types import SimpleNamespace

from broker.host.attempt_ledger import AttemptLedger
from broker.worker import claim

TIMEOUT = 5.0
DENIAL = b'publication_disabled'
_UCRED = struct.Struct('3i')  # Linux struct ucred


def _read_exact(connection, count, deadline):
    chunks = []
    while count:
        remaining = deadline - time.monotonic()
        if remaining <= 0 or not select.select([connection], [], [], remaining)[0]:
            raise ValueError('deadline')
        try:
            chunk = connection.recv(count)
        except BlockingIOError:
            continue
        if not chunk:
            raise ValueError('incomplete frame')
        chunks.append(chunk)
        count -= len(chunk)
    return b''.join(chunks)


def _read_to_eof(connection, deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0 or not select.select([connection], [], [], remaining)[0]:
        raise ValueError('deadline')
    try:
        if connection.recv(1):
            raise ValueError('trailing data')
    except BlockingIOError as exc:
        raise ValueError('deadline') from exc


def _parse(raw, repository, ref):
    body = json.loads(raw.decode('utf-8'), object_pairs_hook=claim._pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError('constant')))
    claim._validate(body, SimpleNamespace(repository=repository, ref=ref))
    if raw != json.dumps(body, ensure_ascii=False, separators=(',', ':')).encode('utf-8'):
        raise ValueError('noncanonical frame')
    return body


class PeerAdmission:
    """One-shot disabled seam; run owns/closes the accepted socket."""

    def __init__(self, connection, *, expected_pid, expected_uid, expected_gid,
                 repository, ref, ledger_dirfd, same_uid_isolated_socket=False):
        self._connection = connection
        self._pid = expected_pid
        self._uid = expected_uid
        self._gid = expected_gid
        self._repository = repository
        self._ref = ref
        self._ledger_dirfd = ledger_dirfd  # borrowed
        self._isolated = same_uid_isolated_socket
        self._used = False
        self._host_pid = os.getpid()

    def run(self):
        """Fixed nonauthorizing denial for accepted frames; otherwise close.

        Failed/ambiguous reservations are never resumed or retried. No error
        details from input or the ledger are sent to the peer.
        """
        if self._used:
            return None
        self._used = True
        connection = self._connection
        try:
            if (type(connection) is not socket.socket or
                    connection.family != socket.AF_UNIX or
                    connection.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_STREAM or
                    os.getpid() != self._host_pid or
                    type(self._pid) is not int or self._pid <= 0 or
                    type(self._uid) is not int or self._uid < 0 or
                    type(self._gid) is not int or self._gid < 0 or
                    type(self._isolated) is not bool or
                    (self._uid == os.geteuid() and not self._isolated) or
                    not claim._valid_repo(self._repository) or
                    not claim._valid_ref(self._ref)):
                return None
            # Kernel peer credentials must match BEFORE reading any bytes.
            peer = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, _UCRED.size)
            if len(peer) != _UCRED.size or _UCRED.unpack(peer) != (self._pid, self._uid, self._gid):
                return None
            ledger = AttemptLedger(self._ledger_dirfd, expected_uid=os.geteuid())
            deadline = time.monotonic() + TIMEOUT
            connection.setblocking(False)
            size = int.from_bytes(_read_exact(connection, 4, deadline), 'big')
            if not 0 < size <= claim.MAX_BODY:
                return None
            raw = _read_exact(connection, size, deadline)
            _read_to_eof(connection, deadline)
            body = _parse(raw, self._repository, self._ref)
            key = body['claimId']  # correlation/replay only
            label = 'admit-' + secrets.token_hex(16)  # host-generated audit label
            ledger.reserve(key, label)
            ledger.mark_attempted(key, label)  # fsynced before any response
            # No stage allocator, signer, source, token, or publication path.
            connection.sendall(DENIAL)
            return DENIAL.decode('ascii')
        except Exception:
            return None
        finally:
            if type(connection) is socket.socket:
                connection.close()


def main(*_args, **_kwargs):
    raise RuntimeError('host peer admission CLI disabled')


if __name__ == '__main__':
    main()
