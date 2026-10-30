"""Dormant write-grant protocol; NOT an operational credential issuer.

The only public entrypoint is disabled. The underscored fixture exercise uses
caller-supplied fake IO and an in-process pipe model, which cannot authenticate
its caller or isolate a real bearer from the agent. Never substitute live IO.
A production implementation needs a trusted, separately isolated transport and
credential-free authorization verifier before any mint operation.
"""

import datetime
import hashlib
import math
import os
import stat
import time

from broker.issuer import read_base as base


WRITE_ISSUER_ENABLED = False
IssuerError = base.IssuerError
_REVOKE = base._REVOKE


def issue(*_args, **_kwargs):
    """Unconditionally disabled, including when passed a deployment path."""
    raise RuntimeError('write issuer disabled: trusted transport and invocation absent')


def main(*_args, **_kwargs):
    """No CLI or live network/key entrypoint."""
    raise RuntimeError('write issuer disabled: trusted transport and invocation absent')


def load_deploy_config(path):
    """Use read_base's protected, owner-only, outside-checkout file parser.

    Only trusted deployment code may choose the path; this does NOT authorize
    issuance. There is no environment or checked-in default configuration.
    """
    return base.load_deploy_config(path)


def _deny(code):
    raise IssuerError(code)


def _valid_token(grant):
    value = grant.get('token') if isinstance(grant, dict) else None
    return type(value) is str and base._TOKEN.fullmatch(value) is not None


def _check_grant(grant, config, clock):
    """Check the exact selected repository, minimal permissions and lifetime."""
    if not isinstance(config, base.DeployConfig) or not _valid_token(grant):
        _deny('app_grant_mismatch')
    repositories = grant.get('repositories')
    permissions = grant.get('permissions')
    if (type(grant.get('repository_selection')) is not str
            or grant['repository_selection'] != 'selected'
            or type(repositories) is not list or len(repositories) != 1
            or type(repositories[0]) is not dict
            or type(repositories[0].get('full_name')) is not str
            or repositories[0]['full_name'].casefold() != config.repository.casefold()
            or ('repository_count' in grant and
                (type(grant['repository_count']) is not int
                 or grant['repository_count'] != 1))
            or type(permissions) is not dict
            or type(permissions.get('contents')) is not str
            or permissions['contents'] != 'write'
            or set(permissions) - {'contents', 'metadata'}
            or type(permissions.get('metadata', 'read')) is not str
            or permissions.get('metadata', 'read') != 'read'):
        _deny('app_grant_mismatch')
    try:
        raw = grant['expires_at']
        if type(raw) is not str:
            _deny('app_grant_mismatch')
        expiry = datetime.datetime.fromisoformat(raw.replace('Z', '+00:00'))
        if expiry.tzinfo is None or expiry.utcoffset() is None:
            _deny('app_grant_mismatch')
        remaining = expiry.timestamp() - clock()
        if not math.isfinite(remaining) or not 30 <= remaining <= 3700:
            _deny('app_grant_mismatch')
    except (KeyError, AttributeError, TypeError, ValueError, OverflowError):
        _deny('app_grant_mismatch')
    return grant['token']


class _OfflinePipeFixture:
    """Test-only synchronous FIFO reader. NOT a protected worker or transport.

    In-process code can inspect this object or the pipe; using real credentials
    here would disclose them. No callback or arbitrary consumer is accepted.
    """

    def __init__(self):
        self.receipt = None  # length and digest only; never expose bearer bytes
        self.deliveries = 0

    def _consume_fd(self, fd):
        if self.deliveries or not stat.S_ISFIFO(os.fstat(fd).st_mode):
            _deny('invalid_fixture_handoff')
        self.deliveries += 1
        digest = hashlib.sha256()
        size = 0
        while True:
            chunk = os.read(fd, 4097 - size)
            if not chunk:
                break
            size += len(chunk)
            if size > 4096:
                _deny('invalid_fixture_handoff')
            digest.update(chunk)
        self.receipt = (size, digest.hexdigest())


def _exercise_fixture(config, *, verify, request, jwt, transport, clock=time.time):
    """OFFLINE FAKE-IO ONLY: preflight, mint, validate, pipe, revoke.

    verify is credential-free and called before JWT/request. Its truth is NOT
    authenticated here. request/jwt and the fixture pipe are not isolation or
    authority boundaries. This function must never be wired to live services.
    Returns no credential (or transport result); revocation errors fail closed.
    """
    if (not isinstance(config, base.DeployConfig)
            or type(transport) is not _OfflinePipeFixture
            or not callable(verify) or not callable(request)
            or not callable(jwt) or not callable(clock)):
        _deny('invalid_fixture_handoff')
    if verify() is not True:
        _deny('authorization_denied')
    token = None
    try:
        grant = request('POST', config.token_path, jwt(),
                        {'repositories': [config.repository_name],
                         'permissions': {'contents': 'write'}})
        # Capture a syntactically usable bearer before denying an overbroad
        # response, so even denied grants are revoked in finally.
        if _valid_token(grant):
            token = grant['token']
        _check_grant(grant, config, clock)
        # Model an FD-only handoff, never a bearer argument or return value.
        # This process-local fixture is NOT safe for real credential transfer.
        read_fd, write_fd = os.pipe2(os.O_CLOEXEC)
        try:
            try:
                data = token.encode('ascii')
                offset = 0
                while offset < len(data):
                    offset += os.write(write_fd, data[offset:])
            finally:
                os.close(write_fd)
            # The issuer retains descriptor ownership, including on a failed
            # or maliciously replaced fixture reader.
            transport._consume_fd(read_fd)
        finally:
            if read_fd is not None:
                os.close(read_fd)
    finally:
        if token is not None:
            request('DELETE', _REVOKE, token)


if __name__ == '__main__':
    main()
