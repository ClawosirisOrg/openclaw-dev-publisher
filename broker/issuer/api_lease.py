"""Trusted-host, one-shot GitHub API leases; never expose to an agent.

Only a trusted host transport may receive the bearer. Injected collaborators
are construction-time test seams, not an authorization boundary. No CLI,
default configuration, environment credential, or token-returning API exists.
"""
import datetime
import http.client
import json
import math
import threading
import time
import urllib.error
import urllib.request

from broker.issuer import read_base as base


READ_PERMISSIONS = {'issues': 'read', 'pull_requests': 'read', 'contents': 'read'}
_PROFILES = ({'issues': 'write'}, {'pull_requests': 'write'},
             {'issues': 'read', 'pull_requests': 'read', 'contents': 'read'})


def _permissions(value):
    if type(value) is not dict or any(type(k) is not str or type(v) is not str
                                      for k, v in value.items()):
        raise base.IssuerError('invalid_api_permissions')
    result = dict(value)
    if result.pop('metadata', 'read') != 'read' or result not in _PROFILES:
        raise base.IssuerError('invalid_api_permissions')
    return result


def _https(config, permissions, method, path, bearer, payload=None):
    """Fixed-origin, exact grant POST; revoke via the existing pinned adapter."""
    permissions = _permissions(permissions)
    if method == 'DELETE' and path == base._REVOKE:
        return base._https(config, method, path, bearer, payload)
    if (method != 'POST' or path != config.token_path or payload != {
            'repositories': [config.repository_name], 'permissions': permissions}):
        raise base.IssuerError('invalid_api_target')
    if type(bearer) is not str or not base._TOKEN.fullmatch(bearer):
        raise base.IssuerError('invalid_bearer')
    request = urllib.request.Request(
        base._API + path, data=json.dumps(payload, separators=(',', ':')).encode('ascii'),
        method='POST', headers={'Authorization': 'Bearer ' + bearer,
            'Accept': 'application/vnd.github+json',
            'X-GitHub-Api-Version': '2026-03-10',
            'User-Agent': 'openclaw-api-issuer', 'Content-Type': 'application/json'})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), base._NoRedirect())
    try:
        with opener.open(request, timeout=15) as response:
            if response.status != 201:
                raise base.IssuerError('github_status_mismatch')
            raw = response.read(65537)
            if len(raw) > 65536:
                raise base.IssuerError('github_response_too_large')
            return base._strict_json(raw)
    except (urllib.error.URLError, OSError, ValueError, http.client.HTTPException):
        raise base.IssuerError('github_request_failed') from None


def _usable_token(grant):
    return (type(grant) is dict and type(grant.get('token')) is str
            and base._TOKEN.fullmatch(grant['token']) is not None)


def _check_grant(grant, config, permissions, clock):
    if not _usable_token(grant):
        raise base.IssuerError('app_grant_mismatch')
    repositories = grant.get('repositories')
    granted = grant.get('permissions')
    if (grant.get('repository_selection') != 'selected'
            or type(repositories) is not list or len(repositories) != 1
            or type(repositories[0]) is not dict
            or type(repositories[0].get('full_name')) is not str
            or repositories[0]['full_name'].casefold() != config.repository.casefold()
            or ('repository_count' in grant and
                (type(grant['repository_count']) is not int or grant['repository_count'] != 1))
            or type(granted) is not dict
            or any(type(k) is not str or type(v) is not str for k, v in granted.items())
            or {k: v for k, v in granted.items() if k != 'metadata'} != permissions
            or granted.get('metadata', 'read') != 'read'):
        raise base.IssuerError('app_grant_mismatch')
    try:
        raw = grant['expires_at']
        if type(raw) is not str:
            raise ValueError()
        expiry = datetime.datetime.fromisoformat(raw.replace('Z', '+00:00'))
        if expiry.tzinfo is None or expiry.utcoffset() is None:
            raise ValueError()
        remaining = expiry.timestamp() - clock()
        if not math.isfinite(remaining) or not 30 <= remaining <= 3700:
            raise ValueError()
    except (KeyError, AttributeError, TypeError, ValueError, OverflowError):
        raise base.IssuerError('app_grant_mismatch') from None


class ApiLease:
    """WriteLease-compatible, broker-private delivery and confirmed revocation.

    The transport must return only sanitized host results, never a bearer or
    raw API response. A failed/uncertain revoke suppresses even successful
    delivery results; the caller must inspect rather than automatically retry.
    """
    def __init__(self, config, permissions, *, request=None, jwt=None, clock=time.time):
        if type(config) is not base.DeployConfig:
            raise base.IssuerError('invalid_deploy_config')
        self._config = config
        self._permissions = _permissions(permissions)
        self._request = request or (lambda *args: _https(config, self._permissions, *args))
        self._jwt = jwt or (lambda: base._jwt(config, clock))
        self._clock = clock
        self._used = False
        self.cleanup_confirmed = False  # credential-free fact, never a reusable permit
        self._lock = threading.Lock()

    def deliver_once(self, transport, assert_current):
        with self._lock:
            if self._used or not callable(transport) or not callable(assert_current):
                raise base.IssuerError('api_lease_already_used')
            self._used = True
        token = None
        try:
            jwt = self._jwt()
            if assert_current() is not True:
                raise base.IssuerError('authorization_denied')
            grant = self._request('POST', self._config.token_path, jwt,
                {'repositories': [self._config.repository_name],
                 'permissions': dict(self._permissions)})
            if _usable_token(grant):
                token = grant['token']  # capture denied but usable grants for revoke
            _check_grant(grant, self._config, self._permissions, self._clock)
            if assert_current() is not True:
                raise base.IssuerError('authorization_denied')
            return transport(token)
        finally:
            if token is not None:
                try:
                    self._request('DELETE', base._REVOKE, token)
                    self.cleanup_confirmed = True
                except BaseException:
                    raise base.IssuerError('revocation_uncertain_inspect_no_retry') from None
                finally:
                    token = None
