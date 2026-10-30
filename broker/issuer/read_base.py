"""Gateway-side, fixed-target GitHub App main-base lookup; no publish capability.

Deployment must call read_main_base with a Gateway-controlled config file outside
this checkout. Injectable collaborators below exist for offline tests, not as
an authorization boundary. Never expose the installation token to an agent.
"""

import base64
import datetime
import http.client
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import time
import urllib.error
import urllib.request


_API = 'https://api.github.com'
_REVOKE = '/installation/token'
_REPO_PART = re.compile(r'[A-Za-z0-9_.-]{1,100}\Z')
_SHA = re.compile(r'[0-9a-f]{40}\Z')
_TOKEN = re.compile(r'[!-~]{1,4096}\Z')
_CHECKOUT = Path(__file__).resolve().parents[2]


class IssuerError(Exception):
    """An intentionally non-secret failure code."""


def _deny(code):
    raise IssuerError(code)


def _within_checkout(path):
    return path == _CHECKOUT or _CHECKOUT in path.parents


def _private_file(path, limit):
    """Read a bounded, owner-only, non-symlink file without following final links."""
    try:
        candidate = Path(path)
        if not candidate.is_absolute() or _within_checkout(candidate.resolve(strict=True)):
            _deny('private_file_unavailable')
        fd = os.open(candidate, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                    or stat.S_IMODE(info.st_mode) & 0o077
                    or not 1 <= info.st_size <= limit):
                _deny('private_file_unavailable')
            return fd
        except BaseException:
            os.close(fd)
            raise
    except (OSError, ValueError, RuntimeError):
        _deny('private_file_unavailable')


def _strict_json(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('duplicate')
            result[key] = value
        return result

    def reject_constant(_value):
        raise ValueError('non-finite')

    try:
        return json.loads(raw.decode('utf-8'), object_pairs_hook=unique,
                          parse_constant=reject_constant)
    except (UnicodeError, ValueError):
        _deny('invalid_json')


def _positive_id(value):
    return type(value) is int and 1 <= value <= 2**63 - 1


class DeployConfig:
    """Validated configuration from a private Gateway deployment file only."""

    def __init__(self, app_id, installation_id, repository, key_path):
        if (not _positive_id(app_id) or not _positive_id(installation_id)
                or not isinstance(repository, str) or repository.count('/') != 1):
            _deny('invalid_deploy_config')
        owner, name = repository.split('/')
        if (not _REPO_PART.fullmatch(owner) or not _REPO_PART.fullmatch(name)
                or owner in ('.', '..') or name in ('.', '..')
                or not isinstance(key_path, str) or not Path(key_path).is_absolute()
                or _within_checkout(Path(key_path).resolve(strict=False))):
            _deny('invalid_deploy_config')
        self.app_id = app_id
        self.installation_id = installation_id
        self.repository = repository
        self.repository_name = name
        self.key_path = key_path
        self.token_path = f'/app/installations/{installation_id}/access_tokens'
        self.base_path = f'/repos/{owner}/{name}/git/ref/heads/main'


def load_deploy_config(path):
    """No env/default config source; file must live outside this agent checkout."""
    fd = _private_file(path, 4096)
    try:
        with os.fdopen(fd, 'rb') as stream:
            raw = stream.read(4097)
    except OSError:
        _deny('private_file_unavailable')
    if len(raw) > 4096:
        _deny('private_file_unavailable')
    data = _strict_json(raw)
    if not isinstance(data, dict) or set(data) != {
            'app_id', 'installation_id', 'repository', 'key_path'}:
        _deny('invalid_deploy_config')
    return DeployConfig(**data)


def _b64(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b'=').decode('ascii')


def _jwt(config, clock=time.time):
    fd = _private_file(config.key_path, 16384)
    try:
        now = int(clock())
        header = _b64(b'{"alg":"RS256","typ":"JWT"}')
        claims = _b64(json.dumps({'iat': now - 30, 'exp': now + 480,
                                  'iss': config.app_id}, separators=(',', ':')).encode('ascii'))
        data = (header + '.' + claims).encode('ascii')
        # The key is opened once and passed as an fd, not re-opened by path.
        try:
            signed = subprocess.run(
                ['openssl', 'dgst', '-sha256', '-sign', f'/proc/self/fd/{fd}'],
                input=data, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                pass_fds=(fd,), close_fds=True, timeout=10, check=True)
        except (OSError, subprocess.SubprocessError):
            _deny('app_signing_failed')
        if not 128 <= len(signed.stdout) <= 1024:
            _deny('app_signing_failed')
        return data.decode('ascii') + '.' + _b64(signed.stdout)
    finally:
        os.close(fd)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        _deny('github_redirect_denied')


def _https(config, method, path, bearer, payload=None):
    if (method, path) not in {('POST', config.token_path),
                              ('GET', config.base_path), ('DELETE', _REVOKE)}:
        _deny('invalid_api_target')
    if not isinstance(bearer, str) or not _TOKEN.fullmatch(bearer):
        _deny('invalid_bearer')
    if method == 'POST':
        if payload != {'repositories': [config.repository_name],
                       'permissions': {'contents': 'read'}}:
            _deny('invalid_api_payload')
        body = json.dumps(payload, separators=(',', ':')).encode('ascii')
    elif payload is not None:
        _deny('invalid_api_payload')
    else:
        body = None
    request = urllib.request.Request(
        _API + path, data=body, method=method,
        headers={'Authorization': 'Bearer ' + bearer,
                 'Accept': 'application/vnd.github+json',
                 'X-GitHub-Api-Version': '2026-03-10',
                 'User-Agent': 'openclaw-read-base-issuer',
                 'Content-Type': 'application/json'})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
    try:
        with opener.open(request, timeout=15) as response:
            if response.status != {'POST': 201, 'GET': 200, 'DELETE': 204}[method]:
                _deny('github_status_mismatch')
            raw = response.read(65537)
            if len(raw) > 65536:
                _deny('github_response_too_large')
            return {} if method == 'DELETE' else _strict_json(raw)
    except (urllib.error.URLError, OSError, ValueError, http.client.HTTPException):
        _deny('github_request_failed')


class BaseIssuer:
    """Fixed repository from config; injected IO is for offline fixtures only."""

    def __init__(self, config, request=None, jwt=None, clock=time.time):
        if not isinstance(config, DeployConfig):
            _deny('invalid_deploy_config')
        self.config = config
        self._request = request or (lambda method, path, bearer, payload=None:
                                    _https(config, method, path, bearer, payload))
        self._jwt = jwt or (lambda: _jwt(config, clock))
        self._clock = clock

    def current_main(self):
        app_jwt = self._jwt()
        token = None
        try:
            grant = self._request('POST', self.config.token_path, app_jwt,
                                  {'repositories': [self.config.repository_name],
                                   'permissions': {'contents': 'read'}})
            # A syntactically valid token from an over-broad grant still needs revocation.
            if isinstance(grant, dict) and isinstance(grant.get('token'), str) \
                    and _TOKEN.fullmatch(grant['token']):
                token = grant['token']
            token = self._check_grant(grant)
            doc = self._request('GET', self.config.base_path, token)
            if (not isinstance(doc, dict) or doc.get('ref') != 'refs/heads/main'
                    or not isinstance(doc.get('object'), dict)
                    or doc['object'].get('type') != 'commit'
                    or not isinstance(doc['object'].get('sha'), str)
                    or not _SHA.fullmatch(doc['object']['sha'])):
                _deny('invalid_main_ref')
            return doc['object']['sha']
        finally:
            if token is not None:
                self._request('DELETE', _REVOKE, token)

    def _check_grant(self, grant):
        if (not isinstance(grant, dict) or not isinstance(grant.get('token'), str)
                or not _TOKEN.fullmatch(grant['token'])
                or grant.get('repository_selection') != 'selected'
                or not isinstance(grant.get('repositories'), list)
                or len(grant['repositories']) != 1
                or not isinstance(grant['repositories'][0], dict)
                or not isinstance(grant['repositories'][0].get('full_name'), str)
                or grant['repositories'][0]['full_name'].casefold()
                    != self.config.repository.casefold()
                or not isinstance(grant.get('permissions'), dict)
                or grant['permissions'].get('contents') != 'read'
                or set(grant['permissions']) - {'contents', 'metadata'}
                or grant['permissions'].get('metadata', 'read') != 'read'):
            _deny('app_grant_mismatch')
        try:
            value = grant['expires_at']
            if not isinstance(value, str):
                _deny('app_grant_mismatch')
            expiry = datetime.datetime.fromisoformat(value.replace('Z', '+00:00'))
            if expiry.tzinfo is None or expiry.utcoffset() is None:
                _deny('app_grant_mismatch')
            remaining = expiry.timestamp() - self._clock()
        except (KeyError, AttributeError, TypeError, ValueError, OverflowError):
            _deny('app_grant_mismatch')
        if not 30 <= remaining <= 3700:
            _deny('app_grant_mismatch')
        return grant['token']


def read_main_base(deploy_config_path):
    """Gateway entry point: returns only a verified SHA after revocation."""
    return BaseIssuer(load_deploy_config(deploy_config_path)).current_main()
