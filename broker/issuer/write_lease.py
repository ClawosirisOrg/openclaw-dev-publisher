"""Gateway-only App lease. Never import this module into a worker image.

No token-returning API or deployment default. The trusted broker owns issuance,
private transport delivery, and revocation. This is not an agent-callable tool.
"""
import http.client
import json
import time
import urllib.error
import urllib.request

from broker.issuer import read_base as base, write_token


def _https(config, method, path, bearer, payload=None):
    if method != 'POST':
        return base._https(config, method, path, bearer, payload)
    if (path != config.token_path or payload != {
            'repositories': [config.repository_name],
            'permissions': {'contents': 'write'}} or
            type(bearer) is not str or not base._TOKEN.fullmatch(bearer)):
        raise base.IssuerError('invalid_api_target')
    request = urllib.request.Request(
        base._API + path, data=json.dumps(payload, separators=(',', ':')).encode('ascii'),
        method='POST', headers={'Authorization': 'Bearer ' + bearer,
            'Accept': 'application/vnd.github+json',
            'X-GitHub-Api-Version': '2026-03-10',
            'User-Agent': 'openclaw-scoped-publisher', 'Content-Type': 'application/json'})
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


class WriteLease:
    """One use, broker-private. Never return/store this instance in an agent API.

    enter() is intentionally absent: the only operation owns token delivery and
    discards the transport result on revocation failure. Collaborators are
    trusted host construction, not request fields or authentication substitutes.
    """
    def __init__(self, config, *, request=None, jwt=None, clock=time.time):
        if type(config) is not base.DeployConfig:
            raise base.IssuerError('invalid_deploy_config')
        self._config = config
        self._request = request or (lambda *args: _https(config, *args))
        self._jwt = jwt or (lambda: base._jwt(config, clock))
        self._clock = clock
        self._used = False

    def deliver_once(self, transport, assert_current):
        if self._used or not callable(transport) or not callable(assert_current):
            raise base.IssuerError('write_lease_already_used')
        self._used = True
        token = None
        try:
            # JWT generation precedes the final current guard; it confers no
            # repository bearer to the worker. No await between guard and POST.
            jwt = self._jwt()
            if assert_current() is not True:
                raise base.IssuerError('authorization_denied')
            grant = self._request('POST', self._config.token_path, jwt,
                {'repositories': [self._config.repository_name],
                 'permissions': {'contents': 'write'}})
            if write_token._valid_token(grant):
                token = grant['token']  # capture before checking overbroad grant
            write_token._check_grant(grant, self._config, self._clock)
            if assert_current() is not True:
                raise base.IssuerError('authorization_denied')
            return transport(token)
        finally:
            if token is not None:
                try:
                    self._request('DELETE', base._REVOKE, token)
                except BaseException:
                    # A push may already have happened. No success or automatic
                    # retry may follow an unconfirmed revocation.
                    raise base.IssuerError('revocation_uncertain_inspect_no_retry') from None
                finally:
                    token = None
