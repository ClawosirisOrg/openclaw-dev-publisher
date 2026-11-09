"""Read-only App grant evidence, runnable as python -m broker.issuer.api_readiness.

The explicit --config is a protected host deployment JSON, never an agent
request field. This worker mints only a narrowly scoped read token. It checks
actual installation permissions with an App JWT, not requested token scopes;
it performs no issue/PR mutations or write-grant probes. Evidence is a point-
in-time snapshot, not authorization for a later publication.
"""
import argparse
import http.client
import json
import sys
import time
import urllib.error
import urllib.request

from broker.issuer import api_lease, read_base as base


def _https(config, method, path, bearer, payload=None):
    if method != 'GET':
        return api_lease._https(config, api_lease.READ_PERMISSIONS,
                                method, path, bearer, payload)
    allowed = {f'/app/installations/{config.installation_id}',
               '/installation/repositories', f'/repos/{config.repository}'}
    if path not in allowed or payload is not None:
        raise base.IssuerError('invalid_api_target')
    if type(bearer) is not str or not base._TOKEN.fullmatch(bearer):
        raise base.IssuerError('invalid_bearer')
    request = urllib.request.Request(base._API + path, method='GET', headers={
        'Authorization': 'Bearer ' + bearer, 'Accept': 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2026-03-10', 'User-Agent': 'openclaw-api-readiness'})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), base._NoRedirect())
    try:
        with opener.open(request, timeout=15) as response:
            if response.status != 200:
                raise base.IssuerError('github_status_mismatch')
            raw = response.read(65537)
            if len(raw) > 65536:
                raise base.IssuerError('github_response_too_large')
            return base._strict_json(raw)
    except (urllib.error.URLError, OSError, ValueError, http.client.HTTPException):
        raise base.IssuerError('github_request_failed') from None


def _installation(doc, config):
    if (type(doc) is not dict or type(doc.get('id')) is not int
            or doc['id'] != config.installation_id or type(doc.get('app_id')) is not int
            or doc['app_id'] != config.app_id
            or doc.get('repository_selection') != 'selected'
            or 'suspended_at' not in doc or doc['suspended_at'] is not None
            or type(doc.get('permissions')) is not dict):
        raise base.IssuerError('installation_grant_mismatch')
    permissions = doc['permissions']
    if (permissions.get('issues') != 'write'
            or permissions.get('pull_requests') != 'write'
            or permissions.get('contents') not in ('read', 'write')
            or permissions.get('metadata', 'read') != 'read'):
        raise base.IssuerError('installation_permissions_insufficient')
    # Return only explicitly inspected, relevant grant evidence, never raw docs.
    return {key: permissions[key] for key in ('issues', 'pull_requests', 'contents')}


def _repository(doc, config):
    owner, name = config.repository.split('/')
    if (type(doc) is not dict or not base._positive_id(doc.get('id'))
            or type(doc.get('full_name')) is not str
            or doc['full_name'].casefold() != config.repository.casefold()
            or type(doc.get('name')) is not str or doc['name'].casefold() != name.casefold()
            or type(doc.get('owner')) is not dict
            or type(doc['owner'].get('login')) is not str
            or doc['owner']['login'].casefold() != owner.casefold()):
        raise base.IssuerError('repository_evidence_mismatch')
    return doc['id']


def check_readiness(config, *, request=None, jwt=None, clock=time.time):
    """Return sanitized actual-grant evidence only after confirmed revocation.

    A valid read token alone is insufficient: the App-authenticated installation
    must actually grant both write permissions. The token's exact repository
    enumeration is cross-checked against the fixed repository metadata ID.
    """
    if type(config) is not base.DeployConfig:
        raise base.IssuerError('invalid_deploy_config')
    request = request or (lambda *args: _https(config, *args))
    jwt = jwt or (lambda: base._jwt(config, clock))
    installation_path = f'/app/installations/{config.installation_id}'
    actual = _installation(request('GET', installation_path, jwt()), config)

    def inspect(token):
        enumeration = request('GET', '/installation/repositories', token)
        if (type(enumeration) is not dict or type(enumeration.get('total_count')) is not int
                or enumeration['total_count'] != 1
                or type(enumeration.get('repositories')) is not list
                or len(enumeration['repositories']) != 1):
            raise base.IssuerError('repository_evidence_mismatch')
        repository_id = _repository(enumeration['repositories'][0], config)
        metadata = request('GET', f'/repos/{config.repository}', token)
        if (_repository(metadata, config) != repository_id
                or metadata.get('archived') is not False
                or metadata.get('disabled') is not False
                or metadata.get('has_issues') is not True):
            raise base.IssuerError('repository_not_api_ready')
        return {'ready': True, 'app_id': config.app_id,
                'installation_id': config.installation_id,
                'repository': config.repository, 'repository_id': repository_id,
                'repository_selection': 'selected',
                'installation_permissions': actual,
                'read_token_permissions': dict(api_lease.READ_PERMISSIONS),
                'evidence': ['app_installation', 'token_repository_enumeration',
                             'repository_metadata'],
                'write_probe_performed': False}

    return api_lease.ApiLease(config, api_lease.READ_PERMISSIONS, request=request,
                             jwt=jwt, clock=clock).deliver_once(inspect, lambda: True)


def main(argv=None):
    parser = argparse.ArgumentParser(description='Read-only GitHub App API grant readiness')
    parser.add_argument('--config', required=True, help='protected host App JSON path')
    args = parser.parse_args(argv)
    try:
        evidence = check_readiness(base.load_deploy_config(args.config))
    except base.IssuerError as error:
        # These modules raise only fixed non-secret codes; never print raw HTTP.
        print(json.dumps({'ready': False, 'error': str(error)}), file=sys.stderr)
        return 1
    except Exception:
        print('{"ready": false, "error": "readiness_failed"}', file=sys.stderr)
        return 1
    print(json.dumps(evidence, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
