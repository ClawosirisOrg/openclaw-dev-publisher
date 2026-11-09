"""Offline readiness evidence: fabricated App API and no write grant/probe."""
import copy
import http.client
import io
import json
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

from broker.issuer import api_lease, api_readiness as ready, read_base as base
from broker.tests.issuer.test_api_lease import config, grant, NOW, JWT, TOKEN, REPO


def repository(**changes):
    doc = {'id': 789, 'full_name': REPO, 'name': REPO.split('/')[1],
           'owner': {'login': REPO.split('/')[0]},
           'archived': False, 'disabled': False, 'has_issues': True}
    doc.update(changes)
    return doc


def installation(**changes):
    doc = {'id': 456, 'app_id': 123, 'repository_selection': 'selected',
           'suspended_at': None, 'permissions': {'issues': 'write',
            'pull_requests': 'write', 'contents': 'read', 'metadata': 'read'}}
    doc.update(changes)
    return doc


class FakeAPI:
    def __init__(self):
        self.calls = []
        self.installation = installation()
        self.grant = grant(api_lease.READ_PERMISSIONS)
        self.enumeration = {'total_count': 1, 'repositories': [repository()]}
        self.metadata = repository()
        self.revoke_error = None
        self.read_error = None

    def __call__(self, method, path, bearer, payload=None):
        self.calls.append((method, path, bearer, payload))
        if (method, path) == ('GET', '/app/installations/456'):
            if bearer != JWT:
                raise AssertionError('installation must use App JWT')
            return copy.deepcopy(self.installation)
        if (method, path) == ('POST', config().token_path):
            if bearer != JWT or payload != {'repositories': ['example-repository'],
                                             'permissions': api_lease.READ_PERMISSIONS}:
                raise AssertionError('write or unpinned grant requested')
            return copy.deepcopy(self.grant)
        if bearer != TOKEN or payload is not None:
            raise AssertionError('invalid read/revoke bearer or payload')
        if method == 'GET' and self.read_error:
            raise self.read_error
        if (method, path) == ('GET', '/installation/repositories'):
            return copy.deepcopy(self.enumeration)
        if (method, path) == ('GET', '/repos/' + REPO):
            return copy.deepcopy(self.metadata)
        if (method, path) == ('DELETE', base._REVOKE):
            if self.revoke_error:
                raise self.revoke_error
            return {}
        raise AssertionError('unexpected fake API target')


class ReadinessTests(unittest.TestCase):
    def check(self, request):
        return ready.check_readiness(config(), request=request, jwt=lambda: JWT, clock=lambda: NOW)

    def test_actual_installation_grants_read_token_and_exact_repository_evidence(self):
        request = FakeAPI()
        result = self.check(request)
        self.assertTrue(result['ready'])
        self.assertEqual(result['installation_permissions'], {
            'issues': 'write', 'pull_requests': 'write', 'contents': 'read'})
        self.assertEqual(result['read_token_permissions'], api_lease.READ_PERMISSIONS)
        self.assertEqual(result['repository_id'], 789)
        self.assertEqual(result['repository'], REPO)
        self.assertEqual(result['write_probe_performed'], False)
        self.assertNotIn(TOKEN, json.dumps(result))
        self.assertNotIn(JWT, json.dumps(result))
        self.assertEqual([(c[0], c[1]) for c in request.calls], [
            ('GET', '/app/installations/456'), ('POST', config().token_path),
            ('GET', '/installation/repositories'), ('GET', '/repos/' + REPO),
            ('DELETE', base._REVOKE)])
        self.assertEqual([c[2] for c in request.calls], [JWT, JWT, TOKEN, TOKEN, TOKEN])

    def test_requested_read_permissions_cannot_prove_actual_write_grants(self):
        for field in ('issues', 'pull_requests', 'contents'):
            for value in (None, 'read' if field != 'contents' else 'none'):
                request = FakeAPI()
                if value is None:
                    del request.installation['permissions'][field]
                else:
                    request.installation['permissions'][field] = value
                with self.subTest(field=field, value=value), self.assertRaisesRegex(
                        base.IssuerError, 'installation_permissions_insufficient'):
                    self.check(request)
                # Refuse before mint, not after a write capability probe.
                self.assertEqual([c[0] for c in request.calls], ['GET'])

    def test_invalid_installation_identity_selection_suspension_fails_before_mint(self):
        for change in ({'id': 457}, {'id': True}, {'app_id': 124},
                       {'repository_selection': 'all'}, {'suspended_at': 'fixture-date'},
                       {'permissions': None}):
            request = FakeAPI()
            request.installation.update(change)
            with self.subTest(change=change), self.assertRaises(base.IssuerError):
                self.check(request)
            self.assertEqual([c[0] for c in request.calls], ['GET'])
        request = FakeAPI()
        del request.installation['suspended_at']
        with self.assertRaises(base.IssuerError):
            self.check(request)
        with self.assertRaises(base.IssuerError):
            ready.check_readiness(object(), request=lambda *_: self.fail('request'))

    def test_actual_contents_write_allowed_but_minted_read_token_still_read_only(self):
        request = FakeAPI()
        request.installation['permissions'].update({'contents': 'write', 'checks': 'write'})
        result = self.check(request)
        self.assertEqual(result['installation_permissions']['contents'], 'write')
        self.assertEqual(request.calls[1][3]['permissions'], api_lease.READ_PERMISSIONS)
        self.assertNotIn('checks', result['installation_permissions'])

    def test_overbroad_read_token_denied_and_revoked_without_repository_reads(self):
        for permissions in ({'issues': 'write', 'pull_requests': 'read', 'contents': 'read'},
                            {**api_lease.READ_PERMISSIONS, 'checks': 'read'},
                            {'contents': 'read'}):
            request = FakeAPI()
            request.grant['permissions'] = permissions
            with self.subTest(permissions=permissions), self.assertRaises(base.IssuerError):
                self.check(request)
            self.assertEqual([c[0] for c in request.calls], ['GET', 'POST', 'DELETE'])

    def test_repository_enumeration_cannot_be_missing_ambiguous_or_another_repo(self):
        invalid = ({}, {'total_count': True, 'repositories': [repository()]},
                   {'total_count': 2, 'repositories': [repository()]},
                   {'total_count': 1, 'repositories': []},
                   {'total_count': 1, 'repositories': [repository(), repository()]},
                   {'total_count': 1, 'repositories': [repository(full_name='Other/repo')]},
                   {'total_count': 1, 'repositories': [repository(id=True)]},
                   {'total_count': 1, 'repositories': [repository(owner={'login': 'Other'})]})
        for enumeration in invalid:
            request = FakeAPI()
            request.enumeration = enumeration
            with self.subTest(enumeration=enumeration), self.assertRaises(base.IssuerError):
                self.check(request)
            self.assertEqual(request.calls[-1][0], 'DELETE')
            self.assertNotIn('/repos/' + REPO, [c[1] for c in request.calls])

    def test_exact_metadata_identity_and_repository_operability_required(self):
        for changes in ({'id': 790}, {'full_name': 'Other/repo'}, {'name': 'other'},
                        {'owner': {}}, {'archived': True}, {'disabled': True},
                        {'has_issues': False}, {'archived': None}):
            request = FakeAPI()
            request.metadata.update(changes)
            with self.subTest(changes=changes), self.assertRaises(base.IssuerError):
                self.check(request)
            self.assertEqual(request.calls[-1][0], 'DELETE')

    def test_read_failure_and_revocation_uncertainty_never_report_ready(self):
        request = FakeAPI()
        request.read_error = base.IssuerError('fixture_read_failed')
        with self.assertRaisesRegex(base.IssuerError, 'fixture_read_failed'):
            self.check(request)
        self.assertEqual(request.calls[-1][0], 'DELETE')
        request = FakeAPI()
        request.revoke_error = ValueError('private fixture details')
        with self.assertRaisesRegex(base.IssuerError, '^revocation_uncertain_inspect_no_retry$'):
            self.check(request)

    def test_default_collaborators_are_production_not_disabled_fixtures(self):
        fake = FakeAPI()
        with mock.patch.object(ready, '_https', side_effect=lambda cfg, *a: fake(*a)) as request, \
                mock.patch.object(base, '_jwt', return_value=JWT) as jwt:
            result = ready.check_readiness(config(), clock=lambda: NOW)
        self.assertTrue(result['ready'])
        self.assertEqual(request.call_count, 5)
        self.assertEqual(jwt.call_count, 2)

    def test_main_requires_explicit_protected_config_and_outputs_sanitized_evidence(self):
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(base, 'load_deploy_config', return_value=config()) as load, \
                mock.patch.object(ready, 'check_readiness', return_value={'ready': True}) as check, \
                redirect_stdout(out), redirect_stderr(err):
            self.assertEqual(ready.main(['--config', '/fixture/protected-app.json']), 0)
        load.assert_called_once_with('/fixture/protected-app.json')
        self.assertEqual(check.call_count, 1)
        self.assertEqual(json.loads(out.getvalue()), {'ready': True})
        self.assertEqual(err.getvalue(), '')
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            ready.main([])
        for error in (base.IssuerError('installation_permissions_insufficient'),
                      ValueError('do not disclose fixture secret')):
            out, err = io.StringIO(), io.StringIO()
            with mock.patch.object(base, 'load_deploy_config', side_effect=error), \
                    redirect_stdout(out), redirect_stderr(err):
                self.assertEqual(ready.main(['--config', '/fixture/protected-app.json']), 1)
            self.assertEqual(out.getvalue(), '')
            self.assertFalse(json.loads(err.getvalue())['ready'])
            self.assertNotIn('fixture secret', err.getvalue())

    def test_https_only_pinned_read_targets_and_narrow_read_grant_adapter(self):
        cfg = config()
        with mock.patch.object(ready.urllib.request, 'build_opener') as build:
            for method, path, bearer, payload in (
                    ('GET', '/user', JWT, None),
                    ('GET', '/app/installations/999', JWT, None),
                    ('GET', '/installation/repositories?page=2', TOKEN, None),
                    ('GET', '/repos/Other/repo', TOKEN, None),
                    ('GET', '/repos/' + REPO, TOKEN, {}),
                    ('GET', '/repos/' + REPO, 'bad\nvalue', None),
                    ('PATCH', '/repos/' + REPO, TOKEN, {}),
                    ('POST', cfg.token_path, JWT, {'repositories': [cfg.repository_name],
                                                  'permissions': {'issues': 'write'}})):
                with self.assertRaises(base.IssuerError):
                    ready._https(cfg, method, path, bearer, payload)
            build.assert_not_called()
        with mock.patch.object(api_lease, '_https', return_value={}) as delegated:
            ready._https(cfg, 'DELETE', base._REVOKE, TOKEN)
            delegated.assert_called_once_with(cfg, api_lease.READ_PERMISSIONS,
                                               'DELETE', base._REVOKE, TOKEN, None)

    def test_https_fixed_origin_proxy_redirect_status_size_and_json_controls(self):
        cfg = config()
        for path in ('/app/installations/456', '/installation/repositories', '/repos/' + REPO):
            for status, raw, succeeds in ((200, b'{"ok":true}', True), (201, b'{}', False),
                    (200, b'x' * 65537, False), (200, b'{"x":1,"x":2}', False),
                    (200, b'{"x":NaN}', False), (200, http.client.IncompleteRead(b'x'), False)):
                response = mock.MagicMock()
                response.__enter__.return_value = response
                response.status = status
                if isinstance(raw, Exception):
                    response.read.side_effect = raw
                else:
                    response.read.return_value = raw
                opener = mock.Mock()
                opener.open.return_value = response
                with mock.patch.object(ready.urllib.request, 'build_opener', return_value=opener) as build:
                    if succeeds:
                        self.assertEqual(ready._https(cfg, 'GET', path, JWT), {'ok': True})
                    else:
                        with self.assertRaises(base.IssuerError):
                            ready._https(cfg, 'GET', path, JWT)
                req = opener.open.call_args.args[0]
                self.assertEqual(req.full_url, 'https://api.github.com' + path)
                self.assertEqual(req.get_method(), 'GET')
                self.assertEqual(opener.open.call_args.kwargs, {'timeout': 15})
                self.assertEqual(build.call_args.args[0].proxies, {})
                self.assertIsInstance(build.call_args.args[1], base._NoRedirect)
                if status == 200:
                    response.read.assert_called_once_with(65537)


if __name__ == '__main__':
    unittest.main()
