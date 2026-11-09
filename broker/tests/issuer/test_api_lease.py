"""Fake HTTP/JWT only: no credentials, private files or external IO."""
import datetime
import http.client
import json
import unittest
from unittest import mock

from broker.issuer import api_lease as api, read_base as base

NOW = 1_700_000_000
TOKEN = 'fixture-api-token'
JWT = 'fixture-app-jwt'
REPO = 'ExampleOrganization/example-repository'


def config():
    return base.DeployConfig(123, 456, REPO, '/fixture/missing.pem')


def expiry(seconds):
    return datetime.datetime.fromtimestamp(NOW + seconds, datetime.timezone.utc).isoformat()


_DEFAULT = object()


def grant(permissions=_DEFAULT, **changes):
    result = {'token': TOKEN, 'repository_selection': 'selected',
              'repositories': [{'full_name': REPO}], 'repository_count': 1,
              'permissions': {'issues': 'write'} if permissions is _DEFAULT else permissions,
              'expires_at': expiry(1800)}
    result.update(changes)
    return result


class FakeAPI:
    def __init__(self, response=None, revoke_error=None):
        self.response = grant() if response is None else response
        self.revoke_error = revoke_error
        self.calls = []

    def __call__(self, method, path, bearer, payload=None):
        self.calls.append((method, path, bearer, payload))
        if method == 'POST':
            return self.response
        if method == 'DELETE' and path == base._REVOKE:
            if self.revoke_error:
                raise self.revoke_error
            return {}
        raise AssertionError('unexpected fake API target')


class ApiLeaseTests(unittest.TestCase):
    def lease(self, request, permissions=None, **kwargs):
        return api.ApiLease(config(), permissions or {'issues': 'write'},
                            request=request, jwt=lambda: JWT, clock=lambda: NOW, **kwargs)

    def test_exact_profiles_two_guards_private_delivery_revocation_one_shot(self):
        for permissions in ({'issues': 'write'}, {'pull_requests': 'write'}, api.READ_PERMISSIONS):
            with self.subTest(permissions=permissions):
                request = FakeAPI(grant(permissions))
                lease = self.lease(request, permissions)
                guards, delivered = [], []
                def current():
                    guards.append(len(request.calls))
                    return True
                result = lease.deliver_once(lambda t: delivered.append(t) or {'ok': True}, current)
                self.assertEqual(result, {'ok': True})
                self.assertEqual(delivered, [TOKEN])
                self.assertEqual(guards, [0, 1])
                self.assertEqual(request.calls, [
                    ('POST', config().token_path, JWT, {'repositories': ['example-repository'],
                                                       'permissions': permissions}),
                    ('DELETE', base._REVOKE, TOKEN, None)])
                self.assertNotIn(TOKEN, repr(result))
                with self.assertRaises(base.IssuerError):
                    lease.deliver_once(lambda _: self.fail('second delivery'), current)
                self.assertEqual(len(request.calls), 2)

    def test_no_combined_write_contents_or_arbitrary_permission_profile(self):
        invalid = ({}, {'issues': 'read'}, {'contents': 'write'},
                   {'issues': 'write', 'pull_requests': 'write'},
                   {'issues': 'write', 'contents': 'read'},
                   {'issues': 'write', 'metadata': 'write'}, {'issues': True}, None, [], 'issues')
        for permissions in invalid:
            with self.subTest(permissions=permissions), self.assertRaises(base.IssuerError):
                api.ApiLease(config(), permissions, request=lambda *_: self.fail('request'))
        with self.assertRaises(base.IssuerError):
            api.ApiLease(object(), {'issues': 'write'})

    def test_permissions_are_copied_and_optional_metadata_read_accepted(self):
        permissions = {'issues': 'write', 'metadata': 'read'}
        request = FakeAPI(grant({'issues': 'write', 'metadata': 'read'}))
        lease = self.lease(request, permissions)
        permissions['contents'] = 'write'
        lease.deliver_once(lambda _: None, lambda: True)
        self.assertEqual(request.calls[0][3]['permissions'], {'issues': 'write'})

    def test_jwt_then_fresh_guard_and_denied_guard_consumes_lease_without_mint(self):
        request = FakeAPI()
        events = []
        lease = api.ApiLease(config(), {'issues': 'write'}, request=request,
                             jwt=lambda: events.append('jwt') or JWT, clock=lambda: NOW)
        def guard():
            events.append('guard')
            return 1  # truthy is not explicit authorization
        with self.assertRaisesRegex(base.IssuerError, 'authorization_denied'):
            lease.deliver_once(lambda _: self.fail('transport'), guard)
        self.assertEqual(events, ['jwt', 'guard'])
        self.assertEqual(request.calls, [])
        with self.assertRaises(base.IssuerError):
            lease.deliver_once(lambda _: None, lambda: True)

    def test_broadened_incomplete_ambiguous_grants_revoked_never_delivered(self):
        changes = [
            {'repository_selection': 'all'}, {'repository_selection': None},
            {'repositories': []}, {'repositories': [{'full_name': 'Other/repo'}]},
            {'repositories': [{'full_name': REPO}, {'full_name': REPO}]},
            {'repository_count': 2}, {'repository_count': True},
            {'permissions': {'issues': 'read'}},
            {'permissions': {'issues': 'write', 'pull_requests': 'write'}},
            {'permissions': {'issues': 'write', 'contents': 'read'}},
            {'permissions': {'issues': 'write', 'metadata': 'write'}},
            {'permissions': {}}, {'permissions': None},
            {'expires_at': expiry(29)}, {'expires_at': expiry(3701)},
            {'expires_at': '2023-11-14T22:43:20'}, {'expires_at': None},
        ]
        for change in changes:
            with self.subTest(change=change):
                request = FakeAPI(grant(**change))
                with self.assertRaises(base.IssuerError):
                    self.lease(request).deliver_once(lambda _: self.fail('delivery'), lambda: True)
                self.assertEqual([c[0] for c in request.calls], ['POST', 'DELETE'])

    def test_lifetime_boundaries_case_insensitive_repository_and_bad_clock(self):
        for seconds in (30, 3700):
            request = FakeAPI(grant(expires_at=expiry(seconds),
                                    repositories=[{'full_name': REPO.lower()}]))
            self.lease(request).deliver_once(lambda _: None, lambda: True)
            self.assertEqual(request.calls[-1][0], 'DELETE')
        for now in (float('nan'), float('inf')):
            request = FakeAPI()
            lease = api.ApiLease(config(), {'issues': 'write'}, request=request,
                                 jwt=lambda: JWT, clock=lambda: now)
            with self.assertRaises(base.IssuerError):
                lease.deliver_once(lambda _: self.fail('delivery'), lambda: True)
            self.assertEqual(request.calls[-1][0], 'DELETE')

    def test_invalid_token_not_delivered_or_used_for_revocation(self):
        for token in ('', 'bad\nvalue', 'x' * 4097, None, True):
            request = FakeAPI(grant(token=token))
            with self.assertRaises(base.IssuerError):
                self.lease(request).deliver_once(lambda _: self.fail('delivery'), lambda: True)
            self.assertEqual([c[0] for c in request.calls], ['POST'])

    def test_stale_guard_guard_exception_and_transport_exception_revoke(self):
        for failure in ('stale', 'guard_exception', 'transport'):
            request = FakeAPI()
            calls = []
            def guard():
                calls.append(True)
                if len(calls) == 2 and failure == 'guard_exception':
                    raise ValueError('fixture guard')
                return not (len(calls) == 2 and failure == 'stale')
            def transport(_):
                raise ValueError('fixture transport')
            with self.subTest(failure=failure), self.assertRaises((base.IssuerError, ValueError)):
                self.lease(request).deliver_once(transport, guard)
            self.assertEqual(request.calls[-1][0], 'DELETE')

    def test_revoke_uncertain_suppresses_success_or_other_failure_and_no_retry(self):
        for error in (ValueError('fixture secret detail'), KeyboardInterrupt()):
            for valid in (True, False):
                request = FakeAPI(grant(repository_selection='selected' if valid else 'all'), error)
                lease = self.lease(request)
                with self.assertRaisesRegex(base.IssuerError, '^revocation_uncertain_inspect_no_retry$'):
                    lease.deliver_once(lambda _: {'ok': True}, lambda: True)
                with self.assertRaises(base.IssuerError):
                    lease.deliver_once(lambda _: None, lambda: True)
                self.assertEqual(len(request.calls), 2)

    def test_default_collaborators_wire_production_adapter_and_signer(self):
        fake = FakeAPI()
        with mock.patch.object(api, '_https', side_effect=lambda cfg, p, *a: fake(*a)) as request, \
                mock.patch.object(base, '_jwt', return_value=JWT) as jwt:
            api.ApiLease(config(), {'issues': 'write'}, clock=lambda: NOW).deliver_once(
                lambda _: None, lambda: True)
        self.assertEqual(jwt.call_count, 1)
        self.assertEqual(request.call_count, 2)

    def test_https_rejects_nonexact_targets_profiles_payloads_and_bad_bearer(self):
        cfg = config()
        payload = {'repositories': [cfg.repository_name], 'permissions': {'issues': 'write'}}
        with mock.patch.object(api.urllib.request, 'build_opener') as build:
            for method, path, bearer, body in (
                    ('GET', cfg.base_path, JWT, None), ('POST', '/user', JWT, payload),
                    ('POST', cfg.token_path, JWT, {'repositories': ['other'], 'permissions': {'issues': 'write'}}),
                    ('POST', cfg.token_path, 'bad\nvalue', payload),
                    ('DELETE', '/other', TOKEN, None)):
                with self.assertRaises(base.IssuerError):
                    api._https(cfg, {'issues': 'write'}, method, path, bearer, body)
            build.assert_not_called()
        with mock.patch.object(base, '_https', return_value={}) as revoke:
            api._https(cfg, {'issues': 'write'}, 'DELETE', base._REVOKE, TOKEN)
            revoke.assert_called_once_with(cfg, 'DELETE', base._REVOKE, TOKEN, None)

    def test_https_pinned_origin_no_proxies_redirects_status_size_and_strict_json(self):
        cfg = config()
        payload = {'repositories': [cfg.repository_name], 'permissions': {'issues': 'write'}}
        for status, raw, succeeds in ((201, b'{"ok":true}', True), (200, b'{}', False),
                (201, b'x' * 65537, False), (201, b'{"x":1,"x":2}', False),
                (201, b'{"x":NaN}', False), (201, http.client.IncompleteRead(b'partial'), False)):
            response = mock.MagicMock()
            response.__enter__.return_value = response
            response.status = status
            if isinstance(raw, Exception):
                response.read.side_effect = raw
            else:
                response.read.return_value = raw
            opener = mock.Mock()
            opener.open.return_value = response
            with mock.patch.object(api.urllib.request, 'build_opener', return_value=opener) as build:
                if succeeds:
                    self.assertEqual(api._https(cfg, {'issues': 'write'}, 'POST', cfg.token_path, JWT, payload), {'ok': True})
                else:
                    with self.assertRaises(base.IssuerError):
                        api._https(cfg, {'issues': 'write'}, 'POST', cfg.token_path, JWT, payload)
            request = opener.open.call_args.args[0]
            self.assertEqual(request.full_url, 'https://api.github.com' + cfg.token_path)
            self.assertEqual(request.get_header('Authorization'), 'Bearer ' + JWT)
            self.assertEqual(json.loads(request.data), payload)
            self.assertEqual(opener.open.call_args.kwargs, {'timeout': 15})
            self.assertEqual(build.call_args.args[0].proxies, {})
            self.assertIsInstance(build.call_args.args[1], base._NoRedirect)
            if status == 201:
                response.read.assert_called_once_with(65537)


if __name__ == '__main__':
    unittest.main()
