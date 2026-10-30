"""Fake-IO-only write protocol tests; never contact GitHub or sign a JWT."""
import datetime
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from broker.issuer import read_base as base
from broker.issuer import write_token as issuer

NOW = 1_700_000_000
REPO = 'FixtureOwner/fixture-repository'
TOKEN = 'fixture-disposable-token'
JWT = 'fixture-jwt'


def expiry(delta=1800):
    return datetime.datetime.fromtimestamp(
        NOW + delta, datetime.timezone.utc).isoformat()


def grant(**changes):
    result = {'token': TOKEN, 'repository_selection': 'selected',
              'repositories': [{'full_name': REPO}], 'repository_count': 1,
              'permissions': {'contents': 'write', 'metadata': 'read'},
              'expires_at': expiry()}
    result.update(changes)
    return result


class FakeRequest:
    def __init__(self, response=None, mint_error=None, revoke_error=None):
        self.response = grant() if response is None else response
        self.mint_error = mint_error
        self.revoke_error = revoke_error
        self.calls = []

    def __call__(self, method, path, bearer, payload=None):
        self.calls.append((method, path, bearer, payload))
        if method == 'POST':
            if self.mint_error:
                raise self.mint_error
            return self.response
        if self.revoke_error:
            raise self.revoke_error
        return {}


class OfflineWriteTests(unittest.TestCase):
    def setUp(self):
        self.cfg = base.DeployConfig(101, 202, REPO, '/fixture/nonexistent-key.pem')

    def exercise(self, request, *, verify=lambda: True, transport=None, clock=lambda: NOW):
        target = transport if transport is not None else issuer._OfflinePipeFixture()
        result = issuer._exercise_fixture(
            self.cfg, verify=verify, request=request, jwt=lambda: JWT,
            transport=target, clock=clock)
        return result, target

    def test_entrypoints_disabled_and_no_live_io(self):
        self.assertFalse(issuer.WRITE_ISSUER_ENABLED)
        with (mock.patch.object(base, '_jwt', side_effect=AssertionError('key touched')),
              mock.patch.object(base, '_https', side_effect=AssertionError('network touched'))):
            for entry in (issuer.issue, issuer.main):
                with self.subTest(entry=entry.__name__), self.assertRaisesRegex(
                        RuntimeError, 'write issuer disabled'):
                    entry('/fixture/deploy.json', callback=lambda token: token)

    def test_protected_config_loader_is_only_explicit_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'fixture-config.json'
            path.write_text(json.dumps({
                'app_id': 101, 'installation_id': 202, 'repository': REPO,
                'key_path': '/fixture/nonexistent-key.pem'}), encoding='utf-8')
            path.chmod(0o600)
            self.assertEqual(issuer.load_deploy_config(path).repository, REPO)
            path.chmod(0o644)
            with self.assertRaises(base.IssuerError):
                issuer.load_deploy_config(path)

    def test_preflight_before_mint_and_exact_fd_handoff_then_revocation(self):
        request = FakeRequest()
        events = []
        def verify():
            self.assertEqual(request.calls, [])
            events.append('verify')
            return True
        with (mock.patch.object(base, '_jwt', side_effect=AssertionError('key touched')),
              mock.patch.object(base, '_https', side_effect=AssertionError('network touched'))):
            result, transport = self.exercise(request, verify=verify)
        self.assertIsNone(result)
        self.assertEqual(events, ['verify'])
        self.assertEqual(transport.receipt,
                         (len(TOKEN), hashlib.sha256(TOKEN.encode('ascii')).hexdigest()))
        self.assertEqual(transport.deliveries, 1)
        self.assertEqual(request.calls, [
            ('POST', self.cfg.token_path, JWT,
             {'repositories': ['fixture-repository'],
              'permissions': {'contents': 'write'}}),
            ('DELETE', base._REVOKE, TOKEN, None)])

    def test_credential_free_denial_and_callback_misuse_never_mint(self):
        for verify in (lambda: False, lambda: 1):
            request = FakeRequest()
            with self.assertRaisesRegex(base.IssuerError, 'authorization_denied'):
                self.exercise(request, verify=verify)
            self.assertEqual(request.calls, [])
        request = FakeRequest()
        for transport in (lambda fd: fd, object(),
                          type('HostileSubclass', (issuer._OfflinePipeFixture,), {})()):
            with self.subTest(transport=type(transport)):
                with self.assertRaisesRegex(base.IssuerError, 'invalid_fixture_handoff'):
                    self.exercise(request, transport=transport)
        self.assertEqual(request.calls, [])
        with self.assertRaises(TypeError):
            issuer._exercise_fixture(self.cfg, verify=lambda: True, request=request,
                                     jwt=lambda: JWT, transport=lambda token: token,
                                     callback=lambda token: token)
        self.assertEqual(request.calls, [])

    def test_overbroad_ambiguous_grants_revoke_before_handoff(self):
        cases = [
            {'repository_selection': 'all'},
            {'repositories': []},
            {'repositories': [{'full_name': REPO}, {'full_name': REPO}]},
            {'repositories': [{'full_name': 'OtherOwner/fixture-repository'}]},
            {'repositories': [{'full_name': 'fixtureowner/other-repository'}]},
            {'repositories': [{'full_name': 'FixtureOwner/Fixture-Repository-Other'}]},
            {'repository_count': 2}, {'repository_count': True},
            {'permissions': {'contents': 'read'}},
            {'permissions': {'contents': 'write', 'metadata': 'write'}},
            {'permissions': {'contents': 'write', 'issues': 'read'}},
            {'permissions': {'contents': 'write', 'administration': 'read'}},
            {'expires_at': expiry(29)}, {'expires_at': expiry(3701)},
            {'expires_at': 'not-a-date'}, {'expires_at': expiry(-1)},
            {'expires_at': '2023-11-14T22:43:20'},
        ]
        for change in cases:
            with self.subTest(change=change):
                request = FakeRequest(grant(**change))
                handoff = issuer._OfflinePipeFixture()
                with self.assertRaisesRegex(base.IssuerError, 'app_grant_mismatch'):
                    self.exercise(request, transport=handoff)
                self.assertIsNone(handoff.receipt)
                self.assertEqual([call[0] for call in request.calls], ['POST', 'DELETE'])
                self.assertEqual(request.calls[-1][2], TOKEN)

    def test_canonical_repository_casing_is_same_selected_target(self):
        request = FakeRequest(grant(repositories=[{'full_name': REPO.lower()}]))
        _, handoff = self.exercise(request)
        self.assertIsNotNone(handoff.receipt)
        self.assertEqual([call[0] for call in request.calls], ['POST', 'DELETE'])

    def test_expiry_boundaries_and_invalid_token(self):
        for delta in (30, 3700):
            with self.subTest(delta=delta):
                request = FakeRequest(grant(expires_at=expiry(delta)))
                _, handoff = self.exercise(request)
                self.assertEqual(handoff.receipt,
                                 (len(TOKEN), hashlib.sha256(TOKEN.encode('ascii')).hexdigest()))
                self.assertEqual([call[0] for call in request.calls], ['POST', 'DELETE'])
        for value in ('', 'bad\nvalue', 'x' * 4097, None, True):
            with self.subTest(value=str(value)[:12]):
                request = FakeRequest(grant(token=value))
                handoff = issuer._OfflinePipeFixture()
                with self.assertRaises(base.IssuerError):
                    self.exercise(request, transport=handoff)
                self.assertIsNone(handoff.receipt)
                self.assertEqual([call[0] for call in request.calls], ['POST'])

    def test_mint_failure_and_revoke_failure(self):
        request = FakeRequest(mint_error=base.IssuerError('fixture_mint_failed'))
        with self.assertRaisesRegex(base.IssuerError, 'fixture_mint_failed'):
            self.exercise(request)
        self.assertEqual([call[0] for call in request.calls], ['POST'])
        request = FakeRequest(revoke_error=base.IssuerError('fixture_revoke_failed'))
        with self.assertRaisesRegex(base.IssuerError, 'fixture_revoke_failed'):
            self.exercise(request)
        self.assertEqual([call[0] for call in request.calls], ['POST', 'DELETE'])

    def test_handoff_failure_still_revokes(self):
        request = FakeRequest()
        target = issuer._OfflinePipeFixture()
        with mock.patch.object(issuer._OfflinePipeFixture, '_consume_fd',
                               side_effect=base.IssuerError('fixture_fd_failed')):
            with self.assertRaisesRegex(base.IssuerError, 'fixture_fd_failed'):
                self.exercise(request, transport=target)
        self.assertEqual([call[0] for call in request.calls], ['POST', 'DELETE'])
        self.assertIsNone(target.receipt)


if __name__ == '__main__':
    unittest.main()
