"""Offline fixture tests only; no production identity, key, credential or GitHub IO."""
import base64
import datetime
import http.client
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

SOURCE = Path(__file__).resolve().parents[2] / 'issuer' / 'read_base.py'
spec = importlib.util.spec_from_file_location('read_base_fixture', SOURCE)
issuer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(issuer)

NOW = 1_700_000_000
SHA = 'a' * 40
BEARER = 'fixture-disposable-bearer'
REPOSITORY = 'ExampleOrganization/example-repository'


def config():
    return issuer.DeployConfig(123, 456, REPOSITORY, '/fixture/private-key.pem')


def grant(**changes):
    value = {'token': BEARER, 'repository_selection': 'selected',
             'repositories': [{'full_name': REPOSITORY}],
             'permissions': {'contents': 'read', 'metadata': 'read'},
             'expires_at': datetime.datetime.fromtimestamp(
                 NOW + 1800, datetime.timezone.utc).isoformat()}
    value.update(changes)
    return value


def ref():
    return {'ref': 'refs/heads/main', 'object': {'type': 'commit', 'sha': SHA}}


class OfflineIssuerTests(unittest.TestCase):
    def run_fixture(self, response=None, main=None, revoke_error=False):
        cfg = config()
        calls = []
        def fake(method, path, bearer, payload=None):
            calls.append((method, path, bearer, payload))
            if method == 'POST':
                return response if response is not None else grant()
            if method == 'GET':
                if isinstance(main, Exception):
                    raise main
                return ref() if main is None else main
            if revoke_error:
                raise issuer.IssuerError('fixture_revoke_failed')
            return {}
        return issuer.BaseIssuer(cfg, request=fake, jwt=lambda: 'fixture-jwt',
                                 clock=lambda: NOW), calls

    def test_fixed_request_scope_and_revocation_before_sha_return(self):
        base, calls = self.run_fixture()
        self.assertEqual(base.current_main(), SHA)
        cfg = config()
        self.assertEqual(calls, [
            ('POST', cfg.token_path, 'fixture-jwt',
             {'repositories': ['example-repository'], 'permissions': {'contents': 'read'}}),
            ('GET', cfg.base_path, BEARER, None),
            ('DELETE', issuer._REVOKE, BEARER, None)])

    def test_overbroad_or_ambiguous_grants_revoke_without_read(self):
        changes = [
            {'repository_selection': 'all'},
            {'repositories': [{'full_name': 'Elsewhere/example-repository'}]},
            {'repositories': []},
            {'repositories': [{'full_name': REPOSITORY}, {'full_name': REPOSITORY}]},
            {'permissions': {'contents': 'write'}},
            {'permissions': {'contents': 'read', 'issues': 'read'}},
            {'permissions': {'contents': 'read', 'metadata': 'write'}},
            {'expires_at': '2023-11-14T22:43:20'},
            {'expires_at': datetime.datetime.fromtimestamp(
                NOW + 3701, datetime.timezone.utc).isoformat()},
            {'expires_at': datetime.datetime.fromtimestamp(
                NOW + 29, datetime.timezone.utc).isoformat()},
        ]
        for change in changes:
            with self.subTest(change=change):
                base, calls = self.run_fixture(response=grant(**change))
                with self.assertRaises(issuer.IssuerError):
                    base.current_main()
                self.assertEqual([x[0] for x in calls], ['POST', 'DELETE'])

    def test_invalid_token_never_used(self):
        for value in ('', 'bad\nvalue', 'x' * 4097):
            with self.subTest(value=value[:12]):
                base, calls = self.run_fixture(response=grant(token=value))
                with self.assertRaises(issuer.IssuerError):
                    base.current_main()
                self.assertEqual([x[0] for x in calls], ['POST'])

    def test_canonical_case_accepted(self):
        base, calls = self.run_fixture(response=grant(
            repositories=[{'full_name': REPOSITORY.lower()}]))
        self.assertEqual(base.current_main(), SHA)
        self.assertEqual(calls[-1][0], 'DELETE')

    def test_failed_read_invalid_ref_and_revoke_failure_never_return_sha(self):
        for main in (issuer.IssuerError('fixture_failed'),
                     {'ref': 'refs/heads/other', 'object': ref()['object']},
                     {'ref': 'refs/heads/main', 'object': {'type': 'tag', 'sha': SHA}},
                     {'ref': 'refs/heads/main', 'object': {'type': 'commit', 'sha': 'Z'*40}}):
            with self.subTest(main=main):
                base, calls = self.run_fixture(main=main)
                with self.assertRaises(issuer.IssuerError):
                    base.current_main()
                self.assertEqual([x[0] for x in calls], ['POST', 'GET', 'DELETE'])
        base, calls = self.run_fixture(revoke_error=True)
        with self.assertRaisesRegex(issuer.IssuerError, 'fixture_revoke_failed'):
            base.current_main()
        self.assertEqual(calls[-1][0], 'DELETE')

    def test_private_deploy_config_is_explicit_and_bounded(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'deploy.json'
            values = {'app_id': 123, 'installation_id': 456,
                      'repository': REPOSITORY, 'key_path': '/fixture/private-key.pem'}
            path.write_text(json.dumps(values), encoding='utf-8')
            path.chmod(0o600)
            loaded = issuer.load_deploy_config(path)
            self.assertEqual(loaded.repository, REPOSITORY)
            self.assertEqual(loaded.base_path,
                             '/repos/ExampleOrganization/example-repository/git/ref/heads/main')
            path.chmod(0o644)
            with self.assertRaises(issuer.IssuerError):
                issuer.load_deploy_config(path)
            path.chmod(0o600)
            path.write_text('{"app_id":1,"app_id":2}', encoding='utf-8')
            with self.assertRaises(issuer.IssuerError):
                issuer.load_deploy_config(path)
            path.write_bytes(b'x' * 4097)
            with self.assertRaises(issuer.IssuerError):
                issuer.load_deploy_config(path)
            link = Path(tmp) / 'link.json'
            link.symlink_to(path)
            with self.assertRaises(issuer.IssuerError):
                issuer.load_deploy_config(link)
        with self.assertRaises(issuer.IssuerError):
            issuer.load_deploy_config(SOURCE)
        for bad in ('../escape/repo', 'org/../../repo', 'org/repo?query', 'org//repo'):
            with self.subTest(bad=bad), self.assertRaises(issuer.IssuerError):
                issuer.DeployConfig(123, 456, bad, '/fixture/key.pem')

    def test_jwt_signs_fd_with_no_bearer_in_process_arguments(self):
        with tempfile.TemporaryDirectory() as tmp:
            key = Path(tmp) / 'fake-key.pem'
            key.write_bytes(b'fixture-nonsecret-key')
            key.chmod(0o600)
            cfg = issuer.DeployConfig(123, 456, REPOSITORY, str(key))
            with mock.patch.object(issuer.subprocess, 'run', return_value=mock.Mock(
                    stdout=b'x' * 256)) as run:
                signed = issuer._jwt(cfg, clock=lambda: NOW)
            args, kwargs = run.call_args
            self.assertEqual(args[0][:4], ['openssl', 'dgst', '-sha256', '-sign'])
            self.assertTrue(args[0][4].startswith('/proc/self/fd/'))
            self.assertEqual(kwargs['pass_fds'], (int(args[0][4].split('/')[-1]),))
            self.assertNotIn(BEARER, str(args) + str(kwargs))
            header, claims, signature = signed.split('.')
            self.assertEqual(json.loads(base64.urlsafe_b64decode(header + '=='))['alg'], 'RS256')
            self.assertEqual(json.loads(base64.urlsafe_b64decode(claims + '=='))['iss'], 123)
            self.assertEqual(len(signature), 342)
            key.chmod(0o644)
            with self.assertRaises(issuer.IssuerError):
                issuer._jwt(cfg, clock=lambda: NOW)

    def test_https_fixed_target_proxy_redirect_bound_and_truncation(self):
        cfg = config()
        with self.assertRaises(issuer.IssuerError):
            issuer._https(cfg, 'GET', '/user', BEARER)
        with self.assertRaises(issuer.IssuerError):
            issuer._https(cfg, 'POST', cfg.token_path, BEARER, {'permissions': {'contents': 'write'}})
        with self.assertRaises(issuer.IssuerError):
            issuer._NoRedirect().redirect_request(None, None, 302, '', {},
                                                    'https://other.example/token')
        class Response:
            status = 200
            def __init__(self, result): self.result = result
            def __enter__(self): return self
            def __exit__(self, *_args): pass
            def read(self, limit):
                self_outer.assertEqual(limit, 65537)
                if isinstance(self.result, Exception): raise self.result
                return self.result
        class Opener:
            def __init__(self, result): self.result = result
            def open(self, req, timeout):
                self_outer.assertEqual(timeout, 15)
                self_outer.assertEqual(req.full_url, 'https://api.github.com' + cfg.base_path)
                self_outer.assertEqual(req.get_header('Authorization'), 'Bearer ' + BEARER)
                return Response(self.result)
        self_outer = self
        for result in (b'x' * 65537, http.client.IncompleteRead(b'partial-bearer'),
                       b'{"ref":1,"ref":2}', b'{"sha":NaN}'):
            with self.subTest(result=type(result)):
                with mock.patch.object(issuer.urllib.request, 'build_opener',
                                       return_value=Opener(result)) as build:
                    with self.assertRaises(issuer.IssuerError):
                        issuer._https(cfg, 'GET', cfg.base_path, BEARER)
                    self.assertIsInstance(build.call_args.args[0], issuer.urllib.request.ProxyHandler)
                    self.assertEqual(build.call_args.args[0].proxies, {})
                    self.assertIsInstance(build.call_args.args[1], issuer._NoRedirect)


if __name__ == '__main__':
    unittest.main()
