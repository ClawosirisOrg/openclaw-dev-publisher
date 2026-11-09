"""Operational composition, real local Git+SSH, fake container/HTTP boundaries.

This proves control flow and byte/object semantics, NOT live namespace isolation,
App installation scope or a deployed Gateway. No external endpoint is contacted.
"""
from collections import deque
from dataclasses import asdict, replace
import datetime
import json
import os
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest import mock

from broker.host import production as host
from broker.issuer import read_base
from broker.issuer.write_lease import WriteLease
from broker.tests.worker import test_offline as fixture
from broker.worker import production as worker, verifier
from broker.transport.production import create_once


class ProductionComposition(unittest.TestCase):
    commit = fixture.Fixture.commit

    def setUp(self):
        fixture.Fixture.setUp(self)
        self.policy = replace(self.config, branch_prefix='dev-syn')
        self.stage_root = self.root / 'stages'
        self.ledger_root = self.root / 'ledger'
        self.stage_root.mkdir(mode=0o700)
        self.ledger_root.mkdir(mode=0o700)
        self.remote = self.root / 'remote.git'
        fixture.run('git', 'init', '-q', '--bare', str(self.remote))
        fixture.run('git', '--git-dir=' + str(self.remote), 'fetch', str(self.repo),
                    self.base + ':refs/heads/main')
        self.data = {'stage_root': str(self.stage_root), 'ledger_root': str(self.ledger_root),
            'stage_host_root': str(self.stage_root), 'source_host': str(self.repo),
            'source_device': self.repo.stat().st_dev, 'source_inode': self.repo.stat().st_ino,
            'runtime_socket': '/fixture/socket', 'image_id': 'a' * 64,
            'transport_network': 'fixture-egress', 'approved_branch': 'dev-syn/composed'}
        self.app = read_base.DeployConfig(101, 202, self.config.repository, '/fixture/missing.pem')
        self.body = {'attempt': 'd' * 32, 'sha': self.invocation.sha,
            'branch': 'dev-syn/composed', 'model': self.invocation.model, 'thinking': 'off'}
        self.publication_key = host.publication_key(self.app.repository, self.body['branch'])
        self.events = []
        self.uncertain_create = False
        self.base_issuer = SimpleNamespace(current_main=lambda: self.base)
        self.fail_reverify = False
        self.deny_phase = None

    def exercise(self):
        owner = self
        class Guard:
            def check(self, phase):
                owner.events.append(phase)
                if phase == owner.deny_phase:
                    raise ValueError('stale invocation')
                return True
        class Session:
            def __init__(self, socket, image, operation, mounts, **kwargs):
                self.operation, self.mounts = operation, mounts
                self.outputs = deque()
                self.terminated = False
                self.initial = None
            def __enter__(self):
                owner.events.append('start-' + self.operation)
                return self
            def __exit__(self, *args):
                self.terminated = True
                owner.events.append('stop-' + self.operation)
            def send(self, body):
                if self.operation == 'capture':
                    value = worker.capture(body, stage_path=self.mounts[0][0], source_path=str(Path(self.mounts[1][0]).parent))
                    self.outputs.append(value)
                elif self.operation == 'reverify':
                    if owner.fail_reverify:
                        raise ValueError('independent verify failed')
                    self.outputs.append(worker.reverify(body, stage_path=self.mounts[0][0]))
                elif self.initial is None:
                    owner.events.append('token-delivery')
                    owner.assertEqual(body.pop('token'), 'fixture-scoped-token')
                    self.initial = body
                    self.outputs.append({'guard': 'create'})
                else:
                    owner.assertEqual(body, {'allow': 'create'})
                    request = self.initial
                    store = self.mounts[0][0]
                    target = SimpleNamespace(remote=str(owner.remote))
                    def call(operation, ref, sha=None, expected_old=None):
                        if operation in ('main', 'branch'):
                            return verifier.git(store, 'ls-remote', str(owner.remote), ref)
                        owner.events.append('local-create')
                        if expected_old and getattr(owner, 'race_update', False):
                            fixture.run('git', '--git-dir=' + str(owner.remote), 'update-ref', ref, owner.base, expected_old)
                        if owner.uncertain_create:
                            raise ValueError('fixture remote write response lost; branch absent')
                        return verifier.git(store, 'push', '--porcelain', '--no-verify', '--no-follow-tags',
                            '--force-with-lease=' + ref + ':' + (expected_old or ''), str(owner.remote), sha + ':' + ref)
                    result = create_once(target, request['sha'], request['branch'], request['base'],
                                         call=call, guard=lambda: True, expected_old=request.get('expected_old'))
                    self.outputs.append({'result': result})
            def receive(self): return self.outputs.popleft()
            def finish(self): pass
        def http(method, path, bearer, payload=None):
            self.events.append('http-' + method)
            if method == 'DELETE': return {}
            self.assertEqual(payload, {'repositories': ['demo'], 'permissions': {'contents': 'write'}})
            return {'token': 'fixture-scoped-token', 'repository_selection': 'selected',
                'repositories': [{'full_name': self.config.repository}],
                'permissions': {'contents': 'write', 'metadata': 'read'},
                'expires_at': datetime.datetime.fromtimestamp(1700001800, datetime.timezone.utc).isoformat()}
        with (mock.patch.object(host, 'protected_directory', side_effect=lambda p: os.open(p, worker.claim.DIR_FLAGS)),
              mock.patch.object(host.read_base, 'BaseIssuer', return_value=self.base_issuer),
              mock.patch.object(host, 'Session', Session),
              mock.patch.object(host, 'WriteLease', side_effect=lambda cfg: WriteLease(cfg,
                    request=http, jwt=lambda: 'fixture-jwt', clock=lambda: 1700000000))):
            return host.run(self.data, self.app, self.policy, self.body, Guard())

    def test_real_signed_capture_reverify_one_local_branch_create_readback_revoke(self):
        result = self.exercise()
        self.assertTrue(result['acknowledged'])
        self.assertTrue(result['readback_checked'])
        self.assertEqual(fixture.run('git', '--git-dir=' + str(self.remote), 'rev-parse',
                         'refs/heads/' + self.body['branch']), self.body['sha'])
        self.assertEqual(self.events, ['base', 'capture', 'start-capture', 'stop-capture',
            'reverify', 'start-reverify', 'stop-reverify', 'mint', 'http-POST', 'deliver',
            'start-transport', 'handoff', 'token-delivery', 'create', 'local-create', 'stop-transport', 'http-DELETE'])
        self.assertTrue((self.ledger_root / (self.publication_key + '.quarantined')).exists())
        self.assertTrue((self.stage_root / ('q-' + self.publication_key)).is_dir())
        # Same trusted tool-call key cannot start a second container or mint,
        # even when a new host process/ledger instance is constructed.
        self.events.clear()
        with self.assertRaises(Exception):
            self.exercise()
        self.assertEqual(self.events, [])

    def test_uncertain_write_cannot_retry_with_new_tool_call_id(self):
        self.uncertain_create = True
        with self.assertRaisesRegex(Exception, 'push attempted'):
            self.exercise()
        self.assertEqual(self.events.count('local-create'), 1)
        self.assertEqual(self.events.count('http-POST'), 1)
        self.assertFalse(fixture.run('git', '--git-dir=' + str(self.remote), 'ls-remote',
                                    str(self.remote), 'refs/heads/' + self.body['branch']))
        self.body['attempt'] = 'e' * 32  # new Gateway tool-call correlation ID
        self.uncertain_create = False
        with self.assertRaises(Exception):
            self.exercise()
        self.assertEqual(self.events.count('local-create'), 1)
        self.assertEqual(self.events.count('http-POST'), 1)

    def test_model_still_must_match_exact_signed_trailers(self):
        self.body['model'] = 'other/model'
        with self.assertRaisesRegex(ValueError, 'attribution'):
            self.exercise()
        self.assertNotIn('http-POST', self.events)

    def private_config(self, **changes):
        app_path = self.root / 'app.json'
        app_path.write_text(json.dumps({'app_id': 101, 'installation_id': 202,
            'repository': self.policy.repository, 'key_path': '/fixture/missing.pem'}))
        app_path.chmod(0o600)
        policy = asdict(self.policy)
        policy['signer_public_key'] = policy['signer_public_key'].decode('ascii')
        data = {**self.data, 'app_config': str(app_path), 'python_path': '/usr/bin/python3',
                'deployment_id': 'fixture-publisher', 'verifier': policy}
        data.update(changes)
        path = self.root / 'deployment.json'
        path.write_text(json.dumps(data))
        path.chmod(0o600)
        return path

    def test_private_config_schema_loads_without_key_or_network_io(self):
        path = self.private_config()
        with (mock.patch.object(host.isolation, 'require_gateway_owner'),
              mock.patch.object(host.read_base, '_jwt', side_effect=AssertionError('key')),
              mock.patch.object(host.read_base, '_https', side_effect=AssertionError('network'))):
            data, app, policy = host.load_config(str(path))
        self.assertEqual(data['approved_branch'], self.body['branch'])
        self.assertEqual(app.repository, self.policy.repository)
        self.assertEqual(policy, self.policy)

    def test_unsafe_or_ambiguous_deployment_config_is_rejected(self):
        for changes in ({'extra': True}, {'image_id': 'latest'}, {'python_path': 'python3'},
                        {'transport_network': 'host'}, {'approved_branch': 'main'},
                        {'source_host': str(self.stage_root)},
                        {'stage_root': '/fixture/../escape'}):
            with self.subTest(changes=changes):
                path = self.private_config(**changes)
                with mock.patch.object(host.isolation, 'require_gateway_owner'):
                    with self.assertRaises((ValueError, host.read_base.IssuerError)):
                        host.load_config(str(path))
        path = self.private_config()
        path.chmod(0o644)
        with self.assertRaises(host.read_base.IssuerError):
            host.load_config(str(path))

    def test_request_cannot_retarget_privately_approved_branch(self):
        self.body['branch'] = 'dev-syn/different'
        with self.assertRaisesRegex(ValueError, 'unapproved branch'):
            self.exercise()
        self.assertEqual(self.events, [])
        self.assertEqual(list(self.ledger_root.iterdir()), [])
        self.assertEqual(list(self.stage_root.iterdir()), [])

    def test_failed_reverification_never_mints_and_spends_attempt(self):
        self.fail_reverify = True
        with self.assertRaisesRegex(ValueError, 'verify failed'):
            self.exercise()
        self.assertNotIn('http-POST', self.events)
        self.assertTrue((self.ledger_root / (self.publication_key + '.quarantined')).exists())

    def test_stale_after_worker_start_never_delivers_token_and_revokes(self):
        self.deny_phase = 'handoff'
        with self.assertRaisesRegex(ValueError, 'stale invocation'):
            self.exercise()
        self.assertIn('start-transport', self.events)
        self.assertIn('http-DELETE', self.events)
        self.assertNotIn('token-delivery', self.events)
        self.assertNotIn('local-create', self.events)

    def test_stale_final_guard_revokes_without_any_local_write(self):
        self.deny_phase = 'create'
        with self.assertRaisesRegex(ValueError, 'stale invocation'):
            self.exercise()
        self.assertIn('http-DELETE', self.events)
        self.assertNotIn('local-create', self.events)
        self.assertFalse(fixture.run('git', '--git-dir=' + str(self.remote), 'ls-remote',
                                    str(self.remote), 'refs/heads/' + self.body['branch']))
