"""Real signed Git + bare remote through operational composition; no network."""
import os
import unittest
from unittest import mock
from broker.tests.host import test_production as fixturehost
from broker.tests.worker import test_offline as fixture
from broker.host import production as host
from broker.host.namespace_ledger import BranchJournal
from broker.host.attempt_ledger import AttemptLedger
from broker.worker import claim


class NamespaceProduction(unittest.TestCase):
    setUp = fixturehost.ProductionComposition.setUp
    commit = fixture.Fixture.commit

    def namespace(self):
        self.data.pop('approved_branch')
        self.data['publication_policy'] = {'actor': 'dev-syn', 'namespace': 'dev-syn',
            'repository': self.app.repository, 'credential_repository': self.app.repository,
            'signer_fingerprint': self.policy.signer_fingerprint, 'max_update_commits': 1,
            'api_author': 'fixture-bot[bot]'}
        self.data['api_app_config'] = '/fixture/no-key.json'

    def exercise(self):
        with mock.patch.object(host.read_base, 'load_deploy_config', return_value=self.app):
            return fixturehost.ProductionComposition.exercise(self)

    def journal(self):
        fd = os.open(self.ledger_root, claim.DIR_FLAGS)
        self.addCleanup(os.close, fd)
        return BranchJournal(AttemptLedger(fd, expected_uid=os.geteuid()), 'dev-syn',
                             self.app.repository, self.body['branch'])

    def update(self, signed=True):
        old = self.body['sha']
        self.commit('review fix', signed=signed)
        self.body = {**self.body, 'operation': 'update', 'expectedOldSha': old,
                     'sha': fixture.run('git', 'rev-parse', 'HEAD', cwd=self.repo)}

    def test_create_then_signed_direct_child_update_and_no_replay(self):
        self.namespace()
        self.exercise()
        with self.journal().locked() as journal:
            self.assertEqual(journal.latest('create')['intent']['new'], self.body['sha'])
        self.update()
        self.exercise()
        self.assertEqual(fixture.run('git', '--git-dir=' + str(self.remote), 'rev-parse',
                         'refs/heads/' + self.body['branch']), self.body['sha'])
        with self.journal().locked() as journal:
            self.assertEqual(journal.latest('update')['intent']['old'], self.body['expectedOldSha'])
            self.assertEqual(len(journal.entries), 2)
        before = len(self.events)
        with self.assertRaisesRegex(ValueError, 'expected head'):
            self.exercise()
        self.assertEqual(len(self.events), before)

    def test_non_ff_signed_sibling_rejected_before_mint_and_spent(self):
        self.namespace()
        self.exercise()
        old = self.body['sha']
        fixture.run('git', 'reset', '--hard', self.base, cwd=self.repo)
        self.commit('signed divergent sibling')
        self.body.update(operation='update', expectedOldSha=old,
                         sha=fixture.run('git', 'rev-parse', 'HEAD', cwd=self.repo))
        self.events.clear()
        with self.assertRaisesRegex(ValueError, 'direct parent'):
            self.exercise()
        self.assertNotIn('http-POST', self.events)
        self.body['attempt'] = 'e' * 32
        with self.assertRaisesRegex(ValueError, 'unresolved'):
            self.exercise()

    def test_unsigned_review_update_rejected_before_mint(self):
        self.namespace(); self.exercise(); self.update(signed=False)
        self.events.clear()
        with self.assertRaises(ValueError): self.exercise()
        self.assertNotIn('http-POST', self.events)

    def test_existing_unowned_ref_not_adopted_even_equal_sha(self):
        self.namespace()
        fixture.run('git', '--git-dir=' + str(self.remote), 'fetch', str(self.repo),
                    self.body['sha'] + ':refs/heads/' + self.body['branch'])
        with self.assertRaisesRegex(ValueError, 'branch exists'):
            self.exercise()
        with self.assertRaisesRegex(ValueError, 'unresolved'):
            self.exercise()

    def test_remote_review_head_drift_exact_lease_not_overwritten(self):
        self.namespace(); self.exercise(); old = self.body['sha']; self.update()
        fixture.run('git', '--git-dir=' + str(self.remote), 'update-ref',
                    'refs/heads/' + self.body['branch'], self.base, old)
        with self.assertRaisesRegex(ValueError, 'head drift'):
            self.exercise()
        self.assertEqual(fixture.run('git', '--git-dir=' + str(self.remote), 'rev-parse',
                         'refs/heads/' + self.body['branch']), self.base)

    def test_ambiguous_write_blocks_different_candidate_and_call(self):
        self.namespace(); self.uncertain_create = True
        with self.assertRaises(Exception): self.exercise()
        self.body['attempt'] = 'e' * 32
        self.body['sha'] = 'f' * 40
        before = len(self.events)
        with self.assertRaisesRegex(ValueError, 'unresolved'): self.exercise()
        self.assertEqual(len(self.events), before)

    def test_legacy_spent_branch_survives_namespace_migration(self):
        self.fail_reverify = True
        with self.assertRaises(ValueError): self.exercise()
        markers = {p.name: p.read_bytes() for p in self.ledger_root.iterdir()}
        self.namespace(); self.fail_reverify = False
        with self.assertRaisesRegex(ValueError, 'legacy spent'): self.exercise()
        for name, content in markers.items():
            self.assertEqual((self.ledger_root / name).read_bytes(), content)

    def test_policy_cannot_grant_another_actor_or_namespace(self):
        self.namespace()
        for key, value in (('actor', 'other'), ('namespace', 'other'),
                           ('credential_repository', 'other/repo'), ('max_update_commits', 2)):
            original = self.data['publication_policy'][key]
            self.data['publication_policy'][key] = value
            with self.assertRaisesRegex(ValueError, 'policy'): self.exercise()
            self.data['publication_policy'][key] = original
        self.assertFalse(list(self.ledger_root.iterdir()))

    def test_update_cannot_adopt_unowned_branch(self):
        self.namespace(); self.update()
        with self.assertRaisesRegex(ValueError, 'publisher-owned'): self.exercise()
        self.assertNotIn('http-POST', self.events)

    def test_exact_lease_rejects_race_after_preflight_without_overwrite(self):
        self.namespace(); self.exercise(); self.update(); self.race_update = True
        with self.assertRaisesRegex(Exception, 'push attempted'): self.exercise()
        self.assertEqual(fixture.run('git', '--git-dir=' + str(self.remote), 'rev-parse',
                         'refs/heads/' + self.body['branch']), self.base)
        with self.assertRaisesRegex(ValueError, 'unresolved'): self.exercise()

    def test_namespace_private_config_exact_schema_and_mixed_schema_denial(self):
        self.namespace()
        self.data['api_app_config'] = str(self.root / 'app.json')
        path = fixturehost.ProductionComposition.private_config(self)
        with mock.patch.object(host.isolation, 'require_gateway_owner'):
            data, app, policy = host.load_config(str(path))
            self.assertEqual(data['publication_policy']['actor'], 'dev-syn')
            self.assertEqual(app.repository, policy.repository)
        path = fixturehost.ProductionComposition.private_config(self, approved_branch='dev-syn/legacy')
        with mock.patch.object(host.isolation, 'require_gateway_owner'):
            with self.assertRaises(ValueError): host.load_config(str(path))
