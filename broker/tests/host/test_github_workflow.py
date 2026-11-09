"""Operational API composition with actual scoped lease, fake HTTP only."""
import copy
import datetime
import os
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock
from broker.host.attempt_ledger import AttemptLedger, LedgerError
from broker.host.namespace_ledger import BranchJournal
from broker.host.github_workflow import GithubWorkflow, marker
from broker.issuer.api_lease import ApiLease
from broker.issuer import read_base

SHA = 'a' * 40
BRANCH = 'dev-syn/review'
REPO = 'fixture/repository'
AUTHOR = 'fixture-bot[bot]'
TEXT = 'Explanation\n\nAgent: fixture\nModel: fixture/model\nThinking: off\nBot-Owner: @testowner'


class WorkflowTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(); self.addCleanup(tmp.cleanup)
        os.chmod(tmp.name, 0o700)
        self.fd = os.open(tmp.name, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, self.fd)
        self.ledger = AttemptLedger(self.fd, expected_uid=os.geteuid())
        self.journal = BranchJournal(self.ledger, 'dev-syn', REPO, BRANCH)
        with self.journal.locked() as j:
            i = j.reserve('create', None, SHA, {'signer_fingerprint': 'fixture'})
            j.complete(i, {'sha': SHA})
        self.app = read_base.DeployConfig(101, 202, REPO, '/fixture/missing.pem')
        self.policy = SimpleNamespace(agent='fixture', bot_owner='testowner', signer_fingerprint='fixture')
        self.events, self.docs = [], {'issue': [], 'pr': []}
        self.lost, self.duplicate, self.deny_phase, self.revoke_fail = None, None, None, False
        self.remote_sha = SHA
        owner = self
        class Guard:
            def check(self, phase):
                owner.events.append(('guard', phase))
                if phase == owner.deny_phase: raise ValueError('stale invocation')
                return True
        self.guard = Guard()
        def lease(permissions):
            def http(method, path, bearer, payload=None):
                self.events.append(('lease', method, permissions.copy()))
                if method == 'DELETE':
                    if self.revoke_fail: raise ValueError('revoke lost')
                    return {}
                self.assertEqual(payload, {'repositories': [self.app.repository_name], 'permissions': permissions})
                self.active_permissions = permissions.copy()
                return {'token': 'fixture-lease-token', 'repository_selection': 'selected',
                        'repositories': [{'full_name': REPO}], 'permissions': permissions,
                        'expires_at': datetime.datetime.fromtimestamp(1700001800, datetime.timezone.utc).isoformat()}
            return ApiLease(self.app, permissions, request=http, jwt=lambda: 'fixture-jwt', clock=lambda: 1700000000)
        self.workflow = GithubWorkflow(self.app, self.policy, AUTHOR, request=self.api, lease=lease)

    def api(self, method, path, token, payload=None):
        self.assertEqual(token, 'fixture-lease-token')
        self.events.append(('api', method, path))
        root = '/repos/' + REPO
        if path.startswith(root + '/git/ref/'):
            self.assertEqual(self.active_permissions.get('contents'), 'read')
            return {'ref': 'refs/heads/' + BRANCH, 'object': {'type': 'commit', 'sha': self.remote_sha}}
        kind = 'issue' if '/issues' in path else 'pr'
        if method == 'GET' and '?' in path:
            return copy.deepcopy(self.docs[kind])
        if method == 'GET':
            number = int(path.rsplit('/', 1)[1])
            return copy.deepcopy(next(d for d in self.docs[kind] if d['number'] == number))
        self.assertEqual(method, 'POST')
        number = len(self.docs[kind]) + 1
        doc = {'number': number, 'html_url': 'https://github.com/' + REPO +
               ('/issues/' if kind == 'issue' else '/pull/') + str(number),
               'title': payload['title'], 'body': payload['body'], 'state': 'open',
               'user': {'login': AUTHOR}}
        if kind == 'pr':
            self.assertEqual(payload['head'], BRANCH); self.assertEqual(payload['base'], 'main')
            self.assertNotIn('auto_merge', payload)
            doc.update({'base': {'ref': 'main', 'repo': {'full_name': REPO}},
                        'head': {'ref': BRANCH, 'sha': SHA, 'repo': {'full_name': REPO}},
                        'merged_at': None, 'auto_merge': None})
        self.docs[kind].append(doc)
        if self.duplicate == kind: self.docs[kind].append(copy.deepcopy(doc))
        if self.lost == kind: raise ValueError('response lost')
        return copy.deepcopy(doc)

    def body(self, action):
        body = {'operation': action, 'sha': SHA, 'branch': BRANCH, 'model': 'fixture/model', 'thinking': 'off'}
        if action in ('issue', 'pr'): body.update(title='Bounded title', body=TEXT)
        return body

    def run_action(self, action, **changes):
        with self.journal.locked() as j:
            self.workflow._used_leases = []
            try:
                return self.workflow.run(j, {**self.body(action), **changes}, self.guard,
                                         {'model': 'fixture/model', 'thinking_source': 'agent_attested'})
            finally:
                if j.pending() and self.workflow.cleanup_confirmed and action != 'reconcile':
                    j.confirm_cleanup(j.pending())

    def posts(self): return [e for e in self.events if e[:2] == ('api', 'POST')]

    def test_issue_first_then_fixed_main_pr_exact_attribution_and_readback(self):
        with self.assertRaisesRegex(ValueError, 'issue before PR'): self.run_action('pr')
        self.assertFalse(self.posts())
        issue = self.run_action('issue'); pr = self.run_action('pr')
        self.assertEqual(issue['url'], 'https://github.com/' + REPO + '/issues/1')
        self.assertEqual(pr['url'], 'https://github.com/' + REPO + '/pull/1')
        final = self.docs['pr'][0]['body']
        self.assertIn('Refs ' + issue['url'], final)
        self.assertTrue(final.endswith(TEXT.split('\n\n')[1]))
        profiles = [e[2] for e in self.events if e[:2] == ('lease', 'POST')]
        self.assertIn({'issues': 'write'}, profiles)
        self.assertIn({'pull_requests': 'write'}, profiles)
        self.assertNotIn({'issues': 'write', 'pull_requests': 'write'}, profiles)
        self.assertTrue(all(e[2].get('contents') != 'write' for e in self.events if e[0] == 'lease'))

    def test_lost_issue_response_reconciles_read_only_without_duplicate_create(self):
        self.lost = 'issue'
        with self.assertRaisesRegex(ValueError, 'response lost'): self.run_action('issue')
        self.assertEqual(len(self.posts()), 1)
        with self.assertRaisesRegex(ValueError, 'unresolved'): self.run_action('issue')
        result = self.run_action('reconcile')
        self.assertTrue(result['readback_checked']); self.assertEqual(len(self.posts()), 1)
        # Lost caller response after durable completion also has a read-only path.
        self.assertEqual(self.run_action('reconcile'), result)
        self.assertEqual(len(self.posts()), 1)

    def test_lost_pr_response_reconciles_without_repeat(self):
        self.run_action('issue'); self.lost = 'pr'
        with self.assertRaises(ValueError): self.run_action('pr')
        count = len(self.posts())
        self.run_action('reconcile')
        self.assertEqual(len(self.posts()), count)

    def test_duplicate_issue_or_pr_never_repeated_or_adopted(self):
        for kind in ('issue', 'pr'):
            with self.subTest(kind=kind):
                if kind == 'pr':
                    # fresh test boundary because duplicate issue intentionally blocks branch
                    self.setUp(); self.run_action('issue')
                self.lost, self.duplicate = kind, kind
                with self.assertRaises(ValueError): self.run_action(kind)
                count = len(self.posts())
                with self.assertRaisesRegex(ValueError, 'duplicate'): self.run_action('reconcile')
                with self.assertRaisesRegex(ValueError, 'unresolved'): self.run_action(kind)
                self.assertEqual(len(self.posts()), count)

    def test_existing_pr_same_head_blocks_new_create_even_without_marker(self):
        self.run_action('issue')
        self.docs['pr'].append({'head': {'ref': BRANCH}, 'body': 'unrelated'})
        with self.assertRaisesRegex(ValueError, 'head already exists'): self.run_action('pr')
        self.assertEqual(len(self.posts()), 1)

    def test_existing_marker_blocks_issue_post_and_must_match_readback(self):
        self.docs['issue'].append({'number': 42, 'body': marker(REPO, 'dev-syn', BRANCH, 'issue'), 'user': {'login': 'other'}})
        with self.assertRaisesRegex(ValueError, 'duplicate'): self.run_action('issue')
        with self.assertRaisesRegex(ValueError, 'readback mismatch'): self.run_action('reconcile')
        self.assertFalse(self.posts())

    def test_bad_attribution_or_text_and_agent_selected_target_denied(self):
        for body in (TEXT + '\n', TEXT.replace('fixture/model', 'forged/model'),
                     TEXT.replace('Thinking: off', 'Thinking: high'),
                     'Thinking: low\n' + TEXT, 'Ｔｈｉｎｋｉｎｇ： low\n' + TEXT):
            with self.subTest(body=body), self.assertRaises(ValueError): self.run_action('issue', body=body)
        with self.assertRaises(ValueError): self.run_action('issue', title='bad\nTitle')
        with self.assertRaises(ValueError): self.run_action('issue', body='x' * 12001)
        self.assertFalse(self.posts())

    def test_stale_final_guard_and_revocation_failure_leave_unresolved(self):
        self.deny_phase = 'api-write'
        with self.assertRaisesRegex(ValueError, 'stale'): self.run_action('issue')
        self.assertFalse(self.posts())
        self.assertEqual(sum(e[:2] == ('lease', 'DELETE') for e in self.events), 2)
        self.deny_phase = None
        with self.assertRaisesRegex(ValueError, 'unresolved'): self.run_action('issue')

    def test_uncertain_revocation_cannot_return_success(self):
        self.revoke_fail = True
        with self.assertRaisesRegex(Exception, 'revocation_uncertain'): self.run_action('issue')
        self.assertFalse(self.posts())  # read preflight revoke failed, no write lease
        with self.assertRaisesRegex(ValueError, 'unresolved'): self.run_action('issue')

    def test_pr_review_update_rejects_repo_head_author_automergemode(self):
        self.run_action('issue'); self.run_action('pr')
        original = copy.deepcopy(self.docs['pr'][0])
        for mutation in ('repo', 'head', 'author', 'auto_merge', 'base'):
            doc = copy.deepcopy(original)
            if mutation == 'repo': doc['head']['repo']['full_name'] = 'foreign/repo'
            if mutation == 'head': doc['head']['sha'] = 'b' * 40
            if mutation == 'author': doc['user']['login'] = 'other'
            if mutation == 'auto_merge': doc['auto_merge'] = {'enabled': True}
            if mutation == 'base': doc['base']['ref'] = 'other'
            self.docs['pr'][0] = doc
            with self.subTest(mutation=mutation), self.journal.locked() as j:
                with self.assertRaises(ValueError):
                    self.workflow.check_review_head(j, BRANCH, SHA, self.guard)
        self.docs['pr'][0] = original
        with self.journal.locked() as j:
            self.workflow.check_review_head(j, BRANCH, SHA, self.guard)

    def test_original_write_revoke_uncertainty_is_not_erased_by_remote_readback(self):
        original_api = self.api
        def api(method, path, token, payload=None):
            doc = original_api(method, path, token, payload)
            if method == 'POST': self.revoke_fail = True
            return doc
        self.workflow._request = api
        with self.assertRaisesRegex(Exception, 'revocation_uncertain'): self.run_action('issue')
        self.assertEqual(len(self.posts()), 1)
        self.revoke_fail = False
        with self.assertRaisesRegex(ValueError, 'original lease cleanup unconfirmed'):
            self.run_action('reconcile')
        with self.assertRaisesRegex(ValueError, 'unresolved'): self.run_action('issue')
        self.assertEqual(len(self.posts()), 1)

    def test_fixed_api_adapter_refuses_merge_retarget_delete_and_overbroad_payloads(self):
        root = '/repos/' + REPO
        for method, path, payload in (
            ('PUT', root + '/pulls/1/merge', {}),
            ('PATCH', root + '/pulls/1', {'base': 'other'}),
            ('DELETE', root + '/issues/1', None),
            ('POST', root + '/pulls', {'title': 'T', 'body': 'B', 'head': BRANCH, 'base': 'other'}),
            ('POST', root + '/pulls', {'title': 'T', 'body': 'B', 'head': BRANCH, 'base': 'main', 'auto_merge': True}),
            ('POST', root + '/issues', {'title': 'T', 'body': 'B', 'labels': ['privileged']}),
            ('POST', '/repos/foreign/repo/issues', {'title': 'T', 'body': 'B'}),
        ):
            with self.subTest(method=method, path=path), self.assertRaises(ValueError):
                self.workflow._https(method, path, 'fixture-token', payload)

    def test_receipt_sync_failure_recovers_only_through_read_only_reconciliation(self):
        sync, create = self.ledger._sync_file, self.ledger._create
        def failed_receipt(fd):
            if os.readlink('/proc/self/fd/' + str(fd)).endswith('.complete'):
                raise OSError('receipt sync failed')
            return sync(fd)
        def unavailable_poison(name, data=b''):
            if name.endswith('completion-uncertain'): raise OSError('poison unavailable')
            return create(name, data)
        with (mock.patch.object(self.ledger, '_sync_file', side_effect=failed_receipt),
              mock.patch.object(self.ledger, '_create', side_effect=unavailable_poison)):
            with self.assertRaises(Exception): self.run_action('issue')
        self.assertEqual(len(self.posts()), 1)
        with self.assertRaisesRegex(ValueError, 'unresolved'): self.run_action('issue')
        result = self.run_action('reconcile')
        self.assertTrue(result['readback_checked'])
        self.assertEqual(len(self.posts()), 1)
        with self.journal.locked() as j:
            self.assertIsNone(j.pending())
            self.assertEqual(j.latest('issue')['result'], result)

    def test_absent_completion_commit_read_only_reconciliation_does_not_repost(self):
        create = self.ledger._create
        def no_commit(name, data=b''):
            if name.endswith('.complete.commit'): raise OSError('commit inode unavailable')
            return create(name, data)
        with mock.patch.object(self.ledger, '_create', side_effect=no_commit):
            with self.assertRaises(LedgerError): self.run_action('issue')
        with self.assertRaisesRegex(ValueError, 'unresolved'): self.run_action('issue')
        self.assertTrue(self.run_action('reconcile')['readback_checked'])
        self.assertEqual(len(self.posts()), 1)

    def test_readable_commit_after_sync_error_is_final_ack_ambiguity_not_effect_retry(self):
        sync = self.ledger._sync_file
        def failed_commit(fd):
            if os.readlink('/proc/self/fd/' + str(fd)).endswith('.complete.commit'):
                raise OSError('commit sync failed with readable record')
            return sync(fd)
        with mock.patch.object(self.ledger, '_sync_file', side_effect=failed_commit):
            with self.assertRaises(Exception): self.run_action('issue')
        # Reopen may accept the exact matching gate: the repository operation,
        # readback, and revocation had all completed before gate creation began.
        with self.assertRaisesRegex(ValueError, 'already attempted/completed'): self.run_action('issue')
        self.assertTrue(self.run_action('reconcile')['readback_checked'])
        self.assertEqual(len(self.posts()), 1)
