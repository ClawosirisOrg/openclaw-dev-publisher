"""Real signed objects + local Git remote + fake API through production.run."""
import unittest
from unittest import mock
from broker.tests.host import test_production as git_fixture, test_github_workflow as api_fixture
from broker.tests.worker import test_offline as fixture
from broker.host import production as host
from broker.host.github_workflow import GithubWorkflow


class FullWorkflow(unittest.TestCase):
    setUp = git_fixture.ProductionComposition.setUp
    commit = fixture.Fixture.commit

    def exercise(self):
        with mock.patch.object(host.read_base, 'load_deploy_config', return_value=self.app):
            return git_fixture.ProductionComposition.exercise(self)

    def test_real_signed_create_issue_pr_and_same_pr_signed_review_update(self):
        self.data.pop('approved_branch')
        self.data['publication_policy'] = {'actor': 'dev-syn', 'namespace': 'dev-syn',
            'repository': self.app.repository, 'credential_repository': self.app.repository,
            'signer_fingerprint': self.policy.signer_fingerprint, 'max_update_commits': 1,
            'api_author': 'fixture-bot[bot]'}
        self.data['api_app_config'] = '/fixture/no-key.json'
        self.exercise()
        old = self.body['sha']
        with (mock.patch.object(api_fixture, 'REPO', self.app.repository),
              mock.patch.object(api_fixture, 'BRANCH', self.body['branch']),
              mock.patch.object(api_fixture, 'SHA', old)):
            api = api_fixture.WorkflowTests()
            api.setUp(); self.addCleanup(api.doCleanups)
            def request(method, path, token, payload=None):
                current = fixture.run('git', '--git-dir=' + str(self.remote), 'rev-parse',
                                      'refs/heads/' + self.body['branch'])
                api.remote_sha = current
                for doc in api.docs['pr']:
                    doc['head']['sha'] = current
                return api.api(method, path, token, payload)
            def workflow(app, policy, author):
                return GithubWorkflow(app, policy, author, request=request, lease=api.workflow._make_lease)
            with mock.patch.object(host, 'GithubWorkflow', side_effect=workflow):
                self.body.update(operation='issue', title='Signed integration', body=api_fixture.TEXT)
                issue = self.exercise()
                self.body['operation'] = 'pr'
                pr = self.exercise()
                self.assertIn(issue['url'], api.docs['pr'][0]['body'])
                self.assertEqual(pr['head'], old)
                self.commit('actual signed review fix')
                self.body = {key: self.body[key] for key in ('attempt', 'branch', 'model', 'thinking')}
                self.body.update(operation='update', expectedOldSha=old,
                                 sha=fixture.run('git', 'rev-parse', 'HEAD', cwd=self.repo))
                result = self.exercise()
                self.assertEqual(result['sha'], self.body['sha'])
                self.assertEqual(api.docs['pr'][0]['head']['sha'], self.body['sha'])
                self.assertEqual(len(api.docs['issue']), 1)
                self.assertEqual(len(api.docs['pr']), 1)
                self.assertEqual(api.docs['pr'][0]['base']['ref'], 'main')
                self.assertIsNone(api.docs['pr'][0]['auto_merge'])
                self.assertEqual(len(api.posts()), 2)

                self.body = {key: self.body[key] for key in ('attempt', 'sha', 'branch', 'model', 'thinking')}
                self.body['operation'] = 'reconcile'
                readback = self.exercise()
                self.assertEqual(readback['url'], pr['url'])
                self.assertEqual(readback['head'], result['sha'])
                self.assertEqual(len(api.posts()), 2)
