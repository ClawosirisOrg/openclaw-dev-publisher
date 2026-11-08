"""Offline real Git/SSH object capture and independent sterile re-import."""
from dataclasses import asdict, replace
import os
import unittest

from broker.tests.worker import test_offline as fixture
run = fixture.run
from broker.worker import production
from broker.host import production as host


class ProductionObjects(unittest.TestCase):
    commit = fixture.Fixture.commit

    def setUp(self):
        fixture.Fixture.setUp(self)
        self.policy = replace(self.config, branch_prefix='dev-syn')
        self.stage = self.root / 'stage'
        self.stage.mkdir(mode=0o700)
        self.body = {'attempt': '1' * 32, 'sha': self.invocation.sha,
                     'branch': 'dev-syn/live-test', 'model': self.invocation.model,
                     'thinking': self.invocation.thinking}
        allocation = type('Allocation', (), {'device': self.stage.stat().st_dev,
                                             'inode': self.stage.stat().st_ino})()
        self.payload = host.worker_payload(self.body, self.base, self.policy, allocation)
        self.payload['source'] = {'device': self.repo.stat().st_dev, 'inode': self.repo.stat().st_ino}

    def capture(self):
        return production.capture(self.payload, stage_path=str(self.stage), source_path=str(self.src))

    def reverify(self):
        return production.reverify(self.payload, stage_path=str(self.stage))

    def test_real_capture_reimport_does_not_trust_source_or_capture_config(self):
        captured = self.capture()
        # An offline capture receipt is NOT a write permit. The production
        # coordinator requires this new independent crypto verification too.
        self.commit('later source mutation')
        old = self.stage / 'capture' / 'store.git'
        (old / 'config').write_text('[core]\n hooksPath = /hostile\n[alias]\n x = !false\n')
        (old / 'hooks').mkdir()
        (old / 'hooks' / 'pre-push').write_text('hostile fixture')
        observed = self.reverify()
        self.assertEqual(captured, observed)
        store = self.stage / 'publish' / 'store.git'
        self.assertEqual((store / 'config').read_text(), '[core]\n\tbare = true\n')
        self.assertFalse((store / 'hooks').exists())
        self.assertEqual(observed['sha'], self.body['sha'])
        self.assertEqual(run('git', '--git-dir=' + str(store), 'show', self.body['sha'] + ':file'), 'candidate')
        with self.assertRaises(FileExistsError):
            self.reverify()
        with self.assertRaises(ValueError):
            self.capture()

    def test_reverify_rejects_object_corruption_and_source_pin_substitution(self):
        self.capture()
        oid = self.body['sha']
        (self.stage / 'capture' / 'store.git' / 'objects' / oid[:2] / oid[2:]).write_bytes(b'broken')
        with self.assertRaises(ValueError):
            self.reverify()

    def test_display_case_attribution_is_preserved_not_lowercased(self):
        message = 'candidate\n\nAgent: Dixie\nModel: fixture/model\nThinking: off\nBot-Owner: @testowner'
        run('git', 'commit', '--amend', '-qm', message, cwd=self.repo)
        self.body['sha'] = run('git', 'rev-parse', 'HEAD', cwd=self.repo)
        self.policy = replace(self.policy, agent='Dixie')
        allocation = type('Allocation', (), {'device': self.stage.stat().st_dev,
                                             'inode': self.stage.stat().st_ino})()
        self.payload = host.worker_payload(self.body, self.base, self.policy, allocation)
        self.payload['source'] = {'device': self.repo.stat().st_dev, 'inode': self.repo.stat().st_ino}
        self.assertEqual(self.capture(), self.reverify())

    def test_bad_source_and_bad_model_cannot_produce_receipt(self):
        self.payload['source']['inode'] += 1
        with self.assertRaisesRegex(ValueError, 'mount inode'):
            self.capture()
        self.payload['source']['inode'] -= 1
        self.payload['claim']['model'] = 'wrong/model'
        with self.assertRaisesRegex(ValueError, 'attribution'):
            self.capture()


if __name__ == '__main__':
    unittest.main()
