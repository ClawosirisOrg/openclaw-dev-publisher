"""Offline fake transport observations; no GitHub traffic."""
from types import SimpleNamespace
import unittest
from broker.transport.production import create_once
from broker.transport.one_shot import UncertainPush

BASE, SHA = 'a' * 40, 'b' * 40
TARGET = SimpleNamespace(remote='https://github.com/fixture/repo.git')
BRANCH = 'dev-syn/live-test'
REF = 'refs/heads/' + BRANCH


class TransportTests(unittest.TestCase):
    def exercise(self, *, existing=False, uncertain=False, drift=False, guard=True):
        self.events = []
        self.created = False
        def call(operation, ref, sha=None):
            self.events.append((operation, ref, sha))
            if operation == 'main':
                main = 'c' * 40 if drift and self.created else BASE
                return (main + '\trefs/heads/main\n').encode()
            if operation == 'branch':
                return ((SHA + '\t' + REF + '\n').encode()
                        if existing or self.created else b'')
            if operation == 'create':
                self.created = True
                if uncertain:
                    raise ValueError('lost write response')
                return ('To ' + TARGET.remote + '\n*\t' + SHA + ':' + REF + '\t[new branch]\nDone\n').encode()
            self.fail('unexpected operation')
        def current():
            self.events.append(('guard',))
            return guard
        return create_once(TARGET, SHA, BRANCH, BASE, call=call, guard=current)

    def test_exact_new_branch_ack_remote_readback_and_stale_reporting(self):
        for drift in (False, True):
            with self.subTest(drift=drift):
                result = self.exercise(drift=drift)
                self.assertTrue(result['acknowledged'])
                self.assertTrue(result['readback_checked'])
                self.assertEqual(result['stale'], drift)
                ops = [e[0] for e in self.events]
                self.assertEqual(ops, ['main', 'branch', 'main', 'guard', 'create', 'branch', 'main'])

    def test_existing_equal_oid_denied_and_stale_guard_never_pushes(self):
        for kwargs in ({'existing': True}, {'guard': False}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                self.exercise(**kwargs)
            self.assertFalse(self.created)

    def test_lost_response_is_uncertain_without_retry(self):
        with self.assertRaises(UncertainPush):
            self.exercise(uncertain=True)
        self.assertEqual(sum(e[0] == 'create' for e in self.events), 1)
