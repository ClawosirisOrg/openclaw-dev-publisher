"""Filesystem durability and cross-process branch-lock regressions."""
import multiprocessing
import os
import tempfile
import unittest
from unittest import mock
from broker.host.attempt_ledger import AttemptLedger, LedgerError
from broker.host.namespace_ledger import BranchJournal


def contender(path, connection):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        journal = BranchJournal(AttemptLedger(fd, expected_uid=os.geteuid()), 'dev-syn', 'fixture/repo', 'dev-syn/test')
        connection.send('started')
        with journal.locked():
            connection.send('acquired')
    finally:
        os.close(fd)
        connection.close()


class JournalTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        os.chmod(self.tmp.name, 0o700)
        self.fd = os.open(self.tmp.name, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, self.fd)
        self.ledger = AttemptLedger(self.fd, expected_uid=os.geteuid())

    def journal(self, actor='dev-syn', repository='fixture/repo', branch='dev-syn/test'):
        return BranchJournal(self.ledger, actor, repository, branch)

    def test_reserved_attempt_never_restores_continuation(self):
        with self.journal().locked() as j:
            intent = j.reserve('create', None, 'a' * 40, {'model': 'fixture/model'})
        with self.journal().locked() as j:
            self.assertEqual(j.pending(), intent)
            with self.assertRaisesRegex(LedgerError, 'unresolved'):
                j.reserve('create', None, 'b' * 40, {})
        self.assertTrue(any(n.endswith('.intent') for n in os.listdir(self.fd)))

    def test_receipts_bound_actor_repo_branch_and_append_only(self):
        with self.journal().locked() as j:
            intent = j.reserve('create', None, 'a' * 40, {'signer_fingerprint': 'fixture'})
            j.complete(intent, {'sha': 'a' * 40})
        with self.assertRaisesRegex(LedgerError, 'binding'):
            with self.journal(actor='other').locked(): pass
        with self.journal(repository='other/repo').locked() as j:
            self.assertIsNone(j.latest('create'))
        with self.journal(branch='dev-syn/other').locked() as j:
            self.assertIsNone(j.latest('create'))
        with self.journal().locked() as j:
            self.assertEqual(j.latest('create')['intent'], intent)
            with self.assertRaises(LedgerError): j.complete(intent, {})

    def test_fsync_failure_keeps_spent_marker(self):
        with self.journal().locked() as j:
            with mock.patch.object(self.ledger, '_sync_file', side_effect=OSError('fixture')):
                with self.assertRaises(LedgerError): j.reserve('create', None, 'a' * 40, {})
        with self.journal().locked() as j:
            self.assertIsNotNone(j.pending())
            with self.assertRaises(LedgerError): j.reserve('create', None, 'b' * 40, {})

    def test_process_lock_covers_full_operation(self):
        # Start the contender BEFORE acquiring the lock in child? Fork while
        # locked would inherit its open flock description. Instead child is
        # started under lock but closes all inherited lock FDs via spawn.
        ctx = multiprocessing.get_context('spawn')
        reader, writer = ctx.Pipe(duplex=False)
        with self.journal().locked():
            process = ctx.Process(target=contender, args=(self.tmp.name, writer))
            process.start(); writer.close()
            self.assertTrue(reader.poll(5)); self.assertEqual(reader.recv(), 'started')
            self.assertFalse(reader.poll(0.1))
        self.assertTrue(reader.poll(5)); self.assertEqual(reader.recv(), 'acquired')
        process.join(5); self.assertEqual(process.exitcode, 0)
        reader.close()

    def test_legacy_markers_never_erased_or_reused(self):
        key = 'a' * 32
        self.ledger.reserve(key, 'legacy')
        self.ledger.mark_attempted(key, 'legacy')
        self.ledger.quarantine(key, 'legacy')
        with self.journal().locked() as j:
            i = j.reserve('create', None, 'b' * 40, {})
            j.complete(i, {})
        self.assertEqual(self.ledger.state(key), 'quarantined')
        with self.assertRaises(LedgerError): self.ledger.reserve(key, 'new')

    def test_receipt_sync_and_poison_creation_failure_leave_intent_pending(self):
        with self.journal().locked() as j:
            intent = j.reserve('create', None, 'a' * 40, {})
            create = self.ledger._create
            attempted = []
            def no_poison(name, data=b''):
                attempted.append(name)
                if name.endswith('completion-uncertain'):
                    raise OSError('poison creation unavailable')
                return create(name, data)
            with (mock.patch.object(self.ledger, '_sync_file', side_effect=OSError('receipt sync failed')),
                  mock.patch.object(self.ledger, '_create', side_effect=no_poison)):
                with self.assertRaises(LedgerError): j.complete(intent, {'sha': 'a' * 40})
            self.assertEqual(len(attempted), 1)  # no commit or best-effort poison attempted
            self.assertTrue(self.ledger._exists(attempted[0]))  # readable receipt is not a commit
            self.assertFalse(self.ledger._exists(attempted[0] + '.commit'))
        with self.journal().locked() as j:
            self.assertEqual(j.pending(), intent)
            self.assertIsNone(j.latest('create'))
            with self.assertRaisesRegex(LedgerError, 'uncommitted receipt'): j.complete(intent, {})

    def test_commit_created_only_after_receipt_file_and_directory_sync_success(self):
        with self.journal().locked() as j:
            intent = j.reserve('create', None, 'a' * 40, {})
            events = []
            create = self.ledger._create
            sync_file, sync_dir = self.ledger._sync_file, self.ledger._sync_directory
            def record_create(name, data=b''):
                events.append(('create', name))
                return create(name, data)
            def record_file(fd):
                events.append(('file-sync',))
                return sync_file(fd)
            def record_dir():
                events.append(('directory-sync',))
                return sync_dir()
            with (mock.patch.object(self.ledger, '_create', side_effect=record_create),
                  mock.patch.object(self.ledger, '_sync_file', side_effect=record_file),
                  mock.patch.object(self.ledger, '_sync_directory', side_effect=record_dir)):
                j.complete(intent, {'sha': 'a' * 40})
            self.assertEqual([e[0] for e in events],
                             ['create', 'file-sync', 'directory-sync', 'create', 'file-sync', 'directory-sync'])
            self.assertTrue(events[3][1].endswith('.complete.commit'))

    def test_receipt_directory_sync_failure_never_attempts_commit(self):
        with self.journal().locked() as j:
            intent = j.reserve('create', None, 'a' * 40, {})
            with mock.patch.object(self.ledger, '_sync_directory', side_effect=OSError('directory sync failed')):
                with self.assertRaises(LedgerError): j.complete(intent, {})
            self.assertFalse(self.ledger._exists(j.prefix + '.000001.complete.commit'))
        with self.journal().locked() as j:
            self.assertEqual(j.pending(), intent)
            self.assertIsNone(j.latest('create'))

    def test_failed_commit_before_creation_stays_pending_and_only_reconciliation_resyncs(self):
        result = {'sha': 'a' * 40}
        with self.journal().locked() as j:
            intent = j.reserve('create', None, 'a' * 40, {})
            create = self.ledger._create
            def fail_commit(name, data=b''):
                if name.endswith('.complete.commit'): raise OSError('commit not created')
                return create(name, data)
            with mock.patch.object(self.ledger, '_create', side_effect=fail_commit):
                with self.assertRaises(OSError): j.complete(intent, result)
        with self.journal().locked() as j:
            self.assertEqual(j.pending(), intent)
            self.assertIsNone(j.latest('create'))
            with self.assertRaisesRegex(LedgerError, 'uncommitted receipt'): j.complete(intent, result)
            with mock.patch.object(self.ledger, '_sync_file', side_effect=OSError('resync failed')):
                with self.assertRaises(OSError): j.complete(intent, result, reconciled=True)
            self.assertFalse(self.ledger._exists(j.prefix + '.000001.complete.commit'))
            j.complete(intent, result, reconciled=True)
        with self.journal().locked() as j:
            self.assertIsNone(j.pending())
            self.assertEqual(j.latest('create')['result'], result)

    def test_failed_commit_sync_with_readable_matching_record_is_ambiguous_ack(self):
        result = {'sha': 'a' * 40}
        with self.journal().locked() as j:
            intent = j.reserve('create', None, 'a' * 40, {})
            sync = self.ledger._sync_file
            def fail_final(fd):
                if os.readlink('/proc/self/fd/' + str(fd)).endswith('.complete.commit'):
                    raise OSError('commit sync failed but record is readable')
                return sync(fd)
            with mock.patch.object(self.ledger, '_sync_file', side_effect=fail_final):
                with self.assertRaises(LedgerError): j.complete(intent, result)
            self.assertEqual(j.pending(), intent)  # no success returned to this invocation
        with self.journal().locked() as j:
            # Explicit chosen contract: a valid matching commit may be adopted
            # on ordinary reopen. This says nothing about power-loss survival;
            # effects/readback/revocation/cleanup preceded the receipt and gate.
            self.assertIsNone(j.pending())
            self.assertEqual(j.latest('create')['result'], result)
            with self.assertRaisesRegex(LedgerError, 'not the pending'): j.complete(intent, result)

    def test_mismatched_commit_cannot_authorize_receipt(self):
        with self.journal().locked() as j:
            intent = j.reserve('create', None, 'a' * 40, {})
            name = j.prefix + '.000001.complete'
            self.ledger._create(name, j._encode({'intent': intent, 'result': {}}))
            self.ledger._create(name + '.commit', j._encode({'version': 1, 'receipt_sha256': '0' * 64}))
        with self.assertRaisesRegex(LedgerError, 'commit mismatch'):
            with self.journal().locked(): pass

    def test_cleanup_receipt_sync_and_poison_failure_cannot_confirm_cleanup(self):
        with self.journal().locked() as j:
            intent = j.reserve('issue', 'a' * 40, 'a' * 40, {})
            create = self.ledger._create
            attempted = []
            def no_poison(name, data=b''):
                attempted.append(name)
                if name.endswith('.uncertain'): raise OSError('poison unavailable')
                return create(name, data)
            with (mock.patch.object(self.ledger, '_sync_file', side_effect=OSError('cleanup receipt sync failed')),
                  mock.patch.object(self.ledger, '_create', side_effect=no_poison)):
                with self.assertRaises(LedgerError): j.confirm_cleanup(intent)
            self.assertEqual(len(attempted), 1)
            self.assertTrue(self.ledger._exists(attempted[0]))
            self.assertFalse(self.ledger._exists(attempted[0] + '.commit'))
        with self.journal().locked() as j:
            self.assertEqual(j.pending(), intent)
            self.assertFalse(j.cleanup_confirmed(intent))
            with self.assertRaisesRegex(LedgerError, 'uncommitted receipt'): j.confirm_cleanup(intent)

    def test_cleanup_commit_sync_failure_has_same_ambiguous_ack_contract(self):
        with self.journal().locked() as j:
            intent = j.reserve('issue', 'a' * 40, 'a' * 40, {})
            sync = self.ledger._sync_file
            def fail_final(fd):
                if os.readlink('/proc/self/fd/' + str(fd)).endswith('.cleanup.commit'):
                    raise OSError('cleanup commit sync failed but readable')
                return sync(fd)
            with mock.patch.object(self.ledger, '_sync_file', side_effect=fail_final):
                with self.assertRaises(LedgerError): j.confirm_cleanup(intent)
        with self.journal().locked() as j:
            self.assertEqual(j.pending(), intent)  # cleanup never completes the operation
            self.assertTrue(j.cleanup_confirmed(intent))  # records known prior revocation only
            self.assertIsNone(j.latest('issue'))

    def test_commit_directory_sync_failure_is_same_ambiguous_ack(self):
        with self.journal().locked() as j:
            intent = j.reserve('create', None, 'a' * 40, {})
            sync = self.ledger._sync_directory
            count = 0
            def fail_final_directory():
                nonlocal count
                count += 1
                if count == 2: raise OSError('commit directory sync failed')
                return sync()
            with mock.patch.object(self.ledger, '_sync_directory', side_effect=fail_final_directory):
                with self.assertRaises(LedgerError): j.complete(intent, {})
            self.assertEqual(j.pending(), intent)
        with self.journal().locked() as j:
            self.assertIsNone(j.pending())
            self.assertEqual(j.latest('create')['intent'], intent)

    def test_old_receipt_only_and_uncertainty_markers_remain_unresolved(self):
        with self.journal().locked() as j:
            intent = j.reserve('create', None, 'a' * 40, {})
            name = j.prefix + '.000001.'
            receipt = {'intent': intent, 'result': {}}
            self.ledger._create(name + 'complete', j._encode(receipt))
            self.ledger._create(name + 'cleanup', j._encode({'intent': intent, 'leases_revoked': True}))
        with self.journal().locked() as j:
            self.assertEqual(j.pending(), intent)
            self.assertIsNone(j.latest('create'))
            self.assertFalse(j.cleanup_confirmed(intent))
            self.ledger._create(name + 'completion-uncertain')
            self.ledger._create(name + 'cleanup.uncertain')
            with self.assertRaisesRegex(LedgerError, 'legacy receipt'): j.complete(intent, {}, reconciled=True)
            with self.assertRaisesRegex(LedgerError, 'legacy cleanup'): j.confirm_cleanup(intent)
        self.assertTrue(self.ledger._exists(name + 'completion-uncertain'))
        self.assertTrue(self.ledger._exists(name + 'cleanup.uncertain'))

    def test_commit_version_requires_exact_integer_not_boolean_or_float(self):
        for version, branch in ((True, 'dev-syn/bool'), (1.0, 'dev-syn/float')):
            with self.subTest(version=version):
                with self.journal(branch=branch).locked() as j:
                    intent = j.reserve('create', None, 'a' * 40, {})
                    receipt = {'intent': intent, 'result': {}}
                    name = j.prefix + '.000001.complete'
                    self.ledger._create(name, j._encode(receipt))
                    commit = {**j._commit_record(receipt), 'version': version}
                    self.ledger._create(name + '.commit', j._encode(commit))
                with self.assertRaisesRegex(LedgerError, 'commit mismatch'):
                    with self.journal(branch=branch).locked(): pass
