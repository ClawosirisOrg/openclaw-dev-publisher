"""Protected append-only branch journal. No receipt is a bearer permit.

The branch flock spans preflight, leases, effects, revocation and cleanup across
processes. An intent without a matching receipt commit stays unresolved until read-only
reconciliation;
changing tool IDs, candidate or deployment never bypasses an uncertain operation.
Legacy AttemptLedger markers remain authoritative and are never altered here.
"""
import hashlib
import json
import os
from contextlib import contextmanager
from broker.host.attempt_ledger import LedgerError
from broker.issuer.read_base import _strict_json


def digest(*parts):
    return hashlib.sha256('\0'.join(parts).encode('ascii')).hexdigest()[:32]


class BranchJournal:
    def __init__(self, ledger, actor, repository, branch):
        self.ledger = ledger
        self.binding = {'actor': actor, 'repository': repository.casefold(), 'branch': branch}
        # Repository+branch lock deliberately excludes actor: policy changes must
        # not admit concurrent writers or adopt a different actor's receipt.
        self.prefix = 'n-' + digest(repository.casefold(), branch)
        self.entries = []

    @contextmanager
    def locked(self):
        with self.ledger._locked(self.prefix + '.lock'):
            self._load()
            yield self

    def _read(self, name):
        fd = self.ledger._open_marker(name)
        if fd is None:
            raise LedgerError('missing journal entry')
        try:
            if os.fstat(fd).st_size > 65536:
                raise LedgerError('oversize journal entry')
            return _strict_json(os.read(fd, 65537))
        finally:
            os.close(fd)

    def _load(self):
        names = sorted(n for n in os.listdir(self.ledger._fd)
                       if n.startswith(self.prefix + '.') and n.endswith('.intent'))
        if len(names) > 4096:
            raise LedgerError('journal capacity reached')
        self.entries = []
        for index, name in enumerate(names, 1):
            if name != self.prefix + '.%06d.intent' % index:
                raise LedgerError('journal gap')
            intent = self._read(name)
            if (type(intent) is not dict or intent.get('binding') != self.binding or
                    intent.get('sequence') != index):
                raise LedgerError('ownership binding mismatch')
            done_name = name[:-6] + 'complete'
            uncertain = self.ledger._exists(name[:-6] + 'completion-uncertain')
            done = self._committed(done_name) if not uncertain else None
            if done is not None and (type(done) is not dict or done.get('intent') != intent):
                raise LedgerError('receipt mismatch')
            if self.entries and self.entries[-1][1] is None:
                raise LedgerError('operation after unresolved attempt')
            self.entries.append((intent, done))

    def pending(self):
        return self.entries[-1][0] if self.entries and self.entries[-1][1] is None else None

    def latest(self, *kinds):
        for intent, done in reversed(self.entries):
            if done is not None and intent['kind'] in kinds:
                return done
        return None

    def reserve(self, kind, old, new, provenance, **detail):
        if len(self.entries) >= 4096:
            raise LedgerError('journal capacity reached')
        if self.pending():
            raise LedgerError('unresolved operation; reconcile read-only, never retry')
        intent = {'binding': self.binding, 'sequence': len(self.entries) + 1,
                  'kind': kind, 'old': old, 'new': new, 'provenance': provenance,
                  'detail': detail}
        self.ledger._create(self.prefix + '.%06d.intent' % intent['sequence'], self._encode(intent))
        self.entries.append((intent, None))
        return intent

    @classmethod
    def _commit_record(cls, receipt):
        return {'version': 1, 'receipt_sha256': hashlib.sha256(cls._encode(receipt)).hexdigest()}

    def _committed(self, name):
        # Receipt existence is never sufficient: a failed receipt sync can
        # leave a completely readable inode. No post-failure poison is needed.
        if not self.ledger._exists(name + '.commit'):
            return None
        receipt = self._read(name)
        commit = self._read(name + '.commit')
        if (type(commit) is not dict or type(commit.get('version')) is not int or
                commit != self._commit_record(receipt)):
            raise LedgerError('receipt commit mismatch')
        return receipt

    def _sync_existing(self, name):
        fd = self.ledger._open_marker(name)
        if fd is None:
            raise LedgerError('missing reconciliation receipt')
        try:
            self.ledger._sync_file(fd)
            self.ledger._sync_directory()
            self.ledger._check_directory()
        finally:
            os.close(fd)

    def _commit_receipt(self, name, receipt, *, reconciled=False):
        """Call ONLY after remote readback/revocation/cleanup are known complete.

        The existing intent remains the unresolved state. The commit record is
        attempted only after receipt fsync AND directory fsync return success.
        Failure at that final record is an ambiguous local acknowledgement,
        NOT permission to repeat effects: a readable matching record may be
        accepted on reopen; if absent, the intent stays pending. We cannot
        infer power-loss durability from either readability or an fsync error.
        Only explicit read-only reconciliation may re-sync an existing receipt.
        """
        committed = self._committed(name)
        if committed is not None:
            if not reconciled or committed != receipt:
                raise LedgerError('commit acknowledgement uncertain; reconcile read-only')
            self._sync_existing(name)
            self._sync_existing(name + '.commit')
            return
        if self.ledger._exists(name):
            if not reconciled or self._read(name) != receipt:
                raise LedgerError('uncommitted receipt; reconcile read-only or inspect owner-side')
            self._sync_existing(name)
        else:
            self.ledger._create(name, self._encode(receipt))
        # There is deliberately no best-effort post-failure poison protocol.
        self.ledger._create(name + '.commit', self._encode(self._commit_record(receipt)))

    def complete(self, intent, result, *, reconciled=False):
        if self.pending() != intent:
            raise LedgerError('not the pending operation')
        name = self.prefix + '.%06d.' % intent['sequence']
        if self.ledger._exists(name + 'completion-uncertain'):
            raise LedgerError('legacy receipt durability uncertain; owner inspection required')
        receipt = {'intent': intent, 'result': result}
        self._commit_receipt(name + 'complete', receipt, reconciled=reconciled)
        self.entries[-1] = (intent, receipt)
        return receipt

    def confirm_cleanup(self, intent):
        name = self.prefix + '.%06d.cleanup' % intent['sequence']
        proof = {'intent': intent, 'leases_revoked': True}
        if self.ledger._exists(name + '.uncertain'):
            raise LedgerError('legacy cleanup durability uncertain; owner inspection required')
        existing = self._committed(name)
        if existing is not None:
            if existing != proof:
                raise LedgerError('cleanup proof mismatch')
        else:
            self._commit_receipt(name, proof)

    def cleanup_confirmed(self, intent):
        name = self.prefix + '.%06d.cleanup' % intent['sequence']
        return (not self.ledger._exists(name + '.uncertain') and
                self._committed(name) == {'intent': intent, 'leases_revoked': True})

    @staticmethod
    def _encode(value):
        return json.dumps(value, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode('ascii')

    def operation_key(self, intent):
        return digest(self.prefix, str(intent['sequence']))


def namespace_policy(data, app, verifier):
    """Exactly one deployed actor. A policy is host-owned, not request-selected."""
    p = data['publication_policy']
    if (type(p) is not dict or set(p) != {'actor', 'repository', 'namespace',
            'signer_fingerprint', 'credential_repository', 'max_update_commits', 'api_author'} or
            p['actor'] != 'dev-syn' or p['namespace'] != 'dev-syn' or
            p['repository'] != app.repository or p['credential_repository'] != app.repository or
            p['repository'] != verifier.repository or
            p['signer_fingerprint'] != verifier.signer_fingerprint or
            type(p['max_update_commits']) is not int or p['max_update_commits'] != 1):
        raise ValueError('invalid actor namespace signer credential policy')
    import re
    if type(p['api_author']) is not str or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9-]{0,99}(?:\[bot\])?', p['api_author']):
        raise ValueError('invalid fixed API author')
    return p
