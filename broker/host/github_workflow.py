"""Fixed-repository issue/PR broker. No merge, retarget, delete or arbitrary URL.

All collaborators are host construction only; requests never select a repo,
base, API author, credential, callback, endpoint or permission. Bearers remain
in this trusted host process, never the agent or source/capture worker.
"""
import http.client
import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from broker.issuer import read_base as base
from broker.issuer.api_lease import ApiLease
from broker.host.namespace_ledger import digest
from broker.worker import verifier

READ = {'issues': 'read', 'pull_requests': 'read', 'contents': 'read'}
INSPECT_PHASES = ('inspect-mint', 'inspect-deliver')
API_PHASES = INSPECT_PHASES + ('api-mint', 'api-deliver', 'api-write')


def text_fields(title, body, policy, model, thinking):
    if (type(title) is not str or not 1 <= len(title.encode('utf-8')) <= 200 or
            title.strip() != title or any(ord(c) < 32 or ord(c) == 127 for c in title) or
            type(body) is not str or not 1 <= len(body.encode('utf-8')) <= 12000 or
            any(ord(c) < 32 and c != '\n' for c in body) or '\x7f' in body or
            '<!-- publisher:' in body):
        raise ValueError('invalid bounded artifact text')
    expected = ['Agent: ' + policy.agent, 'Model: ' + model,
                'Thinking: ' + thinking, 'Bot-Owner: @' + policy.bot_owner]
    lines = body.split('\n')
    if (len(lines) < 6 or lines[-5] != '' or lines[-4:] != expected or
            sum(verifier._attribution(line) for line in lines) != 4):
        raise ValueError('artifact attribution mismatch')
    return title, body


def marker(repository, actor, branch, kind):
    return '<!-- publisher:' + digest(repository.casefold(), actor, branch, kind) + ' -->'


def artifact_body(body, correlation, issue_url=None):
    content, attribution = body.rsplit('\n\n', 1)
    link = '\n\nRefs ' + issue_url if issue_url else ''
    return content + link + '\n\n' + correlation + '\n\n' + attribution


class GithubWorkflow:
    def __init__(self, app, policy, api_author, *, request=None, lease=None):
        self.app, self.policy, self.author = app, policy, api_author
        self.root = '/repos/' + app.repository
        self._request = request or self._https
        self._make_lease = lease or (lambda permissions: ApiLease(app, permissions))
        self._used_leases = []

    def _lease(self, permissions):
        lease = self._make_lease(permissions)
        self._used_leases.append(lease)
        return lease

    @property
    def cleanup_confirmed(self):
        return bool(self._used_leases) and all(lease.cleanup_confirmed for lease in self._used_leases)

    def _https(self, method, path, token, payload=None):
        allowed_get = (path in (self.root + '/issues?state=all&per_page=100&page=1',) or
                       re.fullmatch(re.escape(self.root) + r'/(?:issues|pulls)\?state=all&per_page=100&page=(?:[1-9]|10)', path) or
                       re.fullmatch(re.escape(self.root) + r'/(?:issues|pulls)/[1-9][0-9]{0,9}', path) or
                       re.fullmatch(re.escape(self.root) + r'/git/ref/heads/dev-syn%2F[a-z0-9][a-z0-9-]{0,62}', path))
        allowed_post = ((path == self.root + '/issues' and type(payload) is dict and
                         set(payload) == {'title', 'body'}) or
                        (path == self.root + '/pulls' and type(payload) is dict and
                         set(payload) == {'title', 'body', 'head', 'base'} and
                         payload['base'] == 'main' and type(payload['head']) is str and
                         re.fullmatch(r'dev-syn/[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', payload['head'])))
        if (type(token) is not str or not base._TOKEN.fullmatch(token) or
                not ((method == 'GET' and allowed_get and payload is None) or
                     (method == 'POST' and allowed_post))):
            raise ValueError('API operation denied')
        request = urllib.request.Request(base._API + path, method=method,
            data=None if payload is None else json.dumps(payload, separators=(',', ':')).encode('utf-8'),
            headers={'Authorization': 'Bearer ' + token, 'Accept': 'application/vnd.github+json',
                     'X-GitHub-Api-Version': '2026-03-10', 'User-Agent': 'openclaw-scoped-publisher',
                     'Content-Type': 'application/json'})
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), base._NoRedirect())
        try:
            with opener.open(request, timeout=15) as response:
                if response.status != (201 if method == 'POST' else 200):
                    raise ValueError('API status mismatch')
                raw = response.read(1048577)
                if len(raw) > 1048576:
                    raise ValueError('API response too large')
                return base._strict_json(raw)
        except (urllib.error.URLError, OSError, ValueError, http.client.HTTPException):
            raise ValueError('API failed or uncertain; reconcile read-only') from None

    def _number(self, doc):
        value = doc.get('number') if type(doc) is dict else None
        if type(value) is not int or not 1 <= value <= 9999999999:
            raise ValueError('invalid artifact number')
        return value

    def _head(self, token, branch, sha):
        path = self.root + '/git/ref/heads/' + urllib.parse.quote(branch, safe='')
        doc = self._request('GET', path, token)
        if (type(doc) is not dict or doc.get('ref') != 'refs/heads/' + branch or
                not (type(doc.get('object')) is dict and doc['object'].get('type') == 'commit'
                     and doc['object'].get('sha') == sha)):
            raise ValueError('remote owned head mismatch')

    def validate(self, kind, doc, intent):
        detail = intent['detail']
        number = self._number(doc)
        expected_url = 'https://github.com/' + self.app.repository + ('/issues/' if kind == 'issue' else '/pull/') + str(number)
        if (doc.get('html_url') != expected_url or doc.get('title') != detail['title'] or
                doc.get('body') != detail['body'] or type(doc.get('user')) is not dict or
                doc['user'].get('login') != self.author or doc.get('state') != 'open'):
            raise ValueError('artifact readback mismatch')
        if kind == 'issue' and 'pull_request' in doc:
            raise ValueError('issue is a pull request')
        if kind == 'pr':
            self.validate_pr_head(doc, intent['binding']['branch'], intent['new'])
        return {'number': number, 'url': expected_url, 'head': intent['new'], 'readback_checked': True}

    def validate_pr_head(self, doc, branch, sha):
        for side, ref in (('base', 'main'), ('head', branch)):
            value = doc.get(side)
            if (type(value) is not dict or value.get('ref') != ref or
                    type(value.get('repo')) is not dict or
                    value['repo'].get('full_name') != self.app.repository):
                raise ValueError('PR repository/base/head retargeted')
        if (doc['head'].get('sha') != sha or doc.get('state') != 'open' or
                doc.get('user', {}).get('login') != self.author or
                doc.get('merged_at') is not None or doc.get('auto_merge') is not None):
            raise ValueError('PR head/state/author mismatch')

    def _find(self, token, kind, correlation):
        matches = []
        endpoint = 'issues' if kind == 'issue' else 'pulls'
        for page in range(1, 11):
            docs = self._request('GET', self.root + '/' + endpoint + '?state=all&per_page=100&page=' + str(page), token)
            if type(docs) is not list or len(docs) > 100:
                raise ValueError('invalid API list')
            for doc in docs:
                if type(doc) is not dict:
                    raise ValueError('invalid API list entry')
                if correlation in (doc.get('body') or ''):
                    matches.append(doc)
            if len(docs) < 100:
                return matches
        raise ValueError('bounded duplicate scan exhausted; inspect separately')

    def inspect(self, guard, consume):
        phases = iter(INSPECT_PHASES)
        return self._lease(READ).deliver_once(consume, lambda: guard.check(next(phases)))

    def check_review_head(self, journal, branch, old, guard):
        receipt = journal.latest('pr')
        if receipt:
            def check(token):
                self._head(token, branch, old)
                doc = self._request('GET', self.root + '/pulls/' + str(receipt['result']['number']), token)
                self.validate_pr_head(doc, branch, old)
            self.inspect(guard, check)
        else:
            for phase in INSPECT_PHASES:
                guard.check(phase)

    def run(self, journal, body, guard, provenance):
        action, branch = body['operation'], body['branch']
        owned = journal.latest('create', 'update')
        if (owned is None or owned['intent']['new'] != body['sha'] or
                owned['intent']['provenance'].get('signer_fingerprint') != self.policy.signer_fingerprint):
            raise ValueError('not a proven publisher-owned head')
        pending = journal.pending()
        if action == 'reconcile':
            completed = journal.latest('issue', 'pr')
            intent = pending if pending is not None else (completed['intent'] if completed else None)
            if intent is None or intent['kind'] not in ('issue', 'pr'):
                raise ValueError('no reconcilable API attempt; Git uncertainty requires owner inspection')
            # A completed PR may since have a verified review update. Validate
            # its current proven head, without changing the original artifact
            # payload/provenance or treating an unresolved write as ownership.
            validation_intent = {**intent, 'new': body['sha']}
            def reconcile(token):
                self._head(token, branch, body['sha'])
                matches = self._find(token, intent['kind'], intent['detail']['marker'])
                if len(matches) != 1:
                    raise ValueError('absent or duplicate artifact; never repeat create')
                doc = self._request('GET', self.root + ('/issues/' if intent['kind'] == 'issue' else '/pulls/') + str(self._number(matches[0])), token)
                return self.validate(intent['kind'], doc, validation_intent)
            result = self.inspect(guard, reconcile)
            if pending is not None:
                if not journal.cleanup_confirmed(intent):
                    raise ValueError('original lease cleanup unconfirmed; owner reconciliation required')
                journal.complete(intent, result, reconciled=True)  # original + read-reconciliation leases revoked
            return result
        if pending:
            raise ValueError('unresolved operation; reconcile read-only')
        if journal.latest(action):
            raise ValueError('artifact already attempted/completed; inspect read-only')
        title, text = text_fields(body['title'], body['body'], self.policy, body['model'], body['thinking'])
        issue = journal.latest('issue')
        if action == 'pr' and issue is None:
            raise ValueError('create corresponding issue before PR')
        correlation = marker(self.app.repository, 'dev-syn', branch, action)
        final_body = artifact_body(text, correlation, issue['result']['url'] if action == 'pr' else None)
        # Persist exact effect payload and old/new head BEFORE any API preflight.
        intent = journal.reserve(action, body['sha'], body['sha'], provenance,
                                 title=title, body=final_body, marker=correlation)
        preflight_at = None
        def inspect(token):
            nonlocal preflight_at
            if self._find(token, action, correlation):
                raise ValueError('duplicate/previous artifact; reconcile read-only, never POST')
            if action == 'pr':
                issue_doc = self._request('GET', self.root + '/issues/' + str(issue['result']['number']), token)
                self.validate('issue', issue_doc, issue['intent'])
                # Any PR for this head (including a closed/unrelated PR) denies creation.
                docs = self._all_prs(token)
                if any(d.get('head', {}).get('ref') == branch for d in docs):
                    raise ValueError('PR head already exists; inspect read-only')
            self._head(token, branch, body['sha'])
            preflight_at = time.monotonic()
        self.inspect(guard, inspect)
        endpoint = '/issues' if action == 'issue' else '/pulls'
        payload = {'title': title, 'body': final_body}
        if action == 'pr':
            payload.update({'head': branch, 'base': 'main'})
        def create(token):
            # Write leases deliberately do NOT include contents:read. The
            # separately revoked read lease proved the head; enforce a bounded
            # preflight, then fence immediately before the one mutation.
            if not 0 <= time.monotonic() - preflight_at <= 30:
                raise ValueError('API head preflight expired')
            guard.check('api-write')
            doc = self._request('POST', self.root + endpoint, token, payload)
            number = self._number(doc)
            self.validate(action, doc, intent)
            doc = self._request('GET', self.root + endpoint + '/' + str(number), token)
            return self.validate(action, doc, intent)
        phases = iter(('api-mint', 'api-deliver'))
        result = self._lease({'issues' if action == 'issue' else 'pull_requests': 'write'}).deliver_once(create, lambda: guard.check(next(phases)))
        journal.complete(intent, result)
        return result

    def _all_prs(self, token):
        result = []
        for page in range(1, 11):
            docs = self._request('GET', self.root + '/pulls?state=all&per_page=100&page=' + str(page), token)
            if type(docs) is not list or len(docs) > 100 or any(type(d) is not dict for d in docs):
                raise ValueError('invalid PR list')
            result.extend(docs)
            if len(docs) < 100:
                return result
        raise ValueError('bounded PR scan exhausted')
