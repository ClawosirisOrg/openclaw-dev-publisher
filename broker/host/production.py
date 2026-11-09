"""Gateway-owned per-invocation broker process; no listener or environment defaults.

Only a reviewed host wrapper may invoke this module, with private config argv
and inherited anonymous stdin/stdout. The sandbox must not see that wrapper,
config, App key, Podman socket, storage, or host process namespace. Configuration
and live isolation require operator review before installation.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import select
import signal
import stat
import sys
import time
from dataclasses import asdict

from broker.host.attempt_ledger import AttemptLedger
from broker.host.namespace_ledger import BranchJournal, namespace_policy
from broker.host.github_workflow import GithubWorkflow, API_PHASES, INSPECT_PHASES
from broker.host.stage_allocator import StageAllocator
from broker.host.production_runtime import Session
from broker.issuer import read_base
from broker.issuer.write_lease import WriteLease
from broker.worker import claim, verifier, isolation

KEYS = {'app_config', 'runtime_socket', 'image_id', 'source_host', 'source_device',
        'source_inode', 'stage_root', 'stage_host_root', 'ledger_root',
        'transport_network', 'approved_branch', 'python_path', 'deployment_id', 'verifier'}
PHASES = ('base', 'capture', 'reverify', 'mint', 'deliver', 'handoff', 'create')


def protected_directory(path):
    if type(path) is not str or not path.startswith('/') or path == '/':
        raise ValueError('invalid protected path')
    fd = os.open('/', claim.DIR_FLAGS)
    try:
        parts = path.split('/')[1:]
        for part in parts:
            if part in ('', '.', '..'):
                raise ValueError('invalid protected path')
            child = os.open(part, claim.DIR_FLAGS, dir_fd=fd)
            os.close(fd)
            fd = child
            info = os.fstat(fd)
            if info.st_uid not in (0, os.geteuid()) or info.st_mode & 0o022:
                raise ValueError('unprotected ancestor')
        info = os.fstat(fd)
        if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise ValueError('unprotected directory')
        return fd
    except BaseException:
        os.close(fd)
        raise


def load_config(path):
    fd = read_base._private_file(path, 16384)
    with os.fdopen(fd, 'rb') as stream:
        data = read_base._strict_json(stream.read(16385))
    if type(data) is not dict or set(data) not in (KEYS, (KEYS - {'approved_branch'}) | {'publication_policy', 'api_app_config'}):
        raise ValueError('invalid production config')
    for name in ('source_host', 'stage_root', 'stage_host_root', 'ledger_root', 'runtime_socket', 'app_config'):
        value = data[name]
        if (type(value) is not str or not value.startswith('/') or value == '/' or
                any(p in ('', '.', '..') for p in value.split('/')[1:]) or
                any(c in value for c in ('\0', ',', ':', '\n'))):
            raise ValueError('invalid deployment path')
    isolation.require_gateway_owner()
    if (any(type(data[k]) is not int or data[k] < 0 for k in ('source_device', 'source_inode')) or
            type(data['image_id']) is not str or not re.fullmatch('[0-9a-f]{64}', data['image_id']) or
            type(data['transport_network']) is not str or
            not re.fullmatch('[a-z][a-z0-9_-]{0,62}', data['transport_network']) or
            data['transport_network'] in ('host', 'none', 'bridge', 'slirp4netns', 'pasta')):
        raise ValueError('invalid runtime isolation config')
    source, stage = Path(data['source_host']), Path(data['stage_host_root'])
    if source == stage or source in stage.parents or stage in source.parents:
        raise ValueError('source and stage overlap')
    app = read_base.load_deploy_config(data['app_config'])
    verify = dict(data['verifier'])
    verify['signer_public_key'] = verify['signer_public_key'].encode('ascii')
    policy = verifier.DeployConfig(**verify)
    if (policy.repository != app.repository or policy.branch_prefix != 'dev-syn' or
            policy.base_ref != 'refs/heads/main'):
        raise ValueError('deployment target mismatch')
    if 'publication_policy' in data:
        namespace_policy(data, app, policy)
        api_app = read_base.load_deploy_config(data['api_app_config'])
        if api_app.repository != app.repository:
            raise ValueError('API credential repository mismatch')
    elif type(data['approved_branch']) is not str or not claim.BRANCH.fullmatch(data['approved_branch']):
        raise ValueError('invalid approved branch')
    if (type(data['deployment_id']) is not str or
            not re.fullmatch('[a-z0-9-]{1,64}', data['deployment_id']) or
            type(data['python_path']) is not str or not data['python_path'].startswith('/') or
            any(p in ('', '.', '..') for p in data['python_path'].split('/')[1:])):
        raise ValueError('invalid packaged process configuration')
    # A private config alone is not proof of host mount mappings or namespace
    # isolation. The operator must verify those against the actual deployment.
    return data, app, policy


def read_line(fd=0, *, timeout=5.0):
    raw = bytearray()
    deadline = time.monotonic() + timeout
    while len(raw) <= 32768:
        left = deadline - time.monotonic()
        if left <= 0 or not select.select([fd], [], [], left)[0]:
            raise ValueError('gateway channel expired')
        byte = os.read(fd, 1)
        if not byte:
            raise ValueError('gateway channel closed')
        if byte == b'\n':
            return read_base._strict_json(bytes(raw))
        raw.extend(byte)
    raise ValueError('gateway frame too large')


def write_line(body):
    claim._write_all(1, json.dumps(body, separators=(',', ':'), allow_nan=False).encode('ascii') + b'\n')


class LiveGuard:
    def __init__(self, phases=PHASES):
        self._next = iter(phases)

    def check(self, phase):
        if next(self._next, None) != phase:
            raise ValueError('invalid authorization phase')
        nonce = secrets.token_hex(16)
        write_line({'guard': phase, 'nonce': nonce})
        reply = read_line()
        if reply != {'allow': phase, 'nonce': nonce}:
            raise ValueError('gateway authorization denied')
        return True


def worker_payload(body, base, config, allocation):
    common = {'version': 1, 'transactionId': body['attempt'], 'repository': config.repository,
        'ref': config.base_ref, 'base': base, 'sha': body['sha'], 'branch': body['branch'],
        'model': body['model'], 'thinking': body['thinking'],
        'thinkingSource': 'agent_attested', 'claimId': body['attempt']}
    claim._validate(common, config_pin(config))
    policy = asdict(config)
    policy['signer_public_key'] = policy['signer_public_key'].decode('ascii')
    return {'claim': common, 'verifier': policy,
            'stage': {'device': allocation.device, 'inode': allocation.inode}}


def config_pin(config):
    from types import SimpleNamespace
    return SimpleNamespace(repository=config.repository, ref=config.base_ref)


def validate_request(body):
    if type(body) is not dict:
        raise ValueError('invalid gateway request')
    required = {'attempt', 'sha', 'branch', 'model', 'thinking'}
    operation = body.get('operation', 'create')
    extra = {'operation'} if 'operation' in body else set()
    if operation == 'update':
        extra.add('expectedOldSha')
    elif operation in ('issue', 'pr'):
        extra.update(('title', 'body'))
    elif operation not in ('create', 'reconcile'):
        raise ValueError('invalid operation')
    if (set(body) != required | extra or
            type(body['attempt']) is not str or not claim.ID.fullmatch(body['attempt']) or
            type(body['sha']) is not str or not claim.SHA.fullmatch(body['sha']) or
            type(body['branch']) is not str or not claim.BRANCH.fullmatch(body['branch']) or
            type(body['model']) is not str or not claim.MODEL.fullmatch(body['model']) or
            type(body['thinking']) is not str or body['thinking'] not in claim.THINKING):
        raise ValueError('invalid gateway request')
    if operation == 'update' and (type(body['expectedOldSha']) is not str or
            not claim.SHA.fullmatch(body['expectedOldSha']) or body['expectedOldSha'] == body['sha']):
        raise ValueError('invalid expected old sha')
    if operation in ('issue', 'pr') and (type(body['title']) is not str or type(body['body']) is not str):
        raise ValueError('invalid artifact text')


def publication_key(repository, branch):
    return hashlib.sha256((repository.casefold() + '\0' + branch).encode('ascii')).hexdigest()[:32]


def _publish(data, app, policy, body, guard, review_check=None):
    """Operational composition. Inputs come ONLY from private deployment/channel."""
    stage_fd = protected_directory(data['stage_root'])
    try:
        ledger_fd = protected_directory(data['ledger_root'])
        try:
            if ((os.fstat(stage_fd).st_dev, os.fstat(stage_fd).st_ino) ==
                    (os.fstat(ledger_fd).st_dev, os.fstat(ledger_fd).st_ino)):
                raise ValueError('stage and ledger overlap')
            ledger = AttemptLedger(ledger_fd, expected_uid=os.geteuid())
            allocator = StageAllocator(stage_fd, ledger, expected_uid=os.geteuid(), expected_gid=os.getegid())
            allocation = allocator.allocate(body['attempt'], 's-' + body['attempt'])
            sessions = []
            try:
                guard.check('base')
                base = read_base.BaseIssuer(app).current_main()
                payload = worker_payload(body, body.get('expectedOldSha', base), policy, allocation)
                stage_host = data['stage_host_root'] + '/' + allocation.label
                for operation in ('capture', 'reverify'):
                    guard.check(operation)
                    mounts = [(stage_host, '/stage', False)]
                    worker_input = dict(payload)
                    if operation == 'capture':
                        mounts.append((data['source_host'], '/source/' + policy.source_component, True))
                        worker_input['source'] = {'device': data['source_device'], 'inode': data['source_inode']}
                    session = Session(data['runtime_socket'], data['image_id'], operation, mounts,
                                      attempt=body['attempt'])
                    sessions.append(session)
                    with session:
                        session.send(worker_input)
                        observed = session.receive()
                        session.finish()
                    if (type(observed) is not dict or set(observed) != {'sha', 'tree'} or
                            observed['sha'] != body['sha'] or type(observed['tree']) is not str or
                            not claim.SHA.fullmatch(observed['tree'])):
                        raise ValueError('invalid object verification result')
                    if operation == 'capture':
                        captured = observed
                    elif observed != captured:
                        raise ValueError('independent object verification mismatch')

                if review_check is not None:
                    review_check()

                def transport(token):
                    session = Session(data['runtime_socket'], data['image_id'], 'transport',
                        [(stage_host + '/publish/store.git', '/store', True)],
                        network=data['transport_network'], attempt=body['attempt'])
                    sessions.append(session)
                    with session:
                        # Startup/readiness may await; fence again immediately
                        # before the only bearer write to the private channel.
                        guard.check('handoff')
                        transport_body = {'repository': policy.repository, 'sha': body['sha'],
                            'branch': body['branch'], 'base': base, 'token': token}
                        if 'expectedOldSha' in body:
                            transport_body['expected_old'] = body['expectedOldSha']
                        session.send(transport_body)
                        if session.receive() != {'guard': 'create'}:
                            raise ValueError('invalid transport preflight')
                        guard.check('create')
                        session.send({'allow': 'create'})
                        outcome = session.receive()
                        session.finish()
                    if type(outcome) is not dict or set(outcome) != {'result'}:
                        raise ValueError('push uncertain inspect no retry')
                    result = outcome['result']
                    if (type(result) is not dict or set(result) != {'sha', 'branch', 'base',
                            'acknowledged', 'readback_checked', 'main_at_readback', 'stale'} or
                            result['sha'] != body['sha'] or result['branch'] != body['branch'] or
                            result['base'] != base or result['acknowledged'] is not True or
                            result['readback_checked'] is not True or
                            type(result['main_at_readback']) is not str or
                            not claim.SHA.fullmatch(result['main_at_readback']) or
                            type(result['stale']) is not bool or
                            result['stale'] != (result['main_at_readback'] != base)):
                        raise ValueError('invalid remote readback')
                    return result

                phases = iter(('mint', 'deliver'))
                result = WriteLease(app).deliver_once(transport, lambda: guard.check(next(phases)))
                return result
            finally:
                # Never rename a still-mounted path after uncertain cleanup.
                # Its attempted tombstone remains permanent in either case.
                if all(session.terminated for session in sessions):
                    allocator.quarantine(allocation, worker_terminated=True)
                else:
                    raise ValueError('worker cleanup uncertain; inspect no retry')
        finally:
            os.close(ledger_fd)
    finally:
        os.close(stage_fd)


def run(data, app, policy, body, guard):
    validate_request(body)
    operation = body.get('operation', 'create')
    if 'publication_policy' not in data:
        if operation != 'create' or body['branch'] != data['approved_branch']:
            raise ValueError('unapproved branch or legacy operation')
        body = {**body, 'attempt': publication_key(app.repository, data['approved_branch'])}
        return _publish(data, app, policy, body, guard)
    p = namespace_policy(data, app, policy)
    fd = protected_directory(data['ledger_root'])
    try:
        ledger = AttemptLedger(fd, expected_uid=os.geteuid())
        with BranchJournal(ledger, p['actor'], app.repository, body['branch']).locked() as journal:
            # Never silently adopt/retry a legacy spent branch, even if it has
            # no remote ref or the remote happens to contain the requested SHA.
            if ledger.state(publication_key(app.repository, body['branch'])) is not None:
                raise ValueError('legacy spent branch; owner reconciliation required')
            provenance = {'actor': p['actor'], 'agent': policy.agent, 'model': body['model'],
                'model_source': 'gateway_active_model', 'thinking': body['thinking'],
                'thinking_source': 'agent_attested', 'signer_fingerprint': policy.signer_fingerprint,
                'credential_repository': app.repository,
                'contents_credential': {'app_id': app.app_id, 'installation_id': app.installation_id},
                'invocation_correlation': body['attempt']}
            if operation in ('issue', 'pr', 'reconcile'):
                api_app = read_base.load_deploy_config(data['api_app_config'])
                if api_app.repository != app.repository:
                    raise ValueError('API credential repository mismatch')
                provenance['api_credential'] = {'app_id': api_app.app_id, 'installation_id': api_app.installation_id}
                workflow = GithubWorkflow(api_app, policy, p['api_author'])
                try:
                    return workflow.run(journal, body, guard, provenance)
                finally:
                    pending = journal.pending()
                    if (pending is not None and pending['kind'] in ('issue', 'pr') and
                            workflow.cleanup_confirmed and operation != 'reconcile'):
                        journal.confirm_cleanup(pending)
            if journal.pending():
                raise ValueError('unresolved operation; inspect no retry')
            owned = journal.latest('create', 'update')
            if operation == 'create' and owned is not None:
                raise ValueError('branch already owned; use expected-old update')
            if operation == 'update':
                if owned is None or owned['intent']['new'] != body['expectedOldSha']:
                    raise ValueError('not a proven publisher-owned expected head')
                # The signer pin cannot change underneath an existing branch.
                if owned['intent']['provenance']['signer_fingerprint'] != policy.signer_fingerprint:
                    raise ValueError('branch signer changed')
            intent = journal.reserve(operation, body.get('expectedOldSha'), body['sha'], provenance)
            if operation == 'update':
                api_app = read_base.load_deploy_config(data['api_app_config'])
                if api_app.repository != app.repository:
                    raise ValueError('API credential repository mismatch')
                workflow = GithubWorkflow(api_app, policy, p['api_author'])
                review_check = lambda: workflow.check_review_head(
                    journal, body['branch'], body['expectedOldSha'], guard)
            else:
                review_check = None
            result = _publish(data, app, policy,
                              {**body, 'attempt': journal.operation_key(intent)}, guard, review_check)
            if operation == 'update':
                workflow.check_review_head(journal, body['branch'], body['sha'], guard)
            journal.complete(intent, result)  # only after revocation + cleanup
            return result
    finally:
        os.close(fd)


def request_phases(body):
    operation = body.get('operation', 'create')
    if operation in ('issue', 'pr'):
        return API_PHASES
    if operation == 'reconcile':
        return INSPECT_PHASES
    if operation == 'update':
        return PHASES[:3] + INSPECT_PHASES + PHASES[3:] + INSPECT_PHASES
    return PHASES


def main():
    if len(sys.argv) == 3 and sys.argv[1] == '--check-config':
        data, _app, _policy = load_config(sys.argv[2])
        descriptors = []
        try:
            for field in ('stage_root', 'ledger_root'):
                descriptors.append(protected_directory(data[field]))
            if ((os.fstat(descriptors[0]).st_dev, os.fstat(descriptors[0]).st_ino) ==
                    (os.fstat(descriptors[1]).st_dev, os.fstat(descriptors[1]).st_ino)):
                raise ValueError('stage and ledger overlap')
        finally:
            for fd in descriptors:
                os.close(fd)
        write_line({'config_valid': True, 'uid_mapping': 'rootless-owner',
                    'proof_scope': 'local-config-and-directories-only'})
        return
    if len(sys.argv) != 2:
        raise ValueError('private deployment config required')
    def cancelled(*_args):
        raise InterruptedError('gateway cancelled')
    signal.signal(signal.SIGTERM, cancelled)
    signal.signal(signal.SIGALRM, cancelled)
    signal.alarm(600)
    data, app, policy = load_config(sys.argv[1])
    body = read_line()
    result = run(data, app, policy, body, LiveGuard(request_phases(body)))
    write_line({'result': result})


if __name__ == '__main__':
    try:
        main()
    except BaseException:
        # Any lost response is uncertain; never turn it into permission to retry.
        try:
            write_line({'error': 'publication_failed_or_uncertain_inspect_no_retry'})
        except BaseException:
            pass
        os._exit(1)
