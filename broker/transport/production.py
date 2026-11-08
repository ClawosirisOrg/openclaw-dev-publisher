"""Ephemeral transport worker: no PEM, source checkout, signer or runtime socket.

Only the trusted host launches this with a freshly verified read-only store and
private duplex stdin/stdout. One write attempt; acknowledgments require exact
porcelain plus remote ref readback. No retry or cleanup ref operation exists.
"""
import os
import sys
import time

from broker.transport import git_adapter as git
from broker.transport.one_shot import UncertainPush, _request, OID
from broker.worker import production as protocol


def _pipe(token):
    reader, writer = os.pipe2(os.O_CLOEXEC)
    try:
        data = token.encode('ascii')
        offset = 0
        while offset < len(data):
            offset += os.write(writer, data[offset:])
    except BaseException:
        os.close(reader)
        raise
    finally:
        os.close(writer)
    return reader


def create_once(target, sha, branch, base, *, call, guard, clock=time.monotonic):
    """Trust comes from the host-owned process/pipe and image, not these args."""
    _request(sha, branch, base)
    ref = 'refs/heads/' + branch

    def main():
        raw = call('main', 'refs/heads/main')
        if (type(raw) is not bytes or len(raw) != 57 or
                raw[40:] != b'\trefs/heads/main\n' or
                not OID.fullmatch(raw[:40].decode('ascii'))):
            raise ValueError('invalid main readback')
        return raw[:40].decode('ascii')

    def observe():
        raw = call('branch', ref)
        if raw == b'':
            return None
        suffix = b'\t' + ref.encode('ascii') + b'\n'
        if (type(raw) is not bytes or len(raw) != 40 + len(suffix) or
                raw[40:] != suffix or not OID.fullmatch(raw[:40].decode('ascii'))):
            raise ValueError('invalid branch readback')
        return raw[:40].decode('ascii')

    if main() != base:
        raise ValueError('main drift')
    if observe() is not None:
        raise ValueError('branch exists')
    # Last remote main observation precedes the final live guard. No network
    # lookup or await intervenes between its one-use permit and the push call.
    started = clock()
    if main() != base:
        raise ValueError('main drift')
    if guard() is not True:
        raise ValueError('authorization denied')
    if not 0 <= clock() - started <= 10.0:
        raise ValueError('main preflight expired')
    try:
        response = call('create', ref, sha)
        expected = (b'To ' + target.remote.encode('ascii') + b'\n*\t' + sha.encode('ascii') +
                    b':' + ref.encode('ascii') + b'\t[new branch]\nDone\n')
        if response != expected or observe() != sha:
            raise ValueError('unacknowledged create')
        observed_main = main()
    except BaseException:
        raise UncertainPush('push attempted; inspect separately, never retry') from None
    return {'sha': sha, 'branch': branch, 'base': base, 'acknowledged': True,
            'readback_checked': True, 'main_at_readback': observed_main,
            'stale': observed_main != base}


def main():
    protocol.isolation.require_worker_isolation()
    protocol.write({'ready': 'transport', 'mapping': 'rootless-owner'})
    body = protocol.read()
    if type(body) is not dict or set(body) != {'repository', 'sha', 'branch', 'base', 'token'}:
        raise ValueError('invalid transport input')
    if (type(body['token']) is not str or not 1 <= len(body['token']) <= 4096 or
            any(ord(c) < 33 or ord(c) > 126 for c in body['token'])):
        raise ValueError('invalid token')
    owner, name = body['repository'].split('/')
    target = git._DeployTarget(owner, name, '/store')
    token = body.pop('token')
    def call(operation, ref, sha=None):
        return git._run(target, operation, ref, _pipe(token), sha=sha)
    def guard():
        protocol.write({'guard': 'create'})
        return protocol.read() == {'allow': 'create'}
    try:
        result = create_once(target, body['sha'], body['branch'], body['base'],
                             call=call, guard=guard)
        protocol.write({'result': result})
    except UncertainPush:
        protocol.write({'uncertain': True})
        raise
    finally:
        token = None


if __name__ == '__main__':
    try:
        main()
    except BaseException:
        os._exit(1)
