"""Fixed worker entrypoints, invoked ONLY by the trusted host runtime.

Input is a private framed stdin from the broker, never an agent-facing socket.
Capture/reverify have no network or credential mounts. Transport is separate.
"""
import json
import os
import sys
from dataclasses import asdict
from types import SimpleNamespace

from broker.worker import capture_once, claim, handoff, verifier, isolation

LIMIT = 8192


def encode(body):
    raw = json.dumps(body, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode('ascii')
    if not 0 < len(raw) <= LIMIT:
        raise ValueError('invalid private frame')
    return len(raw).to_bytes(4, 'big') + raw


def read(fd=0):
    import time
    deadline = time.monotonic() + 10.0
    size = int.from_bytes(claim._read_exact(fd, 4, deadline), 'big')
    if not 0 < size <= LIMIT:
        raise ValueError('invalid private frame')
    raw = claim._read_exact(fd, size, deadline)
    body = json.loads(raw.decode('ascii'), object_pairs_hook=claim._pairs,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError('constant')))
    if encode(body)[4:] != raw:
        raise ValueError('invalid private frame')
    return body


def write(body):
    claim._write_all(1, encode(body))


def configuration(body):
    data = dict(body['verifier'])
    data['signer_public_key'] = data['signer_public_key'].encode('ascii')
    config = verifier.DeployConfig(**data)
    if config.branch_prefix != 'dev-syn':
        raise ValueError('invalid branch policy')
    claim._validate(body['claim'], SimpleNamespace(repository=config.repository, ref=config.base_ref))
    return config, verifier.Invocation(body['claim']['sha'], body['claim']['branch'],
        body['claim']['base'], body['claim']['model'], body['claim']['thinking'])


def pin(path, device, inode):
    fd = os.open(path, claim.DIR_FLAGS)
    try:
        st = os.fstat(fd)
        if (st.st_dev, st.st_ino) != (device, inode):
            raise ValueError('mount inode mismatch')
        return claim._mount_id(fd)
    finally:
        os.close(fd)


def capture(body, *, stage_path='/stage', source_path='/source'):
    config, invocation = configuration(body)
    stage = body['stage']
    mount = pin(stage_path, stage['device'], stage['inode'])
    source = body['source']
    # Mount ONLY the repository at this child, never its workspace parent
    # (which could contain an agent socket, private config or sibling repos).
    repository_path = source_path + '/' + config.source_component
    pin(repository_path, source['device'], source['inode'])
    parent = os.open(source_path, claim.DIR_FLAGS)
    try:
        parent_info = os.fstat(parent)
        source_mount = claim._mount_id(parent)
    finally:
        os.close(parent)
    deploy = claim.DeploymentPin(stage_path, stage['device'], stage['inode'], mount,
        os.geteuid(), config.repository, config.base_ref)
    source_bind = capture_once.SourceBind(source_path, parent_info.st_dev, parent_info.st_ino, source_mount)
    reader, writer = os.pipe2(os.O_CLOEXEC)
    try:
        raw = json.dumps(body['claim'], separators=(',', ':'), ensure_ascii=False).encode('utf-8')
        claim._write_all(writer, len(raw).to_bytes(4, 'big') + raw)
    finally:
        os.close(writer)
    result = capture_once.capture_once(reader, deploy, source_bind, config)
    pin(repository_path, source['device'], source['inode'])
    return {'sha': invocation.sha, 'tree': result['capture']['tree']}


def reverify(body, *, stage_path='/stage'):
    """New container, no source mount; import ONLY object payloads into sterile store.

    Never trust capture-generated config, refs, hooks, expected tree or receipt.
    The returned tree is independently derived with the separately pinned key.
    """
    config, invocation = configuration(body)
    pin(stage_path, body['stage']['device'], body['stage']['inode'])
    stage = os.open(stage_path, claim.DIR_FLAGS)
    try:
        os.mkdir('publish', 0o700, dir_fd=stage)
        publish = handoff.directory(stage, 'publish')
        captured = handoff.directory(stage, 'capture')
        try:
            old_store = handoff.directory(captured, 'store.git')
            try:
                old_objects = handoff.directory(old_store, 'objects')
                try:
                    os.mkdir('store.git', 0o700, dir_fd=publish)
                    store = handoff.directory(publish, 'store.git')
                    try:
                        handoff.new_file(store, 'HEAD', b'ref: refs/heads/main\n')
                        handoff.new_file(store, 'config', b'[core]\n\tbare = true\n')
                        os.mkdir('refs', 0o700, dir_fd=store)
                        os.mkdir('objects', 0o700, dir_fd=store)
                        objects = handoff.directory(store, 'objects')
                        try:
                            handoff.copy_objects(old_objects, objects)
                        finally:
                            os.close(objects)
                        tree = verifier.verify_graph(f'/proc/{os.getpid()}/fd/{store}',
                                                     invocation, config, publish)
                    finally:
                        os.close(store)
                finally:
                    os.close(old_objects)
            finally:
                os.close(old_store)
        finally:
            os.close(captured)
            os.close(publish)
    finally:
        os.close(stage)
    return {'sha': invocation.sha, 'tree': tree}


def main():
    # Importing this module does not start workers. No arbitrary command, path,
    # Git config, callback, environment or entrypoint is accepted from input.
    if sys.argv[1:] not in (['capture'], ['reverify']):
        raise ValueError('invalid worker operation')
    isolation.require_worker_isolation()
    write({'ready': sys.argv[1], 'mapping': 'rootless-owner'})
    body = read()
    result = capture(body) if sys.argv[1] == 'capture' else reverify(body)
    write(result)


if __name__ == '__main__':
    try:
        main()
    except BaseException:
        # Never surface object bytes, paths or a private frame in a traceback.
        os._exit(1)
