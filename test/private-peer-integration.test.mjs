import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createConnection } from 'node:net';
import { chmodSync, mkdtempSync, mkdirSync, readFileSync, readdirSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { decodeClaimFrame } from '../src/claim-frame.mjs';
import { createPrivateHostChannel } from '../src/private-host-channel.mjs';

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const repository = 'fixture/repository';
const ref = 'refs/heads/main';
const base = 'b'.repeat(40);
const request = { commitSha: 'a'.repeat(40), branch: 'dev-syn/peer-test', thinking: 'off' };

// A test-only host: no CLI entrypoint, Gateway, container, network, credentials,
// or publisher. The listener, expected kernel peer identity, and ledger fd are
// independent trusted fixtures, not claims extracted from the frame.
const host = String.raw`
import base64
import json
import os
import socket
import struct
import sys
from broker.host import peer_admission, stage_allocator

directory, expected_pid, expected_uid, expected_gid = sys.argv[1:]
expected_pid, expected_uid, expected_gid = map(int, (expected_pid, expected_uid, expected_gid))
ledger_path = os.path.join(directory, 'ledger')
socket_path = os.path.join(directory, 'peer.sock')
fd = os.open(ledger_path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
reads = []
read_calls = []
stage_calls = []
original_read = peer_admission._read_exact
def observed_read(connection, count, deadline):
    read_calls.append(count)  # record attempts even if the read would time out
    data = original_read(connection, count, deadline)
    reads.append(data)
    return data
def forbidden_stage(*args, **kwargs):
    stage_calls.append(True)
    raise AssertionError('stage allocation reached')
peer_admission._read_exact = observed_read
stage_allocator.StageAllocator.allocate = forbidden_stage
try:
    listener.bind(socket_path)
    os.chmod(socket_path, 0o600)
    listener.listen(1)
    listener.settimeout(3)
    print(json.dumps({'phase': 'ready'}), flush=True)
    for phase in ('first', 'replay', 'wrong_peer'):
        connection, _ = listener.accept()
        peer = struct.unpack('3i', connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        reads.clear()
        read_calls.clear()
        admission = peer_admission.PeerAdmission(
            connection, expected_pid=expected_pid + (phase == 'wrong_peer'),
            expected_uid=expected_uid, expected_gid=expected_gid,
            repository='fixture/repository', ref='refs/heads/main',
            ledger_dirfd=fd, same_uid_isolated_socket=True)
        result = admission.run()
        print(json.dumps({'phase': phase, 'result': result, 'peer': peer,
                          'readCalls': len(read_calls),
                          'frame': base64.b64encode(b''.join(reads)).decode('ascii'),
                          'stageCalls': len(stage_calls)}), flush=True)
finally:
    listener.close()
    os.close(fd)
`;

function childEvents(child) {
  let pending, output = '', errors = '', ended = false;
  const queue = [];
  const deliver = event => {
    if (pending) { const done = pending; pending = null; done(event); }
    else queue.push(event);
  };
  child.stdout.on('data', chunk => {
    output += chunk.toString();
    if (output.length > 8192) { deliver({ error: 'oversized host output' }); return; }
    for (let end; (end = output.indexOf('\n')) !== -1;) {
      const line = output.slice(0, end);
      output = output.slice(end + 1);
      try { deliver(JSON.parse(line)); }
      catch { deliver({ error: `invalid host event: ${line}` }); }
    }
  });
  child.stderr.on('data', chunk => { errors = (errors + chunk.toString()).slice(-4096); });
  child.on('error', error => { ended = true; deliver({ error: String(error) }); });
  child.on('exit', (code, signal) => {
    ended = true;
    deliver({ exit: [code, signal], error: errors || undefined });
  });
  return async (phase, timeoutMs = 3500) => {
    const event = queue.length ? queue.shift() : await new Promise((resolve, reject) => {
      if (ended) { reject(new Error(`host exited before ${phase}: ${errors}`)); return; }
      const timer = setTimeout(() => { pending = null; reject(new Error(`host ${phase} timed out: ${errors}`)); }, timeoutMs);
      pending = value => { clearTimeout(timer); resolve(value); };
    });
    assert.equal(event.error, undefined, JSON.stringify(event));
    if (phase === 'exit') assert.deepEqual(event.exit, [0, null]);
    else assert.equal(event.phase, phase, JSON.stringify(event));
    return event;
  };
}

function exchange(path, frame) {
  return new Promise((resolve, reject) => {
    const socket = createConnection(path);
    let bytes = Buffer.alloc(0);
    socket.setTimeout(2500, () => socket.destroy(new Error('peer response timeout')));
    socket.on('connect', () => { if (frame) socket.end(frame); });
    socket.on('data', chunk => { bytes = Buffer.concat([bytes, chunk]); });
    socket.on('error', reject);
    socket.on('end', () => resolve(bytes));
    socket.on('close', () => { if (!socket.readableEnded) reject(new Error('peer closed without EOF')); });
  });
}

test('JS channel and Python peer admission deny after one canonical AF_UNIX frame',
  { timeout: 12000 }, async () => {
    const directory = mkdtempSync(join(tmpdir(), 'private-peer-'));
    chmodSync(directory, 0o700);
    const ledger = join(directory, 'ledger');
    mkdirSync(ledger, { mode: 0o700 });
    const socketPath = join(directory, 'peer.sock');
    let child, closed;
    try {
      child = spawn('python3', ['-B', '-u', '-c', host, directory,
        String(process.pid), String(process.getuid()), String(process.getgid())], {
        cwd: root, stdio: ['ignore', 'pipe', 'pipe'],
        env: { PATH: '/usr/bin:/bin', PYTHONDONTWRITEBYTECODE: '1',
          PYTHONNOUSERSITE: '1' },
      });
      closed = new Promise(resolve => child.once('close', resolve));
      const next = childEvents(child);
      await next('ready');
      assert.equal(statSync(directory).mode & 0o777, 0o700);
      assert.equal(statSync(ledger).mode & 0o777, 0o700);
      assert.equal(statSync(socketPath).mode & 0o777, 0o600);

      const channel = createPrivateHostChannel({ repository, ref, socketPath,
        lookupFixedBaseForTest: async () => base, deadlineMs: 2000 });
      const context = { agentId: 'dev-syn', sandboxed: true,
        activeModel: { modelRef: 'fixture/model' }, assertInvocationCurrent: () => true };
      await assert.rejects(channel.run(context, request), error =>
        error?.message === 'publication_disabled');
      const first = await next('first');
      assert.deepEqual(first.peer, [process.pid, process.getuid(), process.getgid()]);
      assert.equal(first.result, 'publication_disabled');
      assert.equal(first.stageCalls, 0);
      assert.equal(first.readCalls, 2); // one length and one body; EOF checked by host
      const frame = Buffer.from(first.frame, 'base64');
      const body = decodeClaimFrame(frame);
      assert.equal(frame.readUInt32BE(0), frame.length - 4);
      assert.deepEqual(frame.subarray(4), Buffer.from(JSON.stringify(body)));
      assert.equal(body.repository, repository);
      assert.equal(body.ref, ref);
      assert.equal(body.base, base);
      assert.equal(body.sha, request.commitSha);
      assert.equal(body.branch, request.branch);
      assert.equal(body.model, context.activeModel.modelRef);
      assert.equal(body.thinking, request.thinking);
      assert.equal(body.claimId, body.transactionId); // correlation, not authority

      const names = () => readdirSync(ledger).sort();
      const expected = ['.lock', `${body.claimId}.allocated`, `${body.claimId}.attempted`].sort();
      assert.deepEqual(names(), expected);
      const allocated = join(ledger, `${body.claimId}.allocated`);
      const attempted = join(ledger, `${body.claimId}.attempted`);
      const label = readFileSync(allocated, 'utf8');
      assert.match(label, /^admit-[0-9a-f]{32}$/);
      assert.notEqual(label, body.claimId);
      assert.equal(readFileSync(attempted).length, 0);
      for (const name of expected) assert.equal(statSync(join(ledger, name)).mode & 0o777, 0o600);
      const inodes = expected.map(name => statSync(join(ledger, name)).ino);

      await assert.rejects(channel.run(context, request), /handoff_replay_denied/);
      assert.deepEqual(await exchange(socketPath, frame), Buffer.alloc(0));
      const replay = await next('replay');
      assert.deepEqual(replay.peer, first.peer);
      assert.equal(replay.result, null);
      assert.equal(replay.frame, first.frame);
      assert.equal(replay.stageCalls, 0);
      assert.deepEqual(names(), expected);
      assert.deepEqual(expected.map(name => statSync(join(ledger, name)).ino), inodes);

      // Keep the write half open: a read-first implementation would block on
      // its deadline. The kernel identity mismatch must close before any read.
      assert.deepEqual(await exchange(socketPath), Buffer.alloc(0));
      const wrong = await next('wrong_peer');
      assert.deepEqual(wrong.peer, first.peer);
      assert.equal(wrong.result, null);
      assert.equal(wrong.readCalls, 0);
      assert.equal(wrong.frame, '');
      assert.equal(wrong.stageCalls, 0);
      assert.deepEqual(names(), expected);
      assert.deepEqual(readdirSync(directory).sort(), ['ledger', 'peer.sock']);
      await next('exit');
    } finally {
      if (child && child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
      if (closed) await new Promise(resolve => {
        const timer = setTimeout(resolve, 500);
        closed.then(() => { clearTimeout(timer); resolve(); });
      });
      rmSync(directory, { recursive: true, force: true });
    }
  });
