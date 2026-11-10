import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { chmodSync, copyFileSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';
import { PolicyAdapter, loadConfig, provenIssue, issueWriteArgs } from '../mcp-policy/issue-policy.mjs';

const source = fileURLToPath(new URL('../mcp-policy/fixtures/stock-mcp-fake.mjs', import.meta.url));
const READ = ['issue_read', ...Array.from({ length: 17 }, (_, i) => 'read_fixture_' + i)];
const config = Object.freeze({ binary: source, owner: 'Fixture', repo: 'Repo', readTools: READ });
const ERROR = 'mcp_policy_denied_or_uncertain';
function fixture(t, scenario = 'issue', timeout = 300) {
  const dir = mkdtempSync(join(tmpdir(), 'mcp-policy-fixture-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const log = join(dir, 'events'); writeFileSync(log, '');
  const child = spawn(process.execPath, [source, 'stdio', '--tools', [...READ, 'issue_write', 'add_issue_comment'].join(',')], {
    stdio: ['pipe', 'pipe', 'ignore'], env: { ...process.env, FAKE_LOG: log, FAKE_SCENARIO: scenario },
  });
  t.after(() => child.kill('SIGKILL'));
  const out = [];
  const adapter = new PolicyAdapter(config, child, frame => out.push(frame), timeout);
  const seen = () => readFileSync(log, 'utf8').trim().split('\n').filter(Boolean).map(x => JSON.parse(x));
  const send = (id, method, params = {}) => {
    adapter.accept({ jsonrpc: '2.0', id, method, params });
    return wait(() => out.find(x => x.id === id));
  };
  return { adapter, child, out, seen, send };
}
async function wait(predicate, timeout = 1200) {
  for (let i = 0; i < timeout / 5; i++) {
    const value = predicate(); if (value) return value;
    await delay(5);
  }
  throw new Error('test fixture response timeout');
}
async function ready(f) {
  const initial = (await f.send(0, 'initialize', { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'fixture', version: '0' } })).result;
  assert.equal(initial.serverInfo.name, 'fixture');
  assert.deepEqual(initial.capabilities, { tools: {} });
  f.adapter.accept({ jsonrpc: '2.0', method: 'notifications/initialized' });
}
const call = (name, args) => ({ name, arguments: args });
const args = (method = 'update', issue_number = 6) => ({ method, owner: 'fixture', repo: 'REPO',
  ...(method === 'update' ? { issue_number } : {}), title: 'Fixture', body: 'Changed\n\nAgent: fixture\nModel: model/test\nThinking: high\nBot-Owner: @llunved',
  labels: ['triage'], assignees: ['fixture'], state: 'open' });

test('protected host config and executable hash pin, no source defaults', t => {
  const dir = mkdtempSync(join(tmpdir(), 'policy-private-')); t.after(() => rmSync(dir, { recursive: true, force: true }));
  const binary = join(dir, 'stock'); copyFileSync(source, binary); chmodSync(binary, 0o700);
  const file = join(dir, 'deploy.json');
  const valid = { binary, binary_sha256: createHash('sha256').update(readFileSync(binary)).digest('hex'),
    repository: 'Fixture/Repo', read_tools: READ };
  writeFileSync(file, JSON.stringify(valid), { mode: 0o600 });
  assert.deepEqual(loadConfig(file).readTools, READ);
  for (const change of [ { read_tools: [...READ.slice(1), 'issue_write'] },
    { read_tools: [...READ.slice(1), 'add_issue_comment'] },
    { read_tools: [...READ.slice(1), 'merge_pull_request'] }, { repository: 'foreign/repo' },
    { binary_sha256: '0'.repeat(64) }, { token: 'never' } ]) {
    writeFileSync(file, JSON.stringify({ ...valid, ...change }), { mode: 0o600 });
    if (change.repository === 'foreign/repo') assert.equal(loadConfig(file).owner, 'foreign');
    else assert.throws(() => loadConfig(file), /mcp_policy_denied/);
  }
  writeFileSync(file, JSON.stringify(valid)); chmodSync(file, 0o644);
  assert.throws(() => loadConfig(file), /mcp_policy_denied/);
  chmodSync(file, 0o600);
  writeFileSync(binary, 'changed binary');
  assert.throws(() => loadConfig(file), /mcp_policy_denied/);
});

test('exact 20 catalog, readOnly annotations, no UI/hidden write, normal read passthrough', async t => {
  const f = fixture(t); await ready(f);
  const list = (await f.send(1, 'tools/list')).result.tools;
  assert.equal(list.length, 20);
  assert.deepEqual(list.map(x => x.name), [...READ, 'issue_write', 'add_issue_comment']);
  assert.equal(list.find(x => x.name === 'issue_write')._meta.ui, undefined);
  assert.equal((await f.send(2, 'tools/call', call('read_fixture_0', { any: 'read args' }))).result.content[0].text, 'read-through fixture');
  assert.deepEqual(f.seen(), [{ name: 'read_fixture_0', args: { any: 'read args' } }]);
  assert.equal((await f.send(3, 'tools/call', call('merge_pull_request', {}))).error.message, ERROR);
  assert.equal((await f.send(4, 'tools/call', call('delete_file', {}))).error.message, ERROR);
  assert.equal(f.seen().length, 1);
});

test('only exact allowed repo issue create and update are forwarded, legitimate fields preserved', async t => {
  const f = fixture(t); await ready(f);
  const create = args('create');
  assert.equal((await f.send(1, 'tools/call', call('issue_write', create))).result.content[0].text, 'offline issue write fixture');
  assert.equal((await f.send(2, 'tools/call', call('issue_write', args()))).result.content[0].text, 'offline issue write fixture');
  const events = f.seen();
  assert.deepEqual(events.map(e => e.name), ['issue_write', 'issue_read', 'issue_write']);
  assert.deepEqual(events[1].args, { method: 'get', owner: 'Fixture', repo: 'Repo', issue_number: 6 });
  assert.equal(events[2].args.body, args().body);
  assert.equal(events[2].args.state, 'open');
  assert.deepEqual(events[2].args.labels, ['triage']);
});

test('rejects wrong repository, missing/invalid number and cross-target fields BEFORE write', async t => {
  const f = fixture(t); await ready(f);
  const bad = [ { ...args(), owner: 'foreign' }, { ...args(), repo: 'other' },
    { ...args(), issue_number: 0 }, { ...args(), issue_number: 1.5 },
    { ...args(), issue_number: '6' }, { ...args('create'), issue_number: 6 },
    { ...args(), parent_owner: 'foreign' }, { ...args(), parent_issue_number: 7 },
    { ...args(), duplicate_of: 8 }, { ...args(), issue_fields: [] },
    { ...args(), method: 'comment' }, { ...args(), comments: ['bad'] } ];
  for (let i = 0; i < bad.length; i++) {
    assert.equal((await f.send(i + 1, 'tools/call', call('issue_write', bad[i]))).error.message, ERROR);
  }
  assert.deepEqual(f.seen(), []);
});

for (const scenario of ['pr', 'marker', 'wrong-repo', 'wrong-number', 'text-spoof',
  'structured-spoof', 'ambiguous-content', 'error']) {
  test('issue_read ' + scenario + ' cannot authorize update even with issue URL in body', async t => {
    const f = fixture(t, scenario); await ready(f);
    assert.equal((await f.send(1, 'tools/call', call('issue_write', args()))).error.message, ERROR);
    assert.deepEqual(f.seen().map(e => e.name), ['issue_read']);
  });
}

test('stock root JSON content without structured content proves canonical issue', async t => {
  const f = fixture(t, 'issue'); await ready(f);
  assert.equal((await f.send(1, 'tools/call', call('issue_write', args()))).result.content[0].text, 'offline issue write fixture');
  assert.deepEqual(f.seen().map(e => e.name), ['issue_read', 'issue_write']);
});

for (const scenario of ['missing-read', 'untrusted-read']) {
  test('stock inventory ' + scenario + ' fails closed', async t => {
    const f = fixture(t, scenario); await ready(f);
    assert.equal((await f.send(1, 'tools/list')).error.message, ERROR);
    assert.equal((await f.send(2, 'tools/call', call('issue_write', args()))).error.message, ERROR);
    assert.deepEqual(f.seen(), []);
  });
}

for (const scenario of ['crash', 'timeout', 'crash-write', 'timeout-write', 'await-form']) {
  test('child ' + scenario + ' never silently retries issue update', async t => {
    const f = fixture(t, scenario, 70); await ready(f);
    assert.equal((await f.send(1, 'tools/call', call('issue_write', args()))).error.message, ERROR);
    const events = f.seen().map(x => x.name);
    assert.equal(events.filter(x => x === 'issue_write').length, scenario.endsWith('write') || scenario === 'await-form' ? 1 : 0);
    assert.ok(events.filter(x => x === 'issue_read').length <= 1);
    assert.equal((await f.send(2, 'tools/call', call('issue_write', args()))).error.message, ERROR);
    assert.equal(f.seen().filter(x => x.name === 'issue_write').length, events.filter(x => x === 'issue_write').length);
  });
}

test('same ID concurrent collision stops child before a second write and never accepts forged child response', async t => {
  const f = fixture(t, 'timeout', 100); await ready(f);
  f.adapter.accept({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: call('issue_write', args()) });
  await wait(() => f.seen().length > 0);
  f.adapter.accept({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: call('issue_write', args()) });
  await wait(() => f.adapter.failed);
  assert.equal(f.seen().filter(x => x.name === 'issue_write').length, 0);
});

test('client cancellation during update preflight kills child and blocks write', async t => {
  const f = fixture(t, 'timeout', 200); await ready(f);
  f.adapter.accept({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: call('issue_write', args()) });
  await wait(() => f.seen().length > 0);
  f.adapter.accept({ jsonrpc: '2.0', method: 'notifications/cancelled', params: { requestId: 1 } });
  await wait(() => f.adapter.failed);
  assert.equal(f.seen().filter(x => x.name === 'issue_write').length, 0);
});

test('unrecognized protocol methods and server subrequests never auto-approved', async t => {
  const f = fixture(t); await ready(f);
  for (const method of ['resources/read', 'sampling/createMessage', 'prompts/list'])
    assert.equal((await f.send(method, method)).error.message, ERROR);
  assert.deepEqual(f.seen(), []);
});


test('actual --config stdio entry forwards one stock process with bounded protocol', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'mcp-entry-fixture-')); t.after(() => rmSync(dir, { recursive: true, force: true }));
  const binary = join(dir, 'stock'); copyFileSync(source, binary); chmodSync(binary, 0o700);
  const file = join(dir, 'private.json'), log = join(dir, 'events'); writeFileSync(log, '');
  writeFileSync(file, JSON.stringify({ binary, binary_sha256: createHash('sha256').update(readFileSync(binary)).digest('hex'),
    repository: 'Fixture/Repo', read_tools: READ }), { mode: 0o600 });
  const entry = fileURLToPath(new URL('../mcp-policy/issue-policy.mjs', import.meta.url));
  const proc = spawn(process.execPath, [entry, '--config', file], { stdio: ['pipe', 'pipe', 'ignore'],
    env: { ...process.env, FAKE_LOG: log, FAKE_SCENARIO: 'pr' } });
  t.after(() => proc.kill('SIGKILL'));
  let output = '';
  const frames = [];
  proc.stdout.on('data', chunk => {
    output += chunk.toString('utf8');
    for (;;) {
      const index = output.indexOf('\n'); if (index < 0) break;
      frames.push(JSON.parse(output.slice(0, index))); output = output.slice(index + 1);
    }
  });
  const send = (id, method, params = {}) => {
    const frame = JSON.stringify({ jsonrpc: '2.0', id, method, params }) + '\n';
    // Fragment input deliberately to verify framing across chunks.
    proc.stdin.write(frame.slice(0, 7)); proc.stdin.write(frame.slice(7));
    return wait(() => frames.find(f => f.id === id));
  };
  assert.equal((await send(1, 'initialize', { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'fixture', version: '0' } })).result.serverInfo.name, 'fixture');
  proc.stdin.write(JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' }) + '\n');
  assert.equal((await send(2, 'tools/list')).result.tools.length, 20);
  assert.equal((await send(3, 'tools/call', call('issue_write', args()))).error.message, ERROR);
  assert.deepEqual(readFileSync(log, 'utf8').trim().split('\n').map(x => JSON.parse(x).name), ['issue_read']);
});


test('distinct concurrent caller IDs serialize without crossing preflight and write responses', async t => {
  const f = fixture(t); await ready(f);
  const first = f.send('alpha', 'tools/call', call('issue_write', args()));
  const second = f.send('beta', 'tools/call', call('issue_write', args('create')));
  assert.equal((await first).id, 'alpha');
  assert.equal((await second).id, 'beta');
  assert.deepEqual(f.seen().map(x => x.name), ['issue_read', 'issue_write', 'issue_write']);
});

for (const scenario of ['server-subrequest', 'wrong-child-id']) {
  test('child ' + scenario + ' cannot spoof an authorization response', async t => {
    const f = fixture(t, scenario); await ready(f);
    assert.equal((await f.send(1, 'tools/call', call('issue_write', args()))).error.message, ERROR);
    assert.deepEqual(f.seen().map(x => x.name), ['issue_read']);
    assert.equal(f.adapter.failed, true);
  });
}


test('oversized child stdout aborts before update write', async t => {
  const f = fixture(t, 'oversize-child'); await ready(f);
  assert.equal((await f.send(1, 'tools/call', call('issue_write', args()))).error.message, ERROR);
  assert.equal(f.adapter.failed, true);
  assert.deepEqual(f.seen().map(x => x.name), ['issue_read']);
});


test('more than 128 queued caller requests aborts without unbounded pending work', async t => {
  const f = fixture(t, 'timeout', 300); await ready(f);
  for (let id = 1; id <= 129; id++)
    f.adapter.accept({ jsonrpc: '2.0', id, method: 'tools/call', params: call('issue_write', args()) });
  await wait(() => f.adapter.failed);
  assert.equal(f.seen().filter(x => x.name === 'issue_write').length, 0);
});


const comment = (issue_number = 6) => ({ owner: 'fixture', repo: 'REPO', issue_number,
  body: 'A review comment\n\nAgent: fixture\nModel: model/test\nThinking: high\nBot-Owner: @llunved' });

test('stock canonical PR conversation permits exactly one add_issue_comment, never PR issue_write update', async t => {
  const f = fixture(t, 'pr'); await ready(f);
  const tools = (await f.send(1, 'tools/list')).result.tools;
  assert.deepEqual(tools.map(x => x.name), [...READ, 'issue_write', 'add_issue_comment']);
  assert.equal(tools.find(x => x.name === 'add_issue_comment').annotations.readOnlyHint, false);
  assert.equal((await f.send(2, 'tools/call', call('issue_write', args()))).error.message, ERROR);
  assert.equal((await f.send(3, 'tools/call', call('add_issue_comment', comment()))).result.content[0].text, 'offline comment fixture');
  assert.deepEqual(f.seen().map(e => e.name), ['issue_read', 'issue_read', 'add_issue_comment']);
  assert.deepEqual(f.seen()[2].args, { ...comment(), owner: 'Fixture', repo: 'Repo' });
  assert.equal(f.seen().filter(e => e.name === 'issue_write').length, 0);
});

test('ordinary issue conversation permits comment without altering issue state', async t => {
  const f = fixture(t); await ready(f);
  assert.equal((await f.send(1, 'tools/call', call('add_issue_comment', comment()))).result.content[0].text, 'offline comment fixture');
  assert.deepEqual(f.seen().map(e => e.name), ['issue_read', 'add_issue_comment']);
  assert.deepEqual(f.seen()[1].args, { ...comment(), owner: 'Fixture', repo: 'Repo' });
});

test('comment target and body validation rejects foreign repo/cross-repo and review fields before child calls', async t => {
  const f = fixture(t); await ready(f);
  const bad = [ { ...comment(), owner: 'foreign' }, { ...comment(), repo: 'foreign' },
    { ...comment(), issue_number: 0 }, { ...comment(), issue_number: '6' },
    { ...comment(), issue_number: 1.1 }, { ...comment(), body: '' },
    { ...comment(), body: 'x'.repeat(12001) }, { ...comment(), pull_number: 6 },
    { ...comment(), review_id: 3 }, { ...comment(), in_reply_to: 4 },
    { ...comment(), parent_owner: 'foreign' }, { ...comment(), path: 'README' },
    { ...comment(), method: 'edit' }, { ...comment(), comment_id: 4 } ];
  for (let i = 0; i < bad.length; i++)
    assert.equal((await f.send(i + 1, 'tools/call', call('add_issue_comment', bad[i]))).error.message, ERROR);
  for (const name of ['pull_request_review_write', 'create_review', 'merge_pull_request', 'delete_file'])
    assert.equal((await f.send('deny-' + name, 'tools/call', call(name, comment()))).error.message, ERROR);
  assert.deepEqual(f.seen(), []);
});

for (const scenario of ['wrong-repo', 'wrong-number', 'text-spoof', 'structured-spoof',
  'ambiguous-content', 'error', 'marker', 'partial-structured', 'mixed-kind']) {
  test('comment preflight ' + scenario + ' cannot authorize write from nested body URL', async t => {
    const f = fixture(t, scenario); await ready(f);
    assert.equal((await f.send(1, 'tools/call', call('add_issue_comment', comment()))).error.message, ERROR);
    assert.deepEqual(f.seen().map(e => e.name), ['issue_read']);
  });
}

for (const scenario of ['crash-comment', 'timeout-comment']) {
  test('lost stock ' + scenario + ' result never triggers an automatic comment retry', async t => {
    const f = fixture(t, scenario, 70); await ready(f);
    assert.equal((await f.send(1, 'tools/call', call('add_issue_comment', comment()))).error.message, ERROR);
    assert.equal(f.seen().filter(e => e.name === 'add_issue_comment').length, 1);
    assert.equal((await f.send(2, 'tools/call', call('add_issue_comment', comment()))).error.message, ERROR);
    assert.equal(f.seen().filter(e => e.name === 'add_issue_comment').length, 1);
  });
}

test('cancelled PR comment preflight never forwards comment to stock child', async t => {
  const f = fixture(t, 'timeout', 300); await ready(f);
  f.adapter.accept({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: call('add_issue_comment', comment()) });
  await wait(() => f.seen().length > 0);
  f.adapter.accept({ jsonrpc: '2.0', method: 'notifications/cancelled', params: { requestId: 1 } });
  await wait(() => f.adapter.failed);
  assert.deepEqual(f.seen().map(e => e.name), ['issue_read']);
});


test('structured issue and marked PR results require matching root canonical text', async t => {
  for (const scenario of ['structured', 'pr-marker']) {
    const f = fixture(t, scenario); await ready(f);
    assert.equal((await f.send(1, 'tools/call', call('add_issue_comment', comment()))).result.content[0].text,
      'offline comment fixture');
    assert.deepEqual(f.seen().map(e => e.name), ['issue_read', 'add_issue_comment']);
  }
});

test('caller IDs at 256 UTF-8 bytes work; duplicate ID cannot cause another child effect', async t => {
  for (const id of ['a'.repeat(256), 'a'.repeat(254) + 'é',
    'a'.repeat(252) + '🦀', Number.MAX_SAFE_INTEGER]) {
    const f = fixture(t); await ready(f);
    assert.deepEqual((await f.send(id, 'ping')).result, {});
    assert.equal(f.adapter.seq, 2); // initialize + one ping
    assert.equal(f.adapter.claimedIds.size, 2);
    assert.equal(f.adapter.usedClientIds.size, 2);
    assert.equal(f.out.length, 2);
    f.adapter.accept({ jsonrpc: '2.0', id, method: 'ping' });
    assert.equal(f.adapter.failed, true);
    assert.equal(f.adapter.seq, 2);
    assert.equal(f.out.length, 2);
    assert.equal(f.adapter.claimedIds.size, 2);
    assert.equal(f.adapter.usedClientIds.size, 2);
  }
});

test('oversized, malformed and unsafe caller IDs abort before claims, child request or reflection', async t => {
  for (const id of ['a'.repeat(257), 'a'.repeat(255) + 'é',
    'a'.repeat(253) + '🦀', {}, null, 1.5, Number.MAX_SAFE_INTEGER + 1]) {
    const f = fixture(t); await ready(f);
    await wait(() => f.adapter.queued === 0);
    const before = f.out.length;
    const seq = f.adapter.seq;
    f.adapter.accept({ jsonrpc: '2.0', id, method: 'ping' });
    assert.equal(f.adapter.failed, true);
    assert.equal(f.adapter.seq, seq);
    assert.equal(f.adapter.queued, 0);
    assert.equal(f.adapter.claimedIds.size, 1);
    assert.equal(f.adapter.usedClientIds.size, 1);
    assert.equal(f.out.length, before);
    assert.deepEqual(f.seen(), []);
    f.adapter.accept({ jsonrpc: '2.0', id, method: 'ping' });
    assert.equal(f.out.length, before, 'failed state must not reflect rejected IDs');
  }
});

test('direct request entrypoint rejects oversized IDs before key construction or reflection', async t => {
  for (const id of ['a'.repeat(257), 'a'.repeat(255) + 'é',
    'a'.repeat(253) + '🦀', null, Number.MAX_SAFE_INTEGER + 1]) {
    const f = fixture(t); await ready(f);
    const before = f.out.length;
    const seq = f.adapter.seq;
    await f.adapter.request({ jsonrpc: '2.0', id, method: 'ping' });
    assert.equal(f.adapter.failed, true);
    assert.equal(f.adapter.seq, seq);
    assert.equal(f.adapter.claimedIds.size, 1);
    assert.equal(f.adapter.usedClientIds.size, 1);
    assert.equal(f.out.length, before);
    assert.deepEqual(f.seen(), []);
  }
});

test('direct request entrypoint accepts exact 256-byte ASCII and multibyte IDs', async t => {
  for (const id of ['a'.repeat(256), 'a'.repeat(254) + 'é',
    'a'.repeat(252) + '🦀', Number.MAX_SAFE_INTEGER]) {
    const f = fixture(t); await ready(f);
    const seq = f.adapter.seq;
    const before = f.out.length;
    await f.adapter.request({ jsonrpc: '2.0', id, method: 'ping' });
    assert.equal(f.adapter.failed, false);
    assert.equal(f.adapter.seq, seq + 1);
    assert.equal(f.adapter.usedClientIds.size, 2);
    assert.equal(f.adapter.claimedIds.size, 1); // direct entry skips the queue claim
    assert.deepEqual(f.out[before], { jsonrpc: '2.0', id, result: {} });
  }
});
