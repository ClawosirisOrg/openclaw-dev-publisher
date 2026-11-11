import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { PassThrough } from 'node:stream';
import { createHash } from 'node:crypto';
import { chmodSync, copyFileSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';
import { PolicyAdapter, loadConfig, provenIssue, issueWriteArgs, start } from '../mcp-policy/issue-policy.mjs';
import { expandGroups, WRITE_TOOLS, safeRead, goodAttribution, projectTool, WRITE_CONTRACT } from '../mcp-policy/syn-tool-policy.mjs';
import { admitWrite } from '../mcp-policy/syn-write-policy.mjs';

const source = fileURLToPath(new URL('../mcp-policy/fixtures/stock-mcp-fake.mjs', import.meta.url));
const READ = ['issue_read', ...Array.from({ length: 17 }, (_, i) => 'read_fixture_' + i)];
const config = Object.freeze({ binary: source, owner: 'Fixture', repo: 'Repo', readTools: READ });
const v2tools = expandGroups(['issues','pull_requests','actions','repository','releases']);
const v2config = Object.freeze({ binary: source, owner:'Fixture', repo:'Repo', version:2,
  tools:v2tools, readTools:v2tools.filter(n => !WRITE_TOOLS.has(n)) });
const attributed = 'Offline only\n\nAgent: dev-syn\nModel: openai/gpt-6-sol\nThinking: high\nBot-Owner: @llunved';
const ERROR = 'mcp_policy_denied_or_uncertain';
function fixture(t, scenario = 'issue', timeout = 300, policy = config) {
  const dir = mkdtempSync(join(tmpdir(), 'mcp-policy-fixture-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const log = join(dir, 'events'); writeFileSync(log, '');
  const effectLog = join(dir, 'effects'); writeFileSync(effectLog, '');
  const child = spawn(process.execPath, [source, 'stdio', '--tools',
    (policy.tools ?? [...READ, 'issue_write', 'add_issue_comment']).join(',')], {
    stdio: ['pipe', 'pipe', 'ignore'], env: { ...process.env, FAKE_LOG: log, FAKE_EFFECT_LOG: effectLog, FAKE_SCENARIO: scenario },
  });
  t.after(() => child.kill('SIGKILL'));
  const out = [];
  const adapter = new PolicyAdapter(policy, child, frame => out.push(frame), timeout);
  const seen = () => readFileSync(log, 'utf8').trim().split('\n').filter(Boolean).map(x => JSON.parse(x));
  const send = (id, method, params = {}) => {
    adapter.accept({ jsonrpc: '2.0', id, method, params });
    return wait(() => out.find(x => x.id === id));
  };
  const effects = () => readFileSync(effectLog, 'utf8').trim().split('\n').filter(Boolean);
  return { adapter, child, out, seen, send, effects };
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

test('exact 20 catalog, readOnly annotations, no UI/hidden write, bounded fixture read', async t => {
  const f = fixture(t); await ready(f);
  const list = (await f.send(1, 'tools/list')).result.tools;
  assert.equal(list.length, 20);
  assert.deepEqual(list.map(x => x.name), [...READ, 'issue_write', 'add_issue_comment']);
  assert.equal(list.find(x => x.name === 'issue_write')._meta.ui, undefined);
  assert.equal((await f.send(2, 'tools/call', call('read_fixture_0', {}))).result.content[0].text, 'read-through fixture');
  assert.deepEqual(f.seen(), [{ name: 'read_fixture_0', args: {} }]);
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

test('two queued large catalogs drain once each and leave ping/read available', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'mcp-slow-catalog-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const log = join(dir, 'events'); writeFileSync(log, '');
  const child = spawn(process.execPath, [source, 'stdio', '--tools',
    [...READ, 'issue_write', 'add_issue_comment'].join(',')], {
    stdio: ['pipe', 'pipe', 'ignore'], env: { ...process.env, FAKE_LOG: log, FAKE_SCENARIO: 'big-catalog' },
  });
  t.after(() => child.kill('SIGKILL'));
  const stdin = new PassThrough();
  const stdout = new PassThrough({ highWaterMark: 1 });
  const frames = []; let buffer = '';
  stdout.on('data', chunk => {
    buffer += chunk.toString('utf8');
    for (;;) {
      const index = buffer.indexOf(String.fromCharCode(10)); if (index < 0) break;
      frames.push(JSON.parse(buffer.slice(0, index))); buffer = buffer.slice(index + 1);
    }
  });
  const adapter = start(config, stdin, stdout, () => child, 500);
  const send = (id, method, params = {}) => {
    stdin.write(JSON.stringify({ jsonrpc: '2.0', id, method, params }) + String.fromCharCode(10));
    return wait(() => frames.find(f => f.id === id));
  };
  assert.equal((await send(1, 'initialize', { protocolVersion: '2025-06-18', capabilities: {},
    clientInfo: { name: 'fixture', version: '0' } })).result.serverInfo.name, 'fixture');
  stdin.write(JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' }) + String.fromCharCode(10));
  stdout.pause();
  const first = send(2, 'tools/list');
  const second = send(3, 'tools/list');
  await wait(() => stdout.writableNeedDrain);
  assert.equal(adapter.failed, false);
  assert.equal(frames.some(f => f.id === 3), false);
  stdout.resume();
  const listA = (await first).result.tools;
  const listB = (await second).result.tools;
  assert.equal(listA.length, 20); assert.equal(listB.length, 20);
  assert.ok(JSON.stringify({ tools: listA }).length > 60000);
  assert.deepEqual(listA.map(t => t.name), listB.map(t => t.name));
  assert.deepEqual((await send(4, 'ping')).result, {});
  assert.equal((await send(5, 'tools/call', call('issue_read',
    { method: 'get', owner: 'Fixture', repo: 'Repo', issue_number: 6 }))).result.content[0].type, 'text');
  assert.equal(adapter.failed, false);
  assert.deepEqual(readFileSync(log, 'utf8').trim().split(String.fromCharCode(10)).map(x => JSON.parse(x).name), ['issue_read']);
});

test('child stdin write(false) drains without dispatching issue create twice', async t => {
  const f = fixture(t); await ready(f);
  await f.send(1, 'tools/list'); // inventory cached before injected backpressure
  const original = f.child.stdin.write.bind(f.child.stdin);
  const dispatched = [];
  f.child.stdin.write = function (payload) {
    dispatched.push(JSON.parse(payload));
    original(payload);
    queueMicrotask(() => this.emit('drain'));
    return false;
  };
  assert.equal((await f.send(2, 'tools/call', call('issue_write', args('create'))))
    .result.content[0].text, 'offline issue write fixture');
  assert.equal(dispatched.filter(x => x.params?.name === 'issue_write').length, 1);
  assert.deepEqual(f.seen().map(x => x.name), ['issue_write']);
  assert.equal(f.adapter.failed, false);
  assert.deepEqual((await f.send(3, 'ping')).result, {});
});

for (const failure of ['timeout', 'close', 'error']) {
  test('child stdin false then ' + failure + ' fails closed without retrying a write', async t => {
    const f = fixture(t, 'issue', 70); await ready(f); await f.send(1, 'tools/list');
    const original = f.child.stdin.write.bind(f.child.stdin);
    let dispatches = 0;
    f.child.stdin.write = function (payload) {
      dispatches++;
      original(payload);
      if (failure === 'close') queueMicrotask(() => this.emit('close'));
      if (failure === 'error') queueMicrotask(() => this.emit('error', new Error('fixture-stream-error')));
      return false;
    };
    assert.equal((await f.send(2, 'tools/call', call('issue_write', args('create')))).error.message, ERROR);
    assert.equal(f.adapter.failed, true);
    assert.equal(dispatches, 1);
    assert.ok(f.seen().length <= 1); // error may close the child before it handles the queued bytes
    assert.ok(f.seen().every(x => x.name === 'issue_write'));
    assert.equal((await f.send(3, 'tools/call', call('issue_write', args('create')))).error.message, ERROR);
    assert.equal(dispatches, 1);
  });
}

test('initialized notification false-then-drain is sent once and does not kill child', async t => {
  const f = fixture(t); await ready(f);
  await wait(() => f.adapter.queued === 0);
  const original = f.child.stdin.write.bind(f.child.stdin);
  let count = 0;
  f.child.stdin.write = function (payload) {
    if (JSON.parse(payload).method === 'notifications/initialized') count++;
    original(payload);
    queueMicrotask(() => this.emit('drain'));
    return false;
  };
  f.adapter.accept({ jsonrpc: '2.0', method: 'notifications/initialized' });
  await wait(() => f.adapter.queued === 0);
  assert.equal(count, 1);
  assert.equal(f.adapter.failed, false);
  assert.deepEqual((await f.send(1, 'ping')).result, {});
});

for (const failure of ['timeout', 'close', 'error']) {
  test('blocked stdout ' + failure + ' fails closed without retries or unbounded output', async t => {
    const dir = mkdtempSync(join(tmpdir(), 'mcp-blocked-output-'));
    t.after(() => rmSync(dir, { recursive: true, force: true }));
    const log = join(dir, 'events'); writeFileSync(log, '');
    const child = spawn(process.execPath, [source, 'stdio', '--tools',
      [...READ, 'issue_write', 'add_issue_comment'].join(',')], {
      stdio: ['pipe', 'pipe', 'ignore'], env: { ...process.env, FAKE_LOG: log, FAKE_SCENARIO: 'big-catalog' },
    });
    t.after(() => child.kill('SIGKILL'));
    const stdin = new PassThrough();
    const stdout = new PassThrough({ highWaterMark: 1 });
    t.after(() => stdout.destroy());
    const frames = []; let buffer = '';
    stdout.on('data', chunk => {
      buffer += chunk.toString('utf8');
      for (;;) {
        const index = buffer.indexOf(String.fromCharCode(10)); if (index < 0) break;
        frames.push(JSON.parse(buffer.slice(0, index))); buffer = buffer.slice(index + 1);
      }
    });
    const adapter = start(config, stdin, stdout, () => child, 80);
    stdin.write(JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize',
      params: { protocolVersion: '2025-06-18', capabilities: {},
        clientInfo: { name: 'fixture', version: '0' } } }) + String.fromCharCode(10));
    await wait(() => frames.some(x => x.id === 1));
    stdout.pause();
    stdin.write(JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} }) + String.fromCharCode(10));
    await wait(() => stdout.writableNeedDrain);
    if (failure === 'close') stdout.destroy();
    if (failure === 'error') stdout.destroy(new Error('fixture-output-error'));
    await wait(() => adapter.failed);
    assert.ok(adapter.outputQueued <= 1);
    assert.ok(adapter.queued <= 1);
    assert.equal(adapter.seq, 2); // initialize + one stock inventory; no replay
    assert.equal(readFileSync(log, 'utf8'), '');
  });
}

const cancel = (f, requestId, extra = {}) => f.adapter.accept({
  jsonrpc: '2.0', method: 'notifications/cancelled',
  params: { requestId, ...extra },
});

test('late cancellation after completed safe discovery and read does not poison next read', async t => {
  const f = fixture(t); await ready(f);
  const list = (await f.send(1, 'tools/list')).result.tools;
  assert.equal(list.length, 20);
  cancel(f, 1, { reason: 'fixture-abort-after-result' });
  assert.equal(f.adapter.failed, false);
  assert.deepEqual((await f.send(2, 'ping')).result, {});
  cancel(f, 2);
  assert.equal((await f.send(3, 'tools/call', call('issue_read',
    { method: 'get', owner: 'Fixture', repo: 'Repo', issue_number: 6 }))).result.content[0].type, 'text');
  cancel(f, 3);
  assert.equal((await f.send(4, 'tools/call', call('read_fixture_0', {}))).result.content[0].text, 'read-through fixture');
  cancel(f, 4);
  cancel(f, 0); // initialize also completed safely
  assert.equal(f.adapter.failed, false);
  assert.deepEqual((await f.send(5, 'ping')).result, {});
  assert.deepEqual(f.seen().map(x => x.name), ['issue_read', 'read_fixture_0']);
});

for (const type of ['number', 'string']) {
  test('late safe cancellation preserves caller ID ' + type + ' and does not change duplicate-ID guard', async t => {
    const f = fixture(t); await ready(f);
    const id = type === 'string' ? 'é'.repeat(128) : 7;
    assert.equal((await f.send(id, 'tools/list')).result.tools.length, 20);
    cancel(f, type === 'string' ? 7 : '7'); // wrong ID type has no authority
    assert.equal(f.adapter.failed, true);
  });
}

test('completed write ID is never eligible for late safe cancellation', async t => {
  const f = fixture(t); await ready(f);
  assert.equal((await f.send(1, 'tools/call', call('issue_write', args('create')))).result.content[0].text,
    'offline issue write fixture');
  cancel(f, 1);
  assert.equal(f.adapter.failed, true);
  assert.deepEqual(f.seen().map(x => x.name), ['issue_write']);
});

test('queued write cancellation aborts even when another safe response has settled', async t => {
  const f = fixture(t, 'timeout', 100); await ready(f);
  f.adapter.accept({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: call('issue_write', args()) });
  await wait(() => f.seen().length === 1);
  f.adapter.accept({ jsonrpc: '2.0', id: 2, method: 'tools/call', params: call('issue_write', args('create')) });
  cancel(f, 2);
  assert.equal(f.adapter.failed, true);
  assert.deepEqual(f.seen().map(x => x.name), ['issue_read']);
});

for (const params of [undefined, {}, { requestId: null }, { requestId: 1.5 },
  { requestId: 'x'.repeat(257) }, { requestId: 1, reason: 1 },
  { requestId: 1, reason: 'x'.repeat(257) }, { requestId: 1, extra: 2 }]) {
  test('malformed cancellation aborts despite settled safe ID: ' + JSON.stringify(params), async t => {
    const f = fixture(t); await ready(f);
    assert.equal((await f.send(1, 'tools/list')).result.tools.length, 20);
    f.adapter.accept({ jsonrpc: '2.0', method: 'notifications/cancelled', params });
    assert.equal(f.adapter.failed, true);
  });
}

test('rejected request is not marked safe merely because a sanitized error was sent', async t => {
  const f = fixture(t); await ready(f);
  assert.equal((await f.send(1, 'tools/call', call('merge_pull_request', {}))).error.message, ERROR);
  cancel(f, 1);
  assert.equal(f.adapter.failed, true);
});

test('a response queued behind a blocked output cannot authorize its cancellation', async t => {
  const f = fixture(t); await ready(f);
  let release;
  f.adapter.emit = frame => frame.id === 1 ? new Promise(resolve => { release = resolve; }) : f.out.push(frame);
  f.adapter.accept({ jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} });
  await wait(() => release);
  assert.equal(f.adapter.settledSafeIds.has('number:1'), false);
  cancel(f, 1);
  assert.equal(f.adapter.failed, true);
  release();
  await wait(() => f.adapter.queued === 0);
  assert.equal(f.adapter.settledSafeIds.has('number:1'), false);
});

test('settled IDs remain bounded by existing claimed ID cap', async t => {
  const f = fixture(t); await ready(f);
  assert.equal((await f.send(1, 'tools/list')).result.tools.length, 20);
  assert.ok(f.adapter.settledSafeIds.size <= f.adapter.claimedIds.size);
  f.adapter.accept({ jsonrpc: '2.0', id: 1, method: 'ping', params: {} });
  assert.equal(f.adapter.failed, true);
});

test('installed SDK abort of completed tools/list leaves next issue_read available offline', {
  skip: !existsSync('/app/node_modules/@modelcontextprotocol/sdk/dist/esm/client/index.js'),
}, async t => {
  const { Client } = await import('/app/node_modules/@modelcontextprotocol/sdk/dist/esm/client/index.js');
  const { StdioClientTransport } = await import('/app/node_modules/@modelcontextprotocol/sdk/dist/esm/client/stdio.js');
  const dir = mkdtempSync(join(tmpdir(), 'mcp-sdk-late-cancel-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const binary = join(dir, 'stock'); copyFileSync(source, binary); chmodSync(binary, 0o700);
  const file = join(dir, 'config.json');
  writeFileSync(file, JSON.stringify({ binary, binary_sha256: createHash('sha256').update(readFileSync(binary)).digest('hex'),
    repository: 'Fixture/Repo', read_tools: READ }), { mode: 0o600 });
  const log = join(dir, 'events'); writeFileSync(log, '');
  const client = new Client({ name: 'fixture-sdk', version: '0' }, { capabilities: {} });
  const transport = new StdioClientTransport({ command: process.execPath,
    args: [fileURLToPath(new URL('../mcp-policy/issue-policy.mjs', import.meta.url)), '--config', file],
    env: { ...process.env, FAKE_LOG: log, FAKE_SCENARIO: 'issue' } });
  const originalSend = transport.send.bind(transport); let cancellations = 0;
  transport.send = async frame => {
    if (frame.method === 'notifications/cancelled') cancellations++;
    return originalSend(frame);
  };
  t.after(async () => { await client.close(); });
  await client.connect(transport);
  const controller = new AbortController();
  assert.equal((await client.listTools({}, { signal: controller.signal })).tools.length, 20);
  controller.abort();
  await wait(() => cancellations === 1);
  const result = await client.callTool({ name: 'issue_read', arguments: {
    method: 'get', owner: 'Fixture', repo: 'Repo', issue_number: 6,
  } });
  assert.equal(result.content[0].type, 'text');
  assert.deepEqual(readFileSync(log, 'utf8').trim().split(String.fromCharCode(10)).map(x => JSON.parse(x).name), ['issue_read']);
});

test('exact 256 UTF-8 byte safe caller ID is eligible for late cancellation', async t => {
  const f = fixture(t); await ready(f);
  const id = 'é'.repeat(128);
  assert.equal((await f.send(id, 'tools/list')).result.tools.length, 20);
  cancel(f, id);
  assert.equal(f.adapter.failed, false);
  assert.deepEqual((await f.send(1, 'ping')).result, {});
});

test('active read cancellation still aborts despite earlier settled catalog', async t => {
  const f = fixture(t, 'timeout', 100); await ready(f);
  assert.equal((await f.send(1, 'tools/list')).result.tools.length, 20);
  f.adapter.accept({ jsonrpc: '2.0', id: 2, method: 'tools/call', params: call('issue_read',
    { method: 'get', owner: 'Fixture', repo: 'Repo', issue_number: 6 }) });
  await wait(() => f.seen().some(x => x.name === 'issue_read'));
  cancel(f, 2);
  assert.equal(f.adapter.failed, true);
  assert.deepEqual(f.seen().map(x => x.name), ['issue_read']);
});

test('child initialize drops only stock MCP App UI extension, preserving caller parameters', async t => {
  const f = fixture(t, 'ui-form-gate');
  let forwarded;
  const write = f.child.stdin.write.bind(f.child.stdin);
  f.child.stdin.write = function (payload) {
    const frame = JSON.parse(payload);
    if (frame.method === 'initialize') forwarded = frame.params;
    return write(payload);
  };
  const params = { protocolVersion: '2025-06-18', clientInfo: { name: 'fixture', version: '0' },
    capabilities: { elicitation: { form: {}, url: {} }, sampling: { custom: true },
      extensions: { 'io.modelcontextprotocol/ui': { mimeTypes: ['text/html;profile=mcp-app'] },
        'openai/elicitation': { form: {} }, 'custom.fixture': { keep: true } } },
    _meta: { custom: 'unchanged' } };
  const original = structuredClone(params);
  assert.equal((await f.send(0, 'initialize', params)).result.serverInfo.name, 'fixture');
  assert.deepEqual(params, original);
  assert.deepEqual(forwarded, { ...original, capabilities: { ...original.capabilities,
    extensions: { 'openai/elicitation': { form: {} }, 'custom.fixture': { keep: true } } } });
  f.adapter.accept({ jsonrpc: '2.0', method: 'notifications/initialized' });
  assert.equal((await f.send(1, 'tools/call', call('issue_write', args()))).result.structuredContent.issue.url,
    'https://github.com/Fixture/Repo/issues/6');
  assert.deepEqual(f.seen().map(x => x.name), ['issue_read', 'issue_write']);
  assert.equal(f.effects().length, 1);
  assert.equal(f.adapter.failed, false);
});

for (const bad of [{ capabilities: null }, { capabilities: [] }, { capabilities: 'ui' },
  { capabilities: { extensions: null } }, { capabilities: { extensions: [] } },
  { capabilities: { extensions: 'ui' } }]) {
  test('malformed child-facing client capability fails closed before stock: ' + JSON.stringify(bad), async t => {
    const f = fixture(t, 'ui-form-gate');
    let initializeCalls = 0;
    const write = f.child.stdin.write.bind(f.child.stdin);
    f.child.stdin.write = function (payload) {
      if (JSON.parse(payload).method === 'initialize') initializeCalls++;
      return write(payload);
    };
    assert.equal((await f.send(0, 'initialize', { protocolVersion: '2025-06-18',
      clientInfo: { name: 'fixture', version: '0' }, ...bad })).error.message, ERROR);
    assert.equal(initializeCalls, 0);
    assert.equal(f.effects().length, 0);
  });
}

test('UI-capable caller cannot bypass PR preflight or submit a form result', async t => {
  const pr = fixture(t, 'pr');
  await pr.send(0, 'initialize', { protocolVersion: '2025-06-18', clientInfo: { name: 'fixture', version: '0' },
    capabilities: { extensions: { 'io.modelcontextprotocol/ui': {} } } });
  assert.equal((await pr.send(1, 'tools/call', call('issue_write', args()))).error.message, ERROR);
  assert.deepEqual(pr.seen().map(x => x.name), ['issue_read']);
  const form = fixture(t, 'await-form');
  await form.send(0, 'initialize', { protocolVersion: '2025-06-18', clientInfo: { name: 'fixture', version: '0' },
    capabilities: { extensions: { 'io.modelcontextprotocol/ui': {} } } });
  assert.equal((await form.send(1, 'tools/call', call('issue_write', args('create')))).error.message, ERROR);
  assert.equal(form.adapter.failed, true);
});

test('headless issue create still executes once; comment scope remains unchanged', async t => {
  const f = fixture(t, 'ui-form-gate'); await ready(f);
  assert.equal((await f.send(1, 'tools/call', call('issue_write', args('create')))).result.structuredContent.issue.url,
    'https://github.com/Fixture/Repo/issues/6');
  assert.equal((await f.send(2, 'tools/call', call('add_issue_comment', {
    owner: 'Fixture', repo: 'Repo', issue_number: 6, body: 'offline comment',
  }))).result.content[0].text, 'offline comment fixture');
  assert.deepEqual(f.seen().map(x => x.name), ['issue_write', 'issue_read', 'add_issue_comment']);
  assert.equal(f.effects().length, 1);
});

test('installed UI-capable client gets 20 tools and one direct fake update effect', {
  skip: !existsSync('/app/node_modules/@modelcontextprotocol/sdk/dist/esm/client/index.js'),
}, async t => {
  const { Client } = await import('/app/node_modules/@modelcontextprotocol/sdk/dist/esm/client/index.js');
  const { StdioClientTransport } = await import('/app/node_modules/@modelcontextprotocol/sdk/dist/esm/client/stdio.js');
  const dir = mkdtempSync(join(tmpdir(), 'mcp-ui-form-gate-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const binary = join(dir, 'stock-fake'); copyFileSync(source, binary); chmodSync(binary, 0o700);
  const file = join(dir, 'config.json'), log = join(dir, 'events'), effectLog = join(dir, 'effects');
  writeFileSync(file, JSON.stringify({ binary,
    binary_sha256: createHash('sha256').update(readFileSync(binary)).digest('hex'),
    repository: 'Fixture/Repo', read_tools: READ }), { mode: 0o600 });
  writeFileSync(log, ''); writeFileSync(effectLog, '');
  const caps = { elicitation: { form: {}, url: {} }, extensions: {
    'openai/elicitation': { form: {} },
    'io.modelcontextprotocol/ui': { mimeTypes: ['text/html;profile=mcp-app'] },
  } }; const capsBefore = structuredClone(caps);
  const client = new Client({ name: 'openclaw-bundle-mcp', version: '0.0.0' }, { capabilities: caps });
  const env = { ...process.env, FAKE_LOG: log, FAKE_EFFECT_LOG: effectLog, FAKE_SCENARIO: 'ui-form-gate' };
  for (const key of ['GH_TOKEN', 'GITHUB_TOKEN', 'GITHUB_PERSONAL_ACCESS_TOKEN',
    'GITHUB_APP_ID', 'GITHUB_APP_INSTALLATION_ID', 'GITHUB_APP_PRIVATE_KEY_PATH']) delete env[key];
  const transport = new StdioClientTransport({ command: process.execPath,
    args: [fileURLToPath(new URL('../mcp-policy/issue-policy.mjs', import.meta.url)), '--config', file], env });
  t.after(async () => { await client.close(); });
  await client.connect(transport);
  assert.equal((await client.listTools()).tools.length, 20);
  const result = await client.callTool({ name: 'issue_write', arguments: args() });
  assert.deepEqual(JSON.parse(result.content[0].text),
    { id: 'fixture-id', url: 'https://github.com/Fixture/Repo/issues/6' });
  assert.equal(result.structuredContent.method, 'update');
  assert.equal(readFileSync(effectLog, 'utf8').trim().split(String.fromCharCode(10)).length, 1);
  assert.deepEqual(readFileSync(log, 'utf8').trim().split(String.fromCharCode(10)).map(x => JSON.parse(x).name),
    ['issue_read', 'issue_write']);
  assert.deepEqual(caps, capsBefore);
});

test('version-two protected policy template admits only pinned groups', t => {
  const dir = mkdtempSync(join(tmpdir(), 'syn-policy-v2-')); t.after(() => rmSync(dir,{recursive:true,force:true}));
  const bin=join(dir,'stock');copyFileSync(source,bin);chmodSync(bin,0o700);
  const file=join(dir,'policy.json');const data={version:2,binary:bin,
    binary_sha256:createHash('sha256').update(readFileSync(bin)).digest('hex'),
    repository:'Fixture/Repo',tool_groups:['issues','pull_requests','actions','repository','releases']};
  writeFileSync(file,JSON.stringify(data),{mode:0o600});
  assert.equal(loadConfig(file).tools.length,30);
  for(const groups of [['issues','issues'],['repository'],['issues','unknown'],[],null]) {
    writeFileSync(file,JSON.stringify({...data,tool_groups:groups}));
    assert.throws(()=>loadConfig(file),/mcp_policy_denied/);
  }
  writeFileSync(file,JSON.stringify({...data,extra:'toolset-all'}));
  assert.throws(()=>loadConfig(file),/mcp_policy_denied/);
});

test('version-two tool catalog exposes exact 30 Syn-targeted stock names',async t=>{
  const f=fixture(t,'capability-v2',400,v2config);await ready(f);
  const tools=(await f.send(1,'tools/list')).result.tools;
  assert.deepEqual(tools.map(x=>x.name),v2tools);
  assert.equal(tools.filter(x=>x.annotations.readOnlyHint).length,23);
  assert.equal(tools.filter(x=>!x.annotations.readOnlyHint).length,7);
  assert.ok(!tools.some(x=>['push_files','create_or_update_file','delete_file','create_repository',
    'create_repository_ruleset','create_gist'].includes(x.name)));
  assert.equal((await f.send(2,'tools/call',call('push_files',{}))).error.message,ERROR);
  assert.deepEqual(f.seen(),[]);
});

const typedWrites=[
  ['issue_write',{method:'create',owner:'Fixture',repo:'Repo',title:'Scoped issue',body:attributed},[]],
  ['issue_write',{method:'update',owner:'Fixture',repo:'Repo',issue_number:6,body:attributed},['issue_read']],
  ['issue_write',{method:'update',owner:'Fixture',repo:'Repo',issue_number:6,state:'closed',labels:['ready']},['issue_read']],
  ['add_issue_comment',{owner:'Fixture',repo:'Repo',issue_number:6,body:attributed},['issue_read']],
  ['label_write',{method:'create',owner:'Fixture',repo:'Repo',name:'ready',color:'abcdef'},[]],
  ['label_write',{method:'update',owner:'Fixture',repo:'Repo',name:'ready',description:'Reviewed'},['get_label']],
  ['label_write',{method:'delete',owner:'Fixture',repo:'Repo',name:'ready'},['get_label']],
  ['update_pull_request',{owner:'Fixture',repo:'Repo',pullNumber:6,draft:false,body:attributed},['pull_request_read']],
  ['pull_request_review_write',{owner:'Fixture',repo:'Repo',pullNumber:6,method:'create',event:'COMMENT',body:attributed,commitID:'a'.repeat(40)},['pull_request_read']],
  ['merge_pull_request',{owner:'Fixture',repo:'Repo',pullNumber:6,expectedHeadSha:'a'.repeat(40),
    merge_method:'merge',commit_title:'Merge scoped PR',commit_message:attributed},['pull_request_read']],
  ['actions_run_trigger',{owner:'Fixture',repo:'Repo',method:'run_workflow',workflow_id:'build.yml',ref:'main'},['actions_get']],
  ['actions_run_trigger',{owner:'Fixture',repo:'Repo',method:'run_workflow',workflow_id:'3000000000',ref:'main'},['actions_get']],
  ['actions_run_trigger',{owner:'Fixture',repo:'Repo',method:'rerun_failed_jobs',run_id:12345678901},['actions_get']],
  ['actions_run_trigger',{owner:'Fixture',repo:'Repo',method:'cancel_workflow_run',run_id:12345678901},['actions_get']],
];
for(const [name,args,preflight] of typedWrites){
  test('v2 fake '+name+' '+(args.method??'update')+' dispatches one effect after canonical preflight',async t=>{
    const f=fixture(t,'capability-v2',400,v2config);await ready(f);
    assert.equal((await f.send(1,'tools/call',call(name,args))).result.content[0].text,'synthetic effect');
    assert.deepEqual(f.seen().map(x=>x.name),[...preflight,name]);
    assert.deepEqual(f.effects(),[name]);
    assert.deepEqual((await f.send(2,'ping')).result,{});
    cancel(f,1); // completed writes are never safe late-cancellation targets
    assert.equal(f.adapter.failed,true);
    assert.deepEqual(f.effects(),[name]);
  });
}

const rejectedReads=[
  ['issue_read',{method:'get',owner:'Other',repo:'Repo',issue_number:6}],
  ['list_branches',{owner:'Fixture',repo:'Other'}],
  ['get_file_contents',{owner:'Fixture',repo:'Repo',path:'../secrets'}],
  ['get_file_contents',{owner:'Fixture',repo:'Repo',path:'ok',ref:'refs/heads/other'}],
  ['pull_request_read',{method:'get',owner:'Fixture',repo:'Repo',pullNumber:6,extra:'bad'}],
  ['actions_get',{method:'delete',owner:'Fixture',repo:'Repo',resource_id:'1'}],
  ['search_code',{query:'repo:Fixture/Repo good OR repo:Other/Repo'}],
  ['search_code',{query:'repo:Fixture/Repo good%20OR'}],
  ['search_issues',{query:'repo:Other/Repo good'}],
  ['search_pull_requests',{query:'repo:Fixture/Repo repo:Other/Repo'}],
  ['search_issues',{query:'repo:Fixture/Repo good',owner:'Other',repo:'Repo'}],
];
for(const [name,args] of rejectedReads){
  test('v2 read boundary denies '+name+' cross-scope/injected shape',async t=>{
    const f=fixture(t,'capability-v2',400,v2config);await ready(f);
    assert.equal((await f.send(1,'tools/call',call(name,args))).error.message,ERROR);
    assert.deepEqual(f.seen(),[]);assert.deepEqual(f.effects(),[]);
  });
}

test('legacy read boundary rejects foreign repo before child dispatch',async t=>{
  const f=fixture(t);await ready(f);
  assert.equal((await f.send(1,'tools/call',call('issue_read',
    {method:'get',owner:'Other',repo:'Repo',issue_number:6}))).error.message,ERROR);
  assert.deepEqual(f.seen(),[]);
});

test('v2 scoped search permits only simple exact-repo terms',async t=>{
  const f=fixture(t,'capability-v2',400,v2config);await ready(f);
  assert.equal((await f.send(1,'tools/call',call('search_code',
    {query:'repo:Fixture/Repo smoke_test',page:1}))).result.content[0].text,'read-through fixture');
  assert.deepEqual(f.seen().map(x=>x.name),['search_code']);
});

const deniedWrites=[
  ['label_write',{method:'update',owner:'Other',repo:'Repo',name:'ready'}],
  ['label_write',{method:'delete',owner:'Fixture',repo:'Repo',name:'ready',description:'unsafe'}],
  ['label_write',{method:'rename',owner:'Fixture',repo:'Repo',name:'ready'}],
  ['issue_write',{method:'update',owner:'Fixture',repo:'Repo',issue_number:6,body:'missing author footer'}],
  ['issue_write',{method:'create',owner:'Fixture',repo:'Repo',body:attributed}],
  ['issue_write',{method:'update',owner:'Fixture',repo:'Repo',issue_number:6,state:'nonsense'}],
  ['issue_write',{method:'update',owner:'Fixture',repo:'Repo',issue_number:6,labels:['bad\nlabel']}],
  ['issue_write',{method:'update',owner:'Fixture',repo:'Repo',issue_number:6,assignees:['other/user']}],
  ['issue_write',{method:'create',owner:'Fixture',repo:'Repo',title:'x'.repeat(201),body:attributed}],
  ['add_issue_comment',{owner:'Fixture',repo:'Repo',issue_number:6,body:'missing author footer'}],
  ['update_pull_request',{owner:'Fixture',repo:'Repo',pullNumber:6,base:'foreign-main'}],
  ['update_pull_request',{owner:'Fixture',repo:'Repo',pullNumber:6,body:'no footer'}],
  ['pull_request_review_write',{owner:'Fixture',repo:'Repo',pullNumber:6,method:'delete_pending',event:'APPROVE',body:attributed}],
  ['pull_request_review_write',{owner:'Fixture',repo:'Repo',pullNumber:6,method:'create',event:'APPROVE',body:attributed,commitID:'b'.repeat(40)}],
  ['merge_pull_request',{owner:'Fixture',repo:'Repo',pullNumber:6,merge_method:'merge',expectedHeadSha:'b'.repeat(40)}],
  ['merge_pull_request',{owner:'Fixture',repo:'Repo',pullNumber:6,merge_method:'merge'}],
  ['actions_run_trigger',{owner:'Fixture',repo:'Repo',method:'delete_workflow_run_logs',run_id:123}],
  ['actions_run_trigger',{owner:'Fixture',repo:'Repo',method:'run_workflow',workflow_id:'https://evil/a.yml',ref:'main'}],
  ['actions_run_trigger',{owner:'Fixture',repo:'Repo',method:'run_workflow',workflow_id:'build.yml',ref:'other/branch'}],
  ['actions_run_trigger',{owner:'Fixture',repo:'Repo',method:'rerun_workflow_run',run_id:123,inputs:{other:'nested'}}],
  ['create_repository',{owner:'Fixture',repo:'Repo',name:'escape'}],
  ['push_files',{owner:'Fixture',repo:'Repo',branch:'main',files:[]}],
];
for(const [name,args] of deniedWrites){
  test('v2 denies unsupported, foreign, unauthored or unpinned '+name+' write',async t=>{
    const f=fixture(t,'capability-v2',400,v2config);await ready(f);
    assert.equal((await f.send(1,'tools/call',call(name,args))).error.message,ERROR);
    assert.deepEqual(f.effects(),[]);
    assert.ok(f.seen().every(x=>['issue_read','pull_request_read','actions_get'].includes(x.name)));
  });
}
for(const [name,args] of [
  ['update_pull_request',{owner:'Fixture',repo:'Repo',pullNumber:6,state:'closed'}],
  ['merge_pull_request',{owner:'Fixture',repo:'Repo',pullNumber:6,expectedHeadSha:'a'.repeat(40),merge_method:'merge'}],
  ['actions_run_trigger',{owner:'Fixture',repo:'Repo',method:'rerun_workflow_run',run_id:12345678901}],
]){
  test('v2 rejects '+name+' on foreign canonical preflight response',async t=>{
    const f=fixture(t,'capability-v2-wrong-repo',400,v2config);await ready(f);
    assert.equal((await f.send(1,'tools/call',call(name,args))).error.message,ERROR);
    assert.deepEqual(f.effects(),[]);
  });
}
for(const [name,args] of [
  ['label_write',{owner:'Fixture',repo:'Repo',method:'create',name:'ready',color:'abcdef'}],
  ['update_pull_request',{owner:'Fixture',repo:'Repo',pullNumber:6,draft:false}],
  ['actions_run_trigger',{owner:'Fixture',repo:'Repo',method:'cancel_workflow_run',run_id:12345678901}],
]){
  test('v2 lost '+name+' write result never retries or becomes safely cancellable',async t=>{
    const f=fixture(t,'capability-v2-uncertain',100,v2config);await ready(f);
    assert.equal((await f.send(1,'tools/call',call(name,args))).error.message,ERROR);
    assert.equal(f.adapter.failed,true);
    assert.deepEqual(f.effects(),[name]);
    cancel(f,1);
    assert.equal((await f.send(2,'tools/call',call(name,args))).error.message,ERROR);
    assert.deepEqual(f.effects(),[name]);
  });
}

test('v2 rejects write cancellation while canonical PR preflight is unresolved',async t=>{
  const f=fixture(t,'timeout',100,v2config);await ready(f);
  f.adapter.accept({jsonrpc:'2.0',id:1,method:'tools/call',params:call('merge_pull_request',
    {owner:'Fixture',repo:'Repo',pullNumber:6,merge_method:'merge',expectedHeadSha:'a'.repeat(40)})});
  await wait(()=>f.seen().some(x=>x.name==='pull_request_read'));
  cancel(f,1);
  assert.equal(f.adapter.failed,true);
  assert.deepEqual(f.seen().map(x=>x.name),['pull_request_read']);
});

test('v2 search and paths reject encoded scope escapes and URL-shaped refs',()=>{
  const config={owner:'Fixture',repo:'Repo'};
  for(const q of ['repo:Fixture/Repo good OR other','repo:Fixture/Repo good%3Arepo',
    'repo:Fixture/Repo good repo:Other/Repo','repo:Fixture/Repo good+or','repo:Fixture/Repo good%2F'])
    assert.throws(()=>safeRead('search_code',{query:q},config),/mcp_policy_denied/);
  for(const path of ['../x','/etc/passwd','a//b','a/%2e%2e','https://evil/a'])
    assert.throws(()=>safeRead('get_file_contents',{owner:'Fixture',repo:'Repo',path},config),/mcp_policy_denied/);
  assert.equal(goodAttribution(attributed),true);
  assert.equal(goodAttribution(attributed+'\nSpoofed'),false);
});

test('v2 refuses cancellation of a completed Syn workflow run',async t=>{
  const f=fixture(t,'capability-v2-completed-run',400,v2config);await ready(f);
  assert.equal((await f.send(1,'tools/call',call('actions_run_trigger',
    {owner:'Fixture',repo:'Repo',method:'cancel_workflow_run',run_id:12345678901}))).error.message,ERROR);
  assert.deepEqual(f.seen().map(x=>x.name),['actions_get']);
  assert.deepEqual(f.effects(),[]);
});

test('v2 PR conversation comment is allowed but issue_write cannot edit that PR',async t=>{
  const f=fixture(t,'pr',400,v2config);await ready(f);
  assert.equal((await f.send(1,'tools/call',call('add_issue_comment',
    {owner:'Fixture',repo:'Repo',issue_number:6,body:attributed}))).result.content[0].text,
    'offline comment fixture');
  assert.equal((await f.send(2,'tools/call',call('issue_write',
    {method:'update',owner:'Fixture',repo:'Repo',issue_number:6,state:'closed'}))).error.message,ERROR);
  assert.deepEqual(f.seen().map(x=>x.name),['issue_read','add_issue_comment','issue_read']);
});

// These fixtures mirror pinned stock v2.0.2 read roots, not over-rich REST payloads.
const stockRoot = value => ({result:{content:[{type:'text',text:JSON.stringify(value)}]}});
const syn = {owner:'Fixture',repo:'Repo'};
const footer = attributed;
const prRoot = (headRepo='Fixture/Repo') => ({number:6,
  html_url:'https://github.com/Fixture/Repo/pull/6',state:'open',merged_at:null,
  head:{sha:'a'.repeat(40),ref:'dev-syn/fixture',repo:{full_name:headRepo}},
  base:{ref:'main',repo:{full_name:'Fixture/Repo'}}});
const workflowRoot = (id=3000000000) => ({id,
  url:'https://api.github.com/repos/fixture/repo/actions/workflows/'+id,
  path:'.github/workflows/build.yml'}); // stock omits repository
const runRoot = (id=12345678901) => ({id,status:'in_progress',
  html_url:'https://github.com/fixture/repo/actions/runs/'+id}); // stock omits repository/url
function onlyPreflight(name,raw){const calls=[];return {
  calls,call:async(method,p)=>{assert.equal(method,'tools/call');assert.equal(p.name,name);
    calls.push(p);return stockRoot(raw);},
};}

test('version-two preserves all three original Syn security readers and bounded filters',async t=>{
  const f=fixture(t,'capability-v2',400,v2config);await ready(f);
  for(const [name,args] of [
    ['get_code_scanning_alert',{...syn,alertNumber:300}],
    ['list_code_scanning_alerts',{...syn,state:'open',severity:'high',page:1}],
    ['get_code_quality_finding',{...syn,findingNumber:301}],
  ]){
    assert.ok(v2tools.includes(name));
    assert.equal((await f.send(f.seen().length+1,'tools/call',call(name,args))).result.content[0].text,'read-through fixture');
  }
  assert.deepEqual(f.seen().map(x=>x.name),['get_code_scanning_alert','list_code_scanning_alerts','get_code_quality_finding']);
  assert.deepEqual(f.effects(),[]);
  assert.throws(()=>safeRead('list_code_scanning_alerts',{...syn,state:'invalid'},syn),/mcp_policy_denied/);
});

test('Actions read IDs accept positive safe integers and canonical decimal strings only',()=>{
  for(const id of [3000000000,12345678901,Number.MAX_SAFE_INTEGER]){
    assert.equal(safeRead('get_job_logs',{...syn,job_id:id},syn).job_id,id);
    assert.equal(safeRead('actions_get',{...syn,method:'get_workflow_run',resource_id:String(id)},syn).resource_id,String(id));
    assert.equal(safeRead('actions_list',{...syn,method:'list_workflow_jobs',resource_id:String(id)},syn).resource_id,String(id));
  }
  for(const id of [0,-1,1.2,Number.MAX_SAFE_INTEGER+1,'3000000000','1e10',null])
    assert.throws(()=>safeRead('get_job_logs',{...syn,job_id:id},syn),/mcp_policy_denied/);
  for(const id of ['0','01','-1','1e10','NaN','9007199254740992','123.0','',3000000000])
    assert.throws(()=>safeRead('actions_get',{...syn,method:'get_workflow_run',resource_id:id},syn),/mcp_policy_denied/);
  assert.equal(safeRead('actions_get',{...syn,method:'get_workflow',resource_id:'build.yml'},syn).resource_id,'build.yml');
  assert.throws(()=>safeRead('actions_get',{...syn,method:'get_workflow',resource_id:'../build.yml'},syn),/mcp_policy_denied/);
  assert.throws(()=>safeRead('actions_get',{owner:'Other',repo:'Repo',method:'get_workflow_run',resource_id:'12345678901'},syn),/mcp_policy_denied/);
});

for(const method of ['update','delete']){
  test('stock label root without url admits '+method+' only after scoped name and ID proof',async()=>{
    const pre=onlyPreflight('get_label',{id:'LA_kwFixture123',name:'ready',color:'abcdef',description:'real stock shape'});
    const input={...syn,method,name:'ready',...(method==='update'?{description:'New'}:{})};
    assert.deepEqual(await admitWrite('label_write',input,syn,pre.call),input);
    assert.deepEqual(pre.calls.map(x=>x.arguments),[{...syn,name:'ready'}]);
    for(const label of [{id:'LA_kwFixture123',name:'wrong'},
       {id:'../bad',name:'ready'},{id:'',name:'ready'},{name:'ready'}]){
      const wrong=onlyPreflight('get_label',label);
      await assert.rejects(admitWrite('label_write',input,syn,wrong.call),/mcp_policy_denied/);
      assert.equal(wrong.calls.length,1);
    }
    const foreign=onlyPreflight('get_label',{id:'LA_kwFixture123',name:'ready'});
    await assert.rejects(admitWrite('label_write',{...input,owner:'Other'},syn,foreign.call),/mcp_policy_denied/);
    assert.equal(foreign.calls.length,0);
  });
}

for(const id of ['3000000000','build.yml']){
  test('stock workflow GET case-folds only canonical owner/repo and forwards string '+id,async()=>{
    const pre=onlyPreflight('actions_get',workflowRoot());
    const input={...syn,method:'run_workflow',workflow_id:id,ref:'main'};
    assert.deepEqual(await admitWrite('actions_run_trigger',input,syn,pre.call),input);
    assert.equal(pre.calls.length,1);
    assert.equal(pre.calls[0].arguments.resource_id,id);
    for(const url of ['https://api.github.com/repos/Other/repo/actions/workflows/3000000000',
      'https://evil.example/repos/fixture/repo/actions/workflows/3000000000',
      'https://api.github.com/repos/fixture/repo/actions/workflows/3000000000?x=1',
      'https://api.github.com/repos/fixture/repo/actions/runs/3000000000']){
      const bad=onlyPreflight('actions_get',{...workflowRoot(),url});
      await assert.rejects(admitWrite('actions_run_trigger',input,syn,bad.call),/mcp_policy_denied/);
    }
    const numeric=onlyPreflight('actions_get',workflowRoot());
    await assert.rejects(admitWrite('actions_run_trigger',{...input,workflow_id:3000000000},syn,numeric.call),/mcp_policy_denied/);
    assert.equal(numeric.calls.length,0);
  });
}

for(const method of ['rerun_workflow_run','rerun_failed_jobs','cancel_workflow_run']){
  test('eleven-digit stock run canonical GET admits '+method+' without ID truncation',async()=>{
    const pre=onlyPreflight('actions_get',runRoot());
    const input={...syn,method,run_id:12345678901};
    assert.deepEqual(await admitWrite('actions_run_trigger',input,syn,pre.call),input);
    assert.deepEqual(pre.calls.map(x=>x.arguments.resource_id),['12345678901']);
    const foreign=onlyPreflight('actions_get',{...runRoot(),html_url:
      'https://github.com/Other/Repo/actions/runs/12345678901'});
    await assert.rejects(admitWrite('actions_run_trigger',input,syn,foreign.call),/mcp_policy_denied/);
    for(const html_url of ['https://evil.example/fixture/repo/actions/runs/12345678901',
      'https://github.com/fixture/repo/actions/runs/12345678901?x=1',
      'https://github.com/fixture/repo/actions/runs/12345678902'])
      await assert.rejects(admitWrite('actions_run_trigger',input,syn,
        onlyPreflight('actions_get',{...runRoot(),html_url}).call),/mcp_policy_denied/);
    const bad=onlyPreflight('actions_get',runRoot());
    await assert.rejects(admitWrite('actions_run_trigger',{...input,run_id:Number.MAX_SAFE_INTEGER+1},syn,bad.call),/mcp_policy_denied/);
    assert.equal(bad.calls.length,0);
  });
}

for(const [name,input] of [
  ['update_pull_request',{...syn,pullNumber:6,draft:false}],
  ['pull_request_review_write',{...syn,pullNumber:6,method:'create',event:'APPROVE',body:footer,commitID:'a'.repeat(40)}],
  ['pull_request_review_write',{...syn,pullNumber:6,method:'create',event:'REQUEST_CHANGES',body:footer,commitID:'a'.repeat(40)}],
  ['merge_pull_request',{...syn,pullNumber:6,merge_method:'merge',expectedHeadSha:'a'.repeat(40),commit_title:'Merge',commit_message:footer}],
]){
  test('canonical Syn PR with fork head supports pinned '+name,async()=>{
    const pre=onlyPreflight('pull_request_read',prRoot('Contributor/Fork'));
    assert.deepEqual(await admitWrite(name,input,syn,pre.call),input);
    assert.equal(pre.calls.length,1);
    assert.deepEqual(pre.calls[0].arguments,{...syn,method:'get',pullNumber:6});
    for(const altered of [
      {...prRoot('Contributor/Fork'),base:{ref:'main',repo:{full_name:'Other/Repo'}}},
      {...prRoot('Contributor/Fork'),html_url:'https://github.com/Other/Repo/pull/6'},
      prRoot('bad/three/parts'),
      prRoot('../Repo'),
      {...prRoot('Contributor/Fork'),head:{...prRoot('Contributor/Fork').head,sha:'b'.repeat(40)}},
    ]){
      const checked=onlyPreflight('pull_request_read',altered);
      if(altered.head.sha!=='a'.repeat(40)&&name==='update_pull_request')continue; // updates do not claim a caller pin
      await assert.rejects(admitWrite(name,input,syn,checked.call),/mcp_policy_denied/);
    }
  });
}

test('create review requires observed commit for approvals; submit_pending cannot pretend to pin',async()=>{
  for(const event of ['APPROVE','REQUEST_CHANGES']){
    const input={...syn,pullNumber:6,method:'create',event,body:footer};
    const pre=onlyPreflight('pull_request_read',prRoot());
    await assert.rejects(admitWrite('pull_request_review_write',input,syn,pre.call),/mcp_policy_denied/);
    const moved=onlyPreflight('pull_request_read',prRoot());
    await assert.rejects(admitWrite('pull_request_review_write',{...input,commitID:'b'.repeat(40)},syn,moved.call),/mcp_policy_denied/);
    assert.deepEqual(await admitWrite('pull_request_review_write',{...input,commitID:'a'.repeat(40)},syn,moved.call),{...input,commitID:'a'.repeat(40)});
    const pending=onlyPreflight('pull_request_read',prRoot());
    await assert.rejects(admitWrite('pull_request_review_write',{...input,method:'submit_pending',commitID:'a'.repeat(40)},syn,pending.call),/mcp_policy_denied/);
  }
  const comment={...syn,pullNumber:6,method:'submit_pending',event:'COMMENT',body:footer};
  assert.deepEqual(await admitWrite('pull_request_review_write',comment,syn,onlyPreflight('pull_request_read',prRoot()).call),comment);
});

test('issue reasons match pinned stock and plain reopening has one guarded effect',async t=>{
  const f=fixture(t,'capability-v2',400,v2config);await ready(f);
  for(const reason of ['completed','not_planned']){
    const id=f.out.length+1;
    assert.equal((await f.send(id,'tools/call',call('issue_write',{...syn,method:'update',issue_number:6,state:'closed',state_reason:reason}))).result.content[0].text,'synthetic effect');
  }
  const before=f.seen().length;
  for(const reason of ['reopened','duplicate','invalid']){
    const id=f.out.length+1;
    assert.equal((await f.send(id,'tools/call',call('issue_write',{...syn,method:'update',issue_number:6,state:'closed',state_reason:reason}))).error.message,ERROR);
  }
  assert.equal(f.seen().length,before);
  assert.equal((await f.send(f.out.length+1,'tools/call',call('issue_write',{...syn,method:'update',issue_number:6,state:'open'}))).result.content[0].text,'synthetic effect');
  assert.deepEqual(f.effects(),['issue_write','issue_write','issue_write']);
});

const projectedFields={
  issue_write:['method','owner','repo','issue_number','title','body','state','state_reason',
    'labels','assignees','milestone','type'],
  add_issue_comment:['owner','repo','issue_number','body'],
  label_write:['method','owner','repo','name','new_name','color','description'],
  update_pull_request:['owner','repo','pullNumber','title','body','draft','state','maintainer_can_modify'],
  pull_request_review_write:['method','owner','repo','pullNumber','event','body','commitID'],
  merge_pull_request:['owner','repo','pullNumber','expectedHeadSha','merge_method','commit_title','commit_message'],
  actions_run_trigger:['method','owner','repo','workflow_id','ref','run_id','inputs'],
};
const projectedRequired={
  issue_write:['method','owner','repo'],
  add_issue_comment:['owner','repo','issue_number','body'],
  label_write:['method','owner','repo','name'],
  update_pull_request:['owner','repo','pullNumber'],
  pull_request_review_write:['method','owner','repo','pullNumber','event','body'],
  merge_pull_request:['owner','repo','pullNumber','expectedHeadSha','merge_method','commit_title','commit_message'],
  actions_run_trigger:['method','owner','repo'],
};
const projectedEnums={
  issue_write:{method:['create','update'],state_reason:['completed','not_planned']},
  label_write:{method:['create','update','delete']},
  pull_request_review_write:{method:['create','submit_pending'],event:['APPROVE','REQUEST_CHANGES','COMMENT']},
  merge_pull_request:{merge_method:['merge','squash']},
  actions_run_trigger:{method:['run_workflow','rerun_workflow_run','rerun_failed_jobs','cancel_workflow_run']},
};

test('v2 tools/list advertises only supported write methods, fields and unconditional requirements',async t=>{
  const f=fixture(t,'capability-v2',500,v2config);await ready(f);
  const tools=(await f.send(1,'tools/list')).result.tools;
  assert.equal(tools.length,30);assert.deepEqual(Object.keys(WRITE_CONTRACT),Object.keys(projectedFields));
  assert.deepEqual(new Set(Object.keys(WRITE_CONTRACT)),WRITE_TOOLS);
  for(const [name,fields] of Object.entries(projectedFields)){
    const tool=tools.find(x=>x.name===name),schema=tool.inputSchema;
    assert.equal(schema.type,'object');assert.equal(schema.additionalProperties,false);
    assert.deepEqual(Object.keys(schema.properties),fields);
    assert.deepEqual(schema.required,projectedRequired[name]);
    assert.ok(tool.description.startsWith(WRITE_CONTRACT[name].description.slice(0,20)));
    for(const [key,values] of Object.entries(projectedEnums[name]??{}))
      assert.deepEqual(schema.properties[key].enum,values);
    assert.ok(!tool._meta?.ui);
  }
  assert.ok(!tools.find(x=>x.name==='actions_run_trigger').inputSchema.properties.method.enum.includes('delete_workflow_run_logs'));
  assert.ok(!tools.find(x=>x.name==='merge_pull_request').inputSchema.properties.merge_method.enum.includes('rebase'));
  assert.ok(!tools.find(x=>x.name==='pull_request_review_write').inputSchema.properties.method.enum.includes('resolve_thread'));
  assert.ok(!Object.hasOwn(tools.find(x=>x.name==='update_pull_request').inputSchema.properties,'reviewers'));
  assert.ok(!Object.hasOwn(tools.find(x=>x.name==='issue_write').inputSchema.properties,'duplicate_of'));
  assert.deepEqual(tools.find(x=>x.name==='actions_get').inputSchema.properties.method.enum,
    ['get_workflow','get_workflow_run','get_workflow_job','get_workflow_run_usage','get_workflow_run_logs_url']);
  assert.deepEqual(tools.find(x=>x.name==='issue_read').inputSchema.properties.method.enum,
    ['get','get_comments','get_labels']);
  assert.deepEqual(f.effects(),[]);
});

test('projection copies stock schema without modifying vendor metadata or caller input',()=>{
  const stock={name:'merge_pull_request',description:'Stock rebase merge tool',inputSchema:{type:'object',
    properties:Object.fromEntries(projectedFields.merge_pull_request.map(k=>[k,{type:'string',
      ...(k==='merge_method'?{enum:['merge','squash','rebase']}:{}),description:'stock '+k}])),
    required:['owner','repo','pullNumber']}};
  const before=structuredClone(stock),projected=projectTool(stock);
  assert.deepEqual(stock,before);
  assert.deepEqual(projected.inputSchema.properties.merge_method.enum,['merge','squash']);
  assert.deepEqual(stock.inputSchema.properties.merge_method.enum,['merge','squash','rebase']);
  projected.inputSchema.properties.commit_title.description='local test mutation';
  assert.equal(stock.inputSchema.properties.commit_title.description,'stock commit_title');
  assert.throws(()=>projectTool({...stock,inputSchema:{...stock.inputSchema,
    properties:{...stock.inputSchema.properties,commit_message:undefined}}}),/mcp_policy_denied/);
  assert.throws(()=>projectTool({...stock,inputSchema:{...stock.inputSchema,
    properties:{...stock.inputSchema.properties,merge_method:{type:'string',enum:['rebase']}}}}),/mcp_policy_denied/);
});

const advertisedWriteCases=[
  ['issue_write','create',{...syn,method:'create',title:'Scoped issue',body:footer}],
  ['issue_write','update',{...syn,method:'update',issue_number:6,state:'open'}],
  ['add_issue_comment','comment',{...syn,issue_number:6,body:footer}],
  ['label_write','create',{...syn,method:'create',name:'ready',color:'abcdef'}],
  ['label_write','update',{...syn,method:'update',name:'ready',description:'Reviewed'}],
  ['label_write','delete',{...syn,method:'delete',name:'ready'}],
  ['update_pull_request','update',{...syn,pullNumber:6,draft:false}],
  ...['APPROVE','REQUEST_CHANGES','COMMENT'].map(event=>['pull_request_review_write','create',
    {...syn,pullNumber:6,method:'create',event,body:footer,commitID:'a'.repeat(40)}]),
  ['pull_request_review_write','submit_pending',{...syn,pullNumber:6,method:'submit_pending',event:'COMMENT',body:footer}],
  ...['merge','squash'].map(merge_method=>['merge_pull_request',merge_method,
    {...syn,pullNumber:6,expectedHeadSha:'a'.repeat(40),merge_method,
      commit_title:'Merge',commit_message:footer}]),
  ['actions_run_trigger','run_workflow',{...syn,method:'run_workflow',workflow_id:'build.yml',ref:'main'}],
  ...['rerun_workflow_run','rerun_failed_jobs','cancel_workflow_run'].map(method=>
    ['actions_run_trigger',method,{...syn,method,run_id:12345678901}]),
];
for(const [name,advertised,args] of advertisedWriteCases){
  test('advertised v2 '+name+' '+advertised+' has a canonical one-effect example',async t=>{
    const f=fixture(t,'capability-v2',500,v2config);await ready(f);
    const tools=(await f.send(1,'tools/list')).result.tools,tool=tools.find(x=>x.name===name);
    if(args.method)assert.ok(tool.inputSchema.properties.method.enum.includes(args.method));
    if(args.event)assert.ok(tool.inputSchema.properties.event.enum.includes(args.event));
    if(args.merge_method)assert.ok(tool.inputSchema.properties.merge_method.enum.includes(args.merge_method));
    for(const required of tool.inputSchema.required)assert.ok(Object.hasOwn(args,required),required);
    const result=await f.send(2,'tools/call',call(name,args));
    assert.equal(result.result.content[0].text,'synthetic effect');
    assert.equal(f.seen().at(-1).name,name);assert.deepEqual(f.effects(),[name]);
  });
}
