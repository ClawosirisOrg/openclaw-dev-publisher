#!/usr/bin/env node
/** Host-only stdio JSON-RPC policy around the stock GitHub MCP server.
 * No GitHub client, token mint, agent runtime attestation, or deployment default.
 */
import { createHash } from 'node:crypto';
import { spawn } from 'node:child_process';
import { constants, closeSync, fstatSync, lstatSync, openSync, readFileSync } from 'node:fs';
import { dirname, isAbsolute, resolve, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const MAX_LINE = 1024 * 1024;
const TIMEOUT = 30000;
const MAX_CLIENT_IDS = 65536;
const MAX_CLIENT_ID_BYTES = 256;
const MAX_QUEUED = 128;
const PART = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$/;
const NAME = /^[a-z][a-z0-9_]{0,99}$/;
const WRITE_FIELDS = new Set(['method', 'owner', 'repo', 'issue_number', 'title', 'body',
  'state', 'state_reason', 'labels', 'assignees', 'milestone', 'type']);
const own = (x, k) => Object.hasOwn(x, k);
const plain = x => x !== null && typeof x === 'object' && !Array.isArray(x) &&
  (Object.getPrototypeOf(x) === Object.prototype || Object.getPrototypeOf(x) === null);
const fail = () => new Error('mcp_policy_denied_or_uncertain');
const issueNumber = n => Number.isSafeInteger(n) && n > 0 && n <= 2147483647;
const validClientId = id => typeof id === 'string'
  ? Buffer.byteLength(id, 'utf8') <= MAX_CLIENT_ID_BYTES
  : typeof id === 'number' && Number.isSafeInteger(id);
const source = resolve(dirname(fileURLToPath(import.meta.url)), '..');
let inCheckout = false;
try { inCheckout = JSON.parse(readFileSync(join(source, 'package.json'), 'utf8')).name ===
  'openclaw-dev-publisher-prototype'; } catch { /* deployed standalone adapter */ }

function protectedFile(path, max, executable = false) {
  if (typeof path !== 'string' || !isAbsolute(path) || resolve(path) !== path ||
      path.includes('\0') || path.includes('\n') || path.includes('\r') || path === '/' ||
      (inCheckout && (path === source || path.startsWith(source + '/')))) throw fail();
  const uid = process.getuid();
  for (let p = dirname(path); ; p = dirname(p)) {
    const st = lstatSync(p);
    if (!st.isDirectory() || (st.uid !== 0 && st.uid !== uid) ||
        ((st.mode & 0o022) && !(p !== dirname(path) && st.uid === 0 && (st.mode & 0o1000)))) throw fail();
    if (dirname(p) === p) break;
  }
  const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const st = fstatSync(fd);
    if (!st.isFile() || st.nlink !== 1 || st.size < 1 || st.size > max ||
        (executable ? ((st.uid !== 0 && st.uid !== uid) || (st.mode & 0o022) || !(st.mode & 0o100))
          : (st.uid !== uid || (st.mode & 0o077)))) throw fail();
    const bytes = readFileSync(fd);
    if (bytes.length !== st.size) throw fail();
    return bytes;
  } finally { closeSync(fd); }
}

export function loadConfig(path) {
  try {
    const data = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(protectedFile(path, 16384)));
    if (!plain(data) || Object.keys(data).sort().join(',') !==
        'binary,binary_sha256,read_tools,repository' ||
        typeof data.repository !== 'string' || data.repository.split('/').length !== 2 ||
        !data.repository.split('/').every(s => PART.test(s) && !['.', '..'].includes(s)) ||
        !Array.isArray(data.read_tools) || data.read_tools.length !== 18 ||
        new Set(data.read_tools).size !== 18 ||
        !data.read_tools.every(x => typeof x === 'string' && NAME.test(x) && !['issue_write', 'add_issue_comment'].includes(x)) ||
        !data.read_tools.includes('issue_read') ||
        typeof data.binary_sha256 !== 'string' || !/^[0-9a-f]{64}$/.test(data.binary_sha256)) throw fail();
    const bytes = protectedFile(data.binary, 100 * 1024 * 1024, true);
    if (createHash('sha256').update(bytes).digest('hex') !== data.binary_sha256) throw fail();
    const [owner, repo] = data.repository.split('/');
    return Object.freeze({ binary: data.binary, owner, repo, readTools: Object.freeze([...data.read_tools]) });
  } catch { throw fail(); }
}

/** Accept only the stock issue_read get's canonical minimal issue JSON or
 * its structured {method:'get',issue} projection. Comments may target a
 * canonical issue or PR conversation; issue updates remain issue-only.
 * Never scan arbitrary text.
 * Both independently canonical representations, if present, must agree.
 */
export function provenIssue(response, owner, repo, number, allowPull = false) {
  if (!plain(response) || own(response, 'error') || !plain(response.result) ||
      response.result.isError !== false && response.result.isError !== undefined) throw fail();
  const result = response.result;
  const candidates = [];
  if (own(result, 'structuredContent')) {
    const structured = result.structuredContent;
    if (!plain(structured) || structured.method !== 'get' || !plain(structured.issue)) throw fail();
    if (own(structured.issue, 'number') !== own(structured.issue, 'html_url')) throw fail();
    if (own(structured.issue, 'number')) candidates.push(structured.issue);
    else if (own(structured.issue, 'pull_request') || own(structured.issue, 'pullRequest') ||
             own(structured.issue, 'is_pull_request')) throw fail();
  }
  if (own(result, 'content')) {
    if (!Array.isArray(result.content) || result.content.length !== 1 ||
        !plain(result.content[0]) || result.content[0].type !== 'text' ||
        typeof result.content[0].text !== 'string' || result.content[0].text.length > MAX_LINE) throw fail();
    let content;
    try { content = JSON.parse(result.content[0].text); } catch { throw fail(); }
    if (!plain(content)) throw fail();
    candidates.push(content);
  }
  if (!candidates.length) throw fail();
  const prefix = 'https://github.com/' + owner.toLowerCase() + '/' + repo.toLowerCase() + '/';
  let kind;
  for (const item of candidates) {
    if (!issueNumber(item.number) || item.number !== number || typeof item.html_url !== 'string' ||
        !/^https:\/\/github\.com\/[^/?#]+\/[^/?#]+\/(issues|pull)\/[1-9][0-9]*$/.test(item.html_url)) throw fail();
    const url = item.html_url.toLowerCase();
    const observed = url === prefix + 'issues/' + number ? 'issue' :
      url === prefix + 'pull/' + number ? 'pull' : null;
    const marker = own(item, 'pull_request') || own(item, 'pullRequest') || own(item, 'is_pull_request');
    if (!observed || (observed === 'pull' && !allowPull) ||
        (marker && observed !== 'pull') ||
        (own(item, 'is_pull_request') && item.is_pull_request === false && observed === 'pull') ||
        (kind && kind !== observed)) throw fail();
    kind = observed;
  }
  return kind;
}

export function commentArgs(args, config) {
  if (!plain(args) || Object.keys(args).sort().join(',') !== 'body,issue_number,owner,repo' ||
      typeof args.owner !== 'string' || typeof args.repo !== 'string' ||
      args.owner.toLowerCase() !== config.owner.toLowerCase() ||
      args.repo.toLowerCase() !== config.repo.toLowerCase() ||
      !issueNumber(args.issue_number) || typeof args.body !== 'string' ||
      !args.body.length || args.body.length > 12000) throw fail();
  return { owner: config.owner, repo: config.repo,
    issue_number: args.issue_number, body: args.body };
}

export function issueWriteArgs(args, config) {
  if (!plain(args) || Object.keys(args).some(k => !WRITE_FIELDS.has(k)) ||
      !['create', 'update'].includes(args.method) ||
      typeof args.owner !== 'string' || typeof args.repo !== 'string' ||
      args.owner.toLowerCase() !== config.owner.toLowerCase() ||
      args.repo.toLowerCase() !== config.repo.toLowerCase()) throw fail();
  if (args.method === 'update' ? !issueNumber(args.issue_number) : own(args, 'issue_number')) throw fail();
  for (const [key, value] of Object.entries(args)) {
    if (['title', 'body', 'state', 'state_reason', 'type'].includes(key) &&
        !(typeof value === 'string' && value.length <= 12000 || key === 'type' && value === null)) throw fail();
    if (['labels', 'assignees'].includes(key) &&
        (!Array.isArray(value) || value.length > 100 || value.some(x => typeof x !== 'string' || x.length > 200))) throw fail();
    if (key === 'milestone' && !issueNumber(value)) throw fail();
  }
  return { ...args, owner: config.owner, repo: config.repo };
}

function rpcError(id, code = -32000) {
  return { jsonrpc: '2.0', id, error: { code, message: 'mcp_policy_denied_or_uncertain' } };
}

// write(false) means accepted into the stream's buffer, not rejected. Never resend.
function awaitDrain(stream, timeout) {
  if (typeof stream.once !== 'function' || typeof stream.off !== 'function') return Promise.reject(fail());
  return new Promise((resolve, reject) => {
    const clear = () => {
      clearTimeout(timer);
      stream.off('drain', drained); stream.off('error', failed); stream.off('close', failed);
    };
    const drained = () => { clear(); resolve(); };
    const failed = () => { clear(); reject(fail()); };
    const timer = setTimeout(failed, timeout);
    stream.once('drain', drained); stream.once('error', failed); stream.once('close', failed);
  });
}

export class PolicyAdapter {
  constructor(config, child, emit, timeout = TIMEOUT) {
    this.config = config; this.child = child; this.emit = emit; this.timeout = timeout;
    this.buffer = Buffer.alloc(0); this.pending = null; this.draining = false; this.serial = Promise.resolve(); this.seq = 0;
    this.outputSerial = Promise.resolve(); this.outputQueued = 0;
    this.usedClientIds = new Set(); this.claimedIds = new Set(); this.settledSafeIds = new Set();
    this.queued = 0; this.list = null; this.failed = false; this.initialized = false;
    child.stdout.on('data', chunk => this.onChildData(chunk));
    child.stdout.on('end', () => this.abort());
    child.on('error', () => this.abort());
    child.on('exit', () => this.abort());
    child.stdin.on('error', () => this.abort());
  }
  abort() {
    if (this.failed) return;
    this.failed = true; this.buffer = Buffer.alloc(0);
    this.child.kill('SIGKILL');
    if (this.pending) { clearTimeout(this.pending.timer); this.pending.reject(fail()); this.pending = null; }
  }
  send(frame) {
    if (++this.outputQueued > MAX_QUEUED) {
      this.outputQueued--; this.abort(); return Promise.resolve(false);
    }
    const done = this.outputSerial.then(() => Promise.resolve(this.emit(frame)).then(() => !this.failed))
      .catch(() => { this.abort(); return false; }).finally(() => { this.outputQueued--; });
    this.outputSerial = done;
    return done;
  }
  async sendSafe(id, result) {
    if (await this.send({ jsonrpc: '2.0', id, result }) && !this.failed) {
      const key = typeof id + ':' + String(id);
      // Only IDs admitted through accept() may extend the bounded set.
      if (this.claimedIds.has(key)) {
        if (this.settledSafeIds.size >= MAX_CLIENT_IDS) this.abort();
        else this.settledSafeIds.add(key);
      }
    }
  }
  onChildData(chunk) {
    if (this.failed) return;
    this.buffer = Buffer.concat([this.buffer, chunk]);
    if (this.buffer.length > MAX_LINE) { this.abort(); return; }
    for (;;) {
      const index = this.buffer.indexOf(10);
      if (index < 0) break;
      const line = this.buffer.subarray(0, index); this.buffer = this.buffer.subarray(index + 1);
      let body;
      try { body = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(line)); }
      catch { this.abort(); return; }
      const pending = this.pending;
      if (!pending || !plain(body) || body.jsonrpc !== '2.0' || body.id !== pending.id ||
          (own(body, 'result') === own(body, 'error')) ||
          (own(body, 'error') && !plain(body.error))) { this.abort(); return; }
      this.pending = null; clearTimeout(pending.timer); pending.resolve(body);
    }
  }
  call(method, params) {
    if (this.failed || this.pending || this.draining) return Promise.reject(fail());
    const id = 'policy-' + (++this.seq);
    let drain;
    const response = new Promise((resolve, reject) => {
      const timer = setTimeout(() => { this.abort(); }, this.timeout);
      this.pending = { id, resolve, reject, timer };
      const payload = JSON.stringify({ jsonrpc: '2.0', id, method, params });
      try {
        if (Buffer.byteLength(payload) > MAX_LINE) { this.abort(); return; }
        if (!this.child.stdin.write(payload + '\n')) {
          this.draining = true;
          drain = awaitDrain(this.child.stdin, this.timeout)
            .catch(() => { this.abort(); throw fail(); })
            .finally(() => { this.draining = false; });
        }
      } catch { this.abort(); }
    });
    return drain ? Promise.all([response, drain]).then(([result]) => result) : response;
  }
  async inventory() {
    if (this.list) return this.list;
    const response = await this.call('tools/list', {});
    const result = response.result;
    if (own(response, 'error') || !plain(result) || !Array.isArray(result.tools) ||
        own(result, 'nextCursor') || new Set(result.tools.map(t => t?.name)).size !== result.tools.length) throw fail();
    const byName = new Map(result.tools.map(t => [t.name, t]));
    const names = [...this.config.readTools, 'issue_write', 'add_issue_comment'];
    if (names.some(n => !plain(byName.get(n)) ||
        (['issue_write', 'add_issue_comment'].includes(n)
          ? byName.get(n).annotations?.readOnlyHint !== false
          : byName.get(n).annotations?.readOnlyHint !== true))) throw fail();
    this.list = { ...result, tools: names.map(n => {
      const tool = { ...byName.get(n) };
      if (n === 'issue_write') {
        // The MCP App form is an out-of-band write path without our preflight.
        for (const field of ['_meta', 'meta']) {
          if (plain(tool[field])) { tool[field] = { ...tool[field] }; delete tool[field].ui; }
        }
      }
      return tool;
    }) };
    return this.list;
  }
  async request(frame) {
    if (!plain(frame) || frame.jsonrpc !== '2.0' || !own(frame, 'id') ||
        !validClientId(frame.id)) { this.abort(); return; }
    const key = typeof frame.id + ':' + String(frame.id);
    if (this.usedClientIds.has(key)) { this.abort(); await this.send(rpcError(frame.id)); return; }
    this.usedClientIds.add(key);
    const id = frame.id;
    try {
      if (this.failed) throw fail();
      if (frame.method === 'initialize') {
        if (this.initialized || !plain(frame.params)) throw fail();
        const response = await this.call('initialize', frame.params);
        if (own(response, 'error')) throw fail();
        if (!plain(response.result) || !plain(response.result.capabilities) ||
            !plain(response.result.capabilities.tools)) throw fail();
        this.initialized = true;
        await this.sendSafe(id, { ...response.result, capabilities: { tools: {} } });
      } else if (!this.initialized) throw fail();
      else if (frame.method === 'ping') {
        const response = await this.call('ping', {});
        if (own(response, 'error')) throw fail();
        await this.sendSafe(id, response.result);
      } else if (frame.method === 'tools/list') {
        if (frame.params !== undefined && (!plain(frame.params) || Object.keys(frame.params).length)) throw fail();
        await this.sendSafe(id, await this.inventory());
      } else if (frame.method === 'tools/call') {
        if (!plain(frame.params) || Object.keys(frame.params).sort().join(',') !== 'arguments,name' ||
            typeof frame.params.name !== 'string' || !plain(frame.params.arguments)) throw fail();
        await this.inventory();
        const name = frame.params.name;
        if (!['issue_write', 'add_issue_comment'].includes(name) &&
            !this.config.readTools.includes(name)) throw fail();
        if (name === 'issue_write' || name === 'add_issue_comment') {
          const args = name === 'issue_write'
            ? issueWriteArgs(frame.params.arguments, this.config)
            : commentArgs(frame.params.arguments, this.config);
          if (name === 'add_issue_comment' || args.method === 'update') {
            const preflight = await this.call('tools/call', { name: 'issue_read', arguments: {
              method: 'get', owner: this.config.owner, repo: this.config.repo, issue_number: args.issue_number,
            } });
            provenIssue(preflight, this.config.owner, this.config.repo, args.issue_number,
                        name === 'add_issue_comment');
          }
          const response = await this.call('tools/call', { name, arguments: args });
          if (own(response, 'error') || !plain(response.result) || (own(response.result, 'isError') && response.result.isError !== false) ||
              response.result.structuredContent?.status === 'awaiting_user_submission') {
            this.abort(); throw fail();
          }
          await this.send({ jsonrpc: '2.0', id, result: response.result });
        } else {
          const response = await this.call('tools/call', frame.params);
          if (own(response, 'error')) throw fail();
          await this.sendSafe(id, response.result);
        }
      } else throw fail();
    } catch { await this.send(rpcError(id)); if (this.failed) this.abort(); }
  }
  accept(frame) {
    // Reject before key construction, retention, queuing or reflection, even after failure.
    if (plain(frame) && own(frame, 'id') && !validClientId(frame.id)) {
      this.abort(); return;
    }
    if (this.failed) {
      if (plain(frame) && own(frame, 'id')) void this.send(rpcError(frame.id));
      return;
    }
    if (plain(frame) && frame.jsonrpc === '2.0' && !own(frame, 'id') &&
        frame.method === 'notifications/cancelled') {
      const params = frame.params;
      // A late SDK abort of a completed safe response is not cancellation of
      // an in-flight operation. Unknown, queued, write or undrained IDs abort.
      if (!plain(params) || !own(params, 'requestId') || !validClientId(params.requestId) ||
          Object.keys(params).some(k => !['requestId', 'reason'].includes(k)) ||
          (own(params, 'reason') && (typeof params.reason !== 'string' ||
            Buffer.byteLength(params.reason, 'utf8') > MAX_CLIENT_ID_BYTES)) ||
          !this.settledSafeIds.has(typeof params.requestId + ':' + String(params.requestId)))
        this.abort();
      return;
    }
    if (plain(frame) && own(frame, 'id')) {
      const key = typeof frame.id + ':' + String(frame.id);
      if (this.claimedIds.has(key)) { this.abort(); return; }
      this.claimedIds.add(key);
    }
    if (++this.queued > MAX_QUEUED || this.claimedIds.size > MAX_CLIENT_IDS) { this.abort(); return; }
    this.serial = this.serial.then(async () => {
      if (this.failed) return;
      if (plain(frame) && !own(frame, 'id') && frame.jsonrpc === '2.0' &&
          frame.method === 'notifications/initialized' && this.initialized &&
          (frame.params === undefined || plain(frame.params))) {
        if (!this.child.stdin.write(JSON.stringify(frame) + '\n'))
          await awaitDrain(this.child.stdin, this.timeout);
      } else await this.request(frame);
    }).catch(() => this.abort()).finally(() => { this.queued--; });
  }
}

export function start(config, stdin = process.stdin, stdout = process.stdout, launcher = spawn, timeout = TIMEOUT) {
  const tools = [...config.readTools, 'issue_write', 'add_issue_comment'].join(',');
  const child = launcher(config.binary, ['stdio', '--tools', tools], {
    stdio: ['pipe', 'pipe', 'ignore'], env: { ...process.env }, windowsHide: true,
  });
  let outputFailed = false;
  const adapter = new PolicyAdapter(config, child, async frame => {
    if (outputFailed) throw fail();
    try {
      if (!stdout.write(JSON.stringify(frame) + '\n')) await awaitDrain(stdout, timeout);
    } catch { outputFailed = true; throw fail(); }
  }, timeout);
  stdout.on?.('error', () => { outputFailed = true; adapter.abort(); });
  stdout.on?.('close', () => { outputFailed = true; adapter.abort(); });
  let input = Buffer.alloc(0);
  stdin.on('data', chunk => {
    input = Buffer.concat([input, chunk]);
    if (input.length > MAX_LINE) { input = Buffer.alloc(0); stdin.pause(); adapter.abort(); return; }
    for (;;) {
      const index = input.indexOf(10);
      if (index < 0) break;
      const line = input.subarray(0, index); input = input.subarray(index + 1);
      try { adapter.accept(JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(line))); }
      catch { adapter.abort(); return; }
    }
  });
  stdin.on('end', () => adapter.abort());
  return adapter;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    if (process.argv.length !== 4 || process.argv[2] !== '--config') throw fail();
    start(loadConfig(process.argv[3]));
  } catch { process.exitCode = 1; }
}
