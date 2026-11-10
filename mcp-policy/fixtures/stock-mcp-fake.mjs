#!/usr/bin/env node
// Offline test double only. No HTTP, credential, or GitHub identity.
import { appendFileSync } from 'node:fs';
import { createInterface } from 'node:readline';
const names = process.argv[process.argv.indexOf('--tools') + 1]?.split(',') ?? [];
const scenario = process.env.FAKE_SCENARIO ?? 'issue';
const reply = (id, result) => process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id, result }) + '\n');
function issue(number, owner, repo) {
  const url = 'https://github.com/' + owner + '/' + repo + '/' + (scenario === 'pr' || scenario === 'pr-marker' ? 'pull' : 'issues') + '/' + number;
  const result = { number, html_url: url, body: 'body containing https://github.com/fixture/repo/issues/6' };
  if (scenario === 'pr-marker') result.pull_request = { url: 'https://api.github.com/fixture' };
  if (scenario === 'marker') result.pull_request = { url: 'https://api.github.com/fixture' };
  if (scenario === 'wrong-repo') result.html_url = 'https://github.com/foreign/repo/issues/' + number;
  if (scenario === 'wrong-number') result.number = number + 1;
  if (scenario === 'text-spoof') return { content: [{ type: 'text', text: 'body https://github.com/fixture/repo/issues/' + number }] };
  if (scenario === 'structured-spoof') return { structuredContent: { method: 'get', issue: { ...result, pull_request: {} } },
    content: [{ type: 'text', text: JSON.stringify({ number, html_url: 'https://github.com/' + owner + '/' + repo + '/issues/' + number }) }] };
  if (scenario === 'partial-structured') return { structuredContent: { method: 'get', issue: { number: number + 1 } },
    content: [{ type: 'text', text: JSON.stringify(result) }] };
  if (scenario === 'mixed-kind') return { structuredContent: { method: 'get', issue: { ...result, html_url: 'https://github.com/' + owner + '/' + repo + '/pull/' + number } },
    content: [{ type: 'text', text: JSON.stringify(result) }] };
  if (scenario === 'structured') return { structuredContent: { method: 'get', issue: result },
    content: [{ type: 'text', text: JSON.stringify(result) }] };
  return { content: [{ type: 'text', text: JSON.stringify(result) }] };
}
createInterface({ input: process.stdin, crlfDelay: Infinity }).on('line', line => {
  const frame = JSON.parse(line);
  if (frame.method === 'notifications/initialized') return;
  if (frame.method === 'initialize') return reply(frame.id, { protocolVersion: '2025-06-18', capabilities: { tools: {} }, serverInfo: { name: 'fixture', version: '0' } });
  if (frame.method === 'ping') return reply(frame.id, {});
  if (frame.method === 'tools/list') {
    const tools = [...names, 'merge_pull_request', 'delete_file'].map(name => ({ name,
      annotations: { readOnlyHint: !['issue_write', 'add_issue_comment', 'merge_pull_request', 'delete_file'].includes(name) },
      _meta: name === 'issue_write' ? { ui: { resourceUri: 'ui://untrusted-form' } } : {} }));
    if (scenario === 'untrusted-read') tools.find(x => x.name === 'issue_read').annotations.readOnlyHint = false;
    if (scenario === 'missing-read') tools.splice(tools.findIndex(x => x.name === 'issue_read'), 1);
    return reply(frame.id, { tools });
  }
  if (frame.method !== 'tools/call') return reply(frame.id, { isError: true });
  const { name, arguments: args } = frame.params;
  appendFileSync(process.env.FAKE_LOG, JSON.stringify({ name, args }) + '\n');
  if (name === 'issue_read') {
    if (scenario === 'server-subrequest') process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id: 'child-request', method: 'sampling/createMessage', params: {} }) + '\n');
    if (scenario === 'wrong-child-id') process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id: 'client-claimed', result: {} }) + '\n');
    if (scenario === 'crash') process.exit(1);
    if (scenario === 'timeout') return;
    if (scenario === 'oversize-child') { process.stdout.write('x'.repeat(1024 * 1024 + 1)); return; }
    const result = issue(args.issue_number, args.owner, args.repo);
    if (scenario === 'no-structured') delete result.structuredContent;
    if (scenario === 'ambiguous-content') result.content.push(result.content[0]);
    if (scenario === 'error') result.isError = true;
    return reply(frame.id, result);
  }
  if (name === 'add_issue_comment') {
    if (scenario === 'crash-comment') process.exit(1);
    if (scenario === 'timeout-comment') return;
    return reply(frame.id, { content: [{ type: 'text', text: 'offline comment fixture' }] });
  }
  if (name === 'issue_write') {
    if (scenario === 'crash-write') process.exit(1);
    if (scenario === 'timeout-write') return;
    if (scenario === 'await-form') return reply(frame.id, { isError: false, structuredContent: { status: 'awaiting_user_submission' } });
    return reply(frame.id, { content: [{ type: 'text', text: 'offline issue write fixture' }] });
  }
  reply(frame.id, { content: [{ type: 'text', text: 'read-through fixture' }], isError: false });
});
