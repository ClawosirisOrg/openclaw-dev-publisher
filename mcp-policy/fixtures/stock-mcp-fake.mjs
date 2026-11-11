#!/usr/bin/env node
// Offline test double only. No HTTP, credential, or GitHub identity.
import { appendFileSync } from 'node:fs';
import { createInterface } from 'node:readline';
const names = process.argv[process.argv.indexOf('--tools') + 1]?.split(',') ?? [];
const scenario = process.env.FAKE_SCENARIO ?? 'issue';
const reply = (id, result) => process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id, result }) + '\n');
const writes = new Set(['issue_write','add_issue_comment','label_write','update_pull_request',
  'pull_request_review_write','merge_pull_request','actions_run_trigger']);
const stockWriteFields = {
  issue_write:['method','owner','repo','issue_number','title','body','state','state_reason',
    'labels','assignees','milestone','type','duplicate_of','issue_fields',
    'parent_issue_number','parent_owner','parent_repo'],
  add_issue_comment:['owner','repo','issue_number','body','comment_id','reaction'],
  label_write:['method','owner','repo','name','new_name','color','description'],
  update_pull_request:['owner','repo','pullNumber','title','body','draft','state',
    'maintainer_can_modify','base','reviewers'],
  pull_request_review_write:['method','owner','repo','pullNumber','event','body','commitID','threadId'],
  merge_pull_request:['owner','repo','pullNumber','expectedHeadSha','merge_method','commit_title','commit_message'],
  actions_run_trigger:['method','owner','repo','workflow_id','ref','run_id','inputs'],
};
const stockEnums={
  issue_write:{method:['create','update'],state_reason:['completed','not_planned','duplicate']},
  label_write:{method:['create','update','delete']},
  pull_request_review_write:{method:['create','submit_pending','delete_pending','resolve_thread','unresolve_thread'],
    event:['APPROVE','REQUEST_CHANGES','COMMENT']},
  merge_pull_request:{merge_method:['merge','squash','rebase']},
  actions_run_trigger:{method:['run_workflow','rerun_workflow_run','rerun_failed_jobs',
    'cancel_workflow_run','delete_workflow_run_logs']},
};
const stockReadMethods={
  issue_read:['get','get_comments','get_labels','get_sub_issues'],
  pull_request_read:['get','get_diff','get_status','get_files','get_commits',
    'get_review_comments','get_reviews','get_comments','get_check_runs'],
  actions_get:['get_workflow','get_workflow_run','get_workflow_job',
    'get_workflow_run_usage','get_workflow_run_logs_url','download_workflow_run_artifact'],
  actions_list:['list_workflows','list_workflow_runs','list_workflow_jobs','list_workflow_run_artifacts'],
};
const isV2Catalog = scenario.startsWith('capability-v2') || names.includes('label_write');
function stockSchema(name){
  if(!isV2Catalog)return {type:'object',properties:{}};
  const fields=stockWriteFields[name];
  if(fields){
    const properties=Object.fromEntries(fields.map(k=>[k,{type:k==='inputs'?'object':
      ['issue_number','pullNumber','run_id','milestone','duplicate_of'].includes(k)?'number':'string',
      ...(stockEnums[name]?.[k]?{enum:stockEnums[name][k]}:{})}]));
    const required=name==='issue_write'||name==='label_write'||name==='pull_request_review_write'||
      name==='actions_run_trigger'?['method','owner','repo']:['owner','repo'];
    if(['label_write'].includes(name))required.push('name');
    if(['add_issue_comment'].includes(name))required.push('issue_number');
    if(['update_pull_request','pull_request_review_write','merge_pull_request'].includes(name))required.push('pullNumber');
    return {type:'object',properties,required};
  }
  return {type:'object',properties:stockReadMethods[name]?
    {method:{type:'string',enum:stockReadMethods[name]}}:{}};
}
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
let uiCapable = false;
createInterface({ input: process.stdin, crlfDelay: Infinity }).on('line', line => {
  const frame = JSON.parse(line);
  if (frame.method === 'notifications/initialized') return;
  if (frame.method === 'initialize') {
    uiCapable = Object.hasOwn(frame.params.capabilities?.extensions ?? {}, 'io.modelcontextprotocol/ui');
    return reply(frame.id, { protocolVersion: '2025-06-18', capabilities: { tools: {} }, serverInfo: { name: 'fixture', version: '0' } });
  }
  if (frame.method === 'ping') return reply(frame.id, {});
  if (frame.method === 'tools/list') {
    const tools = [...new Set([...names, 'merge_pull_request', 'delete_file'])].map(name => ({ name,
      inputSchema: stockSchema(name),
      description: isV2Catalog ? 'Unrestricted stock fixture description' : undefined,
      annotations: { readOnlyHint: !writes.has(name) && name !== 'delete_file' },
      _meta: name === 'issue_write' ? { ui: { resourceUri: 'ui://untrusted-form' } } : {} }));
    if (scenario === 'big-catalog') for (const tool of tools) tool.description = 'x'.repeat(3000);
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
  if (name === 'get_label' && scenario.startsWith('capability-v2')) {
    const name=scenario==='capability-v2-wrong-label-name'?'foreign':args.name;
    const id=scenario==='capability-v2-bad-label-id'?'./bad': 'LA_kwFixture123';
    return reply(frame.id, { content: [{ type:'text', text:JSON.stringify({
      name,id,color:'abcdef',description:'Offline stock-shaped label' }) }] });
  }
  if (name === 'pull_request_read' && scenario.startsWith('capability-v2')) {
    const repo = scenario === 'capability-v2-wrong-repo' ? 'Other/Repo' : args.owner+'/'+args.repo;
    const sha = 'a'.repeat(40);
    const headRepo=scenario==='capability-v2-fork'?'Contributor/Fork':repo;
    const pr = { number:args.pullNumber, html_url:'https://github.com/'+repo+'/pull/'+args.pullNumber,
      state:'open',merged_at:null, head:{sha,ref:'dev-syn/fixture',repo:{full_name:headRepo}},
      base:{ref:'main',repo:{full_name:repo}} };
    if(scenario==='capability-v2-foreign-base') pr.base.repo.full_name='Other/Repo';
    if(scenario==='capability-v2-wrong-head') pr.head.repo.full_name='invalid/head/escape';
    if(scenario==='capability-v2-wrong-pr-url') pr.html_url='https://github.com/Other/Repo/pull/'+args.pullNumber;
    return reply(frame.id, { content:[{type:'text',text:JSON.stringify(pr)}] });
  }
  if (name === 'actions_get' && scenario.startsWith('capability-v2')) {
    const repo = scenario === 'capability-v2-wrong-repo' ? 'Other/Repo' : args.owner+'/'+args.repo;
    const run = args.method === 'get_workflow_run';
    const id=run ? 12345678901 : 3000000000;
    const canonicalRepo=scenario==='capability-v2-wrong-repo'?'Other/Repo':
      scenario==='capability-v2-wrong-api-url'?'Other/Repo':repo;
    const doc = { id, ...(run ? {
      html_url:'https://github.com/'+canonicalRepo.toLowerCase()+'/actions/runs/'+id,
      status:scenario==='capability-v2-completed-run'?'completed':'in_progress'} : {
      url:'https://api.github.com/repos/'+canonicalRepo.toLowerCase()+'/actions/workflows/'+id}),
      path:'.github/workflows/build.yml' };
    return reply(frame.id,{ content:[{type:'text',text:JSON.stringify(doc)}] });
  }
  if (scenario.startsWith('capability-v2') && writes.has(name)) {
    appendFileSync(process.env.FAKE_EFFECT_LOG, name + '\n');
    if (scenario === 'capability-v2-uncertain') process.exit(1);
    return reply(frame.id, { isError:false, content:[{type:'text',text:'synthetic effect'}] });
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
    if (scenario === 'ui-form-gate' && uiCapable)
      return reply(frame.id, { isError: true, structuredContent: { status: 'awaiting_user_submission' } });
    if (scenario === 'ui-form-gate') {
      appendFileSync(process.env.FAKE_EFFECT_LOG, 'synthetic issue write effect\n');
      const minimal = { id: 'fixture-id', url: 'https://github.com/Fixture/Repo/issues/6' };
      return reply(frame.id, { isError: false, content: [{ type: 'text', text: JSON.stringify(minimal) }],
        structuredContent: { method: args.method, issue: minimal } });
    }
    return reply(frame.id, { content: [{ type: 'text', text: 'offline issue write fixture' }] });
  }
  reply(frame.id, { content: [{ type: 'text', text: 'read-through fixture' }], isError: false });
});
