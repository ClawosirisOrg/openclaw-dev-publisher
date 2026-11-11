/** Stock github-mcp-server v2.0.2 (eb47a99), curated Syn-only API surface.
 * All entries are explicit. This module never receives or handles credentials.
 * A stock annotation is checked by the adapter, not treated as authorization.
 */
const deny = () => { throw new Error('mcp_policy_denied_or_uncertain'); };
const plain = x => x !== null && typeof x === 'object' && !Array.isArray(x) &&
  (Object.getPrototypeOf(x) === Object.prototype || Object.getPrototypeOf(x) === null);
const n = x => Number.isSafeInteger(x) && x > 0 && x <= 2147483647;
const actionId = x => Number.isSafeInteger(x) && x > 0;
const decimalId = x => typeof x === 'string' && /^[1-9][0-9]{0,15}$/.test(x) &&
  actionId(Number(x)) && String(Number(x)) === x;
const workflowFile = x => typeof x === 'string' && /^[A-Za-z0-9_.-]{1,100}\.ya?ml$/.test(x);
const text = (x, max = 400, multiline = false) => typeof x === 'string' && x.length > 0 &&
  Buffer.byteLength(x, 'utf8') <= max && ![...x].some(c =>
    c.charCodeAt(0) < 32 && !(multiline && c.charCodeAt(0) === 10) || c.charCodeAt(0) === 127);
const sha = x => typeof x === 'string' && /^[a-f0-9]{40}$/.test(x);
const ref = x => typeof x === 'string' && /^(?:main|dev-syn\/[a-z0-9][a-z0-9-]{0,62})$/.test(x);
const path = x => typeof x === 'string' && x.length <= 256 &&
  x.split('/').every(s => /^[A-Za-z0-9._-]{1,100}$/.test(s) && s !== '.' && s !== '..');
const fields = x => Array.isArray(x) && x.length <= 30 &&
  x.every(s => typeof s === 'string' && /^[A-Za-z_]{1,50}$/.test(s));
const scalar = x => typeof x === 'boolean' || n(x) || text(x, 400);
const primitiveList = x => Array.isArray(x) && x.length <= 30 && x.every(y => scalar(y));
const own = (x,k) => Object.hasOwn(x,k);
const GROUPS = Object.freeze({
  issues: ['issue_read','list_issues','get_label','list_label','issue_write','add_issue_comment','label_write'],
  pull_requests: ['pull_request_read','list_pull_requests','update_pull_request','pull_request_review_write','merge_pull_request'],
  actions: ['actions_get','actions_list','get_job_logs','actions_run_trigger'],
  repository: ['get_file_contents','get_repository_tree','list_branches','get_commit','list_commits',
    'search_code','search_issues','search_pull_requests',
    'get_code_quality_finding','get_code_scanning_alert','list_code_scanning_alerts'],
  releases: ['list_releases','get_latest_release','get_release_by_tag'],
});
const WRITES = new Set(['issue_write','add_issue_comment','label_write','update_pull_request',
  'pull_request_review_write','merge_pull_request','actions_run_trigger']);
const READS = new Set(Object.values(GROUPS).flat().filter(x => !WRITES.has(x)));
const LEGACY_READS = new Set(['get_code_quality_finding','get_code_scanning_alert','list_code_scanning_alerts']);
export const TOOL_GROUPS = GROUPS;
export const WRITE_TOOLS = WRITES;
export const READ_TOOLS = READS;
export function expandGroups(groups) {
  if (!Array.isArray(groups) || groups.length === 0 || groups.length > Object.keys(GROUPS).length ||
      new Set(groups).size !== groups.length || groups.some(g => !own(GROUPS,g))) deny();
  // Issue read is mandatory for canonical issue/PR conversation preflight.
  if (!groups.includes('issues')) deny();
  return [...new Set(groups.flatMap(g => GROUPS[g]))];
}
const SPECS = Object.freeze({
  issue_read: ['method','issue_number','page','perPage'], list_issues: ['state','labels','since','perPage','orderBy','direction','after','fields'],
  get_label: ['name'], list_label: [], pull_request_read: ['method','pullNumber','page','perPage','after'],
  list_pull_requests: ['base','head','state','sort','direction','page','perPage'],
  actions_get: ['method','resource_id'], actions_list: ['method','resource_id','page','perPage'],
  get_job_logs: ['job_id','run_id','failed_only','return_content','tail_lines'],
  get_file_contents: ['path','ref','sha','fields'],get_repository_tree: ['path_filter','recursive','tree_sha'],
  list_branches: ['page','perPage'],get_commit: ['sha','detail','page','perPage'],
  list_commits: ['sha','path','author','since','until','page','perPage','fields'],
  search_code: ['query','page','perPage','sort','order'],
  search_issues: ['query','page','perPage','sort','order'],
  search_pull_requests: ['query','page','perPage','sort','order'],
  list_releases: ['page','perPage','fields'],get_latest_release: [],get_release_by_tag: ['tag'],
  get_code_quality_finding: ['findingNumber'],get_code_scanning_alert: ['alertNumber'],
  list_code_scanning_alerts: ['page','perPage','ref','severity','state','tool_name'],
});
const CHOICES = Object.freeze({
  state:['open','closed','all','OPEN','CLOSED','dismissed','fixed'],
  direction:['asc','desc','ASC','DESC'],
  sort:['created','updated','popularity','long-running','comments','reactions','interactions'],
  order:['asc','desc'],orderBy:['CREATED_AT','UPDATED_AT','COMMENTS'],
  detail:['none','stats','full_patch'],
  severity:['critical','high','medium','low','warning','note','error'],
});
// Metadata only: the admission guards remain authoritative. Keep this small
// projection in lockstep with issueWriteArgs/commentArgs and admitWrite tests.
export const WRITE_CONTRACT = Object.freeze({
  issue_write:{
    fields:['method','owner','repo','issue_number','title','body','state','state_reason',
      'labels','assignees','milestone','type'],
    required:['method','owner','repo'],
    enums:{method:['create','update'],state_reason:['completed','not_planned']},
    notes:{body:'Attributed body required on create; optional on update.',
      state_reason:'Only completed/not_planned when closing with state=closed. Reopen using state=open without a reason.'},
    description:'Syn issues only. create requires title and attributed body; update requires issue_number and a change. state_reason is completed/not_planned only with state=closed; reopen with state=open and no reason. Existing milestone numbers only. No duplicate or cross-repository parent fields.',
  },
  add_issue_comment:{
    fields:['owner','repo','issue_number','body'],
    required:['owner','repo','issue_number','body'],
    notes:{body:'Required attributed comment body; reactions are not supported.'},
    description:'Add an attributed comment to a canonical Syn issue or PR. No reactions or comment edits.',
  },
  label_write:{
    fields:['method','owner','repo','name','new_name','color','description'],
    required:['method','owner','repo','name'],
    enums:{method:['create','update','delete']},
    description:'Syn label resource create/update/delete. Supply a six-hex color for creation; new_name is for update. Update/delete require scoped get_label proof.',
  },
  update_pull_request:{
    fields:['owner','repo','pullNumber','title','body','draft','state','maintainer_can_modify'],
    required:['owner','repo','pullNumber'],
    description:'Update an existing canonical Syn PR with at least one permitted change. Body must be attributed. No base retarget or reviewer assignment.',
  },
  pull_request_review_write:{
    fields:['method','owner','repo','pullNumber','event','body','commitID'],
    required:['method','owner','repo','pullNumber','event','body'],
    enums:{method:['create','submit_pending'],event:['APPROVE','REQUEST_CHANGES','COMMENT']},
    notes:{commitID:'For create APPROVE/REQUEST_CHANGES, required and must match the observed PR head; omit for submit_pending COMMENT.'},
    description:'Create an attributed review; APPROVE/REQUEST_CHANGES creation requires commitID matching the observed PR head. submit_pending supports attributed COMMENT only and no commitID; stock ignores commitID on pending submission. No thread resolution or deletion.',
  },
  merge_pull_request:{
    fields:['owner','repo','pullNumber','expectedHeadSha','merge_method','commit_title','commit_message'],
    required:['owner','repo','pullNumber','expectedHeadSha','merge_method','commit_title','commit_message'],
    enums:{merge_method:['merge','squash']},
    notes:{expectedHeadSha:'Required SHA matching a fresh canonical PR GET.'},
    description:'Merge/squash a canonical open Syn PR into main only when expectedHeadSha matches fresh PR GET. Attributed commit_message and commit_title required. No rebase.',
  },
  actions_run_trigger:{
    fields:['method','owner','repo','workflow_id','ref','run_id','inputs'],
    required:['method','owner','repo'],
    enums:{method:['run_workflow','rerun_workflow_run','rerun_failed_jobs','cancel_workflow_run']},
    notes:{workflow_id:'String numeric ID or workflow filename required for run_workflow.',
      ref:'Bounded Syn branch required for run_workflow.',
      run_id:'Positive safe-integer run ID required for rerun/cancel methods.'},
    description:'Syn workflow dispatch requires workflow_id string (numeric ID or filename) and bounded ref; rerun/cancel require positive safe-integer run_id and canonical run GET. Cancel only a cancellable run. No log deletion.',
  },
});
const METHODS = Object.freeze({
  issue_read: ['get','get_comments','get_labels'], // hierarchy can point outside Syn
  pull_request_read: ['get','get_diff','get_status','get_files','get_commits','get_review_comments','get_reviews','get_comments','get_check_runs'],
  actions_get: ['get_workflow','get_workflow_run','get_workflow_job','get_workflow_run_usage','get_workflow_run_logs_url'],
  actions_list: ['list_workflows','list_workflow_runs','list_workflow_jobs','list_workflow_run_artifacts'],
});
export function projectTool(tool) {
  if (!plain(tool) || typeof tool.name!=='string') deny();
  const contract=WRITE_CONTRACT[tool.name];
  if (WRITE_TOOLS.has(tool.name) && !contract) deny();
  const methods=METHODS[tool.name];
  if (!contract && !methods) return { ...tool };
  const source=tool.inputSchema;
  if (!plain(source) || source.type!=='object' || !plain(source.properties)) deny();
  if (contract) {
    if (!Array.isArray(source.required) ||
        source.required.some(k=>!contract.required.includes(k)) ||
        contract.fields.some(k=>!plain(source.properties[k])) ||
        contract.required.some(k=>!contract.fields.includes(k))) deny();
    const properties=Object.fromEntries(contract.fields.map(k=>{
      const property={...source.properties[k]};
      if (own(contract.enums??{},k)) {
        const stock=source.properties[k].enum;
        if (!Array.isArray(stock) || contract.enums[k].some(v=>!stock.includes(v))) deny();
        property.enum=[...contract.enums[k]];
        property.description='Allowed Syn values: '+property.enum.join(', ');
      }
      if(own(contract.notes??{},k))property.description=contract.notes[k];
      return [k,property];
    }));
    return { ...tool, description:contract.description, inputSchema:{...source,
      properties,required:[...contract.required],additionalProperties:false} };
  }
  const method=source.properties.method;
  if (!plain(method) || !Array.isArray(method.enum) ||
      methods.some(v=>!method.enum.includes(v))) deny();
  return { ...tool, description:'Syn read-only methods: '+methods.join(', '),
    inputSchema:{...source,properties:{...source.properties,
    method:{...method,enum:[...methods],
      description:'Allowed Syn read methods: '+methods.join(', ')}},additionalProperties:false} };
}
function target(args, config, extra) {
  if (!plain(args) || typeof args.owner !== 'string' || typeof args.repo !== 'string' ||
      args.owner.toLowerCase() !== config.owner.toLowerCase() ||
      args.repo.toLowerCase() !== config.repo.toLowerCase() ||
      Object.keys(args).some(k => !['owner','repo',...extra].includes(k))) deny();
  return { ...args, owner: config.owner, repo: config.repo };
}
function scopedQuery(q, config) {
  const tokens = typeof q === 'string' ? q.split(' ') : [];
  const prefix = 'repo:' + config.owner + '/' + config.repo;
  if (tokens.length < 2 || tokens.length > 20 || tokens[0] !== prefix ||
      tokens.slice(1).some(s => !/^[A-Za-z0-9_.-]{1,50}$/.test(s) || /^(or|not|and)$/i.test(s)) ||
      Buffer.byteLength(q,'utf8') > 512) deny();
}
export function safeRead(name, args, config) {
  if (!READS.has(name) && !LEGACY_READS.has(name)) deny();
  const extra=SPECS[name];
  if (!extra) deny();
  const a = name.startsWith('search_')
    ? (plain(args) && Object.keys(args).every(k => [...extra,'owner','repo'].includes(k)) &&
      (!own(args,'owner') || args.owner.toLowerCase()===config.owner.toLowerCase()) &&
      (!own(args,'repo') || args.repo.toLowerCase()===config.repo.toLowerCase())
      ? { ...args, ...(own(args,'owner') ? {owner:config.owner}:{}), ...(own(args,'repo') ? {repo:config.repo}:{}) } : deny())
    : target(args,config,extra);
  if (name.startsWith('search_')) scopedQuery(a.query,config);
  if (METHODS[name] && !METHODS[name].includes(a.method)) deny();
  if (name==='list_code_scanning_alerts' && own(a,'state') &&
      !['open','closed','dismissed','fixed'].includes(a.state)) deny();
  if (name==='actions_get' &&
      !(a.method==='get_workflow'
        ? decimalId(a.resource_id) || workflowFile(a.resource_id)
        : decimalId(a.resource_id))) deny();
  if (name==='actions_list' && own(a,'resource_id') &&
      !(a.method==='list_workflow_runs'
        ? decimalId(a.resource_id) || workflowFile(a.resource_id)
        : decimalId(a.resource_id))) deny();
  for(const [k,v] of Object.entries(a)) {
    if (k==='owner'||k==='repo'||k==='method'||k==='query') continue;
    if (own(CHOICES,k) && !CHOICES[k].includes(v)) deny();
    if (k==='resource_id') continue; // method-specific decimal/string check above
    if (['job_id','run_id'].includes(k)) {if (!actionId(v)) deny(); continue;}
    if (['issue_number','pullNumber','findingNumber','alertNumber','page','perPage','tail_lines'].includes(k) && (!n(v) ||
        (['page','perPage'].includes(k) && v>100))) deny();
    else if (['path','path_filter'].includes(k) && !path(v)) deny();
    else if (['ref','base'].includes(k) && !ref(v)) deny();
    else if (['sha','tree_sha'].includes(k) && !sha(v)) deny();
    else if (k==='head' && !(ref(v) || v===config.owner+':main')) deny();
    else if (['fields','labels'].includes(k) && !(k==='fields'?fields(v):primitiveList(v))) deny();
    else if (['failed_only','return_content','recursive'].includes(k) && typeof v!=='boolean') deny();
    else if (!scalar(v) && !['fields','labels'].includes(k)) deny();
  }
  if (name==='issue_read' && !n(a.issue_number) || name==='pull_request_read' && !n(a.pullNumber) ||
      name==='get_commit' && !sha(a.sha) || name==='get_label' &&
        !(typeof a.name==='string' && /^[A-Za-z0-9_. -]{1,100}$/.test(a.name)) ||
      name==='get_release_by_tag' &&
        !(typeof a.tag==='string' && /^[A-Za-z0-9._-]{1,100}$/.test(a.tag) &&
          a.tag!=='.' && a.tag!=='..')) deny();
  if (name==='get_job_logs' && !actionId(a.job_id) && !actionId(a.run_id) ||
      name==='get_code_quality_finding' && !n(a.findingNumber) ||
      name==='get_code_scanning_alert' && !n(a.alertNumber)) deny();
  if (name==='get_file_contents' && own(a,'sha') && own(a,'ref')) deny();
  return a;
}
export function safeLegacyRead(name,args,config) {
  if (/^read_fixture_[0-9]+$/.test(name) && plain(args) && !Object.keys(args).length) return args;
  return safeRead(name,args,config);
}
export function exactTarget(args, config, allowed) { return target(args,config,allowed); }
export function goodNumber(x) {return n(x);}
export function goodActionNumber(x) {return actionId(x);}
export function goodDecimalId(x) {return decimalId(x);}
export function goodWorkflowFile(x) {return workflowFile(x);}
export function goodSHA(x) {return sha(x);}
export function goodRef(x) {return ref(x);}
export function goodPath(x) {return path(x);}
export function goodText(x,max=12000) {return text(x,max);}
export function goodAttribution(body) {
  if (!text(body,12000,true)) return false;
  const eol=String.fromCharCode(10);
  const lines=(body.endsWith(eol)?body.slice(0,-1):body).split(eol);
  return lines.length>=5 && lines.at(-5)==='' && lines.at(-4)==='Agent: dev-syn' &&
    /^Model: [A-Za-z0-9][A-Za-z0-9._/+:-]{0,127}$/.test(lines.at(-3)) &&
    /^Thinking: (off|minimal|low|medium|high|xhigh)$/.test(lines.at(-2)) &&
    lines.at(-1)==='Bot-Owner: @llunved';
}
