/** Typed Syn-only write admission. No generic API, URL, or credential route. */
import {exactTarget,goodNumber,goodActionNumber,goodDecimalId,goodWorkflowFile,
  goodSHA,goodRef,goodText,goodAttribution} from './syn-tool-policy.mjs';
const deny=()=>{throw new Error('mcp_policy_denied_or_uncertain');};
const own=(x,k)=>Object.hasOwn(x,k);
const plain=x=>x!==null&&typeof x==='object'&&!Array.isArray(x)&&
  (Object.getPrototypeOf(x)===Object.prototype||Object.getPrototypeOf(x)===null);
const required=(a,k)=>k.every(x=>own(a,x));
const suffix=(repo,part)=>'https://github.com/'+repo+'/'+part;
// GitHub canonicalizes owner/repo case, but never host, path shape, query or resource ID.
function canonicalRunHtmlUrl(url,config,id){
  if(typeof url!=='string'||!goodActionNumber(id))return false;
  const match=/^https:\/\/github\.com\/([A-Za-z0-9_.-]{1,100})\/([A-Za-z0-9_.-]{1,100})\/actions\/runs\/([1-9][0-9]{0,15})$/.exec(url);
  return match!==null&&match[1].toLowerCase()===config.owner.toLowerCase()&&
    match[2].toLowerCase()===config.repo.toLowerCase()&&match[3]===String(id);
}
function canonicalApiUrl(url,config,part,id){
  if(typeof url!=='string'||!goodActionNumber(id))return false;
  const match=/^https:\/\/api\.github\.com\/repos\/([A-Za-z0-9_.-]{1,100})\/([A-Za-z0-9_.-]{1,100})\/actions\/(workflows|runs)\/([1-9][0-9]{0,15})$/.exec(url);
  return match!==null&&match[1].toLowerCase()===config.owner.toLowerCase()&&
    match[2].toLowerCase()===config.repo.toLowerCase()&&match[3]===part&&
    match[4]===String(id);
}
function root(response){
  if(!plain(response)||own(response,'error')||!plain(response.result)||
     response.result.isError!==false&&response.result.isError!==undefined)deny();
  const r=response.result;
  if(!Array.isArray(r.content)||r.content.length!==1||!plain(r.content[0])||
     r.content[0].type!=='text'||typeof r.content[0].text!=='string'||
     Buffer.byteLength(r.content[0].text,'utf8')>1024*1024)deny();
  let doc;try{doc=JSON.parse(r.content[0].text);}catch{deny();}
  if(!plain(doc))deny();
  return {doc,structured:r.structuredContent};
}
function sameRepo(value,config){return typeof value==='string'&&value.toLowerCase()===(config.owner+'/'+config.repo).toLowerCase();}
function validRepo(value){
  if(typeof value!=='string'||!value.includes('/'))return false;
  const parts=value.split('/');
  return parts.length===2&&parts.every(s=>/^[A-Za-z0-9_.-]{1,100}$/.test(s)&&
    s!=='.'&&s!=='..');
}
function canonicalPR(response,config,number){
  const {doc,structured}=root(response),repo=config.owner+'/'+config.repo;
  const check=x=>plain(x)&&x.number===number&&x.html_url?.toLowerCase()===suffix(repo,'pull/'+number).toLowerCase()&&
    plain(x.head)&&plain(x.base)&&
    validRepo(x.head.repo?.full_name)&&
    sameRepo(x.base.repo?.full_name,config)&&
    goodSHA(x.head.sha)&&typeof x.head.ref==='string'&&typeof x.base.ref==='string';
  if(!check(doc))deny();
  if(structured!==undefined){
    if(!plain(structured)||structured.method!=='get'||!check(structured.pullRequest??structured.pull_request??structured.pull))deny();
    if(structured.pullRequest?.head?.sha&&structured.pullRequest.head.sha!==doc.head.sha)deny();
  }
  return doc;
}
async function preflight(call,name,args){return call('tools/call',{name,arguments:args});}
function attributed(x){if(!goodAttribution(x))deny();}
function boundText(a,keys){for(const key of keys)if(own(a,key)&&!goodText(a[key],key==='title'?200:12000))deny();}
export async function admitWrite(name,raw,config,call){
  if(name==='label_write'){
    const a=exactTarget(raw,config,['method','name','new_name','color','description']);
    if(!required(a,['method','name'])||!['create','update','delete'].includes(a.method)||
      !/^[A-Za-z0-9_. -]{1,100}$/.test(a.name)||
      (own(a,'new_name')&&!/^[A-Za-z0-9_. -]{1,100}$/.test(a.new_name))||
      (own(a,'color')&&!/^[a-fA-F0-9]{6}$/.test(a.color))||
      (own(a,'description')&&!goodText(a.description,1000))||
      (a.method==='delete'&&Object.keys(a).some(k=>!['method','name','owner','repo'].includes(k))))deny();
    if(a.method!=='create'){
      const {doc}=root(await preflight(call,'get_label',{owner:config.owner,repo:config.repo,name:a.name}));
      // Stock get_label returns a scoped name and stable GraphQL ID, not an API URL.
      if(doc.name!==a.name||typeof doc.id!=='string'||
        !/^[A-Za-z0-9_-]{4,190}={0,2}$/.test(doc.id))deny();
    }
    return a;
  }
  if(['update_pull_request','pull_request_review_write','merge_pull_request'].includes(name)){
    const allowed={update_pull_request:['pullNumber','title','body','draft','state','maintainer_can_modify'],
      pull_request_review_write:['pullNumber','method','event','body','commitID'],
      merge_pull_request:['pullNumber','expectedHeadSha','merge_method','commit_title','commit_message']}[name];
    const a=exactTarget(raw,config,allowed);
    if(!goodNumber(a.pullNumber))deny();
    const pr=canonicalPR(await preflight(call,'pull_request_read',{
      method:'get',owner:config.owner,repo:config.repo,pullNumber:a.pullNumber}),config,a.pullNumber);
    if(name==='update_pull_request'){
      if(Object.keys(a).length<=3||own(a,'state')&&!['open','closed'].includes(a.state)||
        own(a,'draft')&&typeof a.draft!=='boolean'||own(a,'maintainer_can_modify')&&typeof a.maintainer_can_modify!=='boolean')deny();
      boundText(a,['title']);if(own(a,'body'))attributed(a.body);
    }else if(name==='pull_request_review_write'){
      if(pr.state!=='open'||!['create','submit_pending'].includes(a.method)||
        !['APPROVE','REQUEST_CHANGES','COMMENT'].includes(a.event)||!own(a,'body'))deny();
      attributed(a.body);
      if(a.method==='create'){
        if((a.event==='APPROVE'||a.event==='REQUEST_CHANGES')&&!own(a,'commitID'))deny();
        if(own(a,'commitID')&&(!goodSHA(a.commitID)||a.commitID!==pr.head.sha))deny();
      }else if(a.event!=='COMMENT'||own(a,'commitID'))deny();
      // Stock submit_pending ignores commitID: do not claim a pinned approval.
      // No caller-controlled review/thread IDs, deletion, or claimed author.
    }else{
      if(pr.state!=='open'||pr.merged_at!=null||pr.base.ref!=='main'||
        !goodSHA(a.expectedHeadSha)||a.expectedHeadSha!==pr.head.sha||
        !['merge','squash'].includes(a.merge_method)||
        !own(a,'commit_title')||!own(a,'commit_message'))deny();
      boundText(a,['commit_title']);attributed(a.commit_message);
    }
    return a;
  }
  if(name==='actions_run_trigger'){
    const a=exactTarget(raw,config,['method','workflow_id','ref','run_id','inputs']);
    if(!['run_workflow','rerun_workflow_run','rerun_failed_jobs','cancel_workflow_run'].includes(a.method))deny();
    if(a.method==='run_workflow'){
      if(!required(a,['workflow_id','ref'])||!goodRef(a.ref)||
        !(goodDecimalId(a.workflow_id)||goodWorkflowFile(a.workflow_id))||
        own(a,'run_id'))deny();
      if(own(a,'inputs')&&(!plain(a.inputs)||Object.keys(a.inputs).length>20||
        Object.entries(a.inputs).some(([k,v])=>!/^[A-Za-z0-9_-]{1,50}$/.test(k)||!goodText(v,500))))deny();
      const {doc}=root(await preflight(call,'actions_get',{method:'get_workflow',
        owner:config.owner,repo:config.repo,resource_id:String(a.workflow_id)}));
      if(!goodActionNumber(doc.id)||doc.repository!==undefined &&
          !sameRepo(doc.repository?.full_name,config)||
        !canonicalApiUrl(doc.url,config,'workflows',doc.id)||
        (String(doc.id)!==a.workflow_id&&
          !(goodWorkflowFile(a.workflow_id)&&
            doc.path==='.github/workflows/'+a.workflow_id)))deny();
    }else{
      if(!goodActionNumber(a.run_id)||Object.keys(a).some(k=>!['owner','repo','method','run_id'].includes(k)))deny();
      const {doc}=root(await preflight(call,'actions_get',{method:'get_workflow_run',
        owner:config.owner,repo:config.repo,resource_id:String(a.run_id)}));
      if(doc.id!==a.run_id||
        !canonicalRunHtmlUrl(doc.html_url,config,a.run_id)||
        (doc.repository!==undefined&&!sameRepo(doc.repository?.full_name,config))||
        (doc.url!==undefined&&!canonicalApiUrl(doc.url,config,'runs',a.run_id))||
        a.method==='cancel_workflow_run' &&
          !['queued','in_progress','waiting','requested','pending'].includes(doc.status))deny();
    }
    return a;
  }
  deny();
}
