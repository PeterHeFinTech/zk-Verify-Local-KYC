import fs from 'node:fs';
import path from 'node:path';
import {spawn,spawnSync} from 'node:child_process';
import assert from 'node:assert/strict';
import {PROJECT,readJSON,writeJSON} from '../lib/files.mjs';
const dir=path.join(PROJECT,'reports','integration-'+Date.now());
const env={...process.env,ZK_STATE_DIR:dir};
const results=[];
function cli(args,expected=true){
  const r=spawnSync(process.execPath,['scripts/cli.mjs',...args],{cwd:PROJECT,env,encoding:'utf8',timeout:120000});
  if(expected&&r.status!==0)throw new Error(r.stderr||r.error?.message||'CLI failed');
  if(!expected)assert.notEqual(r.status,0);return r.stdout;
}
function pass(name){results.push({name,passed:true});console.log('PASS:',name);}
async function main(){
  cli(['import','/Users/hetianqu/Downloads/archive','source-flags']);
  const m=readJSON(path.join(dir,'data/manifest.json'));
  assert.equal(m.totalClients,2000);assert.equal(m.sources[1].rows,50000);assert(m.denied>0);assert(m.expired>0);pass('Both actual CSVs imported with flag-derived simulation; flagged records not issued');
  cli(['import'],false);pass('Reimport cannot overwrite state');
  const id=m.examples.valid,registry=readJSON(path.join(dir,'state/authority/registry.private.json'));
  const next=structuredClone(registry[id]);next.revision++;next.U.client.client_name+=' [TEST APPROVED UPDATE]';
  const approved=path.join(dir,'approved-update.private.json');writeJSON(approved,next);
  const walletPath=path.join(dir,'wallets',id,'credential.private.json'),oldWallet=readJSON(walletPath);
  cli(['update',id,approved]);cli(['local-check',id]);pass('Authority-approved replacement, wallet distribution and local check');
  writeJSON(walletPath,oldWallet);cli(['recover',id,approved]);cli(['local-check',id]);pass('Recovery after interrupted wallet distribution');
  const addition=structuredClone(next);addition.handle='integration-new';addition.U.client.client_id=addition.handle;addition.U.transactions=[];addition.revision=1;
  const newFile=path.join(dir,'approved-new.private.json');writeJSON(newFile,addition);
  cli(['enroll-source',newFile]);cli(['local-check',addition.handle]);pass('New authenticated leaf appended');
  const server=spawn(process.execPath,['server/main.mjs'],{cwd:PROJECT,env:{...env,PORT:'0'},stdio:['ignore','pipe','pipe']});
  let errors='';server.stderr.on('data',d=>{errors+=d.toString();});
  try{
    const port=await new Promise((resolve,reject)=>{
      const timer=setTimeout(()=>reject(new Error('Server startup timeout: '+errors)),20000);
      server.stdout.on('data',d=>{const match=d.toString().match(/127\.0\.0\.1:(\d+)/);if(match){clearTimeout(timer);resolve(match[1]);}});
      server.on('exit',code=>{clearTimeout(timer);reject(new Error('Server exited '+code+': '+errors));});
    });
    const url=`http://127.0.0.1:${port}`,token=readJSON(path.join(dir,'state/verifier-access.private.json')).token;
    const headers={Authorization:`Bearer ${token}`,'Content-Type':'application/json'};
    assert.equal((await fetch(url+'/status')).status,401);
    assert.equal((await fetch(url+'/status',{headers:{...headers,Origin:'https://untrusted.example'}})).status,403);pass('API rejects missing authentication and browser-origin requests');
    assert.equal((await fetch(url+'/status',{headers})).status,200);
    const req=await fetch(url+'/requests',{method:'POST',headers,body:'{}'});assert.equal(req.status,201);const q=await req.json();
    const requestFile=path.join(dir,'api-request.private.json');writeJSON(requestFile,q);
    const output=cli(['prove',id,requestFile]).trim();const submission=readJSON(output);
    const wrong=await fetch(url+'/verify',{method:'POST',headers,body:JSON.stringify({...submission,sessionToken:'wrong'})});assert.equal(wrong.status,400);
    const posts=await Promise.all([1,2].map(()=>fetch(url+'/verify',{method:'POST',headers,body:JSON.stringify(submission)})));
    assert.deepEqual(posts.map(r=>r.status).sort(),[200,400]);pass('Real proof accepted by HTTP verifier exactly once under concurrent submission');
    cli(['revoke',addition.handle]);cli(['demo',addition.handle],false);pass('Revoked holder cannot retrieve a current path');
  }finally{server.kill('SIGTERM');await new Promise(resolve=>{if(server.exitCode!==null)resolve();else{server.once('exit',resolve);setTimeout(()=>{server.kill('SIGKILL');resolve();},5000).unref();}});}
  writeJSON(path.join(PROJECT,'reports/latest-integration.json'),{success:true,directory:dir,tests:results});
}
main().then(()=>process.exit(0)).catch(e=>{writeJSON(path.join(PROJECT,'reports/latest-integration.json'),{success:false,directory:dir,tests:results,error:e.message});console.error(e.message);process.exit(1);});
