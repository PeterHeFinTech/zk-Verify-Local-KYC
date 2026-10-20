import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import {groth16} from 'snarkjs';
import {p,artifacts,openStore,prove,verifySubmission,calculateWitness} from '../lib/runtime.mjs';
import {readJSON,writeJSON,nowSeconds} from '../lib/files.mjs';
import {privateInput} from '../lib/protocol.mjs';
import {response} from '../lib/crypto.mjs';
async function main(){
  const a=artifacts(),manifest=readJSON(p('data/manifest.json')),trust=readJSON(p('state/trust.json')),s=openStore();
  const report={startedAt:new Date().toISOString(),tests:[],mode:'SIMULATED_SOURCE',setup:'DEVELOPMENT_SINGLE_OPERATOR_SETUP'};
  const dir=p('reports',`e2e-${Date.now()}`);fs.mkdirSync(dir,{recursive:true,mode:0o700});
  const pass=(name,detail={})=>{report.tests.push({name,passed:true,...detail});console.log('PASS:',name);};
  try{
    s.pinProfile(a.vkHash);const q=s.createRequest(),wallet=readJSON(p('wallets',manifest.examples.valid,'credential.private.json'));
    const input=privateInput(wallet,s.pathFor(manifest.examples.valid,q.version),q,trust.sourcePublicKey);
    const result=await prove(input,path.join(dir,'valid'));
    assert.equal(result.publicSignals.length,7);
    assert.deepEqual(result.publicSignals,[response(wallet.secret,q.context),q.root,String(q.currentTime),String(q.expires),q.context,'1','20261020']);
    assert(await groth16.verify(a.vk,result.publicSignals,result.proof));pass('Real Groth16 proof verifies, exact public signal order');
    const changed=[...result.publicSignals];changed[1]='1';assert.equal(await groth16.verify(a.vk,changed,result.proof),false);pass('Public-root tampering rejected cryptographically');
    const changedContext=[...result.publicSignals];changedContext[4]='1';assert.equal(await groth16.verify(a.vk,changedContext,result.proof),false);pass('Request-context tampering rejected cryptographically');
    const submission={requestId:q.id,sessionToken:q.sessionToken,...result};
    writeJSON(path.join(dir,'valid/submission.private.json'),submission);writeJSON(path.join(dir,'valid/request.private.json'),q);
    assert((await verifySubmission(s,submission)).accepted);pass('Full policy + proof acceptance');
    await assert.rejects(()=>verifySubmission(s,submission));pass('Replay rejected');
    const cases=[
      ['wrong-secret',x=>{x.secret=(BigInt(x.secret)+1n).toString();}],
      ['changed-U',x=>{x.u[0]=(BigInt(x.u[0])+1n).toString();}],
      ['unverified',x=>{x.verified='0';}],
      ['expired',x=>{x.expiry=String(q.currentTime-1);}],
      ['expiry-before-request-end',x=>{x.expiry=String(q.expires-1);}],
      ['future-issued',x=>{x.issuedAt=String(q.currentTime+1);}],
      ['timestamp-overflow',x=>{x.expiry=String(2**32);}],
      ['invalid-path-bit',x=>{x.pathIndices[0]='2';}],
      ['wrong-path',x=>{x.pathElements[0]='123';}],
      ['wrong-issuer',x=>{x.issuerId='2';}],
      ['wrong-policy',x=>{x.policyId='2';}],
      ['zero-secret',x=>{x.secret='0';}]
    ];
    for(const [name,mutate] of cases){const bad=structuredClone(input);mutate(bad);writeJSON(path.join(dir,name+'.private.json'),bad);
      await assert.rejects(()=>calculateWitness(bad,a.wasm));pass(name+' rejected by circuit');}
    const expiredWallet=readJSON(p('wallets',manifest.examples.expired,'credential.private.json'));
    const expiredInput=privateInput(expiredWallet,s.pathFor(manifest.examples.expired,q.version),q,trust.sourcePublicKey);
    writeJSON(path.join(dir,'expired-source.private.json'),expiredInput);
    await assert.rejects(()=>calculateWitness(expiredInput,a.wasm));pass('Authentically issued expired credential rejected');
    report.success=true;report.finishedAt=new Date().toISOString();writeJSON(path.join(dir,'report.json'),report);
    writeJSON(p('reports/latest-e2e.json'),{...report,directory:dir});console.log('Report:',path.join(dir,'report.json'));
  }catch(e){report.success=false;report.error=e.message;writeJSON(path.join(dir,'report.json'),report);throw e;}finally{s.close();}
}
main().then(()=>process.exit(0)).catch(e=>{console.error(e.message);process.exit(1);});
