import fs from 'node:fs';
import path from 'node:path';
import { loadArchive } from '../lib/data.mjs';
import { keypair, holderCommitment, randomField, sha } from '../lib/crypto.mjs';
import { attest, checkLocal, privateInput } from '../lib/protocol.mjs';
import { writeJSON, readJSON, safeId, nowSeconds } from '../lib/files.mjs';
import { base, p, openStore, artifacts, prove, verifySubmission } from '../lib/runtime.mjs';
const [command,...args]=process.argv.slice(2);
const usage=`Commands:
  import [archive-directory] [simulate-clear|source-flags]
  status
  local-check <handle>
  path <handle> [version]
  request [version]
  prove <handle> <request-file>
  verify <submission-file>
  update <handle> <approved-source-record.json>
  recover <handle> <approved-source-record.json>
  enroll-source <approved-source-record.json>
  revoke <handle>
  demo [handle]
All UI/log text is English. Raw data and secrets are never printed.
Source approval and signing commands are authority-only SIMULATIONS, not a real identity service.`;

async function main() {
  if(command==='import') {
    const archive=path.resolve(args[0]||'/Users/hetianqu/Downloads/archive');
    const policy=args[1]||'simulate-clear';if(!['simulate-clear','source-flags'].includes(policy))throw new Error('Unknown simulation policy');
    if(fs.existsSync(p('state')))throw new Error('State already exists. Use ZK_STATE_DIR pointing to a NEW directory; import never overwrites existing state.');
    const {users,manifest}=loadArchive(archive);
    const authority=keypair(),issuer=keypair();const now=nowSeconds();
    fs.mkdirSync(p('state/authority'),{recursive:true,mode:0o700});fs.mkdirSync(p('state/issuer'),{recursive:true,mode:0o700});
    fs.writeFileSync(p('state/authority/source-private.pem'),authority.privateKey,{mode:0o600,flag:'wx'});
    fs.writeFileSync(p('state/issuer/root-private.pem'),issuer.privateKey,{mode:0o600,flag:'wx'});
    writeJSON(p('state/trust.json'),{mode:'SIMULATED_SOURCE',sourcePublicKey:authority.publicKey,rootPublicKey:issuer.publicKey});
    fs.mkdirSync(p('data/raw'),{recursive:true,mode:0o700});
    for(const s of manifest.sources){fs.copyFileSync(path.join(archive,s.name),p('data/raw',s.name));fs.chmodSync(p('data/raw',s.name),0o600);}
    const registry={},envelopes=[];let expired=0,denied=0;
    const examples={};
    for(let i=0;i<users.length;i++) {
      const U=users[i],handle=safeId(U.client.client_id),secret=randomField();
      const isExpired=i%20===19;
      // User explicitly requested a simulated all-clear scenario. Keep original flags intact.
      const verified=policy==='simulate-clear'?1:Number(U.client.sanctions_flag==='0'&&!U.transactions.some(t=>t.ofac_match_flag==='1'));
      const record={handle,U,issuedAt:now-365*86400,expiry:isExpired?now-86400:now+90*86400,verified,revision:1};
      registry[handle]=record;
      const attestation=attest(record,holderCommitment(secret),authority.privateKey);
      const wallet={schema:'wallet-v1',mode:'SIMULATED_SOURCE',U,secret,attestation};
      checkLocal(wallet,authority.publicKey);
      writeJSON(p('wallets',handle,'credential.private.json'),wallet);
      if(verified){envelopes.push(attestation);if(isExpired){expired++;examples.expired??=handle;}else examples.valid??=handle;}else {denied++;examples.denied??=handle;}
    }
    writeJSON(p('state/authority/registry.private.json'),registry);
    const store=openStore({writer:true});
    try{store.bootstrap(envelopes);}finally{store.close();}
    writeJSON(p('data/manifest.json'),{...manifest,importedAt:now,policy,simulatedFields:['issuedAt','expiry','verified','secret','holder commitment','source signatures'],
      simulation:'Every 20th client is expired; other clients expire 90 days after import. Original risk flags are preserved. Verified is NOT a real KYC or sanctions decision.',
      sourceTruth:'CSV accuracy and individual identity ownership are not independently verified.',totalClients:users.length,issued:envelopes.length,expired,denied,examples});
    console.log(JSON.stringify({imported:users.length,issued:envelopes.length,expired,denied,examples,mode:'SIMULATED_SOURCE',project:base},null,2));return;
  }
  if(command==='local-check') {
    const id=safeId(args[0]);const w=readJSON(p('wallets',id,'credential.private.json'));
    checkLocal(w,readJSON(p('state/trust.json')).sourcePublicKey);console.log('Source signature, raw-data digest, holder binding and leaf checked locally.');return;
  }
  if(command==='status'){const s=openStore();try{console.log(JSON.stringify(s.summary(),null,2));}finally{s.close();}return;}
  if(command==='path') {
    const id=safeId(args[0]),s=openStore();try{const snapshot=s.pathFor(id,args[1]?Number(args[1]):undefined);const file=p('wallets',id,`path-v${snapshot.version}.private.json`);writeJSON(file,snapshot);console.log(file);}finally{s.close();}return;
  }
  if(command==='request') {
    const a=artifacts(),s=openStore();try{s.pinProfile(a.vkHash);const request=s.createRequest({version:args[0]?Number(args[0]):undefined});const file=p('proofs',request.id,'request.private.json');writeJSON(file,request);console.log(file);}finally{s.close();}return;
  }
  if(command==='prove') {
    const id=safeId(args[0]),request=readJSON(path.resolve(args[1])),s=openStore();
    let snapshot;try{snapshot=s.pathFor(id,request.version);}finally{s.close();}
    const wallet=readJSON(p('wallets',id,'credential.private.json')),trust=readJSON(p('state/trust.json'));
    const input=privateInput(wallet,snapshot,request,trust.sourcePublicKey),dir=p('proofs',safeId(request.id));
    const result=await prove(input,dir);
    const file=path.join(dir,'submission.private.json');writeJSON(file,{requestId:request.id,sessionToken:request.sessionToken,...result});console.log(file);return;
  }
  if(command==='verify') {const s=openStore();try{console.log(await verifySubmission(s,readJSON(path.resolve(args[0]))));}finally{s.close();}return;}
  if(command==='revoke') {const s=openStore({writer:true});try{console.log(JSON.stringify(s.change(null,{revoke:true,handle:safeId(args[0])}),null,2));}finally{s.close();}return;}
  if(command==='recover') {
    const id=safeId(args[0]),next=readJSON(path.resolve(args[1])),old=readJSON(p('wallets',id,'credential.private.json'));
    if(next.handle!==id||next.U.client.client_id!==id)throw new Error('Recovery owner mismatch');
    const s=openStore();let envelope;
    try {const row=s.db.prepare("SELECT envelope FROM credentials WHERE handle=? AND status='active'").get(id);if(!row)throw new Error('No active committed credential');envelope=JSON.parse(row.envelope);}finally{s.close();}
    for(const key of ['issuedAt','expiry','verified','revision'])if(next[key]!==envelope.payload[key])throw new Error('Recovery metadata differs from committed credential');
    const wallet={...old,U:next.U,attestation:envelope};checkLocal(wallet,readJSON(p('state/trust.json')).sourcePublicKey);
    const registry=readJSON(p('state/authority/registry.private.json'));registry[id]=next;
    writeJSON(p('state/authority/registry.private.json'),registry);writeJSON(p('wallets',id,'credential.private.json'),wallet);
    console.log('Recovered local distribution from the issuer-committed source attestation.');return;
  }
  if(command==='enroll-source') {
    const next=readJSON(path.resolve(args[0])),id=safeId(next.handle),registry=readJSON(p('state/authority/registry.private.json'));
    if(registry[id]||fs.existsSync(p('wallets',id))||next.U.client.client_id!==id||next.revision!==1)throw new Error('Enrollment requires a new matching handle and revision 1');
    const secret=randomField(),attestation=attest(next,holderCommitment(secret),fs.readFileSync(p('state/authority/source-private.pem'),'utf8'));
    const wallet={schema:'wallet-v1',mode:'SIMULATED_SOURCE',U:next.U,secret,attestation};checkLocal(wallet,readJSON(p('state/trust.json')).sourcePublicKey);
    // Save secret before publishing; a failed enrollment remains a recoverable pending wallet.
    writeJSON(p('wallets',id,'credential.private.json'),wallet);
    const s=openStore({writer:true});try{s.change(attestation);}finally{s.close();}
    registry[id]=next;writeJSON(p('state/authority/registry.private.json'),registry);
    console.log('Source-approved credential appended. Superseded root grace window: 600 seconds.');return;
  }
  if(command==='update') {
    // Authority operation: explicitly load the operator-approved replacement record.
    const id=safeId(args[0]),old=readJSON(p('wallets',id,'credential.private.json'));
    const registry=readJSON(p('state/authority/registry.private.json')),next=readJSON(path.resolve(args[1]));
    if(next.handle!==id||next.U.client.client_id!==id||next.revision!==registry[id].revision+1)throw new Error('Replacement owner/revision mismatch');
    const envelope=attest(next,old.attestation.payload.holderCommitment,fs.readFileSync(p('state/authority/source-private.pem'),'utf8'));
    const wallet={...old,U:next.U,attestation:envelope};checkLocal(wallet,readJSON(p('state/trust.json')).sourcePublicKey);
    const s=openStore({writer:true});try{s.change(envelope);}finally{s.close();}
    registry[id]=next;writeJSON(p('state/authority/registry.private.json'),registry);writeJSON(p('wallets',id,'credential.private.json'),wallet);
    console.log('Credential replaced; all earlier roots invalidated. Obtain a new request and path.');return;
  }
  if(command==='demo') {
    const id=safeId(args[0]||readJSON(p('data/manifest.json')).examples.valid),s=openStore(),a=artifacts();
    try {
      s.pinProfile(a.vkHash);const request=s.createRequest();const snapshot=s.pathFor(id,request.version);
      const wallet=readJSON(p('wallets',id,'credential.private.json'));
      const input=privateInput(wallet,snapshot,request,readJSON(p('state/trust.json')).sourcePublicKey);
      const dir=p('proofs',request.id);writeJSON(path.join(dir,'request.private.json'),request);writeJSON(path.join(dir,'path.private.json'),snapshot);
      const proof=await prove(input,dir),submission={requestId:request.id,sessionToken:request.sessionToken,...proof};
      writeJSON(path.join(dir,'submission.private.json'),submission);
      const start=performance.now(),result=await verifySubmission(s,submission);
      writeJSON(path.join(dir,'result.json'),{...result,verificationMs:performance.now()-start,mode:'SIMULATED_SOURCE'});
      console.log(JSON.stringify({...result,outputDirectory:dir,mode:'SIMULATED_SOURCE'},null,2));
    } finally{s.close();}return;
  }
  console.log(usage);if(command&&command!=='help')process.exitCode=1;
}
main().then(()=>process.exit(process.exitCode||0)).catch(e=>{console.error('ERROR:',e.message);process.exit(1);});
