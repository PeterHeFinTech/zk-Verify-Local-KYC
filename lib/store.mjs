import fs from 'node:fs';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { H, DEPTH, leaf, hashField, randomToken, sha, sameToken, signed, field } from './crypto.mjs';
import { validateAttestation, ISSUER_ID, POLICY_ID } from './protocol.mjs';

export class Store {
  constructor(file,{sourcePublicKey,rootPrivateKey,clock=()=>Math.floor(Date.now()/1000)}={}) {
    fs.mkdirSync(path.dirname(file),{recursive:true,mode:0o700});
    this.db=new DatabaseSync(file);fs.chmodSync(file,0o600);
    this.sourcePublicKey=sourcePublicKey;this.rootPrivateKey=rootPrivateKey;this.clock=clock;
    this.db.exec(`PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;
      CREATE TABLE IF NOT EXISTS nodes(level INTEGER,idx INTEGER,version INTEGER,value TEXT,PRIMARY KEY(level,idx,version));
      CREATE TABLE IF NOT EXISTS roots(version INTEGER PRIMARY KEY,root TEXT,published INTEGER,retired INTEGER,invalid INTEGER DEFAULT 0,manifest TEXT);
      CREATE TABLE IF NOT EXISTS credentials(handle TEXT PRIMARY KEY,idx INTEGER UNIQUE,envelope TEXT,status TEXT);
      CREATE TABLE IF NOT EXISTS requests(id TEXT PRIMARY KEY,tokenHash TEXT,body TEXT,expires INTEGER,status TEXT);
      CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY,time INTEGER,event TEXT,object TEXT);
      CREATE TABLE IF NOT EXISTS config(key TEXT PRIMARY KEY,value TEXT);`);
    this.zeros=['0'];for(let i=0;i<DEPTH;i++)this.zeros.push(H([this.zeros[i],this.zeros[i]]));
  }
  close(){this.db.close();}
  atomic(fn){this.db.exec('BEGIN IMMEDIATE');try{const v=fn();this.db.exec('COMMIT');return v;}catch(e){this.db.exec('ROLLBACK');throw e;}}
  audit(event,object){this.db.prepare('INSERT INTO audit(time,event,object) VALUES(?,?,?)').run(this.clock(),event,String(object));}
  latest(){return this.db.prepare('SELECT * FROM roots ORDER BY version DESC LIMIT 1').get();}
  node(level,idx,version){return this.db.prepare('SELECT value FROM nodes WHERE level=? AND idx=? AND version<=? ORDER BY version DESC LIMIT 1').get(level,idx,version)?.value??this.zeros[level];}
  setNode(level,idx,version,value){this.db.prepare('INSERT OR REPLACE INTO nodes VALUES(?,?,?,?)').run(level,idx,version,value);}
  publish(version,root,reason) {
    const time=this.clock();
    this.db.prepare('UPDATE roots SET retired=? WHERE retired IS NULL').run(time);
    const payload={treeId:'local-kyc-depth12',issuerId:ISSUER_ID,policyId:POLICY_ID,version,root,published:time,reason};
    const manifest=signed(payload,this.rootPrivateKey);
    this.db.prepare('INSERT INTO roots(version,root,published,manifest) VALUES(?,?,?,?)').run(version,root,time,JSON.stringify(manifest));
    this.audit('root-published',version);return manifest;
  }
  bootstrap(envelopes) {
    if(envelopes.length===0||envelopes.length>2**DEPTH)throw new Error('Tree capacity exceeded/empty batch');
    const entries=envelopes.map(e=>({e,a:validateAttestation(e,this.sourcePublicKey)}));
    if(new Set(entries.map(x=>x.a.handle)).size!==entries.length)throw new Error('Duplicate credential');
    return this.atomic(()=>{
      if(this.latest())throw new Error('Already initialized');
      let values=Array(2**DEPTH).fill('0');
      entries.forEach(({e,a},i)=>{
        if(a.verified!==1)throw new Error('Unverified source record');
        values[i]=leaf(a);
        this.db.prepare('INSERT INTO credentials VALUES(?,?,?,?)').run(a.handle,i,JSON.stringify(e),'active');
      });
      for(let level=0;level<=DEPTH;level++){
        values.forEach((v,i)=>this.setNode(level,i,1,v));
        if(level<DEPTH)values=Array.from({length:values.length/2},(_,i)=>H([values[2*i],values[2*i+1]]));
      }
      return this.publish(1,values[0],'initial-batch');
    });
  }
  change(envelope,{revoke=false,handle=null,invalidateOld=true}={}) {
    const a=revoke?null:validateAttestation(envelope,this.sourcePublicKey);
    if(a&&a.verified!==1)throw new Error('Unverified source record');
    return this.atomic(()=>{
      const latest=this.latest();if(!latest)throw new Error('Tree not initialized');
      const id=revoke?handle:a.handle;
      const existing=this.db.prepare('SELECT * FROM credentials WHERE handle=?').get(id);
      if(revoke&&!existing)throw new Error('Unknown credential');
      if(existing&&!revoke&&a.revision<=JSON.parse(existing.envelope).payload.revision)throw new Error('Stale credential revision');
      const idx=existing?.idx??this.db.prepare('SELECT COALESCE(MAX(idx),-1)+1 AS n FROM credentials').get().n;
      if(idx>=2**DEPTH)throw new Error('Tree full');
      if(existing&&!revoke&&!invalidateOld)throw new Error('Replacement requires historical-root invalidation');
      let position=idx,value=revoke?'0':leaf(a);const version=latest.version+1;
      this.setNode(0,position,version,value);
      for(let level=0;level<DEPTH;level++){
        const sibling=this.node(level,position^1,version);
        value=position%2?H([sibling,value]):H([value,sibling]);position=Math.floor(position/2);
        this.setNode(level+1,position,version,value);
      }
      if(revoke)this.db.prepare("UPDATE credentials SET status='revoked' WHERE handle=?").run(id);
      else this.db.prepare('INSERT INTO credentials VALUES(?,?,?,?) ON CONFLICT(handle) DO UPDATE SET envelope=excluded.envelope,status=excluded.status').run(id,idx,JSON.stringify(envelope),'active');
      // Conservative immediate revocation: invalidates ALL earlier roots for this tree.
      if(revoke||(existing&&invalidateOld))this.db.prepare('UPDATE roots SET invalid=1').run();
      this.audit(revoke?'credential-revoked':existing?'credential-updated':'credential-added',id);
      return this.publish(version,value,revoke?'revoke':existing?'replace':'append');
    });
  }
  acceptedRoot(version,root) {
    const r=this.db.prepare('SELECT * FROM roots WHERE version=?').get(version);
    if(!r||r.root!==root||r.invalid||r.published>this.clock()||(r.retired!==null&&this.clock()>=r.retired+600))throw new Error('Root not accepted');
    return r;
  }
  pathFor(handle,version=this.latest()?.version) {
    const r=this.db.prepare('SELECT * FROM roots WHERE version=?').get(version);if(!r)throw new Error('Unknown root version');
    const c=this.db.prepare('SELECT * FROM credentials WHERE handle=?').get(handle);if(!c)throw new Error('Unknown credential');
    let idx=c.idx;const pathElements=[],pathIndices=[];
    const value=this.node(0,idx,version);if(value==='0')throw new Error('Credential absent in snapshot');
    for(let level=0;level<DEPTH;level++){pathElements.push(this.node(level,idx^1,version));pathIndices.push(idx%2);idx=Math.floor(idx/2);}
    return {treeId:'local-kyc-depth12',version,root:r.root,leaf:value,pathElements,pathIndices,manifest:JSON.parse(r.manifest)};
  }
  pinProfile(hash) {
    const old=this.db.prepare("SELECT value FROM config WHERE key='vkHash'").get();
    if(old&&old.value!==hash)throw new Error('Verifier key changed; use a new state directory/profile');
    this.db.prepare("INSERT OR IGNORE INTO config VALUES('vkHash',?)").run(hash);
  }
  createRequest({audience='local-demo-verifier',version=this.latest()?.version}={}) {
    const vkHash=this.db.prepare("SELECT value FROM config WHERE key='vkHash'").get()?.value;if(!vkHash)throw new Error('Verifier profile not pinned');
    const r=this.db.prepare('SELECT * FROM roots WHERE version=?').get(version);if(!r)throw new Error('Unknown root');this.acceptedRoot(version,r.root);
    if(typeof audience!=='string'||audience.length<1||audience.length>200)throw new Error('Invalid audience');
    const id=randomToken(),token=randomToken(),currentTime=this.clock();
    const body={id,audience,version,root:r.root,currentTime,expires:currentTime+300,vkHash,issuerId:ISSUER_ID,policyId:POLICY_ID};
    body.context=hashField(['request-v1',body]);
    this.db.prepare('INSERT INTO requests VALUES(?,?,?,?,?)').run(id,sha(token),JSON.stringify(body),body.expires,'pending');
    this.audit('request-created',id);return {...body,sessionToken:token};
  }
  checkSubmission(id,token,signals,vkHash) {
    const r=this.db.prepare('SELECT * FROM requests WHERE id=?').get(id);
    if(!r||!sameToken(token,r.tokenHash))throw new Error('Request owner authentication failed');
    if(r.status!=='pending')throw new Error('Request already consumed');
    if(this.clock()>=r.expires)throw new Error('Request expired');
    const q=JSON.parse(r.body);this.acceptedRoot(q.version,q.root);
    const pinned=this.db.prepare("SELECT value FROM config WHERE key='vkHash'").get()?.value;
    if(vkHash!==q.vkHash||vkHash!==pinned)throw new Error('Verification key mismatch');
    if(!Array.isArray(signals)||signals.length!==7)throw new Error('Wrong public signal count');
    signals.forEach(field);
    const expected=[q.root,String(q.currentTime),String(q.expires),q.context,ISSUER_ID,POLICY_ID];
    if(signals.slice(1).some((v,i)=>v!==expected[i]))throw new Error('Public signals violate request policy');
    return q;
  }
  async verifySubmission({requestId,sessionToken,proof,publicSignals},vkHash,verifyProof) {
    this.checkSubmission(requestId,sessionToken,publicSignals,vkHash);
    if(!await verifyProof(proof,publicSignals))throw new Error('Cryptographic verification failed');
    return this.atomic(()=>{
      // Recheck after expensive asynchronous verification: expiry, revocation, replay race.
      this.checkSubmission(requestId,sessionToken,publicSignals,vkHash);
      const result=this.db.prepare("UPDATE requests SET status='accepted' WHERE id=? AND status='pending'").run(requestId);
      if(result.changes!==1)throw new Error('Concurrent acceptance');
      this.audit('proof-accepted',requestId);return {accepted:true,requestId};
    });
  }
  summary(){return {credentials:this.db.prepare('SELECT status,COUNT(*) AS count FROM credentials GROUP BY status').all(),root:this.latest(),requests:this.db.prepare('SELECT status,COUNT(*) AS count FROM requests GROUP BY status').all()};}
}
