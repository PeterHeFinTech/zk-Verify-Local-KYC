import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {parseCSV,CLIENT_FIELDS,TX_FIELDS,digestU} from '../lib/data.mjs';
import {keypair,holderCommitment,randomField,leaf,H,sha,authentic,response,FIELD} from '../lib/crypto.mjs';
import {attest,checkLocal,validateAttestation,ISSUER_ID,POLICY_ID} from '../lib/protocol.mjs';
import {Store} from '../lib/store.mjs';

function record(id='test1') {
  const client=Object.fromEntries(CLIENT_FIELDS.map(f=>[f,'0']));client.client_id=id;client.client_name='Test, Client';
  return {handle:id,U:{client,transactions:[]},issuedAt:1000,expiry:50000,verified:1,revision:1};
}
function credential(source,keys,secret=randomField()) {
  return {secret,U:source.U,attestation:attest(source,holderCommitment(secret),keys.privateKey)};
}
function fold(snapshot){let n=snapshot.leaf;for(let i=0;i<snapshot.pathElements.length;i++)n=snapshot.pathIndices[i]?H([snapshot.pathElements[i],n]):H([n,snapshot.pathElements[i]]);return n;}
test('CSV quoted fields, escaped quote, embedded newline, CRLF, malformed input',()=>{
  const result=parseCSV('a,b\r\n1,"hello, world"\r\n2,"a""b\nc"\r\n');
  assert.equal(result.records[0].b,'hello, world');assert.equal(result.records[1].b,'a"b\nc');
  assert.throws(()=>parseCSV('a,b\n1,"bad'));assert.throws(()=>parseCSV('a,b\n1,2,3'));
});
test('Local authenticity and tampering checks',()=>{
  const keys=keypair(),r=record(),w=credential(r,keys);checkLocal(w,keys.publicKey);
  const changed=structuredClone(w);changed.U.client.client_name='Other';
  assert.throws(()=>checkLocal(changed,keys.publicKey),/Raw U/);
  const changedSecret={...w,secret:randomField()};assert.throws(()=>checkLocal(changedSecret,keys.publicKey),/secret/);
  const expiry=structuredClone(w);expiry.attestation.payload.expiry++;assert.throws(()=>checkLocal(expiry,keys.publicKey),/signature/);
  assert.throws(()=>validateAttestation(w.attestation,keypair().publicKey),/signature/);
  const tx=Object.fromEntries(TX_FIELDS.map(k=>[k,'0']));tx.client_id='wrong';
  assert.throws(()=>digestU({...r.U,transactions:[tx]}),/owner/);
  assert.notEqual(response(w.secret,'1'),response(w.secret,'2'));
});
test('Persistent trees, version windows, request policy, races, revocation and updates',async t=>{
  const directory=fs.mkdtempSync(path.join(os.tmpdir(),'zk-verify-tests-'));
  const source=keypair(),issuer=keypair();let clock=2000;
  const file=path.join(directory,'state.sqlite');
  const options={sourcePublicKey:source.publicKey,rootPrivateKey:issuer.privateKey,clock:()=>clock};
  let s=new Store(file,options);const r1=record('test1'),r2=record('test2'),w1=credential(r1,source),w2=credential(r2,source);
  s.bootstrap([w1.attestation,w2.attestation]);s.pinProfile('pinned-vk');
  const signals=q=>[response(w1.secret,q.context),q.root,String(q.currentTime),String(q.expires),q.context,ISSUER_ID,POLICY_ID];
  const submission=q=>({requestId:q.id,sessionToken:q.sessionToken,proof:{},publicSignals:signals(q)});
  await t.test('all paths fold to the same root and manifests are authenticated',()=>{
    for(const id of ['test1','test2']){const p=s.pathFor(id);assert.equal(fold(p),p.root);assert(authentic(p.manifest,issuer.publicKey));}
    assert.throws(()=>s.pathFor('missing'));
  });
  const old=s.pathFor('test1');
  await t.test('append updates exactly depth+1 nodes and old snapshot remains available',()=>{
    const w3=credential(record('test3'),source);clock=2100;s.change(w3.attestation);
    assert.equal(s.db.prepare('SELECT COUNT(*) AS n FROM nodes WHERE version=2').get().n,13);
    assert.deepEqual(s.pathFor('test1',1),old);
    assert.equal(fold(s.pathFor('test1')),s.latest().root);
    assert(s.acceptedRoot(1,old.root));
  });
  await t.test('retired root expires at exactly ten minutes, latest root does not',()=>{
    clock=2699;assert(s.acceptedRoot(1,old.root));clock=2700;assert.throws(()=>s.acceptedRoot(1,old.root));
    clock=10000;assert(s.acceptedRoot(2,s.latest().root));clock=2200;
  });
  await t.test('wrong owner, wrong key, wrong public signal, noncanonical signal, invalid proof',async()=>{
    const q=s.createRequest(),x=submission(q);
    await assert.rejects(()=>s.verifySubmission({...x,sessionToken:'wrong'},'pinned-vk',async()=>true),/owner/);
    await assert.rejects(()=>s.verifySubmission(x,'other-key',async()=>true),/key/);
    const altered=signals(q);altered[1]='1';await assert.rejects(()=>s.verifySubmission({...x,publicSignals:altered},'pinned-vk',async()=>true),/signals/);
    altered[0]=FIELD.toString();await assert.rejects(()=>s.verifySubmission({...x,publicSignals:altered},'pinned-vk',async()=>true),/field/);
    await assert.rejects(()=>s.verifySubmission(x,'pinned-vk',async()=>false),/Cryptographic/);
    assert.throws(()=>s.pinProfile('other-key'));
  });
  await t.test('request expiry',async()=>{
    const q=s.createRequest();clock=q.expires;
    await assert.rejects(()=>s.verifySubmission(submission(q),'pinned-vk',async()=>true),/expired/);clock=2200;
  });
  await t.test('single-use acceptance and concurrent race',async()=>{
    const q=s.createRequest(),x=submission(q);
    const results=await Promise.allSettled([s.verifySubmission(x,'pinned-vk',async()=>true),s.verifySubmission(x,'pinned-vk',async()=>true)]);
    assert.equal(results.filter(r=>r.status==='fulfilled').length,1);
    await assert.rejects(()=>s.verifySubmission(x,'pinned-vk',async()=>true),/consumed/);
  });
  await t.test('expiry rechecked after cryptographic verification',async()=>{
    const q=s.createRequest();await assert.rejects(()=>s.verifySubmission(submission(q),'pinned-vk',async()=>{clock=q.expires;return true;}),/expired/);clock=2200;
  });
  await t.test('immediate revocation rejects even an already generated old-root proof',async()=>{
    const q=s.createRequest();s.change(null,{revoke:true,handle:'test2'});
    await assert.rejects(()=>s.verifySubmission(submission(q),'pinned-vk',async()=>true),/Root/);
    assert.throws(()=>s.pathFor('test2'),/absent/);
  });
  await t.test('source-authorized replacement and revision anti-replay',()=>{
    const newRecord={...r1,U:structuredClone(r1.U),revision:2};newRecord.U.client.client_name='Updated';
    const newWallet=credential(newRecord,source,w1.secret);const before=s.latest();s.change(newWallet.attestation);
    assert.equal(s.pathFor('test1').leaf,leaf(newWallet.attestation.payload));
    assert.throws(()=>s.acceptedRoot(before.version,before.root));assert.throws(()=>s.change(w1.attestation),/revision/);
  });
  await t.test('restart retains roots and consumed request state',()=>{
    const root=s.latest().root;s.close();s=new Store(file,options);assert.equal(s.latest().root,root);
    assert.equal(s.db.prepare("SELECT COUNT(*) AS n FROM requests WHERE status='accepted'").get().n,1);
  });
  s.close();
});
