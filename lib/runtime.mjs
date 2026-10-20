import fs from 'node:fs';
import path from 'node:path';
import { groth16 } from 'snarkjs';
import { createRequire } from 'node:module';
import { PROJECT, readJSON, writeJSON } from './files.mjs';
import { sha } from './crypto.mjs';
import { Store } from './store.mjs';

export const base = process.env.ZK_STATE_DIR ? path.resolve(process.env.ZK_STATE_DIR) : PROJECT;
export const p=(...parts)=>path.join(base,...parts);
const require=createRequire(import.meta.url);
export async function calculateWitness(input,wasmFile) {
  const factory=require(path.join(path.dirname(wasmFile),'witness_calculator.js'));
  const calculator=await factory(fs.readFileSync(wasmFile));
  return calculator.calculateWTNSBin(input,0);
}
export function openStore({writer=false,clock}={}) {
  const keys=readJSON(p('state/trust.json'));
  return new Store(p('state/issuer.sqlite'),{sourcePublicKey:keys.sourcePublicKey,
    rootPrivateKey:writer?fs.readFileSync(p('state/issuer/root-private.pem'),'utf8'):undefined,clock});
}
export function artifacts() {
  const dir=path.join(PROJECT,'build'),manifest=readJSON(path.join(dir,'manifest.json'));
  const files={wasm:'kyc_js/kyc.wasm',key:'kyc.zkey',vk:'verification_key.json'};
  for(const [name,file] of Object.entries(files)) {
    const expected=manifest[{wasm:'wasmSha256',key:'provingKeySha256',vk:'verificationKeySha256'}[name]];
    if(sha(fs.readFileSync(path.join(dir,file)))!==expected)throw new Error('Artifact integrity mismatch: '+name);
  }
  if(sha(fs.readFileSync(path.join(PROJECT,'circuits/kyc.circom')))!==manifest.circuitSha256)throw new Error('Circuit changed after setup');
  return {wasm:path.join(dir,files.wasm),key:path.join(dir,files.key),vk:readJSON(path.join(dir,files.vk)),vkHash:manifest.verificationKeySha256};
}
export async function prove(input,outputDir) {
  const a=artifacts();fs.mkdirSync(outputDir,{recursive:true,mode:0o700});
  writeJSON(path.join(outputDir,'input.private.json'),input);
  const start=performance.now();
  const witness=await calculateWitness(input,a.wasm);
  fs.writeFileSync(path.join(outputDir,'witness.wtns'),witness,{mode:0o600});
  const witnessMs=performance.now()-start,proofStart=performance.now();
  const result=await groth16.prove(a.key,path.join(outputDir,'witness.wtns'));
  writeJSON(path.join(outputDir,'proof.json'),result.proof);
  writeJSON(path.join(outputDir,'public.json'),result.publicSignals);
  writeJSON(path.join(outputDir,'metrics.json'),{witnessMs,proveMs:performance.now()-proofStart,proofBytes:Buffer.byteLength(JSON.stringify(result.proof))});
  return result;
}
export async function verifySubmission(store,submission) {
  const a=artifacts();return store.verifySubmission(submission,a.vkHash,(proof,signals)=>groth16.verify(a.vk,signals,proof));
}
