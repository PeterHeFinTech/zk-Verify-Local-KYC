import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { PROJECT, writeJSON } from '../lib/files.mjs';
process.chdir(PROJECT);
const dir=path.join(PROJECT,'build');fs.mkdirSync(dir,{recursive:true,mode:0o700});
if(fs.existsSync(path.join(dir,'manifest.json')))throw new Error('Setup exists. Do not overwrite keys used by active proofs. Use a new project/profile for a new setup.');
function run(cmd,args){const r=spawnSync(cmd,args,{stdio:'inherit',cwd:PROJECT});if(r.status!==0)throw new Error('Setup command failed: '+cmd);}
const snark=args=>run(process.execPath,[path.join(PROJECT,'node_modules/snarkjs/build/cli.cjs'),...args]);
console.log('LOCAL SINGLE-OPERATOR DEVELOPMENT SETUP. Not a production ceremony.');
run(process.env.CIRCOM||'circom',['circuits/kyc.circom','--r1cs','--wasm','--sym','-l','node_modules','-o','build']);
// Generated calculator is CommonJS, whereas the application uses ES modules.
writeJSON(path.join(dir,'kyc_js/package.json'),{type:'commonjs'});
snark(['r1cs','info','build/kyc.r1cs']);
snark(['powersoftau','new','bn128','14','build/pot0.ptau']);
snark(['powersoftau','contribute','build/pot0.ptau','build/pot1.ptau','--name=local-development',`-e=${randomBytes(64).toString('hex')}`]);
snark(['powersoftau','prepare','phase2','build/pot1.ptau','build/pot-final.ptau']);
snark(['groth16','setup','build/kyc.r1cs','build/pot-final.ptau','build/initial.zkey']);
snark(['zkey','contribute','build/initial.zkey','build/kyc.zkey','--name=local-development',`-e=${randomBytes(64).toString('hex')}`]);
snark(['zkey','verify','build/kyc.r1cs','build/pot-final.ptau','build/kyc.zkey']);
snark(['zkey','export','verificationkey','build/kyc.zkey','build/verification_key.json']);
const {sha}=await import('../lib/crypto.mjs');
writeJSON(path.join(dir,'manifest.json'),{mode:'DEVELOPMENT_SINGLE_OPERATOR_SETUP',depth:12,publicSignals:['response','issuerRoot','currentTime','validUntil','context','issuerId','policyId'],
  circuitSha256:sha(fs.readFileSync('circuits/kyc.circom')),r1csSha256:sha(fs.readFileSync('build/kyc.r1cs')),
  wasmSha256:sha(fs.readFileSync('build/kyc_js/kyc.wasm')),provingKeySha256:sha(fs.readFileSync('build/kyc.zkey')),verificationKeySha256:sha(fs.readFileSync('build/verification_key.json'))});
console.log('Setup and zkey verification complete.');
