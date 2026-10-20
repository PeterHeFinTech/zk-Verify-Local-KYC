import { authentic, signed, holderCommitment, leaf, field } from './crypto.mjs';
import { digestU, encodeU } from './data.mjs';

export const ISSUER_ID='1';
export const POLICY_ID='20261020';
const KEYS=['schema','mode','handle','uDigest','holderCommitment','issuedAt','expiry','verified','issuerId','policyId','revision'];
export function validateAttestation(envelope, sourcePublicKey) {
  if(!authentic(envelope,sourcePublicKey))throw new Error('Source signature invalid');
  const a=envelope.payload;
  if(Object.keys(a).sort().join('|')!==[...KEYS].sort().join('|'))throw new Error('Attestation schema mismatch');
  if(a.schema!=='source-attestation-v1'||a.mode!=='SIMULATED_SOURCE')throw new Error('Unsupported source mode');
  if(a.issuerId!==ISSUER_ID||a.policyId!==POLICY_ID)throw new Error('Issuer/policy mismatch');
  if(!/^[A-Za-z0-9_-]{1,100}$/.test(a.handle))throw new Error('Invalid handle');
  field(a.uDigest);field(a.holderCommitment);
  for(const k of ['issuedAt','expiry','revision'])if(!Number.isSafeInteger(a[k])||a[k]<0||a[k]>=2**32)throw new Error('Invalid timestamp/revision');
  if(a.expiry<a.issuedAt||a.revision<1||![0,1].includes(a.verified))throw new Error('Invalid attestation attributes');
  return a;
}
// Called in the SOURCE trust domain. Never sign an arbitrary client-supplied digest.
// sourceRecord is loaded by the authority from its pinned registry, not the wallet.
export function attest(sourceRecord, commitment, privateKey) {
  field(commitment);
  const payload={schema:'source-attestation-v1',mode:'SIMULATED_SOURCE',handle:sourceRecord.handle,
    uDigest:digestU(sourceRecord.U),holderCommitment:commitment,
    issuedAt:sourceRecord.issuedAt,expiry:sourceRecord.expiry,verified:sourceRecord.verified,
    issuerId:ISSUER_ID,policyId:POLICY_ID,revision:sourceRecord.revision};
  return signed(payload,privateKey);
}
// Local checker: no network; secret and raw U stay in the holder process.
export function checkLocal(wallet, sourcePublicKey) {
  const a=validateAttestation(wallet.attestation,sourcePublicKey);
  if(a.uDigest!==digestU(wallet.U))throw new Error('Raw U differs from authenticated source');
  if(a.holderCommitment!==holderCommitment(wallet.secret))throw new Error('Holder secret mismatch');
  return {leaf:leaf(a),handle:a.handle,revision:a.revision};
}
export function privateInput(wallet, snapshot, request, sourcePublicKey) {
  const checked=checkLocal(wallet,sourcePublicKey),a=wallet.attestation.payload;
  if(checked.leaf!==snapshot.leaf||snapshot.root!==request.root||snapshot.version!==request.version)throw new Error('Snapshot/credential mismatch');
  return {u:encodeU(wallet.U),secret:wallet.secret,verified:String(a.verified),issuedAt:String(a.issuedAt),expiry:String(a.expiry),
    pathElements:snapshot.pathElements,pathIndices:snapshot.pathIndices.map(String),
    issuerRoot:request.root,currentTime:String(request.currentTime),validUntil:String(request.expires),context:request.context,issuerId:ISSUER_ID,policyId:POLICY_ID};
}
