import { createHash, randomBytes, generateKeyPairSync, sign, verify, timingSafeEqual } from 'node:crypto';
import { buildPoseidon } from 'circomlibjs';

export const FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
export const DEPTH = 12;
export const DOM = { holder: '202610201', leaf: '202610202', response: '202610203' };
const poseidon = await buildPoseidon();
export function field(v) {
  if (typeof v !== 'string' || !/^(0|[1-9][0-9]*)$/.test(v) || BigInt(v) >= FIELD) throw new Error('Non-canonical field value');
  return v;
}
export const H = values => poseidon.F.toObject(poseidon(values.map(v => BigInt(field(String(v)))))).toString();
export const sha = bytes => createHash('sha256').update(bytes).digest('hex');
export const canonical = value => {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
  return '{' + Object.keys(value).sort().map(k => JSON.stringify(k) + ':' + canonical(value[k])).join(',') + '}';
};
export const hashField = value => (BigInt('0x' + sha(canonical(value))) % FIELD).toString();
export const randomField = () => (BigInt('0x' + randomBytes(31).toString('hex')) + 1n).toString();
export const randomToken = () => randomBytes(32).toString('hex');
export const holderCommitment = secret => H([DOM.holder, secret]);
export const leaf = a => H([DOM.leaf, a.uDigest, a.holderCommitment, a.issuedAt, a.expiry, a.verified, a.issuerId, a.policyId]);
export const response = (secret, context) => H([DOM.response, secret, context]);
export function keypair() {
  const k = generateKeyPairSync('ed25519');
  return { privateKey: k.privateKey.export({type:'pkcs8',format:'pem'}), publicKey:k.publicKey.export({type:'spki',format:'pem'}) };
}
export const signed = (payload, key) => ({payload, signature:sign(null, Buffer.from(canonical(payload)), key).toString('base64')});
export function authentic(envelope, key) {
  try { return verify(null, Buffer.from(canonical(envelope.payload)), key, Buffer.from(envelope.signature,'base64')); } catch { return false; }
}
export function sameToken(token, digest) {
  if (typeof token !== 'string' || typeof digest !== 'string') return false;
  const a = Buffer.from(sha(token)), b = Buffer.from(digest);
  return a.length === b.length && timingSafeEqual(a,b);
}
