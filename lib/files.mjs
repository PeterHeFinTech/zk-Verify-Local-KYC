import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomBytes } from 'node:crypto';
export const PROJECT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
export function writeJSON(file, value) {
  fs.mkdirSync(path.dirname(file), {recursive:true,mode:0o700});
  const temp = file + '.' + randomBytes(6).toString('hex') + '.tmp';
  fs.writeFileSync(temp, JSON.stringify(value,null,2)+'\n', {mode:0o600,flag:'wx'});
  fs.renameSync(temp,file);
}
export const readJSON = file => JSON.parse(fs.readFileSync(file,'utf8'));
export function safeId(value) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]{1,100}$/.test(value)) throw new Error('Invalid identifier');
  return value;
}
export const nowSeconds = () => Math.floor(Date.now()/1000);
