import fs from 'node:fs';
import path from 'node:path';
import { PROJECT } from '../lib/files.mjs';
const source=path.resolve(process.argv[2]||'/Users/hetianqu/Documents/zk-Verify/node_modules');
const target=path.join(PROJECT,'node_modules');
if(fs.existsSync(target))throw new Error('node_modules already exists; refusing to replace');
for(const [name,version] of Object.entries({snarkjs:'0.7.6',circomlib:'2.0.5',circomlibjs:'0.1.7'})) {
  if(JSON.parse(fs.readFileSync(path.join(source,name,'package.json'),'utf8')).version!==version)throw new Error('Installed version differs: '+name);
}
fs.symlinkSync(source,target,'dir');console.log('Linked existing installed dependencies. No downloads or changes to the original project.');
