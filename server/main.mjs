import http from 'node:http';
import fs from 'node:fs';
import { randomToken, sha, sameToken } from '../lib/crypto.mjs';
import { p,openStore,artifacts,verifySubmission } from '../lib/runtime.mjs';
import { writeJSON,readJSON } from '../lib/files.mjs';
// Loopback verifier adapter only. Authority keys/wallets are NOT served by any route.
const tokenFile=p('state/verifier-access.private.json');
if(!fs.existsSync(tokenFile))writeJSON(tokenFile,{token:randomToken()});
const tokenHash=sha(readJSON(tokenFile).token),store=openStore(),a=artifacts();store.pinProfile(a.vkHash);
const server=http.createServer(async(req,res)=>{
  res.setHeader('Content-Type','application/json');res.setHeader('Cache-Control','no-store');res.setHeader('X-Content-Type-Options','nosniff');
  const reply=(code,value)=>{res.statusCode=code;res.end(JSON.stringify(value));};
  if(req.headers.origin)return reply(403,{error:'Browser cross-origin requests disabled'});
  if(!sameToken((req.headers.authorization||'').replace(/^Bearer /,''),tokenHash))return reply(401,{error:'Verifier access token required'});
  try {
    if(req.method==='GET'&&req.url==='/status')return reply(200,store.summary());
    let bytes=0,parts=[];
    for await(const part of req){bytes+=part.length;if(bytes>65536){reply(413,{error:'Request too large'});return;}parts.push(part);}
    const body=JSON.parse(Buffer.concat(parts).toString()||'{}');
    if(req.method==='POST'&&req.url==='/requests')return reply(201,store.createRequest({audience:'loopback-verifier'}));
    if(req.method==='POST'&&req.url==='/verify')return reply(200,await verifySubmission(store,body));
    return reply(404,{error:'Not found'});
  }catch(e){reply(400,{error:e.message});}
});
server.requestTimeout=30000;server.headersTimeout=10000;
server.on('error',error=>{console.error('Verifier cannot start:',error.code||error.message);store.close();process.exit(1);});
server.listen(Number(process.env.PORT??8788),'127.0.0.1',()=>console.log(`Loopback verifier listening on 127.0.0.1:${server.address().port}. Token is stored in ${tokenFile}; do not share it.`));
for(const sig of ['SIGINT','SIGTERM'])process.on(sig,()=>server.close(()=>{store.close();process.exit(0);}));
