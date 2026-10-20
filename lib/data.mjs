import fs from 'node:fs';
import path from 'node:path';
import { H, hashField, sha } from './crypto.mjs';

export const CLIENT_FIELDS = ['client_id','client_name','client_type','sector','sector_risk','country','pep_flag','sanctions_flag','fatf_country_flag','ofac_country_flag','sectoral_sanctions_flag','ownership_opacity_score'];
export const TX_FIELDS = ['transaction_id','client_id','amount','transaction_type','timestamp','client_country','counterparty_country','ofac_match_flag','fatf_country_flag','structuring_pattern_flag','rapid_movement_flag','trade_mispricing_flag'];
// RFC4180-style parser: quoted commas, escaped quotes, CRLF, embedded newlines.
export function parseCSV(text) {
  text=text.replace(/^\uFEFF/,'');
  const rows=[]; let row=[], cell='', quoted=false, closed=false;
  for(let i=0;i<text.length;i++) {
    const c=text[i];
    if(quoted) {
      if(c==='"' && text[i+1]==='"'){cell+='"';i++;}
      else if(c==='"'){quoted=false;closed=true;} else cell+=c;
    } else if(c==='"') {
      if(cell!=='' || closed) throw new Error('Malformed CSV quote');
      quoted=true;
    } else if(c===','){row.push(cell);cell='';closed=false;}
    else if(c==='\n'||c==='\r') {
      if(c==='\r'&&text[i+1]==='\n')i++;
      row.push(cell); if(row.some(v=>v!=='')) rows.push(row);
      row=[];cell='';closed=false;
    } else {if(closed)throw new Error('Unexpected text after CSV quote');cell+=c;}
  }
  if(quoted)throw new Error('Unclosed CSV quote');
  if(cell!==''||row.length||closed){row.push(cell);rows.push(row);}
  const headers=rows.shift();
  if(!headers || new Set(headers).size!==headers.length)throw new Error('Missing/duplicate CSV headers');
  return {headers,records:rows.map((r,i)=>{
    if(r.length!==headers.length)throw new Error(`CSV column mismatch at row ${i+2}`);
    return Object.fromEntries(headers.map((h,j)=>[h,r[j]]));
  })};
}
export function encodeU(U) {
  if(!U || !Array.isArray(U.transactions))throw new Error('Missing transactions');
  if(Object.keys(U.client).sort().join('|')!==[...CLIENT_FIELDS].sort().join('|'))throw new Error('Unexpected client schema');
  for(const f of CLIENT_FIELDS)if(typeof U.client[f]!=='string')throw new Error('Client fields must be source strings');
  const transactions=[...U.transactions].sort((a,b)=>a.transaction_id.localeCompare(b.transaction_id));
  if(new Set(transactions.map(t=>t.transaction_id)).size!==transactions.length)throw new Error('Duplicate transaction');
  for(const t of transactions) {
    if(t.client_id!==U.client.client_id)throw new Error('Transaction owner mismatch');
    if(Object.keys(t).sort().join('|')!==[...TX_FIELDS].sort().join('|'))throw new Error('Unexpected transaction schema');
    for(const f of TX_FIELDS)if(typeof t[f]!=='string')throw new Error('Transaction fields must be source strings');
  }
  // String normalization is deliberately NOT performed: bind exact decoded CSV values.
  return [...CLIENT_FIELDS.map(f=>hashField(['client-field-v1',f,U.client[f]])),hashField(['transactions-v1',transactions])];
}
export const digestU = U => H(encodeU(U));
export function loadArchive(dir) {
  const names=['clients_with_fatf_ofac.csv','transactions_with_fatf_ofac.csv'];
  const sources=names.map(name=>{const bytes=fs.readFileSync(path.join(dir,name));return {name,bytes,parsed:parseCSV(bytes.toString('utf8'))};});
  for(const [i,fields] of [CLIENT_FIELDS,TX_FIELDS].entries())if(sources[i].parsed.headers.join('|')!==fields.join('|'))throw new Error('Source header mismatch');
  const clients=sources[0].parsed.records, transactions=sources[1].parsed.records;
  const grouped=new Map(clients.map(c=>[c.client_id,[]]));
  if(grouped.size!==clients.length)throw new Error('Duplicate client ID');
  if(new Set(transactions.map(t=>t.transaction_id)).size!==transactions.length)throw new Error('Duplicate transaction ID');
  for(const t of transactions){if(!grouped.has(t.client_id))throw new Error('Orphan transaction');grouped.get(t.client_id).push(t);}
  const counts={};
  for(const [i,s] of sources.entries()) {
    counts[s.name]={};
    for(const f of s.parsed.headers.filter(f=>f.endsWith('_flag'))) {
      const d={}; for(const r of s.parsed.records){if(!['0','1'].includes(r[f]))throw new Error(`Invalid binary ${f}`);d[r[f]]=(d[r[f]]||0)+1;}counts[s.name][f]=d;
    }
  }
  return {users:clients.map(client=>({client,transactions:grouped.get(client.client_id)})), manifest:{sources:sources.map(s=>({name:s.name,sha256:sha(s.bytes),rows:s.parsed.records.length})),counts,orphanTransactions:0,provenance:'User-supplied CSV; real-world identity and sanctions accuracy NOT established'}};
}
