import test from 'node:test';
import assert from 'node:assert/strict';
import { registerHooks } from 'node:module';
import { createPrivateKey, sign, verify, createPublicKey } from 'node:crypto';
import bs58 from 'bs58';
const assetUrl = new URL('../node_modules/bulk-keychain-wasm/bulk_keychain_wasm_bg.wasm', import.meta.url).href;
registerHooks({
  resolve(specifier, context, next) {
    if (specifier === 'bulk-keychain-wasm/bulk_keychain_wasm_bg.wasm?url') return { url: 'test:create-wasm', shortCircuit: true };
    return next(specifier, context);
  },
  load(url, context, next) {
    if (url === 'test:create-wasm') return { format: 'module', source: `import {readFileSync} from 'node:fs'; export default readFileSync(new URL(${JSON.stringify(assetUrl)}));`, shortCircuit: true };
    return next(url, context);
  },
});
const { loadSdk } = await import('../lib/crypto.ts');
const { subaccountName, prepareSubaccount, finalizeSubaccount, assertCreateRequest, creationResult, exportSubaccountRequest, importSubaccountRequest, submitSubaccount, verifySubaccount } = await import('../lib/subaccounts.ts');
const sdk = await loadSdk();
const pair = new sdk.WasmKeypair(); const owner = pair.pubkey;
const signer = createPrivateKey({key:Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'),pair.secretKey()]),format:'der',type:'pkcs8'}); pair.free();
const childPair = new sdk.WasmKeypair(); const child = childPair.pubkey; childPair.free();
const nonce = '1788816000000000123';
async function signed(network = 'testnet') {
  const prepared = await prepareSubaccount(network, owner, 'desk-1', nonce);
  try {
    return { format:'bulk-subaccount-request-v1',network,owner,name:'desk-1',request:await finalizeSubaccount(prepared,new Uint8Array(sign(null,prepared.messageBytes,signer)),owner,'desk-1'),address:null };
  } finally {prepared.free();}
}
const receipt = {status:'ok',response:{type:'order',data:{statuses:[{createSubAccount:{master:owner,sub:child,name:'desk-1',margin:0}}]}}};
test('creation validates names before preparing any wallet request', async () => {
  for (const name of ['a','desk-1_A','a'.repeat(32)]) assert.equal(subaccountName(name),name);
  for (const name of ['', 'a'.repeat(33), ' a', 'a ', 'a b', 'бот', 'a\n', '<script>', 'x/y']) {
    assert.throws(()=>subaccountName(name));
    await assert.rejects(()=>prepareSubaccount('testnet',owner,name));
  }
});
test('both networks use the official unfunded create action and canonical bytes', async () => {
  for (const network of ['testnet','mainnet']) {
    const value = await signed(network);
    assert.deepEqual(value.request.actions,[{createSubAccount:{name:'desk-1'}}]);
    const u64 = value => {const b=Buffer.alloc(8);b.writeBigUInt64LE(BigInt(value));return b;};
    const discriminant=Buffer.alloc(4);discriminant.writeUInt32LE(27);
    const expected=Buffer.concat([u64(1),discriminant,u64(6),Buffer.from('desk-1'),Buffer.from([0]),u64(nonce),Buffer.from(bs58.decode(owner)),Buffer.from([network==='mainnet'?1:2])]);
    assert.ok(verify(null,expected,createPublicKey(signer),bs58.decode(value.request.signature)));
    assert.equal(value.request.account,owner); assert.equal(value.request.signer,owner);
  }
});
test('no margin, extra action, or different owner can enter a creation request', async () => {
  const {request}=await signed();
  for (const tx of [
    {...request,account:child}, {...request,signer:child}, {...request,extra:true},
    {...request,actions:[{createSubAccount:{name:'other'}}]},
    {...request,actions:[...request.actions,{createSubAccount:{name:'another'}}]},
    ...[{marginAmount:0},{marginAmount:100},{marginSymbol:'USDC'},{x:true}].map(fields=>({...request,actions:[{createSubAccount:{name:'desk-1',...fields}}]})),
    {...request,actions:[{createSubAccount:{name:'desk-1'},transfer:{}}]},
  ]) assert.throws(()=>assertCreateRequest(tx,owner,'desk-1'));
  for (const badNonce of ['0','01', '0'.repeat(17000)+nonce,'18446744073709551616',1,-1,'1e10']) assert.throws(()=>assertCreateRequest({...request,nonce:badNonce},owner,'desk-1'));
});
test('signed recovery import verifies network, name, nonce, owner, signature and schema', async () => {
  const value=await signed();
  assert.deepEqual(await importSubaccountRequest(exportSubaccountRequest(value)),value);
  for (const forged of [
    {...value,network:'mainnet'}, {...value,network:'custom'}, {...value,owner:child},
    {...value,name:'other',request:{...value.request,actions:[{createSubAccount:{name:'other'}}]}},
    {...value,request:{...value.request,nonce:'1'}},
    {...value,request:{...value.request,signature:bs58.encode(new Uint8Array(64))}},
    {...value,address:owner}, {...value,confirmed:true},
  ]) await assert.rejects(()=>importSubaccountRequest(JSON.stringify(forged)));
  await assert.rejects(()=>importSubaccountRequest(' '.repeat(8193)));
});
test('foreign or malformed creation responses never supply a selected address', async () => {
  const value=await signed();
  assert.equal(creationResult(receipt,value),child);
  for (const body of [{status:'error'}, {status:'ok'}, {...receipt,response:{...receipt.response,type:'other'}},
    ...[{master:child},{name:'wrong'},{sub:owner},{sub:'invalid'},{margin:1},{margin:'0'}].map(change=>({status:'ok',response:{type:'order',data:{statuses:[{createSubAccount:{...receipt.response.data.statuses[0].createSubAccount,...change}}]}}})),
    {status:'ok',response:{type:'order',data:{statuses:[...receipt.response.data.statuses,...receipt.response.data.statuses]}}},
    {status:'ok',response:{type:'order',data:{statuses:[{createSubAccountFailed:{message:'duplicate name'}}]}}},
  ]) assert.equal(creationResult(body,value),null);
});
test('timeout retry sends exactly the saved nonce and signature with no new wallet operation', async () => {
  const value=await signed('mainnet'); const calls=[];
  const fetcher=async(url,options)=>{calls.push({url,options});if(calls.length===1)throw new TypeError('network');return new Response(JSON.stringify(receipt));};
  await assert.rejects(()=>submitSubaccount(value,fetcher));
  const restored=await importSubaccountRequest(exportSubaccountRequest(value));
  assert.equal(await submitSubaccount(restored,fetcher),child);
  assert.equal(calls.length,2);assert.equal(calls[0].options.body,calls[1].options.body);
  assert.equal(calls[0].url,'https://mainnet-api1.bulk.trade/api/v1/order');
  assert.equal(calls[0].options.credentials,'omit');assert.equal(calls[0].options.redirect,'error');
  assert.deepEqual(JSON.parse(calls[0].options.body),value.request);
});
test('invalid recovery signature is rejected before any HTTP submission', async()=>{
  const value=await signed();let calls=0;
  await assert.rejects(()=>submitSubaccount({...value,request:{...value.request,nonce:'2'}},async()=>{calls++;return new Response('{}');}));
  assert.equal(calls,0);
});
test('a changed wallet context after async signature verification prevents dispatch', async()=>{
  const value=await signed();let calls=0,guardCalls=0;
  await assert.rejects(()=>submitSubaccount(value,async()=>{calls++;return new Response('{}');},()=>{guardCalls++;throw new Error('Wallet changed');}),/Wallet changed/);
  assert.equal(guardCalls,1);assert.equal(calls,0);
});
test('child readback verifies parent directly even when no master list contains it', async()=>{
  const value=await signed();const calls=[];
  const info=await verifySubaccount(value,child,async(url,options)=>{calls.push(JSON.parse(options.body));return new Response(JSON.stringify([{fullAccount:{kind:'SubAccount',parent:owner,name:'desk-1'}}]));});
  assert.equal(info.parent,owner);assert.deepEqual(calls,[{type:'fullAccount',user:child}]);
  for(const fullAccount of [{kind:'SubAccount',parent:child,name:'desk-1'},{kind:'MasterEOA',name:'desk-1'},{kind:'SubAccount',parent:owner,name:'other'},{kind:'SubAccount',parent:owner}]) {
    await assert.rejects(()=>verifySubaccount(value,child,async()=>new Response(JSON.stringify([{fullAccount}]))));
  }
  // Only a fresh matching API receipt can independently bind a missing readback name.
  assert.equal((await verifySubaccount(value,child,async()=>new Response(JSON.stringify([{fullAccount:{kind:'SubAccount',parent:owner}}])),false)).kind,'SubAccount');
});
