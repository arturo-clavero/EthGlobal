import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {runInNewContext} from 'node:vm';
import {eraseAzureInputs} from './browser-result.mjs';

test('per-run API is reused, each proof uses its pinned key, and cleanup failure still reports failure',async()=>{
 // Stub cryptography only; packaged proof/key checks are out of scope here.
 const source=readFileSync(new URL('./browser-worker.mjs',import.meta.url),'utf8').replace(/^import .*;\n/gm,'');
 const messages=[],witnesses=[];let initialized=0,verified=0,destroyed=0,rejectProof=false,current;
 const key=new Uint8Array([7]),api={destroy:async()=>{destroyed++;throw new Error('cleanup failed');}};
 const self={postMessage:message=>{
  if(message.ok)assert.deepEqual(current.values,[0,0]);
  messages.push(message);
 }};
 runInNewContext(source,{self,URL,btoa,eraseAzureInputs,
  loadAzureCircuit:async()=>({circuit:{bytecode:'synthetic'},verificationKey:key}),azureProofOptions:{},azureProofFields:()=>{},
  BackendType:{Wasm:'Wasm'},Barretenberg:{new:async()=>{initialized++;return api;}},
  Noir:class{async execute(){const witness=new Uint8Array([4,5]);witnesses.push(witness);return {witness};}},
  UltraHonkBackend:class{async generateProof(){return {proof:new Uint8Array([1]),publicInputs:['0x01']};}},
  UltraHonkVerifierBackend:class{async verifyProof(value){assert.equal(value.verificationKey,key);verified++;return !rejectProof;}},
 });
 for(let i=0;i<3;i++){
  current={values:[4,5]};rejectProof=i===2;
  await self.onmessage({data:{id:`job-${i}`,circuitId:'header-v1',inputs:current,final:false}});
  assert.deepEqual(current.values,[0,0]);
 }
 assert.equal(initialized,1);assert.equal(verified,3);assert.equal(destroyed,1);
 assert.deepEqual(messages.map(message=>message.ok),[true,true,false]);
 assert.equal(messages[2].error,'AZURE_PRIVATE_PROVING_FAILED');
 assert.ok(witnesses.every(witness=>witness.every(value=>value===0)));
});

test('final proof waits for runtime cleanup and rejects a malformed final flag or cleanup failure',async()=>{
 const source=readFileSync(new URL('./browser-worker.mjs',import.meta.url),'utf8').replace(/^import .*;\n/gm,'');
 for(const failCleanup of [false,true]){
  const messages=[];let finish,started,initialized=0,destroyed=0;
  const cleaning=new Promise(resolve=>{started=resolve;});
  const self={postMessage:message=>messages.push(message)};
  const api={destroy:async()=>{
   if(destroyed++)throw new Error('cleanup failed');
   started();await new Promise((resolve,reject)=>{finish=failCleanup?()=>reject(new Error('cleanup failed')):resolve;});
  }};
  runInNewContext(source,{self,URL,btoa,eraseAzureInputs,
   loadAzureCircuit:async()=>({circuit:{bytecode:'synthetic'},verificationKey:new Uint8Array([7])}),azureProofOptions:{},azureProofFields:()=>{},
   BackendType:{Wasm:'Wasm'},Barretenberg:{new:async()=>{initialized++;return api;}},
   Noir:class{async execute(){return {witness:new Uint8Array([4,5])};}},
   UltraHonkBackend:class{async generateProof(){return {proof:new Uint8Array([1]),publicInputs:['0x01']};}},
   UltraHonkVerifierBackend:class{async verifyProof(){return true;}},
  });
  const invalid={values:[4,5]};
  await self.onmessage({data:{id:'bad-final',circuitId:'header-v1',inputs:invalid,final:'true'}});
  assert.equal(messages.pop().ok,false);assert.equal(initialized,0);assert.deepEqual(invalid.values,[0,0]);
  const inputs={values:[4,5]};
  const running=self.onmessage({data:{id:'last-job',circuitId:'header-v1',inputs,final:true}});
  await cleaning;assert.equal(messages.length,0);assert.deepEqual(inputs.values,[0,0]);
  finish();await running;
  assert.equal(destroyed,1);assert.equal(messages.length,1);assert.equal(messages[0].ok,!failCleanup);
  if(failCleanup)assert.equal(messages[0].error,'AZURE_PRIVATE_PROVING_FAILED');
 }
});
