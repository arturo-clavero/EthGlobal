import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {createAzurePrivateModule} from './browser-client.mjs';
import {syntheticAzureAttempt,syntheticAzureWitnesses} from './browser-plan.fixtures.mjs';

test('reports progress, waits after worker termination, and allows abort or clear during the grace period',async()=>{
 for(const cancellation of [undefined,'abort','clear']){
 const originals={location:globalThis.location,Worker:globalThis.Worker};
 const events=[],workers=[],finalJobs=[];let stoppedAt,module;const controller=new AbortController();
 const pins=JSON.parse(readFileSync(new URL('./generated/artifacts.json',import.meta.url)));
 class FakeWorker extends EventTarget{
  constructor(){super();workers.push(this);assert.ok(events.length>0);}
  postMessage(message){
   assert.deepEqual(Object.keys(message).sort(),['circuitId','final','id','inputs']);
   const {id,circuitId,inputs,final}=message;
   finalJobs.push(final);
   const artifact=JSON.parse(readFileSync(new URL(`./dist/${pins.circuits[circuitId].artifactFile}`,import.meta.url)));
   const publicInputs=artifact.abi.parameters.filter(p=>p.visibility==='public').flatMap(p=>[inputs[p.name]].flat(Infinity))
    .map(v=>'0x'+BigInt(v).toString(16).padStart(64,'0'));
   queueMicrotask(()=>this.dispatchEvent(new MessageEvent('message',{data:{id,ok:true,entry:{circuitId,proof:'AQID',publicInputs}}})));
  }
  terminate(){
   this.stopped=true;stoppedAt=Date.now();
   if(cancellation)queueMicrotask(()=>cancellation==='abort'?controller.abort():module.clear());
  }
 }
 globalThis.location=new URL('chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/offscreen.html');globalThis.Worker=FakeWorker;
 const attempt=syntheticAzureAttempt();module=createAzurePrivateModule({attempt,
  workerUrl:'chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/azure-private/browser-worker.js',
  onProgress:value=>{events.push({...value});if(value.completedProofs===0)throw new Error('Observer failure');}});
 try{
  const outcome=module.prove(syntheticAzureWitnesses(attempt),controller.signal);
  if(cancellation){
   await assert.rejects(outcome,/AZURE_PRIVATE_PROVING_FAILED/);
   assert.equal(workers.length,1);assert.equal(workers[0].stopped,true);assert.ok(Date.now()-stoppedAt<1000);
   continue;
  }
  const result=await outcome;assert.ok(Date.now()-stoppedAt>=4900);
  const total=result.proofs.length;assert.ok(total>0&&total<128);
  assert.deepEqual(finalJobs,Array.from({length:total},(_,i)=>i===total-1));
  assert.deepEqual(events,Array.from({length:total+1},(_,completedProofs)=>({completedProofs,totalProofs:total})));
  assert.equal(workers.length,1);assert.ok(workers.every(worker=>worker.stopped));
 }finally{module.clear();for(const[key,value]of Object.entries(originals)){if(value===undefined)delete globalThis[key];else globalThis[key]=value;}}
 }
});

test('one run owns its worker and terminates pending work on abort, malformed reply or worker error',async()=>{
 const originals={location:globalThis.location,Worker:globalThis.Worker};
 globalThis.location=new URL('chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/offscreen.html');
 try{
  for(const failure of ['abort','malformed','error']){
   let current,started;
   const ready=new Promise(resolve=>{started=resolve;});
   class PendingWorker extends EventTarget{
    constructor(){super();current=this;}
    postMessage(message){this.message=message;started();}
    terminate(){this.stopped=true;}
   }
   globalThis.Worker=PendingWorker;
   const attempt=syntheticAzureAttempt(),controller=new AbortController();
   const module=createAzurePrivateModule({attempt,workerUrl:'chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/azure-private/browser-worker.js'});
   const outcome=assert.rejects(module.prove(syntheticAzureWitnesses(attempt),controller.signal),/AZURE_PRIVATE_PROVING_FAILED/);
   await ready;
   if(failure==='abort')controller.abort();
   else if(failure==='malformed')current.dispatchEvent(new MessageEvent('message',{data:{id:'wrong-run',ok:true,entry:{}}}));
   else current.dispatchEvent(new Event('error'));
   await outcome;assert.equal(current.stopped,true);
   await assert.rejects(module.prove(syntheticAzureWitnesses(attempt),new AbortController().signal));
   module.clear();
  }
 }finally{for(const[key,value]of Object.entries(originals)){if(value===undefined)delete globalThis[key];else globalThis[key]=value;}}
});
