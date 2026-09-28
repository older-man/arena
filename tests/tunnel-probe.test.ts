import { test } from 'node:test';
import assert from 'node:assert/strict';
import { probePublicMcp } from '../src/tunnel-probe.js';

test('public MCP probe retries until it receives the server-specific session response',async()=>{
  let calls=0;
  const result=await probePublicMcp('https://example.test/mcp/token',{attempts:3,retryDelayMs:0,sleep:async()=>{},fetchImpl:async()=>{
    calls++;
    return calls===1 ? new Response('not ready',{status:502}) : new Response(JSON.stringify({error:'Unknown MCP session'}),{status:404,headers:{'Content-Type':'application/json'}});
  }});
  assert.deepEqual(result,{ready:true});
  assert.equal(calls,2);
});

test('public MCP probe does not accept an unrelated 404 page',async()=>{
  const result=await probePublicMcp('https://example.test/mcp/token',{attempts:1,fetchImpl:async()=>new Response('not found',{status:404})});
  assert.deepEqual(result,{ready:false,message:'The public MCP health check returned HTTP 404.'});
});
