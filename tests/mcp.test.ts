import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { ProjectTools } from '../src/tools.js';
import { ApprovalGate } from '../src/mcp.js';
import { createBridge } from '../src/bridge.js';

test('MCP endpoint initializes, lists tools, calls read-only tools, and protects its URL token',async()=>{
  const base=await mkdtemp(join(tmpdir(),'mcp-test-')); const root=join(base,'project'); await mkdir(root); await writeFile(join(root,'hello.ts'),'export const greeting = "hello";\n');
  const token='a'.repeat(48); const approval=new ApprovalGate(); const server=createBridge(await ProjectTools.create(root),token,undefined,approval);
  await new Promise<void>(resolve=>server.listen(0,'127.0.0.1',resolve));
  const address=server.address(); assert(address && typeof address!=='string'); const endpoint=`http://127.0.0.1:${address.port}/mcp/${token}`;
  const rpc=async(body:unknown,session?:string)=>{
    const response=await fetch(endpoint,{method:'POST',headers:{'Content-Type':'application/json',...(session?{'Mcp-Session-Id':session}:{})},body:JSON.stringify(body)});
    return {response,body:response.status===202?undefined:await response.json()};
  };
  try {
    assert.equal((await fetch(endpoint.replace(token,'wrong-token'))).status,401);
    const initialize=await rpc({jsonrpc:'2.0',id:1,method:'initialize',params:{protocolVersion:'2025-03-26',capabilities:{},clientInfo:{name:'test',version:'1'}}});
    assert.equal(initialize.response.status,200); assert.equal(initialize.body.result.serverInfo.name,'local-mcp-studio');
    const session=initialize.response.headers.get('mcp-session-id'); assert(session);
    assert.equal((await rpc({jsonrpc:'2.0',method:'notifications/initialized'},session)).response.status,202);
    const tools=await rpc({jsonrpc:'2.0',id:2,method:'tools/list'},session);
    assert(tools.body.result.tools.some((tool:{name:string})=>tool.name==='apply_patch'));
    const read=await rpc({jsonrpc:'2.0',id:3,method:'tools/call',params:{name:'read_file',arguments:{path:'hello.ts'}}},session);
    assert.match(read.body.result.content[0].text,/greeting/);
    const invalid=await rpc({jsonrpc:'2.0',id:4,method:'tools/call',params:{name:'read_file',arguments:{path:'../outside'}}},session);
    assert.equal(invalid.body.result.isError,true);
  } finally { server.closeAllConnections(); await new Promise<void>(resolve=>server.close(()=>resolve())); await rm(base,{recursive:true,force:true}); }
});

test('MCP apply_patch waits for an explicit desktop approval',async()=>{
  const base=await mkdtemp(join(tmpdir(),'mcp-approval-')); const root=join(base,'project'); await mkdir(root); await writeFile(join(root,'hello.ts'),'export const answer = 1;\n');
  const token='b'.repeat(48); const approval=new ApprovalGate(); const server=createBridge(await ProjectTools.create(root),token,undefined,approval);
  await new Promise<void>(resolve=>server.listen(0,'127.0.0.1',resolve)); const address=server.address(); assert(address && typeof address!=='string'); const endpoint=`http://127.0.0.1:${address.port}/mcp/${token}`;
  const request=(body:unknown,session?:string)=>fetch(endpoint,{method:'POST',headers:{'Content-Type':'application/json',...(session?{'Mcp-Session-Id':session}:{})},body:JSON.stringify(body)});
  try {
    const initialize=await request({jsonrpc:'2.0',id:1,method:'initialize',params:{}}); const session=initialize.headers.get('mcp-session-id'); assert(session);
    const pendingApproval=new Promise<{id:string}>(resolve=>approval.once('requested',resolve));
    const patch='diff --git a/hello.ts b/hello.ts\n--- a/hello.ts\n+++ b/hello.ts\n@@ -1 +1 @@\n-export const answer = 1;\n+export const answer = 2;\n';
    const responsePromise=request({jsonrpc:'2.0',id:2,method:'tools/call',params:{name:'apply_patch',arguments:{patch}}},session);
    const requestForApproval=await pendingApproval;
    assert.match(await (await import('node:fs/promises')).readFile(join(root,'hello.ts'),'utf8'),/answer = 1/);
    approval.approve(requestForApproval.id);
    const response=await responsePromise; const payload=await response.json(); assert.equal(payload.result.isError,undefined);
    assert.match(await (await import('node:fs/promises')).readFile(join(root,'hello.ts'),'utf8'),/answer = 2/);
  } finally { server.closeAllConnections(); await new Promise<void>(resolve=>server.close(()=>resolve())); await rm(base,{recursive:true,force:true}); }
});
