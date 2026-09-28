import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, mkdir, symlink, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFile } from 'node:child_process';
import { request as httpRequest } from 'node:http';
import { promisify } from 'node:util';
import { ProjectTools } from '../src/tools.js';
import { createBridge } from '../src/bridge.js';
import { parseCall } from '../src/protocol.js';
const exec=promisify(execFile);
const call=(tool:string,args:Record<string,unknown>,id='test-call')=>parseCall({version:1,type:'tool_call',id,tool,arguments:args});
async function fixture() {
  const base=await mkdtemp(join(tmpdir(),'arena-test-'));const root=join(base,'project');await mkdir(root);
  await writeFile(join(root,'hello.ts'),'const answer = 42;\n');await writeFile(join(base,'outside.txt'),'OUTSIDE_SECRET');
  await writeFile(join(root,'.env'),'SECRET_TOKEN=private');await symlink(join(base,'outside.txt'),join(root,'link'));await symlink(base,join(root,'linked-directory'));
  return {base,root,tools:await ProjectTools.create(root)};
}
test('project confinement, symlinks, sensitive paths, binary and schema rejection',async()=>{
  const f=await fixture();try {
    for(const path of ['../outside.txt',join(f.base,'outside.txt'),'linked-directory/outside.txt','link','.env','./.env','a/../../outside.txt','C:\\secret','../project/hello.ts']) await assert.rejects(f.tools.safePath(path));
    assert.equal((await f.tools.read('hello.ts',0,100)).text,'const answer = 42;\n');
    assert.throws(()=>call('read_file',{path:'hello.ts',shell:'cat /etc/passwd'}));
    assert.throws(()=>call('run_shell',{command:'id'}));
    assert.throws(()=>call('read_file',{path:'hello.ts',limit:1e9}));
    await writeFile(join(f.root,'binary'),Buffer.from([0,1,2]));await assert.rejects(f.tools.read('binary',0,100));
    const listing=await f.tools.list('.');assert(!listing.entries.some(e=>['.env','link','linked-directory'].includes(e.name)));
    const found=await f.tools.search('.','answer');assert.equal(found.matches.length,1);
    assert.equal((await f.tools.search('.','OUTSIDE_SECRET')).matches.length,0);
    const snapshot=await f.tools.execute(call('project_snapshot',{maxChars:10000},'snapshot')) as {text:string;filesDiscovered:number;filesIncluded:number;included:string[];omitted:string[]};
    assert.match(snapshot.text,/===== hello\.ts =====/);assert.match(snapshot.text,/answer = 42/);
    assert(!snapshot.text.includes('OUTSIDE_SECRET'));assert(!snapshot.text.includes('SECRET_TOKEN'));
    assert(snapshot.filesDiscovered>=1);assert(snapshot.filesIncluded===snapshot.included.length);assert(snapshot.included.includes('hello.ts'));
  } finally {await rm(f.base,{recursive:true,force:true});}
});
test('git tools never run external diff drivers; reject broad and sensitive diffs',async()=>{
  const f=await fixture();try {
    await exec('git',['init','-q'],{cwd:f.root});await exec('git',['add','hello.ts','.env'],{cwd:f.root});
    await exec('git',['-c','user.name=Test','-c','user.email=test@example.invalid','commit','-qm','fixture'],{cwd:f.root});
    await writeFile(join(f.root,'hello.ts'),'const answer = 43;\n');
    await exec('git',['config','diff.external','not-a-real-program'],{cwd:f.root});
    const diff=await f.tools.execute(call('git_diff',{path:'hello.ts'})) as {text:string};assert.match(diff.text,/43/);
    await assert.rejects(f.tools.execute(call('git_diff',{path:'.'})));
    await assert.rejects(f.tools.execute(call('git_diff',{path:'.env'})));
    const status=await f.tools.execute(call('git_status',{})) as {text:string};assert.match(status.text,/hello.ts/);
  } finally {await rm(f.base,{recursive:true,force:true});}
});
test('HTTP end-to-end auth, CORS, validation, replay, redacted errors and timings',async()=>{
  const f=await fixture();const token='a'.repeat(48);const server=createBridge(f.tools,token,'test-extension');
  await new Promise<void>(resolve=>server.listen(0,'127.0.0.1',resolve));
  const address=server.address();assert(address && typeof address!=='string');const base=`http://127.0.0.1:${address.port}`;
  const headers={Authorization:`Bearer ${token}`,'Content-Type':'application/json'};
  const post=(body:unknown)=>fetch(`${base}/call`,{method:'POST',headers,body:JSON.stringify(body)});
  try {
    assert.equal((await fetch(`${base}/health`)).status,401);
    assert.equal((await fetch(`${base}/health`,{headers:{...headers,Origin:'https://arena.ai'}})).status,403);
    const badHost = await new Promise<number>(resolve => {
      const req = httpRequest({hostname:'127.0.0.1',port:address.port,path:'/health',method:'GET',headers:{...headers,Host:'attacker.invalid'}}, res=>{res.resume();res.on('end',()=>resolve(res.statusCode!));});
      req.end();
    });
    assert.equal(badHost,403);
    assert.equal((await fetch(`${base}/health`,{headers:{...headers,Origin:'chrome-extension://test-extension'}})).status,200);
    assert.equal((await (await fetch(`${base}/tools`,{headers})).json()).tools.length,22);
    const request=call('read_file',{path:'hello.ts'});const first=await (await post(request)).json();
    assert.equal(first.ok,true);assert.equal(first.type,'tool_result');assert.equal(first.id,request.id);assert(first.timing.bridgeMs>=first.timing.toolMs);
    assert.deepEqual(await (await post(request)).json(),first);
    assert.equal((await post(call('list_files',{},request.id))).status,409);
    assert.equal((await post({...request,arguments:{path:'hello.ts',extra:true}})).status,400);
    assert.equal((await post({...request,arguments:{path:'x'.repeat(20_000)}})).status,413);
    const escaped=await (await post(call('read_file',{path:'../outside.txt'},'escape'))).json();assert.equal(escaped.ok,false);assert.equal(escaped.error.code,'PATH_DENIED');
    const missing=await (await post(call('read_file',{path:'missing'},'missing'))).text();assert(!missing.includes(f.root));assert(!missing.includes(token));
  } finally {server.closeAllConnections();await new Promise<void>(resolve=>server.close(()=>resolve()));await rm(f.base,{recursive:true,force:true});}
});
