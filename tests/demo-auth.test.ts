import { test } from 'node:test';
import assert from 'node:assert/strict';
import { DemoAuthFlow, MemoryDemoAccountStore } from '../src/demo-auth.js';

test('demo auth creates one local account and restores it',async()=>{
  const store=new MemoryDemoAccountStore(); const flow=new DemoAuthFlow(store,()=>new Date('2026-09-17T00:00:00Z'));
  const created=await flow.register();
  assert.equal(created.phase,'registered'); assert.match(created.account!.email,/^demo-[a-f0-9]+@local\.test$/);
  assert.equal(created.account!.createdAt,'2026-09-17T00:00:00.000Z');
  const repeated=await flow.register(); assert.equal(repeated.account!.email,created.account!.email);
  const restored=await new DemoAuthFlow(store).restore(); assert.equal(restored.phase,'registered');
  const loggedIn=await new DemoAuthFlow(store).login(); assert.equal(loggedIn.phase,'authenticated');
});

test('demo auth rejects an explicitly wrong password without changing state',async()=>{
  const store=new MemoryDemoAccountStore(); const flow=new DemoAuthFlow(store); const created=await flow.register();
  const rejected=await flow.login('wrong'); assert.equal(rejected.phase,'registered');
  const accepted=await flow.login(created.account!.password); assert.equal(accepted.phase,'authenticated');
});
