import { test } from 'node:test';
import assert from 'node:assert/strict';
import { extractToolCalls, parseToolCallText, callSignature, chooseRandom, responseChoices, uniqueCalls } from '../extension/detection.js';

const json='{"version":1,"type":"tool_call","id":"call_001","tool":"list_files","arguments":{"path":"."}}';
test('strict detection accepts complete JSON and JSON fences',()=>{
  assert.equal(parseToolCallText(json).tool,'list_files');
  assert.equal(parseToolCallText('```json\n'+json+'\n```').id,'call_001');
  assert.equal(callSignature(parseToolCallText(json)),callSignature(parseToolCallText(json)));
});
test('strict detection rejects prose, partial JSON and extra fields',()=>{
  assert.throws(()=>parseToolCallText(`Here is the call: ${json}`));
  assert.throws(()=>parseToolCallText(json.slice(0,-1)));
  assert.throws(()=>parseToolCallText('{"version":1,"type":"tool_call","id":"x","tool":"list_files","arguments":{},"extra":true}'));
});
test('random selection deduplicates identical model answers and is deterministic when injected',()=>{
  const first=parseToolCallText(json);
  const second=parseToolCallText(json.replace('list_files','git_status').replace('{"path":"."}','{}'));
  const choices=uniqueCalls([{call:first},{call:first},{call:second}]);
  assert.equal(choices.length,2);
  assert.equal(chooseRandom(choices,()=>0)?.call.tool,'list_files');
  assert.equal(chooseRandom(choices,()=>0.999)?.call.tool,'git_status');
  assert.equal(chooseRandom([],()=>0),undefined);
});
test('fallback uses a lone latest call and skips the likely user example for multiple occurrences',()=>{
  const only={role:'unknown',value:'answer'};
  assert.deepEqual(responseChoices([only]),[only]);
  assert.deepEqual(responseChoices([{role:'unknown',value:'example'},only]),[only]);
  const assistant={role:'assistant',value:'model'};
  assert.deepEqual(responseChoices([{role:'unknown',value:'example'},assistant]),[assistant]);
});
test('extracts multiple adjacent tool calls from one assistant bubble',()=>{
  const first='{"version":1,"type":"tool_call","id":"a","tool":"list_files","arguments":{"path":"src"}}';
  const second='{"version":1,"type":"tool_call","id":"b","tool":"list_files","arguments":{"path":"tests"}}';
  assert.deepEqual(extractToolCalls(first+'\n'+second).map(call=>call.id),['a','b']);
});
