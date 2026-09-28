import { parseCall } from '../src/protocol.js';
const token=process.env.BRIDGE_TOKEN;
if(!token) throw new Error('Set BRIDGE_TOKEN');
const base=`http://127.0.0.1:${process.env.BRIDGE_PORT??4318}`;
const call=parseCall({version:1,type:'tool_call',id:`cli-${Date.now()}`,tool:'list_files',arguments:{path:'.'}});
for(const route of ['health','tools','call']) {
  const start=performance.now();
  const response=await fetch(`${base}/${route}`,{method:route==='call'?'POST':'GET',headers:{Authorization:`Bearer ${token}`,'Content-Type':'application/json'},...(route==='call'?{body:JSON.stringify(call)}:{}),signal:AbortSignal.timeout(10_000)});
  if(!response.ok)throw new Error(`${route}: HTTP ${response.status}`);
  const data=await response.json();if(route==='call' && (!data.ok||data.id!==call.id))throw new Error('Invalid result');
  console.log(JSON.stringify({stage:route,roundTripMs:Math.round(performance.now()-start),result:data},null,2));
}
