import { parseCall } from '../src/protocol.js';

// Keep the token inaccessible to content scripts, which share the Arena renderer.
void chrome.storage.local.setAccessLevel({accessLevel:'TRUSTED_CONTEXTS'});

const arenaUrl=/^https:\/\/(www\.)?arena\.ai\//;
async function bridgeRequest(call?: ReturnType<typeof parseCall>) {
  const config=await chrome.storage.local.get(['token','port']);
  const port=Number(config.port??4318);
  if(!Number.isInteger(port)||port<1024||port>65535||typeof config.token!=='string'||config.token.length<32) throw new Error('Configure token and port first');
  const start=performance.now();
  const response=await fetch(`http://127.0.0.1:${port}/${call?'call':'health'}`,{method:call?'POST':'GET',headers:{Authorization:`Bearer ${config.token}`,'Content-Type':'application/json'},...(call?{body:JSON.stringify(call)}:{}),signal:AbortSignal.timeout(10_000)});
  if(!response.ok) throw new Error(`Bridge HTTP ${response.status}`);
  return {data:await response.json(),roundTripMs:Math.round(performance.now()-start)};
}

chrome.runtime.onMessage.addListener((message,sender,respond)=>{
  const popup=sender.id===chrome.runtime.id && !sender.tab && sender.url===chrome.runtime.getURL('popup.html');
  const senderPageUrl=sender.url??sender.tab?.url??'';
  const arena=sender.id===chrome.runtime.id && Boolean(sender.tab) && arenaUrl.test(senderPageUrl);
  if(!popup && !arena) return;
  (async()=>{
    if(message.type==='bridge' && popup) {
      const call=message.call===undefined?undefined:parseCall(message.call);
      return {ok:true,...await bridgeRequest(call)};
    }
    if(message.type==='autoBridge' && arena) {
      const config=await chrome.storage.local.get(['autoMode','selectors','hideProtocol']);
      if(config.autoMode!==true) return {ok:true,enabled:false};
      const original=parseCall(message.call);
      const internal=parseCall({...original,id:message.executionId});
      const response=await bridgeRequest(internal);
      return {ok:true,enabled:true,data:{...response.data,id:original.id},roundTripMs:response.roundTripMs,selectors:config.selectors};
    }
    if(message.type==='autoStatus' && arena) {
      const config=await chrome.storage.local.get(['autoMode','selectors','hideProtocol']);
      return {ok:true,enabled:config.autoMode===true,selectors:config.selectors,hideProtocol:config.hideProtocol!==false};
    }
    throw new Error('Unsupported request');
  })().then(respond,err=>respond({ok:false,error:err instanceof Error?err.message:'Request failed'}));
  return true;
});

chrome.storage.onChanged.addListener((changes,area)=>{
  if(area!=='local'||!changes.autoMode)return;
  void chrome.tabs.query({url:['https://arena.ai/*','https://www.arena.ai/*']}).then(tabs=>Promise.all(tabs.flatMap(tab=>tab.id?[chrome.tabs.sendMessage(tab.id,{type:'autoModeChanged',enabled:changes.autoMode.newValue===true}).catch(()=>undefined)]:[])));
});
