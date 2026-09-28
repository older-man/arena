import { parseCall } from '../src/protocol.js';
import { defaults, selector } from './selectors.js';
import { callSignature } from './detection.js';
const element=<T extends HTMLElement>(id:string)=>document.getElementById(id) as T;
const input=(id:string)=>element<HTMLInputElement>(id);
const status=(text:string)=>{element('status').textContent=text;};
let latest: {id:string;text:string;signature:string}|undefined;
let detection: {call:ReturnType<typeof parseCall>;executionId:string;detectedAt:number;detectionMs:number;detectionLatencyMs:number}|undefined;
const tab=async()=>{const [active]=await chrome.tabs.query({active:true,currentWindow:true});if(!active?.id||!/^https:\/\/(www\.)?arena\.ai\//.test(active.url??'')) throw new Error('请在 Arena 页面打开扩展');return active.id;};
async function sendToArena<T=any>(message: Record<string, unknown>) {
  const id=await tab();
  try {
    return await chrome.tabs.sendMessage(id,message) as T;
  } catch (error) {
    const text=error instanceof Error?error.message:String(error);
    if (!/Receiving end does not exist|Could not establish connection/i.test(text)) throw error;
    try {
      await chrome.scripting.executeScript({target:{tabId:id},files:['content.js']});
      return await chrome.tabs.sendMessage(id,message) as T;
    } catch (retryError) {
      const retryText=retryError instanceof Error?retryError.message:String(retryError);
      throw new Error(`Arena 页面工具脚本未连接，请刷新当前 Arena 页面后重试（${retryText}）`);
    }
  }
}
const selectors=()=>({replies:selector(input('replies').value,defaults.replies),composer:selector(input('composer').value,defaults.composer),send:selector(input('send').value,defaults.send)});
const guard=(fn:()=>Promise<void>)=>async()=>{try{await fn();}catch(e){status(e instanceof Error?e.message:'操作失败');}};
async function initialize() {
const saved=await chrome.storage.local.get(['token','port','selectors','autoMode','hideProtocol']);
input('token').value=saved.token??'';input('port').value=String(saved.port??4318);
input('autoMode').checked=saved.autoMode===true;
input('hideProtocol').checked=saved.hideProtocol!==false;
input('replies').value=saved.selectors?.replies??defaults.replies;input('composer').value=saved.selectors?.composer??defaults.composer;input('send').value=saved.selectors?.send??defaults.send;
input('autoMode').addEventListener('change',()=>void chrome.storage.local.set({autoMode:input('autoMode').checked}).then(()=>status(input('autoMode').checked?'自动工具模式已开启':'自动工具模式已关闭')));
input('hideProtocol').addEventListener('change',()=>void chrome.storage.local.set({hideProtocol:input('hideProtocol').checked}).then(async()=>{
  await sendToArena({type:'hideProtocolChanged',enabled:input('hideProtocol').checked});
  status(input('hideProtocol').checked?'工具协议消息已隐藏':'工具协议消息已显示');
}).catch(error=>status(error instanceof Error?error.message:'无法更新工具消息显示')));
element('settings').addEventListener('submit',event=>{event.preventDefault();void guard(async()=>{
  const config=selectors();for(const value of Object.values(config)) document.querySelector(value);
  await chrome.storage.local.set({token:input('token').value,port:Number(input('port').value),autoMode:input('autoMode').checked,hideProtocol:input('hideProtocol').checked,selectors:config});status(input('autoMode').checked?'配置已保存，自动工具模式已开启':'配置已保存');
  if(input('autoMode').checked) await detect();
})();});
element('health').onclick=guard(async()=>{const response=await chrome.runtime.sendMessage({type:'bridge'});status(response.ok?'Bridge 已连接':response.error);});
element('initTools').onclick=guard(async()=>{
  const button=element<HTMLButtonElement>('initTools');button.disabled=true;status('正在初始化当前 Arena 对话');
  try {const response=await sendToArena({type:'initTools',selectors:selectors()});if(!response?.ok) throw new Error(response?.error??'初始化失败');status('工具说明已发送；现在可发送“分析整个项目”');}
  finally {button.disabled=false;}
});
const detect=async()=>{
  const response=await sendToArena({type:'scan',selectors:selectors()});
  if(response.pending){input('call').value=JSON.stringify(response.pending.call,null,2);detection=response.pending;}
  if(response.diagnostic?.includes('自动模式失败')) status(response.diagnostic);
  status(response.diagnostic);
};
element('scan').onclick=guard(detect);
element('execute').onclick=guard(async()=>{
  const call=parseCall(JSON.parse(input('call').value));
  const detectedUnchanged=detection && JSON.stringify(detection.call)===JSON.stringify(call);
  const executionId=detectedUnchanged && detection?.executionId?detection.executionId:`exec_${crypto.randomUUID().replaceAll('-','')}`;
  const bridgeCall={...call,id:executionId};
  const button=element<HTMLButtonElement>('execute');button.disabled=true;status('正在执行');
  try {
    const response=await chrome.runtime.sendMessage({type:'bridge',call:bridgeCall});
    if(!response.ok) throw new Error(response.error);
    const modelResult={...response.data,id:call.id};
    latest={id:call.id,signature:callSignature(call),text:JSON.stringify(modelResult,null,2)};input('result').value=latest.text;
    element<HTMLButtonElement>('fill').disabled=false;element<HTMLButtonElement>('copy').disabled=false;
    element('timing').textContent=JSON.stringify({arenaInferenceMs:null,domDetectionMs:detection?.detectionLatencyMs??null,domScanMs:detection?.detectionMs??null,approvalWaitMs:detection?Date.now()-detection.detectedAt-response.roundTripMs:null,bridgeRoundTripMs:response.roundTripMs,...modelResult.timing},null,2);
    status(modelResult.ok?'执行完成，请检查结果':'工具返回错误');
  } finally {button.disabled=false;}
});
element('fill').onclick=guard(async()=>{if(!latest)return;await sendToArena({type:'scan',selectors:selectors()});const response=await sendToArena({type:'fill',...latest});if(!response.ok)throw new Error(response.error);const timing=JSON.parse(element('timing').textContent||'{}');timing.resultFillMs=response.fillMs;element('timing').textContent=JSON.stringify(timing,null,2);status(`已回填，等待手动发送 (${response.fillMs} ms)`);});
element('copy').onclick=guard(async()=>{if(latest){await navigator.clipboard.writeText(latest.text);status('结果已复制');}});
try {if(input('autoMode').checked) status('自动工具模式已开启；发送原始问题即可按模型调用读取项目'); else await detect();} catch {status('配置已加载；请在 Arena 页面检测回复');}
}
void initialize().catch(()=>status('无法加载配置'));
