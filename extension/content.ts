import type { Call } from '../src/protocol.js';
import { defaults } from './selectors.js';
import { callSignature, chooseRandom, extractToolCalls, parseToolCallText, responseChoices, uniqueCalls } from './detection.js';
let config={...defaults};
let pending: {call:Call;executionId:string;detectedAt:number;detectionMs:number;detectionLatencyMs:number}|undefined;
let diagnostic='Waiting for assistant reply';
let timer:ReturnType<typeof setTimeout>|undefined;
let lastMutationAt=Date.now();
let autoRunning=false;
let baselineScanned=false;
let pendingQueue: Call[]=[];
let autoModeEnabled=false;
let hideProtocolMessages=true;
const handled = new Set<string>();
const autoProcessed = new Set<string>();
const repeatNotices = new Set<string>();
const executionAttempts = new Map<string,number>();
const signatures = new WeakMap<Element,string>();
const outboundProtocolMessages = new Map<string,string>();
const collapsedAttribute='data-arena-local-bridge-protocol';
function protocolLabel(text:string) {
  const trimmed=text.trim();
  const outbound=outboundProtocolMessages.get(trimmed);
  if(outbound) return outbound;
  try {
    const value=JSON.parse(trimmed) as {type?:unknown};
    if(value?.type==='tool_result') return '工具结果（已折叠）';
    if(value?.type==='tool_call') return '工具调用（已折叠）';
  } catch {
    if(extractToolCalls(trimmed).length) return '工具调用（已隐藏）';
    try {parseToolCallText(trimmed);return '工具调用（已隐藏）';} catch {return;}
  }
}
function collapseProtocolMessages() {
  for(const node of document.querySelectorAll<HTMLElement>(`[${collapsedAttribute}]`)) {
    if(!['PRE','CODE','P'].includes(node.tagName)&&!outboundProtocolMessages.has(node.textContent?.trim()??'')) {node.hidden=false;node.removeAttribute(collapsedAttribute);}
  }
  const candidates=[...document.querySelectorAll<HTMLElement>('pre,code,p,div')].filter(node=>{
    if(node.hasAttribute(collapsedAttribute)) return false;
    const text=node.textContent?.trim()??'';
    const outbound=outboundProtocolMessages.get(text);
    return text.length>0 && text.length<=32_000 && (Boolean(outbound)||(!node.matches('div')&&Boolean(protocolLabel(text))));
  });
  const deepest=candidates.filter(node=>!candidates.some(other=>other!==node&&node.contains(other)&&node.textContent?.trim()===other.textContent?.trim()));
  for(const node of deepest) {
    const label=protocolLabel(node.textContent??'');
    if(!label||!node.parentElement) continue;
    node.setAttribute(collapsedAttribute,label);node.hidden=hideProtocolMessages;
  }
}
function setProtocolVisibility(hidden:boolean) {
  hideProtocolMessages=hidden;
  for(const node of document.querySelectorAll<HTMLElement>(`[${collapsedAttribute}]`)) {
    node.hidden=hidden;
    const text=node.textContent?.trim()??'';
    if((node.matches('div')&&!outboundProtocolMessages.has(text))||!protocolLabel(text)) {node.hidden=false;node.removeAttribute(collapsedAttribute);}
  }
  collapseProtocolMessages();
}
function visible(node: Element) {
  const style=getComputedStyle(node);
  return style.display!=='none' && style.visibility!=='hidden' && node.getClientRects().length>0;
}
function visibleGenerating() {
  const nodes=[...document.querySelectorAll(config.replies)];
  return nodes.some(node=>visible(node) && /(?:Generating\.{3}|Generating…|生成中)/i.test(node.textContent??''));
}
function roleHint(node: Element) {
  let current: Element|null=node;
  for(let depth=0;current && depth<6;depth++,current=current.parentElement) {
    const hint=[current.getAttribute('data-message-author-role'),current.getAttribute('data-role'),current.getAttribute('aria-label'),current.id,current.className].filter(value=>typeof value==='string').join(' ').toLowerCase();
    if(/(^|[\s_-])(user|human)([\s_-]|$)/.test(hint) || /用户消息/.test(hint)) return 'user';
    if(/(^|[\s_-])(assistant|model|response|bot)([\s_-]|$)/.test(hint) || /助手\s*[ab]/i.test(hint)) return 'assistant';
  }
  return 'unknown';
}
function parsedElement(node: Element) {
  const raw=node.textContent??'';
  if(raw.length<20 || raw.length>16_384 || !raw.includes('tool_call') || !visible(node)) return;
  try {return {node,raw,call:parseToolCallText(raw),role:roleHint(node)};} catch {return;}
}
function parsedElements(node: Element) {
  const raw=node.textContent??'';
  if(raw.length<20 || raw.length>16_384 || !raw.includes('tool_call') || !visible(node)) return [];
  const calls=extractToolCalls(raw);
  if(calls.length<=1) {try {const call=parseToolCallText(raw);return [{node,raw,call,role:roleHint(node)}];} catch {return [];}}
  return calls.map(call=>({node,raw:`${raw}\u0000${callSignature(call)}`,call,role:roleHint(node)}));
}
function fallbackCandidates() {
  const elements=new Set<Element>();
  const walker=document.createTreeWalker(document.body,NodeFilter.SHOW_TEXT);
  let textNode: Node|null;
  while((textNode=walker.nextNode())) {
    const text=textNode.textContent??'';
    if(!text.includes('tool_call') && !text.includes('"type"')) continue;
    let element=textNode.parentElement;
    for(let depth=0;element && depth<5;depth++,element=element.parentElement) {
      if(element.matches('textarea,input,[contenteditable="true"]')) break;
      if((element.textContent?.length??0)>16_384) break;
      elements.add(element);
    }
  }
  const parsed=[...elements].flatMap(parsedElements);
  // Keep the deepest element for each rendered occurrence, not all of its ancestors.
  return parsed.filter(item=>!parsed.some(other=>other!==item && item.node.contains(other.node) && item.raw===other.raw));
}
function setPending(call: Call, start: number) {
  pending={call,executionId:`exec_${crypto.randomUUID().replaceAll('-','')}`,detectedAt:Date.now(),detectionMs:Math.round(performance.now()-start),detectionLatencyMs:Date.now()-lastMutationAt};
}
function freshCandidates<T extends {node: Element;raw: string}>(items: T[]) {
  const fresh=items.filter(item=>signatures.get(item.node)!==item.raw);
  for(const item of items) signatures.set(item.node,item.raw);
  return fresh;
}
function chooseStable<T extends {call: Call}>(items: T[], start: number) {
  const choices=uniqueCalls(items).filter(item=>(executionAttempts.get(callSignature(item.call))??0)<3);
  if(!choices.length) return {count:0};
  const existing=choices.find(item=>pending && callSignature(item.call)===callSignature(pending.call));
  const chosen=existing??chooseRandom(choices);
  if(chosen && !existing) setPending(chosen.call,start);
  return {count:choices.length,chosen,choices:choices.map(item=>item.call)};
}
function composer() {
  const inputs=[...document.querySelectorAll<HTMLElement>(config.composer)].filter(visible);
  if(inputs.length!==1) throw new Error(`Expected one visible composer, found ${inputs.length}`);
  return inputs[0];
}
function fillComposer(text:string) {
  const input=composer();
  if(input instanceof HTMLTextAreaElement || input instanceof HTMLInputElement) {
    if(input.value.trim()) throw new Error('Composer contains a draft');
    const prototype=input instanceof HTMLTextAreaElement?HTMLTextAreaElement.prototype:HTMLInputElement.prototype;
    Object.getOwnPropertyDescriptor(prototype,'value')!.set!.call(input,text);
  } else {
    if(input.textContent?.trim()) throw new Error('Composer contains a draft');
    input.textContent=text;
  }
  input.dispatchEvent(new Event('input',{bubbles:true}));input.dispatchEvent(new Event('change',{bubbles:true}));input.focus();
  return input;
}
async function submitComposer(input:HTMLElement) {
  await new Promise<void>(resolve=>requestAnimationFrame(()=>requestAnimationFrame(()=>resolve())));
  const form=input.closest('form');
  const scope=form??document;
  const buttons=[...scope.querySelectorAll<HTMLButtonElement>(config.send)].filter(button=>visible(button)&&!button.disabled);
  const button=buttons.at(-1);
  if(button) button.click();
  else if(form) form.requestSubmit();
  else throw new Error('No visible Arena send button matched');
}
async function autoSend(text:string,selectors?:Partial<typeof defaults>,collapsedLabel?:string) {
  if(selectors) config={...config,...selectors};
  if(collapsedLabel) outboundProtocolMessages.set(text.trim(),collapsedLabel);
  const input=fillComposer(text);
  await submitComposer(input);
}
const toolBootstrap=`本对话有本地只读工具。需要数据时，仅输出一条 JSON：{"version":1,"type":"tool_call","id":"唯一ID","tool":"工具名","arguments":{}}。工具：list_files、read_file、search_code、git_status、git_diff。路径必须相对项目根目录。收到 tool_result 后继续；信息足够时直接用简洁中文回答用户。不要输出工具协议说明、项目 JSON、过程清单或代码全文。`;
async function maybeAutoRun() {
  const current=pending;
  if(!current||autoRunning||autoProcessed.has(current.executionId)) return;
  autoRunning=true;
  try {
    const calls=pendingQueue.length?pendingQueue:[current.call];
    const results=[];let selectors;
    for(const call of calls) {
      const executionId=`exec_${crypto.randomUUID().replaceAll('-','')}`;
      const response=await chrome.runtime.sendMessage({type:'autoBridge',call,executionId});
    if(!response?.ok) throw new Error(response?.error??'自动执行失败：后台未返回结果');
      if(!response.enabled) return;
      selectors=response.selectors;results.push(response.data);
      const signature=callSignature(call);executionAttempts.set(signature,(executionAttempts.get(signature)??0)+1);handled.add(signature);
    }
    autoProcessed.add(current.executionId);pending=undefined;pendingQueue=[];
    try {await autoSend(results.map(result=>JSON.stringify(result)).join('\n'),selectors,'工具结果（已隐藏）');}
    catch(error) {pending=current;throw error;}
    diagnostic=`已自动执行本轮 ${results.length} 个工具调用并发送结果，等待模型继续或给出最终答案`;
  } catch(error) {diagnostic=error instanceof Error?`自动模式失败：${error.message}`:'自动模式失败';}
  finally {autoRunning=false;}
}
async function maybeNotifyRepeat(call:Call) {
  const signature=callSignature(call);
  if(autoRunning||repeatNotices.has(signature)) return;
  autoRunning=true;
  try {
    const response=await chrome.runtime.sendMessage({type:'autoStatus'});
    if(!response?.enabled) return;
    repeatNotices.add(signature);
    await autoSend('你重复了一个已经完成的工具调用。不要再次请求相同调用；请根据已有 tool_result 选择其他必要工具，信息足够时直接给出最终答案。',response.selectors);
    diagnostic='模型重复调用，已自动要求它继续其他步骤或给出最终答案';
  } catch(error) {diagnostic=error instanceof Error?`自动模式失败：${error.message}`:'自动模式失败';}
  finally {autoRunning=false;}
}
function scan(manual=false) {
  const start=performance.now();
  try {
    if(visibleGenerating()) {
      diagnostic='Arena 仍在生成回复，请等待完整 tool_call';
      return;
    }
    const initialPageScan=!baselineScanned;
    baselineScanned=true;
    const selected=[...document.querySelectorAll(config.replies)];
    const direct=selected.flatMap(node=>{
      const candidates=[node,...node.querySelectorAll('pre,code,p,div')].slice(-100);
      return candidates.flatMap(parsedElements);
    });
    const freshDirect=freshCandidates(direct);
    const latestDirect=freshDirect.at(-1);
    if(latestDirect) {
      const batch=freshDirect.filter(item=>item.node===latestDirect.node);
      const choice=chooseStable(batch,start);
      pendingQueue=choice.chosen?[choice.chosen.call]:[];
      diagnostic=choice.count>1?`已从 ${choice.count} 个助手调用中随机选择 1 个，等待批准执行`:`已检测到 1 个助手调用，等待批准执行`;
      if(choice.chosen) void maybeAutoRun();
      else {
        const repeated=batch.find(item=>handled.has(callSignature(item.call)));
        if(repeated) void maybeNotifyRepeat(repeated.call);
      }
      return;
    }
    const fallback=fallbackCandidates().filter(item=>item.role!=='user');
    const freshFallback=freshCandidates(fallback);
    const latestId=freshFallback.at(-1)?.call.id;
    const latestNode=freshFallback.at(-1)?.node;
    const batch=freshFallback.filter(item=>item.node===latestNode || item.call.id===latestId);
    const eligible=initialPageScan?responseChoices(batch):batch;
    const choice=chooseStable(eligible,start);
    pendingQueue=choice.chosen?[choice.chosen.call]:[];
    if(choice.chosen) {
      diagnostic=choice.count>1?`已从本轮 ${choice.count} 个 Arena 调用中随机选择 1 个，等待批准执行`:`已检测到本轮 1 个 Arena 调用，等待批准执行`;
      void maybeAutoRun();
    } else {
      const repeated=eligible.find(item=>handled.has(callSignature(item.call)));
      if(repeated) void maybeNotifyRepeat(repeated.call);
      else if(pending) {diagnostic='当前 tool_call 已填入上方，等待点击“批准并执行”';void maybeAutoRun();}
      else diagnostic=`匹配到 ${selected.length} 个助手节点；暂未发现新的完整 tool_call`;
    }
  } catch {diagnostic='回复 DOM 选择器无效';}
}
new MutationObserver(()=>{lastMutationAt=Date.now();clearTimeout(timer);timer=setTimeout(()=>{scan();collapseProtocolMessages();},600);}).observe(document.body,{childList:true,subtree:true,characterData:true});
void chrome.runtime.sendMessage({type:'autoStatus'}).then(response=>{autoModeEnabled=response?.enabled===true;hideProtocolMessages=response?.hideProtocol!==false;if(response?.selectors)config={...config,...response.selectors};collapseProtocolMessages();}).catch(()=>undefined);
scan();
collapseProtocolMessages();
chrome.runtime.onMessage.addListener((message,sender,respond)=>{
  if(sender.id!==chrome.runtime.id) return;
  if(message.type==='contentReady') {
    respond({ok:true});
  } else if(message.type==='hideProtocolChanged') {
    setProtocolVisibility(message.enabled!==false);respond({ok:true});
  } else if(message.type==='scan') {
    if(message.selectors) config=message.selectors;
    scan(true);respond({pending,diagnostic,url:location.origin});
  } else if(message.type==='autoModeChanged') {
    autoModeEnabled=message.enabled===true;respond({ok:true});
  } else if(message.type==='fill') {
    const start=performance.now();
    try {
      fillComposer(message.text);
      const signature=message.signature??(pending?callSignature(pending.call):message.id);
      handled.add(signature);if(pending&&callSignature(pending.call)===signature) pending=undefined;
      respond({ok:true,fillMs:Math.round(performance.now()-start)});
      } catch(error) {respond({ok:false,error:error instanceof Error?error.message:'Fill failed'});}
  } else if(message.type==='initTools') {
    void autoSend(toolBootstrap,message.selectors,'本地工具说明（已折叠）').then(()=>respond({ok:true})).catch(error=>respond({ok:false,error:error instanceof Error?error.message:'初始化失败'}));
    return true;
  }
});
