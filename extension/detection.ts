import { parseCall, type Call } from '../src/protocol.js';

export function parseToolCallText(text: string): Call {
  const trimmed=text.trim();
  const fenced=/^```(?:json)?\s*\n([\s\S]*?)\n```$/i.exec(trimmed);
  return parseCall(JSON.parse(fenced?fenced[1]:trimmed));
}

// Some Arena models emit several adjacent JSON objects in one assistant bubble.
// Extract balanced objects while respecting strings and escaped quotes.
export function extractToolCalls(text: string): Call[] {
  const calls: Call[]=[]; let start=-1, depth=0, quoted=false, escaped=false;
  for(let i=0;i<text.length;i++) {
    const ch=text[i];
    if(quoted) { if(escaped) escaped=false; else if(ch==='\\') escaped=true; else if(ch==='"') quoted=false; continue; }
    if(ch==='"') {quoted=true;continue;}
    if(ch==='{') {if(depth===0) start=i;depth++;}
    else if(ch==='}' && depth>0) {depth--;if(depth===0 && start>=0) {try {calls.push(parseCall(JSON.parse(text.slice(start,i+1))));} catch {} start=-1;}}
  }
  return calls;
}

export function callSignature(call: Call) {
  return JSON.stringify(call);
}

export function uniqueCalls<T extends {call: Call}>(items: T[]) {
  const seen=new Set<string>();
  return items.filter(item=>{
    const signature=callSignature(item.call);
    if(seen.has(signature)) return false;
    seen.add(signature);
    return true;
  });
}

export function chooseRandom<T>(items: T[], random: ()=>number=Math.random) {
  if(!items.length) return undefined;
  return items[Math.min(items.length-1,Math.floor(random()*items.length))];
}

export function responseChoices<T extends {role: string}>(batch: T[]) {
  const assistants=batch.filter(item=>item.role==='assistant');
  if(assistants.length) return assistants;
  // Arena commonly renders the user's JSON example before one or more answers.
  // A lone latest candidate is still useful because execution remains user-approved.
  return batch.length>1?batch.slice(1):batch;
}
