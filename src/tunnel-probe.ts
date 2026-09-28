export type PublicMcpProbe = {ready:true}|{ready:false;message:string};

type FetchLike = (input:string, init:RequestInit)=>Promise<Response>;
type ProbeOptions = {attempts?:number;retryDelayMs?:number;timeoutMs?:number;fetchImpl?:FetchLike;sleep?:(ms:number)=>Promise<void>};

const pause=(ms:number)=>new Promise<void>(resolve=>setTimeout(resolve,ms));

// A valid, unaffiliated GET has no MCP session, so the server must answer with
// this precise JSON 404. Checking the body avoids treating a tunnel-provider
// error page as proof that the MCP route is reachable.
export async function probePublicMcp(url:string, options:ProbeOptions={}):Promise<PublicMcpProbe> {
  const attempts=options.attempts??5;
  const retryDelayMs=options.retryDelayMs??2_000;
  const timeoutMs=options.timeoutMs??10_000;
  const fetchImpl=options.fetchImpl??((input,init)=>fetch(input,init));
  const sleep=options.sleep??pause;
  let lastMessage='The public MCP health check did not receive a response.';
  for(let attempt=0;attempt<attempts;attempt++) {
    try {
      const response=await fetchImpl(url,{signal:AbortSignal.timeout(timeoutMs)});
      const payload=await response.json().catch(()=>undefined) as {error?:unknown}|undefined;
      if(response.status===404 && payload?.error==='Unknown MCP session') return {ready:true};
      lastMessage=`The public MCP health check returned HTTP ${response.status}.`;
    } catch {
      lastMessage='The public MCP health check timed out.';
    }
    if(attempt<attempts-1) await sleep(retryDelayMs);
  }
  return {ready:false,message:lastMessage};
}
