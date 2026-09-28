import { createServer } from 'node:http';
import { timingSafeEqual } from 'node:crypto';
import { parseCall, catalog, type Result } from './protocol.js';
import { ProjectTools, ToolError } from './tools.js';
import { ApprovalGate, McpServer } from './mcp.js';
export function createBridge(project: ProjectTools, token: string, extensionId?: string, approval=new ApprovalGate()) {
  if(token.length<32) throw new Error('BRIDGE_TOKEN must contain at least 32 characters');
  const mcp=new McpServer(project,token,approval);
  const allowedOrigin = extensionId ? `chrome-extension://${extensionId}` : undefined;
  let running = false;
  const cache = new Map<string,{signature:string;result:Result}>();
  return createServer(async (req,res)=>{
    if (req.url?.startsWith('/mcp/')) return mcp.handle(req,res);
    const start=performance.now();
    const send=(status:number,body:unknown)=>{res.writeHead(status,{'Content-Type':'application/json','Cache-Control':'no-store'});res.end(JSON.stringify(body));};
    if(!/^127\.0\.0\.1(?::\d+)?$/.test(req.headers.host??'')) return send(403,{error:'Invalid host'});
    const origin=req.headers.origin;
    const extensionOrigin = /^chrome-extension:\/\/[a-p]{32}$/.test(origin??'');
    if(origin && origin!==allowedOrigin && !(extensionOrigin && !allowedOrigin)) return send(403,{error:'Origin denied'});
    if(origin) {res.setHeader('Access-Control-Allow-Origin',origin);res.setHeader('Vary','Origin');}
    if(req.method==='OPTIONS') {
      res.setHeader('Access-Control-Allow-Methods','GET, POST');res.setHeader('Access-Control-Allow-Headers','Authorization, Content-Type');res.writeHead(204);res.end();return;
    }
    const auth=Buffer.from(req.headers.authorization??''); const expected=Buffer.from(`Bearer ${token}`);
    if(auth.length!==expected.length || !timingSafeEqual(auth,expected)) return send(401,{error:'Unauthorized'});
    if(req.method==='GET' && req.url==='/health') return send(200,{ok:true,version:1});
    if(req.method==='GET' && req.url==='/tools') return send(200,{version:1,tools:catalog});
    if(req.method!=='POST' || req.url!=='/call') return send(404,{error:'Not found'});
    if(!req.headers['content-type']?.startsWith('application/json')) return send(415,{error:'Expected application/json'});
    let call;
    try {
      let size=0;const chunks:Buffer[]=[];
      for await(const chunk of req) {size+=chunk.length;if(size>16_384) {send(413,{error:'Request too large'});return;}chunks.push(chunk);}
      call=parseCall(JSON.parse(Buffer.concat(chunks).toString('utf8')));
    } catch {return send(400,{error:'Invalid tool_call or arguments'});}
    const signature=JSON.stringify(call);
    const previous=cache.get(call.id);
    if(previous) return previous.signature===signature ? send(200,previous.result) : send(409,{error:'Call id already used with different arguments'});
    if(running) return send(429,{error:'Bridge busy; retry later'});
    running=true;const toolStart=performance.now();
    let result:Result={version:1,type:'tool_result',id:call.id,tool:call.tool,ok:true,timing:{toolMs:0,bridgeMs:0}};
    try {result.data=await project.execute(call);} catch(error) {
      result.ok=false;result.error=error instanceof ToolError?{code:error.code,message:error.message}:{code:'TOOL_FAILED',message:'Tool failed: verify path, repository, permissions and output limits'};
    } finally {running=false;}
    result.timing={toolMs:Math.round(performance.now()-toolStart),bridgeMs:Math.round(performance.now()-start)};
    cache.set(call.id,{signature,result});if(cache.size>100) cache.delete(cache.keys().next().value!);
    console.info(JSON.stringify({event:'tool_complete',id:call.id,tool:call.tool,ok:result.ok,...result.timing}));
    send(200,result);
  });
}
