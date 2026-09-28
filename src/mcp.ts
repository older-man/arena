import { EventEmitter } from 'node:events';
import { randomUUID, timingSafeEqual } from 'node:crypto';
import type { IncomingMessage, ServerResponse } from 'node:http';
import { argumentSchemas, type Call } from './protocol.js';
import { ProjectTools, ToolError } from './tools.js';

type JsonRpcRequest = {jsonrpc?: unknown; id?: unknown; method?: unknown; params?: unknown};
type ApprovalRequest = {id:string; tool:'apply_patch'; arguments:Record<string, unknown>};

export class ApprovalGate extends EventEmitter {
  private pending = new Map<string,{resolve:()=>void; reject:(error:Error)=>void}>();
  async request(tool: 'apply_patch', args: Record<string, unknown>) {
    const id = randomUUID();
    const result = new Promise<void>((resolve, reject) => this.pending.set(id,{resolve,reject}));
    this.emit('requested',{id,tool,arguments:args} satisfies ApprovalRequest);
    const timeout = setTimeout(()=>this.reject(id,'Approval timed out'),90_000);
    try { await result; } finally { clearTimeout(timeout); this.pending.delete(id); }
  }
  approve(id: string) { this.pending.get(id)?.resolve(); }
  reject(id: string, message='Operation rejected') { this.pending.get(id)?.reject(new ToolError('APPROVAL_DENIED',message)); }
  rejectAll(message='Desktop application stopped') { for (const id of this.pending.keys()) this.reject(id,message); }
}

const toolDefinitions = [
  {name:'read_file',description:'Read a UTF-8 text file inside the selected project.',inputSchema:{type:'object',additionalProperties:false,properties:{path:{type:'string'},offset:{type:'integer',minimum:0,default:0},limit:{type:'integer',minimum:1,maximum:32000,default:16000}},required:['path']}},
  {name:'list_files',description:'List visible files and directories inside the selected project.',inputSchema:{type:'object',additionalProperties:false,properties:{path:{type:'string',default:'.'}}}},
  {name:'search_code',description:'Search visible text files for a literal, case-sensitive string.',inputSchema:{type:'object',additionalProperties:false,properties:{path:{type:'string',default:'.'},query:{type:'string'}},required:['query']}},
  {name:'project_snapshot',description:'Create a size-limited project snapshot for orientation.',inputSchema:{type:'object',additionalProperties:false,properties:{maxChars:{type:'integer',minimum:10000,maximum:200000,default:120000}}}},
  {name:'git_status',description:'Read the repository status without invoking hooks.',inputSchema:{type:'object',additionalProperties:false,properties:{}}},
  {name:'git_diff',description:'Read the diff for one visible project file.',inputSchema:{type:'object',additionalProperties:false,properties:{path:{type:'string'},staged:{type:'boolean',default:false}},required:['path']}},
  {name:'apply_patch',description:'Apply a unified diff after a person approves it in Local MCP Studio.',inputSchema:{type:'object',additionalProperties:false,properties:{patch:{type:'string',minLength:1,maxLength:100000}},required:['patch']}},
  {name:'binary_metadata',description:'Read bounded metadata from a Windows PE executable or DLL.',inputSchema:{type:'object',additionalProperties:false,properties:{path:{type:'string'}},required:['path']}},
  {name:'binary_strings',description:'Extract bounded printable ASCII and UTF-16 strings from a binary file.',inputSchema:{type:'object',additionalProperties:false,properties:{path:{type:'string'},minLength:{type:'integer',minimum:4,maximum:200,default:5},maxResults:{type:'integer',minimum:1,maximum:10000,default:1000}},required:['path']}},
  {name:'binary_imports',description:'Read imported libraries and symbols from a Windows PE executable or DLL.',inputSchema:{type:'object',additionalProperties:false,properties:{path:{type:'string'},maxResults:{type:'integer',minimum:1,maximum:10000,default:1000}},required:['path']}},
  {name:'db_schema',description:'Read SQLite schema or parse SQL DDL text without modifying the database. SQL Server MDF requires an external SQL Server runtime.',inputSchema:{type:'object',additionalProperties:false,properties:{path:{type:'string'},maxTables:{type:'integer',minimum:1,maximum:1000,default:200}},required:['path']}},
  {name:'db_sample_rows',description:'Read a bounded sample from a SQLite table, CSV file, or JSON collection. SQL Server MDF requires an external SQL Server runtime.',inputSchema:{type:'object',additionalProperties:false,properties:{path:{type:'string'},table:{type:'string'},limit:{type:'integer',minimum:1,maximum:100,default:20}},required:['path','table']}}
  ,{name:'file_info',description:'Return size, modification time, and SHA-256 for a project file.',inputSchema:{type:'object',additionalProperties:false,properties:{path:{type:'string'}},required:['path']}},
  {name:'binary_read_range',description:'Read a bounded raw byte range from a project binary as hex and ASCII.',inputSchema:{type:'object',additionalProperties:false,properties:{path:{type:'string'},offset:{type:'integer',minimum:0},length:{type:'integer',minimum:1,maximum:65536,default:4096}},required:['path','offset']}},
  {name:'pe_function_index',description:'Index PE entry point, exports, and bounded function-prologue candidates.',inputSchema:{type:'object',additionalProperties:false,properties:{path:{type:'string'},maxFunctions:{type:'integer',minimum:1,maximum:10000,default:2000}},required:['path']}},
  {name:'pe_string_xrefs',description:'Find bounded static x86/x64 machine-code references to a string offset returned by binary_strings.',inputSchema:{type:'object',additionalProperties:false,properties:{path:{type:'string'},stringOffset:{type:'integer',minimum:0},maxResults:{type:'integer',minimum:1,maximum:2000,default:200}},required:['path','stringOffset']}},
  {name:'pe_disassemble',description:'Perform bounded, best-effort PE instruction decoding from an RVA; unsupported bytes remain explicit db entries.',inputSchema:{type:'object',additionalProperties:false,properties:{path:{type:'string'},rva:{type:'integer',minimum:0},maxInstructions:{type:'integer',minimum:1,maximum:1000,default:100}},required:['path','rva']}},
  {name:'mssql_schema',description:'Read object names and table structure from a schema-only Microsoft SQL Server DDL export.',inputSchema:{type:'object',additionalProperties:false,properties:{path:{type:'string'},maxObjects:{type:'integer',minimum:1,maximum:1000,default:200}},required:['path']}},
  {name:'mssql_object_definition',description:'Read one bounded object definition from a schema-only Microsoft SQL Server DDL export.',inputSchema:{type:'object',additionalProperties:false,properties:{path:{type:'string'},name:{type:'string'},maxChars:{type:'integer',minimum:100,maximum:100000,default:20000}},required:['path','name']}},
  {name:'spf_index',description:'Inspect an SPF file as bounded raw blocks when no verified container specification is available.',inputSchema:{type:'object',additionalProperties:false,properties:{path:{type:'string'},maxEntries:{type:'integer',minimum:1,maximum:10000,default:1000}},required:['path']}},
  {name:'spf_entry_read_range',description:'Read a bounded byte range relative to a raw SPF block offset returned by spf_index.',inputSchema:{type:'object',additionalProperties:false,properties:{path:{type:'string'},entryOffset:{type:'integer',minimum:0},offset:{type:'integer',minimum:0,default:0},length:{type:'integer',minimum:1,maximum:65536,default:4096}},required:['path','entryOffset']}},
  {name:'ldt_table',description:'Read bounded rows from text LDT, CSV, TSV, or JSON table data.',inputSchema:{type:'object',additionalProperties:false,properties:{path:{type:'string'},table:{type:'string',default:'default'},limit:{type:'integer',minimum:1,maximum:500,default:100}},required:['path']}}
] as const;

function equalToken(actual: string, expected: string) {
  const a = Buffer.from(actual); const b = Buffer.from(expected);
  return a.length === b.length && timingSafeEqual(a,b);
}
function json(res: ServerResponse, status: number, body: unknown, headers: Record<string,string>={}) {
  res.writeHead(status,{'Content-Type':'application/json','Cache-Control':'no-store',...headers});
  res.end(JSON.stringify(body));
}
function error(id: unknown, code: number, message: string) { return {jsonrpc:'2.0',id:id??null,error:{code,message}}; }
function textResult(value: unknown, isError=false) { return {content:[{type:'text',text:JSON.stringify(value,null,2)}],...(isError?{isError:true}:{})}; }

export class McpServer {
  private readonly sessions = new Set<string>();
  constructor(private readonly project: ProjectTools, private readonly token: string, private readonly approval: ApprovalGate) {}
  async handle(req: IncomingMessage, res: ServerResponse) {
    const requestUrl = new URL(req.url ?? '/', 'http://localhost');
    const prefix = '/mcp/';
    if (!requestUrl.pathname.startsWith(prefix) || !equalToken(requestUrl.pathname.slice(prefix.length),this.token)) return json(res,401,{error:'Unauthorized'});
    if (req.method === 'GET') return this.handleSse(req,res);
    if (req.method === 'DELETE') {
      const session = req.headers['mcp-session-id'];
      if (typeof session === 'string') this.sessions.delete(session);
      res.writeHead(204); res.end(); return;
    }
    if (req.method !== 'POST') { res.setHeader('Allow','GET, POST, DELETE'); return json(res,405,{error:'Method not allowed'}); }
    if (!req.headers['content-type']?.startsWith('application/json')) return json(res,415,{error:'Expected application/json'});
    try {
      let size=0; const chunks: Buffer[]=[];
      for await (const chunk of req) { size += chunk.length; if (size>1_000_000) return json(res,413,{error:'Request too large'}); chunks.push(chunk); }
      const payload = JSON.parse(Buffer.concat(chunks).toString('utf8')) as JsonRpcRequest;
      if (!payload || Array.isArray(payload) || payload.jsonrpc!=='2.0' || typeof payload.method!=='string') return json(res,400,error(null,-32600,'Invalid JSON-RPC request'));
      const response = await this.dispatch(payload,req.headers['mcp-session-id']);
      if (response===undefined) { res.writeHead(202); res.end(); return; }
      json(res,200,response,response.session?{'Mcp-Session-Id':response.session}:{});
    } catch { json(res,400,error(null,-32700,'Invalid JSON')); }
  }
  private handleSse(req: IncomingMessage, res: ServerResponse) {
    const session = req.headers['mcp-session-id'];
    if (typeof session!=='string' || !this.sessions.has(session)) return json(res,404,{error:'Unknown MCP session'});
    res.writeHead(200,{'Content-Type':'text/event-stream','Cache-Control':'no-cache','Connection':'keep-alive'});
    res.write(': connected\n\n');
    const keepalive=setInterval(()=>res.write(': keepalive\n\n'),15_000);
    req.once('close',()=>clearInterval(keepalive));
  }
  private validSession(value: string|string[]|undefined) { return typeof value==='string' && this.sessions.has(value); }
  private async dispatch(payload: JsonRpcRequest, session: string|string[]|undefined): Promise<({jsonrpc:string;id:unknown;result?:unknown;error?:unknown;session?:string}|undefined)> {
    const id = payload.id;
    if (payload.method==='initialize') {
      const newSession=randomUUID(); this.sessions.add(newSession);
      return {jsonrpc:'2.0',id,result:{protocolVersion:'2025-03-26',capabilities:{tools:{listChanged:false}},serverInfo:{name:'local-mcp-studio',version:'0.2.0'},instructions:'Use project-relative paths. Read and search before proposing a patch. apply_patch always waits for local approval.'},session:newSession};
    }
    if (!this.validSession(session)) return {jsonrpc:'2.0',id,error:{code:-32001,message:'Initialize an MCP session first'}};
    if (payload.method==='notifications/initialized' || payload.method==='notifications/cancelled') return undefined;
    if (payload.method==='ping') return {jsonrpc:'2.0',id,result:{}};
    if (payload.method==='tools/list') return {jsonrpc:'2.0',id,result:{tools:toolDefinitions}};
    if (payload.method!=='tools/call') return {jsonrpc:'2.0',id,error:{code:-32601,message:'Method not found'}};
    const params = payload.params as {name?:unknown;arguments?:unknown}|undefined;
    if (!params || typeof params.name!=='string' || !(params.name in argumentSchemas) || !params.arguments || typeof params.arguments!=='object' || Array.isArray(params.arguments)) return {jsonrpc:'2.0',id,error:{code:-32602,message:'Invalid tool arguments'}};
    const tool=params.name as keyof typeof argumentSchemas;
    try {
      const args=argumentSchemas[tool].parse(params.arguments) as Record<string,unknown>;
      if (tool==='apply_patch') await this.approval.request('apply_patch',args);
      const call: Call={version:1,type:'tool_call',id:`mcp_${randomUUID().replaceAll('-','')}`,tool,arguments:args};
      return {jsonrpc:'2.0',id,result:textResult(await this.project.execute(call))};
    } catch (caught) {
      const result=caught instanceof ToolError?{code:caught.code,message:caught.message}:{code:'TOOL_FAILED',message:'Tool failed'};
      return {jsonrpc:'2.0',id,result:textResult(result,true)};
    }
  }
}
