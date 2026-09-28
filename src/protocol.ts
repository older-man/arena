import { z } from 'zod';

const path = z.string().min(1).max(500);
export const argumentSchemas = {
  read_file: z.object({path, offset: z.number().int().min(0).max(2_000_000).default(0), limit: z.number().int().min(1).max(32_000).default(16_000)}).strict(),
  list_files: z.object({path: path.default('.')} ).strict(),
  search_code: z.object({path: path.default('.'), query: z.string().min(1).max(200)}).strict(),
  project_snapshot: z.object({maxChars: z.number().int().min(10_000).max(200_000).default(120_000)}).strict(),
  git_status: z.object({}).strict(),
  git_diff: z.object({path, staged: z.boolean().default(false)}).strict(),
  apply_patch: z.object({patch: z.string().min(1).max(100_000)}).strict(),
  binary_metadata: z.object({path}).strict(),
  binary_strings: z.object({path, maxResults: z.number().int().min(1).max(10_000).default(1_000), minLength: z.number().int().min(4).max(200).default(5)}).strict(),
  binary_imports: z.object({path, maxResults: z.number().int().min(1).max(10_000).default(1_000)}).strict(),
  db_schema: z.object({path, maxTables: z.number().int().min(1).max(1_000).default(200)}).strict(),
  db_sample_rows: z.object({path, table: z.string().min(1).max(200), limit: z.number().int().min(1).max(100).default(20)}).strict(),
  file_info: z.object({path}).strict(),
  binary_read_range: z.object({path, offset: z.number().int().min(0).max(2_000_000_000), length: z.number().int().min(1).max(65_536).default(4_096)}).strict(),
  pe_function_index: z.object({path, maxFunctions: z.number().int().min(1).max(10_000).default(2_000)}).strict(),
  pe_string_xrefs: z.object({path, stringOffset: z.number().int().min(0).max(2_000_000_000), maxResults: z.number().int().min(1).max(2_000).default(200)}).strict(),
  pe_disassemble: z.object({path, rva: z.number().int().min(0).max(2_000_000_000), maxInstructions: z.number().int().min(1).max(1_000).default(100)}).strict(),
  mssql_schema: z.object({path, maxObjects: z.number().int().min(1).max(1_000).default(200)}).strict(),
  mssql_object_definition: z.object({path, name: z.string().min(1).max(300), maxChars: z.number().int().min(100).max(100_000).default(20_000)}).strict(),
  spf_index: z.object({path, maxEntries: z.number().int().min(1).max(10_000).default(1_000)}).strict(),
  spf_entry_read_range: z.object({path, entryOffset: z.number().int().min(0).max(2_000_000_000), offset: z.number().int().min(0).max(2_000_000_000).default(0), length: z.number().int().min(1).max(65_536).default(4_096)}).strict(),
  ldt_table: z.object({path, table: z.string().min(1).max(200).default('default'), limit: z.number().int().min(1).max(500).default(100)}).strict()
};
export const envelope = z.object({version: z.literal(1), type: z.literal('tool_call'), id: z.string().regex(/^[a-zA-Z0-9_-]{1,64}$/), tool: z.enum(['read_file','list_files','search_code','project_snapshot','git_status','git_diff','apply_patch','binary_metadata','binary_strings','binary_imports','db_schema','db_sample_rows','file_info','binary_read_range','pe_function_index','pe_string_xrefs','pe_disassemble','mssql_schema','mssql_object_definition','spf_index','spf_entry_read_range','ldt_table']), arguments: z.record(z.unknown())}).strict();
export type Call = z.infer<typeof envelope>;
export function parseCall(input: unknown): Call {
  const call = envelope.parse(input);
  argumentSchemas[call.tool].parse(call.arguments);
  return call;
}
export type Result = {version: 1; type: 'tool_result'; id: string; tool: string; ok: boolean; data?: unknown; error?: {code: string; message: string}; timing: {toolMs: number; bridgeMs: number}};
export const catalog = [
  {name:'read_file', arguments:{path:'relative file path',offset:'optional byte offset',limit:'optional bytes, max 32000'}},
  {name:'list_files', arguments:{path:'optional relative directory, default .'}},
  {name:'search_code', arguments:{path:'optional relative directory',query:'literal case-sensitive text'}},
  {name:'project_snapshot', arguments:{maxChars:'optional context character limit, max 200000'}},
  {name:'git_status', arguments:{}},
  {name:'git_diff', arguments:{path:'required relative regular file',staged:'optional boolean'}},
  {name:'apply_patch', arguments:{patch:'unified diff; requires an approval in the desktop app'}},
  {name:'binary_metadata', arguments:{path:'relative PE executable or DLL path'}},
  {name:'binary_strings', arguments:{path:'relative binary path',minLength:'minimum string length, default 5',maxResults:'maximum results, default 1000'}},
  {name:'binary_imports', arguments:{path:'relative PE executable or DLL path',maxResults:'maximum imported symbols, default 1000'}},
  {name:'db_schema', arguments:{path:'relative SQLite database or SQL DDL text path',maxTables:'maximum tables, default 200'}},
  {name:'db_sample_rows', arguments:{path:'relative SQLite database, CSV, or JSON path',table:'SQLite table or CSV/JSON collection name',limit:'maximum rows, default 20'}}
  ,{name:'file_info', arguments:{path:'relative file path'}},
  {name:'binary_read_range', arguments:{path:'relative binary path',offset:'byte offset',length:'1–65536 bytes'}},
  {name:'pe_function_index', arguments:{path:'relative PE path',maxFunctions:'maximum candidates, default 2000'}},
  {name:'pe_string_xrefs', arguments:{path:'relative PE path',stringOffset:'raw file offset returned by binary_strings',maxResults:'maximum references, default 200'}},
  {name:'pe_disassemble', arguments:{path:'relative PE path',rva:'start relative virtual address',maxInstructions:'maximum instructions, default 100'}},
  {name:'mssql_schema', arguments:{path:'schema-only SQL DDL export',maxObjects:'maximum objects, default 200'}},
  {name:'mssql_object_definition', arguments:{path:'schema-only SQL DDL export',name:'schema-qualified object name',maxChars:'maximum definition length'}},
  {name:'spf_index', arguments:{path:'relative SPF data file',maxEntries:'maximum inferred entries, default 1000'}},
  {name:'spf_entry_read_range', arguments:{path:'relative SPF data file',entryOffset:'raw byte offset returned by spf_index',offset:'relative byte offset',length:'1–65536 bytes'}},
  {name:'ldt_table', arguments:{path:'relative LDT, CSV, TSV, or JSON table file',table:'JSON collection name, default default',limit:'maximum rows, default 100'}}
];
