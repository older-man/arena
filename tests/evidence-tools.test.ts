import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { ProjectTools } from '../src/tools.js';
import { parseCall } from '../src/protocol.js';

test('evidence tools read PE metadata, strings, imports and SQLite data read-only', async () => {
  const base=await mkdtemp(join(tmpdir(),'evidence-tools-')); const root=join(base,'project'); await mkdir(root);
  try {
    const pe=Buffer.alloc(0x400); pe.write('MZ',0,'ascii'); pe.writeUInt32LE(0x80,0x3c); pe.write('PE\0\0',0x80,'ascii'); pe.writeUInt16LE(0x8664,0x84); pe.writeUInt16LE(1,0x86); pe.writeUInt32LE(1_700_000_000,0x88); pe.writeUInt16LE(0xf0,0x94); pe.writeUInt16LE(0x20b,0x98); pe.writeUInt32LE(0x1000,0xa8); pe.writeBigUInt64LE(0x140000000n,0xb0); pe.write('.text\0\0\0',0x188,'ascii'); pe.writeUInt32LE(0x200,0x190); pe.writeUInt32LE(0x1000,0x194); pe.writeUInt32LE(0x200,0x198); pe.writeUInt32LE(0x200,0x19c); pe.writeUInt8(0x55,0x200); pe.writeUInt8(0x8b,0x201); pe.writeUInt8(0xec,0x202); pe.writeUInt8(0xc3,0x203); pe.write('HelloMCP\0',0x220,'ascii'); pe.writeUInt8(0x48,0x230); pe.writeUInt8(0x8d,0x231); pe.writeUInt8(0x05,0x232); pe.writeInt32LE(-23,0x233); pe.write('W\0i\0n\0d\0o\0w\0s\0\0\0',0x240,'binary'); await writeFile(join(root,'sample.exe'),pe);
    const database=new DatabaseSync(join(root,'sample.sqlite')); database.exec('CREATE TABLE users(id INTEGER PRIMARY KEY, name TEXT); INSERT INTO users(name) VALUES (\'Ada\');'); database.close();
    await writeFile(join(root,'schema.sql'),'CREATE TABLE accounts (id INTEGER PRIMARY KEY, name TEXT NOT NULL);');
    await writeFile(join(root,'schema-mssql.sql'),'CREATE TABLE [dbo].[accounts] ([id] int NOT NULL, [name] nvarchar(50));\nGO\nCREATE PROCEDURE [dbo].[Login] AS SELECT 1;\nGO\n');
    await writeFile(join(root,'world.spf'),Buffer.from('SPF\0test-data'));
    await writeFile(join(root,'world.ldt'),'id,name\n1,slime\n');
    const tools=await ProjectTools.create(root);
    const metadata=await tools.execute(parseCall({version:1,type:'tool_call',id:'metadata',tool:'binary_metadata',arguments:{path:'sample.exe'}})) as {format:string;architecture:string}; assert.equal(metadata.format,'PE'); assert.equal(metadata.architecture,'x64');
    const strings=await tools.execute(parseCall({version:1,type:'tool_call',id:'strings',tool:'binary_strings',arguments:{path:'sample.exe',minLength:5}})) as {strings:{text:string}[]}; assert(strings.strings.some(value=>value.text.includes('HelloMCP')));
    const imports=await tools.execute(parseCall({version:1,type:'tool_call',id:'imports',tool:'binary_imports',arguments:{path:'sample.exe'}})) as {imports:unknown[]}; assert.deepEqual(imports.imports,[]);
    const schema=await tools.execute(parseCall({version:1,type:'tool_call',id:'schema',tool:'db_schema',arguments:{path:'sample.sqlite'}})) as {format:string;tables:{name:string}[]}; assert.equal(schema.format,'sqlite'); assert.equal(schema.tables[0].name,'users');
    const rows=await tools.execute(parseCall({version:1,type:'tool_call',id:'rows',tool:'db_sample_rows',arguments:{path:'sample.sqlite',table:'users'}})) as {rows:{name:string}[]}; assert.equal(rows.rows[0].name,'Ada');
    const ddl=await tools.execute(parseCall({version:1,type:'tool_call',id:'ddl',tool:'db_schema',arguments:{path:'schema.sql'}})) as {tables:{name:string}[]}; assert.equal(ddl.tables[0].name,'accounts');
    const info=await tools.execute(parseCall({version:1,type:'tool_call',id:'info',tool:'file_info',arguments:{path:'sample.exe'}})) as {size:number;sha256:string}; assert.equal(info.size,0x400); assert.match(info.sha256,/^[a-f0-9]{64}$/);
    const range=await tools.execute(parseCall({version:1,type:'tool_call',id:'range',tool:'binary_read_range',arguments:{path:'sample.exe',offset:0x200,length:4}})) as {hex:string}; assert.equal(range.hex,'55 8b ec c3');
    const functions=await tools.execute(parseCall({version:1,type:'tool_call',id:'functions',tool:'pe_function_index',arguments:{path:'sample.exe'}})) as {functions:{rva:number}[]}; assert(functions.functions.some(item=>item.rva===0x1000));
    const xrefs=await tools.execute(parseCall({version:1,type:'tool_call',id:'xrefs',tool:'pe_string_xrefs',arguments:{path:'sample.exe',stringOffset:0x220}})) as {references:{rva:number}[]}; assert(xrefs.references.some(item=>item.rva===0x1030));
    const disassembly=await tools.execute(parseCall({version:1,type:'tool_call',id:'disassembly',tool:'pe_disassemble',arguments:{path:'sample.exe',rva:0x1000}})) as {instructions:{text:string}[]}; assert.deepEqual(disassembly.instructions.slice(0,4).map(item=>item.text),['push ebp','mov ebp, esp','ret','db 0x00']);
    const mssql=await tools.execute(parseCall({version:1,type:'tool_call',id:'mssql',tool:'mssql_schema',arguments:{path:'schema-mssql.sql'}})) as {objects:{name:string}[]}; assert(mssql.objects.some(item=>item.name==='dbo.Login'));
    const definition=await tools.execute(parseCall({version:1,type:'tool_call',id:'definition',tool:'mssql_object_definition',arguments:{path:'schema-mssql.sql',name:'dbo.Login'}})) as {definition:string}; assert.match(definition.definition,/SELECT 1/);
    const spf=await tools.execute(parseCall({version:1,type:'tool_call',id:'spf',tool:'spf_index',arguments:{path:'world.spf'}})) as {entries:{offset:number}[]}; assert.equal(spf.entries[0].offset,0);
    const spfRange=await tools.execute(parseCall({version:1,type:'tool_call',id:'spf-range',tool:'spf_entry_read_range',arguments:{path:'world.spf',entryOffset:0,length:3}})) as {ascii:string}; assert.equal(spfRange.ascii,'SPF');
    const ldt=await tools.execute(parseCall({version:1,type:'tool_call',id:'ldt',tool:'ldt_table',arguments:{path:'world.ldt'}})) as {rows:{name:string}[]}; assert.equal(ldt.rows[0].name,'slime');
  } finally { await rm(base,{recursive:true,force:true}); }
});

test('MDF access reports the missing SQL Server runtime explicitly', async () => {
  const base=await mkdtemp(join(tmpdir(),'evidence-mdf-')); const root=join(base,'project'); await mkdir(root); await writeFile(join(root,'world.mdf'),Buffer.from('not a parser target'));
  try { const tools=await ProjectTools.create(root); await assert.rejects(tools.execute(parseCall({version:1,type:'tool_call',id:'mdf',tool:'db_schema',arguments:{path:'world.mdf'}})),(error:unknown)=>error instanceof Error && 'code' in error && (error as {code:string}).code==='DB_RUNTIME_REQUIRED'); } finally { await rm(base,{recursive:true,force:true}); }
});
