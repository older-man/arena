import { constants, createReadStream } from 'node:fs';
import { createHash } from 'node:crypto';
import { lstat, realpath, open, readdir, readFile, stat } from 'node:fs/promises';
import { resolve, relative, isAbsolute, sep } from 'node:path';
import { execFile, spawn } from 'node:child_process';
import { promisify } from 'node:util';
import { argumentSchemas, type Call } from './protocol.js';
const exec = promisify(execFile);
export class ToolError extends Error { constructor(public code: string, message: string) { super(message); } }
const denied = /^(?:\.git|\.env(?:\..*)?|\.ssh|\.aws|\.npmrc|\.netrc|id_rsa|id_ed25519|.*\.(?:pem|key|p12))$/i;
const skipped = new Set(['node_modules','dist','build','.next','coverage']);
const BINARY_LIMIT = 32 * 1024 * 1024;
const readU16 = (buffer: Buffer, offset: number) => offset + 2 <= buffer.length ? buffer.readUInt16LE(offset) : 0;
const readU32 = (buffer: Buffer, offset: number) => offset + 4 <= buffer.length ? buffer.readUInt32LE(offset) : 0;
const readU64 = (buffer: Buffer, offset: number) => offset + 8 <= buffer.length ? Number(buffer.readBigUInt64LE(offset)) : 0;
const cString = (buffer: Buffer, offset: number) => {
  if (offset < 0 || offset >= buffer.length) return '';
  const end = buffer.indexOf(0, offset);
  return buffer.subarray(offset, end < 0 ? buffer.length : end).toString('ascii');
};
type PeSection = {name:string;virtualSize:number;virtualAddress:number;rawSize:number;rawPointer:number};
type PeInfo = {buffer:Buffer; peOffset:number; machine:number; sections:PeSection[]; optional:number; magic:number; entryPoint:number; imageBase:number; exportRva:number; exportSize:number; importRva:number; importSize:number};
function parsePe(buffer: Buffer): PeInfo {
  if (buffer.length < 0x40 || buffer.toString('ascii',0,2) !== 'MZ') throw new ToolError('BINARY_FORMAT','The file is not a Windows PE binary');
  const peOffset=readU32(buffer,0x3c);
  if (peOffset < 0x40 || buffer.toString('ascii',peOffset,peOffset+4) !== 'PE\0\0') throw new ToolError('BINARY_FORMAT','The file is not a valid Windows PE binary');
  const machine=readU16(buffer,peOffset+4), sectionCount=readU16(buffer,peOffset+6), optionalSize=readU16(buffer,peOffset+20);
  const optional=peOffset+24, magic=readU16(buffer,optional);
  if (magic!==0x10b && magic!==0x20b) throw new ToolError('BINARY_FORMAT','Unsupported PE optional header');
  const sections:PeSection[]=[]; const sectionStart=optional+optionalSize;
  for(let i=0;i<sectionCount;i++) { const at=sectionStart+i*40; if(at+40>buffer.length) break; sections.push({name:cString(buffer,at).replace(/\0.*$/,''),virtualSize:readU32(buffer,at+8),virtualAddress:readU32(buffer,at+12),rawSize:readU32(buffer,at+16),rawPointer:readU32(buffer,at+20)}); }
  const directoryStart=optional+(magic===0x20b?112:96);
  return {buffer,peOffset,machine,sections,optional,magic,entryPoint:readU32(buffer,optional+16),imageBase:magic===0x20b?readU64(buffer,optional+24):readU32(buffer,optional+28),exportRva:readU32(buffer,directoryStart),exportSize:readU32(buffer,directoryStart+4),importRva:readU32(buffer,directoryStart+8),importSize:readU32(buffer,directoryStart+12)};
}
function rvaOffset(info:PeInfo, rva:number) {
  const section=info.sections.find(s=>rva>=s.virtualAddress && rva<s.virtualAddress+Math.max(s.virtualSize,s.rawSize));
  if(!section) return rva<info.buffer.length ? rva : -1;
  const offset=section.rawPointer+(rva-section.virtualAddress);
  return offset<info.buffer.length ? offset : -1;
}
function offsetRva(info:PeInfo, offset:number) {
  const section=info.sections.find(s=>offset>=s.rawPointer && offset<s.rawPointer+s.rawSize);
  return section ? section.virtualAddress+(offset-section.rawPointer) : offset;
}
function hex(buffer:Buffer) { return buffer.toString('hex').replace(/(..)/g,'$1 ').trim(); }
function asciiPreview(buffer:Buffer) { return buffer.toString('ascii').replace(/[^\x20-\x7e]/g,'.'); }
async function sha256(file:string) {
  const hash=createHash('sha256');
  await new Promise<void>((resolvePromise,reject)=>{ const stream=createReadStream(file); stream.on('data',chunk=>hash.update(chunk)); stream.once('error',reject); stream.once('end',resolvePromise); });
  return hash.digest('hex');
}
function csvRows(text:string,limit:number) {
  const lines=text.split(/\r?\n/).filter(Boolean); const headers=(lines.shift()??'').split(',').map(value=>value.trim());
  return lines.slice(0,limit).map(line=>Object.fromEntries(line.split(',').map((value,index)=>[headers[index]??`column${index+1}`,value.trim()])));
}
function mssqlObjects(text:string,maxObjects:number) {
  const objects:{name:string;type:string;definition:string}[]=[];
  const re=/^\s*CREATE\s+(?:OR\s+ALTER\s+)?(TABLE|VIEW|PROC(?:EDURE)?|FUNCTION|TRIGGER)\s+(?:\[([^\]]+)\]\.)?\[?([^\]\s(]+)\]?/gim;
  for(const match of text.matchAll(re)) { if(objects.length>=maxObjects) break; const start=match.index??0; const next=/^\s*GO\s*$/gim; next.lastIndex=start+match[0].length; const boundary=next.exec(text); const end=boundary?.index??text.length; objects.push({name:match[2]?`${match[2]}.${match[3]}`:match[3],type:match[1].toUpperCase().replace('PROCEDURE','PROC'),definition:text.slice(start,end).trim()}); }
  return objects;
}
async function readBinary(root:ProjectTools, path:string) {
  const file=await root.safePath(path); const metadata=await stat(file);
  if(!metadata.isFile()) throw new ToolError('INVALID_FILE','Regular files only');
  if(metadata.size>BINARY_LIMIT) throw new ToolError('OUTPUT_LIMIT','Binary files larger than 32 MiB are not supported');
  return readFile(file);
}
function parseSqlDdl(text:string, maxTables:number) {
  const tables:[string,Array<{name:string;type:string;definition:string}>][]=[];
  const re=/CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?((?:(?:\[[^\]]+\]|["`]?[-\w.]+["`]?)\s*\.\s*)?(?:\[[^\]]+\]|["`]?[-\w.]+["`]?))\s*\(([^;]*?)\)\s*;?/gis;
  for(const match of text.matchAll(re)) {
    if(tables.length>=maxTables) break;
    const columns=match[2].split(/,(?![^()]*\))/).map(part=>part.trim()).filter(part=>part && !/^(?:constraint|primary\s+key|unique|foreign\s+key|check)\b/i.test(part)).map(def=>{const m=def.match(/^[\["`]?([^\]"`\s]+)[\]"`]?\s+(.+)$/s);return {name:m?.[1]??def.slice(0,80),type:m?.[2]?.split(/\s+/)[0]??'unknown',definition:def.slice(0,300)};});
    tables.push([match[1].replace(/[\[\]"`\s]/g,''),columns]);
  }
  return tables.map(([name,columns])=>({name,columns}));
}
export class ProjectTools {
  private constructor(readonly root: string) {}
  static async create(root: string) {
    if (!isAbsolute(root)) throw new Error('PROJECT_ROOT must be absolute');
    const canonical = await realpath(root);
    if (!(await lstat(canonical)).isDirectory()) throw new Error('PROJECT_ROOT must be a directory');
    return new ProjectTools(canonical);
  }
  async safePath(input: string) {
    if (isAbsolute(input) || input.includes('\\') || input.includes('\0') || input.split('/').includes('..') || /^[a-zA-Z]:/.test(input)) throw new ToolError('PATH_DENIED','Use a project-relative path without parent traversal');
    const parts = input.split('/').filter(p => p && p !== '.');
    if (parts.some(p => denied.test(p))) throw new ToolError('PATH_DENIED','Sensitive paths are excluded');
    let current = this.root;
    for (const part of parts) {
      current = resolve(current, part);
      if ((await lstat(current)).isSymbolicLink()) throw new ToolError('PATH_DENIED','Symbolic links are excluded');
    }
    const actual = await realpath(current);
    const rel = relative(this.root, actual);
    if (rel === '..' || rel.startsWith('..' + sep) || isAbsolute(rel)) throw new ToolError('PATH_DENIED','Path outside project');
    return actual;
  }
  async safeWritePath(input: string) {
    if (isAbsolute(input) || input.includes('\\') || input.includes('\0') || input.split('/').includes('..') || /^[a-zA-Z]:/.test(input)) throw new ToolError('PATH_DENIED','Use a project-relative path without parent traversal');
    const parts = input.split('/').filter(part => part && part !== '.');
    if (!parts.length || parts.some(part => denied.test(part))) throw new ToolError('PATH_DENIED','Sensitive paths are excluded');
    let current = this.root;
    for (const part of parts) {
      current = resolve(current, part);
      try {
        if ((await lstat(current)).isSymbolicLink()) throw new ToolError('PATH_DENIED','Symbolic links are excluded');
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
      }
    }
    const rel = relative(this.root, current);
    if (rel === '..' || rel.startsWith('..' + sep) || isAbsolute(rel)) throw new ToolError('PATH_DENIED','Path outside project');
    return current;
  }
  async read(path: string, offset: number, limit: number) {
    const file = await open(await this.safePath(path), constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    try {
      const stat = await file.stat();
      if (!stat.isFile()) throw new ToolError('INVALID_FILE','Regular files only');
      const buffer = Buffer.alloc(limit);
      const {bytesRead} = await file.read(buffer,0,limit,offset);
      if (buffer.subarray(0,bytesRead).includes(0)) throw new ToolError('BINARY_FILE','Binary files are excluded');
      return {path, text:buffer.subarray(0,bytesRead).toString('utf8'), nextOffset:offset+bytesRead, truncated:offset+bytesRead < stat.size};
    } finally { await file.close(); }
  }
  async list(path: string) {
    const entries = await readdir(await this.safePath(path),{withFileTypes:true});
    const visible = entries.filter(e => !e.isSymbolicLink() && !denied.test(e.name) && !skipped.has(e.name)).sort((a,b)=>a.name.localeCompare(b.name));
    return {entries:visible.slice(0,500).map(e=>({name:e.name,type:e.isDirectory()?'directory':'file'})),truncated:visible.length>500};
  }
  async search(path: string, query: string) {
    const matches: {path:string;line:number;text:string}[] = [];
    let visited = 0, bytes = 0, truncated = false;
    const deadline = performance.now()+2000;
    const walk = async (dir: string, depth: number): Promise<void> => {
      if (depth > 12 || visited >= 500 || bytes >= 2_000_000 || performance.now()>deadline || matches.length>=100) {truncated=true;return;}
      const listed = await this.list(dir); truncated ||= listed.truncated;
      for (const e of listed.entries) {
        if (visited>=500 || bytes>=2_000_000 || matches.length>=100 || performance.now()>deadline) {truncated=true;break;}
        const child = `${dir}/${e.name}`;
        visited++;
        if (e.type==='directory') await walk(child,depth+1);
        else {
          try {
            const result = await this.read(child,0,32_000); bytes+=Buffer.byteLength(result.text); truncated ||= result.truncated;
            for (const [index,line] of result.text.split('\n').entries()) if (line.includes(query)) {
              matches.push({path:child,line:index+1,text:line.slice(0,500)});
              if(matches.length>=100) {truncated=true;break;}
            }
          } catch { /* Files can disappear or be binary during a scan. */ }
        }
      }
    };
    await walk(path,0);
    return {matches,visited,truncated};
  }
  async snapshot(maxChars: number) {
    const files:string[]=[];const omitted:string[]=[];let text='';
    const walk=async(dir:string,depth:number):Promise<void>=>{
      if(depth>16||files.length>=500)return;
      const listing=await this.list(dir);
      for(const entry of listing.entries) {
        const child=dir==='.'?entry.name:`${dir}/${entry.name}`;
        if(entry.type==='directory') await walk(child,depth+1);
        else files.push(child);
      }
    };
    await walk('.',0);
    for(const file of files) {
      if(text.length>=maxChars) {omitted.push(file);continue;}
      try {
        const result=await this.read(file,0,Math.min(32_000,maxChars-text.length));
        const section=`\n\n===== ${file} =====\n${result.text}`;
        if(text.length+section.length>maxChars) {omitted.push(file);continue;}
        text+=section;if(result.truncated) omitted.push(`${file} (remaining content)`);
      } catch {omitted.push(`${file} (binary or unreadable)`);}
    }
    const included=files.filter(file=>text.includes(`===== ${file} =====`));
    return {root:'.',filesDiscovered:files.length,filesIncluded:included.length,included,omitted,truncated:omitted.length>0,text:text.trimStart()};
  }
  async git(args: string[]) {
    // Exclude worktree gitdir pointers and external repository metadata.
    const metadata = await lstat(resolve(this.root,'.git'));
    if (!metadata.isDirectory() || metadata.isSymbolicLink()) throw new ToolError('GIT_DENIED','A repository with a local .git directory is required');
    const {stdout} = await exec('git',['--no-optional-locks','-c','core.fsmonitor=false','-c','core.hooksPath=/dev/null',...args],{
      cwd:this.root,timeout:3000,maxBuffer:128_000,encoding:'utf8',
      env:{PATH:process.env.PATH,HOME:this.root,LANG:'C.UTF-8',GIT_CONFIG_NOSYSTEM:'1',GIT_CONFIG_GLOBAL:'/dev/null',GIT_TERMINAL_PROMPT:'0',GIT_DIR:resolve(this.root,'.git'),GIT_WORK_TREE:this.root}
    });
    return {text:stdout};
  }
  async applyPatch(patch: string) {
    if (patch.includes('\0') || /(?:^|\n)(?:GIT binary patch|rename (?:from|to) )/m.test(patch)) throw new ToolError('PATCH_DENIED','Binary patches and file renames are excluded');
    const paths = [...patch.matchAll(/^(?:---|\+\+\+) (?:a\/|b\/)([^\t\n]+)(?:\t.*)?$/gm)].map(match => match[1]);
    if (!paths.length) throw new ToolError('INVALID_PATCH','A unified diff with project-relative file paths is required');
    for (const path of paths) await this.safeWritePath(path);
    await new Promise<void>((resolvePromise, rejectPromise) => {
      const child = spawn('git',['apply','--whitespace=nowarn','--recount','-'],{
        cwd:this.root,
        env:{PATH:process.env.PATH,LANG:'C.UTF-8',GIT_CONFIG_NOSYSTEM:'1',GIT_CONFIG_GLOBAL:'/dev/null',GIT_TERMINAL_PROMPT:'0'},
        stdio:['pipe','ignore','pipe']
      });
      let stderr='';
      child.stderr.on('data',chunk=>{stderr+=String(chunk);});
      child.on('error',()=>rejectPromise(new ToolError('PATCH_FAILED','Unable to start git apply')));
      child.on('close',code=>code===0?resolvePromise():rejectPromise(new ToolError('PATCH_FAILED',stderr.length?'Patch did not apply cleanly':'Patch did not apply')));
      child.stdin.end(patch);
    });
    return {applied:true,files:[...new Set(paths)]};
  }
  async binaryMetadata(path:string) {
    const info=parsePe(await readBinary(this,path));
    const characteristics=readU16(info.buffer,info.peOffset+22);
    return {format:'PE',architecture:info.magic===0x20b?'x64':'x86',machine:`0x${info.machine.toString(16)}`,entryPoint:`0x${info.entryPoint.toString(16)}`,imageBase:`0x${info.imageBase.toString(16)}`,timestamp:new Date(readU32(info.buffer,info.peOffset+8)*1000).toISOString(),characteristics:`0x${characteristics.toString(16)}`,sections:info.sections.map(section=>({...section,rawSize:section.rawSize,virtualSize:section.virtualSize}))};
  }
  async binaryStrings(path:string,maxResults:number,minLength:number) {
    const buffer=await readBinary(this,path); const results:{offset:number;encoding:'ascii'|'utf16le';text:string}[]=[];
    const collect=(encoding:'ascii'|'utf16le', step:number) => {
      let start=-1, text='';
      const flush=(end:number) => { if(text.length>=minLength && results.length<maxResults) results.push({offset:start,encoding,text}); start=-1;text=''; };
      for(let offset=0;offset<buffer.length;offset+=step) {
        const code=encoding==='ascii'?buffer[offset]:readU16(buffer,offset); const printable=code>=0x20&&code<=0x7e;
        if(printable) { if(start<0) start=offset; text+=String.fromCharCode(code); } else if(start>=0) flush(offset);
        if(results.length>=maxResults) break;
      }
      if(start>=0 && results.length<maxResults) flush(buffer.length);
    };
    collect('ascii',1); if(results.length<maxResults) collect('utf16le',2);
    return {path,strings:results.slice(0,maxResults),truncated:results.length>=maxResults};
  }
  async binaryImports(path:string,maxResults:number) {
    const info=parsePe(await readBinary(this,path)); const imports:{library:string;symbols:Array<string|number>}[]=[];
    const directory=rvaOffset(info,info.importRva); if(directory<0 || !info.importRva) return {path,imports,unsupported:false};
    const width=info.magic===0x20b?8:4; const ordinalMask=info.magic===0x20b?0x8000000000000000n:0x80000000n;
    for(let index=0;index<1000 && imports.length<maxResults;index++) {
      const at=directory+index*20; if(at+20>info.buffer.length) break;
      const original=readU32(info.buffer,at), nameRva=readU32(info.buffer,at+12), first=readU32(info.buffer,at+16); if(!original&&!nameRva&&!first) break;
      const nameOffset=rvaOffset(info,nameRva); if(nameOffset<0) continue;
      const library=cString(info.buffer,nameOffset); const symbols:(string|number)[]=[]; const thunkRva=original||first; const thunkOffset=rvaOffset(info,thunkRva);
      if(thunkOffset>=0) for(let t=0;t<10000 && symbols.length<maxResults;t++) {
        const pos=thunkOffset+t*width; if(pos+width>info.buffer.length) break; const value=width===8?readU64(info.buffer,pos):readU32(info.buffer,pos); if(!value) break;
        if((BigInt(value)&ordinalMask)!==0n) symbols.push(Number(BigInt(value)&0xffffn)); else { const hintOffset=rvaOffset(info,Number(value)); if(hintOffset>=0) symbols.push(cString(info.buffer,hintOffset+2)); }
      }
      imports.push({library,symbols});
    }
    return {path,imports,truncated:imports.reduce((sum,item)=>sum+item.symbols.length,0)>=maxResults};
  }
  async dbSchema(path:string,maxTables:number) {
    const file=await this.safePath(path); const extension=path.toLowerCase().split('.').pop();
    if(extension==='mdf' || extension==='ndf' || extension==='ldf') throw new ToolError('DB_RUNTIME_REQUIRED','MDF/NDF/LDF files require a SQL Server runtime, which is not available in this MCP process');
    if(extension==='sql' || extension==='ddl' || extension==='txt') return {format:'sql-ddl',tables:parseSqlDdl((await readFile(file,'utf8')),maxTables)};
    if(extension!=='sqlite' && extension!=='sqlite3' && extension!=='db') throw new ToolError('DB_FORMAT','Supported database inputs are SQLite, SQL DDL text, or SQL Server MDF with an external runtime');
    try {
      const sqlite=await import('node:sqlite') as unknown as {DatabaseSync:new(path:string,options?:{readOnly?:boolean})=>{prepare(sql:string):{all(...args:unknown[]):unknown[]};close():void}};
      const database=new sqlite.DatabaseSync(file,{readOnly:true});
      try { const tables=database.prepare("SELECT name, sql FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name LIMIT ?").all(maxTables) as {name:string;sql:string}[]; return {format:'sqlite',tables:tables.map(table=>({name:table.name,sql:table.sql,columns:parseSqlDdl(table.sql,maxTables)[0]?.columns??[]}))}; } finally {database.close();}
    } catch(error) { if(error instanceof ToolError) throw error; throw new ToolError('DB_READ_FAILED','Unable to open the SQLite database read-only'); }
  }
  async dbSampleRows(path:string,table:string,limit:number) {
    const file=await this.safePath(path); const extension=path.toLowerCase().split('.').pop();
    if(extension==='mdf' || extension==='ndf' || extension==='ldf') throw new ToolError('DB_RUNTIME_REQUIRED','MDF/NDF/LDF files require a SQL Server runtime, which is not available in this MCP process');
    if(extension==='csv') {
      const lines=(await readFile(file,'utf8')).split(/\r?\n/).filter(Boolean); const headers=(lines.shift()??'').split(',').map(value=>value.trim()); return {format:'csv',table,rows:lines.slice(0,limit).map(line=>Object.fromEntries(line.split(',').map((value,index)=>[headers[index]??`column${index+1}`,value.trim()]))) };
    }
    if(extension==='json') { const value=JSON.parse(await readFile(file,'utf8')) as unknown; const rows=Array.isArray(value)?value:(value&&typeof value==='object'&&Array.isArray((value as Record<string,unknown>)[table])?(value as Record<string,unknown>)[table]:[]); return {format:'json',table,rows:(rows as unknown[]).slice(0,limit)}; }
    if(extension!=='sqlite' && extension!=='sqlite3' && extension!=='db') throw new ToolError('DB_FORMAT','Sample rows support SQLite, CSV, or JSON inputs');
    try {
      const sqlite=await import('node:sqlite') as unknown as {DatabaseSync:new(path:string,options?:{readOnly?:boolean})=>{prepare(sql:string):{all(...args:unknown[]):unknown[]};close():void}};
      const database=new sqlite.DatabaseSync(file,{readOnly:true}); try { const identifier=table.replaceAll('"','""'); const rows=database.prepare(`SELECT * FROM "${identifier}" LIMIT ?`).all(limit); return {format:'sqlite',table,rows}; } finally {database.close();}
    } catch { throw new ToolError('DB_READ_FAILED','Unable to read the requested table read-only'); }
  }
  async fileInfo(path:string) {
    const file=await this.safePath(path); const metadata=await stat(file);
    if(!metadata.isFile()) throw new ToolError('INVALID_FILE','Regular files only');
    return {path,size:metadata.size,modifiedAt:metadata.mtime.toISOString(),sha256:await sha256(file)};
  }
  async binaryReadRange(path:string,offset:number,length:number) {
    const file=await this.safePath(path); const metadata=await stat(file);
    if(!metadata.isFile()) throw new ToolError('INVALID_FILE','Regular files only');
    if(offset>=metadata.size) throw new ToolError('RANGE_DENIED','Offset is beyond the end of the file');
    const actualLength=Math.min(length,metadata.size-offset); const handle=await open(file,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);
    try { const buffer=Buffer.alloc(actualLength); const {bytesRead}=await handle.read(buffer,0,actualLength,offset); const value=buffer.subarray(0,bytesRead); return {path,offset,length:bytesRead,hex:hex(value),ascii:asciiPreview(value),truncated:offset+bytesRead<metadata.size}; } finally {await handle.close();}
  }
  async peFunctionIndex(path:string,maxFunctions:number) {
    const info=parsePe(await readBinary(this,path)); const results:{rva:number;rawOffset:number;name?:string;source:'entry_point'|'export'|'prologue_heuristic'}[]=[]; const add=(rva:number,source:'entry_point'|'export'|'prologue_heuristic',name?:string)=>{
      const rawOffset=rvaOffset(info,rva); if(rawOffset<0 || results.some(item=>item.rva===rva&&item.name===name)) return;
      results.push({rva,rawOffset,source,...(name?{name}:{} )});
    };
    add(info.entryPoint,'entry_point');
    const exportOffset=rvaOffset(info,info.exportRva);
    if(exportOffset>=0 && info.exportRva) {
      const base=readU32(info.buffer,exportOffset+16), functionCount=readU32(info.buffer,exportOffset+20), nameCount=readU32(info.buffer,exportOffset+24), functions=rvaOffset(info,readU32(info.buffer,exportOffset+28)), names=rvaOffset(info,readU32(info.buffer,exportOffset+32)), ordinals=rvaOffset(info,readU32(info.buffer,exportOffset+36));
      for(let i=0;i<Math.min(nameCount,maxFunctions);i++) { const nameOffset=names>=0?rvaOffset(info,readU32(info.buffer,names+i*4)):-1; const ordinal=ordinals>=0?readU16(info.buffer,ordinals+i*2):i; const target=functions>=0?readU32(info.buffer,functions+ordinal*4):0; if(target) add(target,'export',nameOffset>=0?cString(info.buffer,nameOffset):`ordinal_${base+ordinal}`); }
      for(let i=0;i<Math.min(functionCount,maxFunctions);i++) { const target=functions>=0?readU32(info.buffer,functions+i*4):0; if(target) add(target,'export',`ordinal_${base+i}`); }
    }
    for(const section of info.sections.filter(section=>/^(?:\.text|CODE)$/i.test(section.name))) {
      const end=Math.min(info.buffer.length,section.rawPointer+section.rawSize);
      for(let offset=section.rawPointer;offset+4<=end && results.length<maxFunctions;offset++) {
        const b=info.buffer; const x86=b[offset]===0x55&&b[offset+1]===0x8b&&b[offset+2]===0xec; const x64=(b[offset]===0x40||b[offset]===0x48)&&[0x53,0x55,0x57].includes(b[offset+1]);
        if(x86||x64) add(section.virtualAddress+(offset-section.rawPointer),'prologue_heuristic');
      }
    }
    results.sort((a,b)=>a.rva-b.rva);
    return {path,architecture:info.magic===0x20b?'x64':'x86',functions:results.slice(0,maxFunctions),truncated:results.length>=maxFunctions,notes:['Export and entry-point locations are authoritative when present; prologue_heuristic candidates are not symbols.']};
  }
  async peStringXrefs(path:string,stringOffset:number,maxResults:number) {
    const info=parsePe(await readBinary(this,path)); if(stringOffset>=info.buffer.length) throw new ToolError('RANGE_DENIED','String offset is beyond the end of the file');
    const targetRva=offsetRva(info,stringOffset), targetVa=BigInt(info.imageBase)+BigInt(targetRva); const results:{rva:number;rawOffset:number;kind:'absolute_va'|'rip_relative'}[]=[];
    for(const section of info.sections.filter(section=>/^(?:\.text|CODE)$/i.test(section.name))) {
      const end=Math.min(info.buffer.length,section.rawPointer+section.rawSize);
      for(let offset=section.rawPointer;offset+4<=end && results.length<maxResults;offset++) {
        const value=readU32(info.buffer,offset); if(BigInt(value)===targetVa) results.push({rva:section.virtualAddress+(offset-section.rawPointer),rawOffset:offset,kind:'absolute_va'});
        if(offset+7<=end && (info.buffer[offset]===0x48||info.buffer[offset]===0x4c) && (info.buffer[offset+1]===0x8d||info.buffer[offset+1]===0x8b) && (info.buffer[offset+2]&0xc7)===0x05) { const origin=section.virtualAddress+(offset-section.rawPointer); const target=origin+7+info.buffer.readInt32LE(offset+3); if(target===targetRva) results.push({rva:origin,rawOffset:offset,kind:'rip_relative'}); }
      }
    }
    return {path,stringOffset,stringRva:targetRva,references:results,truncated:results.length>=maxResults,notes:['References are static machine-code patterns only; indirect or computed references are not included.']};
  }
  async peDisassemble(path:string,rva:number,maxInstructions:number) {
    const info=parsePe(await readBinary(this,path)); const start=rvaOffset(info,rva); if(start<0) throw new ToolError('RVA_DENIED','RVA does not map to this PE image'); const section=info.sections.find(value=>rva>=value.virtualAddress&&rva<value.virtualAddress+Math.max(value.virtualSize,value.rawSize)); const end=section?Math.min(info.buffer.length,section.rawPointer+section.rawSize):Math.min(info.buffer.length,start+65_536); const instructions:{rva:number;rawOffset:number;bytes:string;text:string}[]=[]; let offset=start;
    const reg=['eax','ecx','edx','ebx','esp','ebp','esi','edi']; const reg64=['rax','rcx','rdx','rbx','rsp','rbp','rsi','rdi'];
    while(offset<end&&instructions.length<maxInstructions) {
      const atRva=offsetRva(info,offset), b=info.buffer; let length=1,text=`db 0x${b[offset].toString(16).padStart(2,'0')}`;
      if(b[offset]===0x90) text='nop'; else if(b[offset]===0xc3) text='ret'; else if(b[offset]===0x55) text='push ebp'; else if(b[offset]===0x68&&offset+5<=end) {length=5;text=`push 0x${readU32(b,offset+1).toString(16)}`;} else if(b[offset]===0x6a&&offset+2<=end) {length=2;text=`push 0x${b[offset+1].toString(16)}`;} else if((b[offset]===0xe8||b[offset]===0xe9)&&offset+5<=end) {length=5;text=`${b[offset]===0xe8?'call':'jmp'} 0x${(atRva+5+b.readInt32LE(offset+1)).toString(16)}`;} else if(b[offset]>=0xb8&&b[offset]<=0xbf&&offset+5<=end) {length=5;text=`mov ${reg[b[offset]-0xb8]}, 0x${readU32(b,offset+1).toString(16)}`;} else if(b[offset]===0x8b&&b[offset+1]===0xec) {length=2;text='mov ebp, esp';} else if(b[offset]===0x83&&b[offset+1]===0xec&&offset+3<=end) {length=3;text=`sub esp, 0x${b[offset+2].toString(16)}`;} else if(b[offset]===0x48&&b[offset+1]===0x89&&b[offset+2]===0xe5) {length=3;text='mov rbp, rsp';} else if(b[offset]===0x48&&b[offset+1]===0x83&&b[offset+2]===0xec&&offset+4<=end) {length=4;text=`sub rsp, 0x${b[offset+3].toString(16)}`;} else if(b[offset]===0x48&&b[offset+1]>=0xb8&&b[offset+1]<=0xbf&&offset+10<=end) {length=10;text=`mov ${reg64[b[offset+1]-0xb8]}, 0x${readU64(b,offset+2).toString(16)}`;}
      instructions.push({rva:atRva,rawOffset:offset,bytes:hex(b.subarray(offset,Math.min(end,offset+length))),text}); offset+=length;
    }
    return {path,architecture:info.magic===0x20b?'x64':'x86',instructions,truncated:offset<end&&instructions.length>=maxInstructions,notes:['This is a bounded instruction decoder, not a decompiler. Unsupported opcodes are emitted as db bytes.']};
  }
  async mssqlSchema(path:string,maxObjects:number) {
    const file=await this.safePath(path); const text=await readFile(file,'utf8'); const objects=mssqlObjects(text,maxObjects); return {format:'mssql-ddl',objects:objects.map(({definition,...object})=>object),tables:parseSqlDdl(text,maxObjects),truncated:objects.length>=maxObjects};
  }
  async mssqlObjectDefinition(path:string,name:string,maxChars:number) {
    const file=await this.safePath(path); const object=mssqlObjects(await readFile(file,'utf8'),1_000).find(value=>value.name.toLowerCase()===name.replace(/[\[\]]/g,'').toLowerCase()); if(!object) throw new ToolError('OBJECT_NOT_FOUND','No matching object definition was found in the DDL export'); return {format:'mssql-ddl',name:object.name,type:object.type,definition:object.definition.slice(0,maxChars),truncated:object.definition.length>maxChars};
  }
  async spfIndex(path:string,maxEntries:number) {
    if(!/\.spf$/i.test(path)) throw new ToolError('FORMAT_DENIED','spf_index only accepts .spf files'); const file=await this.safePath(path); const metadata=await stat(file); const handle=await open(file,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);
    try { const header=Buffer.alloc(Math.min(64,metadata.size)); const {bytesRead}=await handle.read(header,0,header.length,0); const nonEmpty=Math.max(0,Math.ceil(metadata.size/65_536)); const count=Math.min(maxEntries,Math.max(1,nonEmpty)); const entries=Array.from({length:count},(_,index)=>{const offset=index*65_536;return {offset,length:Math.min(65_536,metadata.size-offset),kind:index===0?'header_or_first_block':'raw_block'};}); return {path,size:metadata.size,magicHex:hex(header.subarray(0,Math.min(bytesRead,16))),magicAscii:asciiPreview(header.subarray(0,Math.min(bytesRead,16))),format:'unrecognized_spf_container',entries,truncated:count<nonEmpty,notes:['No verified SPF specification is bundled with this project. Entries are fixed, bounded raw blocks; their offsets may be passed to spf_entry_read_range without claiming game-data semantics.']}; } finally {await handle.close();}
  }
  async spfEntryReadRange(path:string,entryOffset:number,offset:number,length:number) { if(!/\.spf$/i.test(path)) throw new ToolError('FORMAT_DENIED','spf_entry_read_range only accepts .spf files'); return this.binaryReadRange(path,entryOffset+offset,length); }
  async ldtTable(path:string,table:string,limit:number) {
    const file=await this.safePath(path); const extension=path.toLowerCase().split('.').pop(); if(!['ldt','csv','tsv','json'].includes(extension??'')) throw new ToolError('FORMAT_DENIED','ldt_table only accepts LDT, CSV, TSV, or JSON text files'); const data=await readFile(file,'utf8');
    if(extension==='json') {const value=JSON.parse(data) as unknown; const rows=Array.isArray(value)?value:(value&&typeof value==='object'&&Array.isArray((value as Record<string,unknown>)[table])?(value as Record<string,unknown>)[table]:[]); return {format:'json',table,rows:(rows as unknown[]).slice(0,limit)};}
    const delimiter=extension==='tsv'?'\t':','; const lines=data.split(/\r?\n/).filter(Boolean); const headers=(lines.shift()??'').split(delimiter).map(value=>value.trim()); return {format:extension==='ldt'?'ldt-text':'delimited',table,columns:headers,rows:lines.slice(0,limit).map(line=>Object.fromEntries(line.split(delimiter).map((value,index)=>[headers[index]??`column${index+1}`,value.trim()])))};
  }
  async execute(call: Call): Promise<unknown> {
    switch(call.tool) {
      case 'read_file': {const a=argumentSchemas.read_file.parse(call.arguments);return this.read(a.path,a.offset,a.limit);}
      case 'list_files': return this.list(argumentSchemas.list_files.parse(call.arguments).path);
      case 'search_code': {const a=argumentSchemas.search_code.parse(call.arguments);return this.search(a.path,a.query);}
      case 'project_snapshot': return this.snapshot(argumentSchemas.project_snapshot.parse(call.arguments).maxChars);
      case 'git_status': return this.git(['status','--porcelain=v1','--untracked-files=no']);
      case 'git_diff': {
        const a=argumentSchemas.git_diff.parse(call.arguments);
        if (!(await lstat(await this.safePath(a.path))).isFile()) throw new ToolError('INVALID_FILE','Select a regular file');
        // Explicit literal pathspecs prevent caller-controlled git glob magic.
        const paths = [`:(literal)${relative(this.root,await this.safePath(a.path))}`];
        return this.git(['diff','--no-ext-diff','--no-textconv','--no-color',...(a.staged?['--cached']:[]),'--',...paths]);
      }
      case 'apply_patch': return this.applyPatch(argumentSchemas.apply_patch.parse(call.arguments).patch);
      case 'binary_metadata': {const a=argumentSchemas.binary_metadata.parse(call.arguments);return this.binaryMetadata(a.path);}
      case 'binary_strings': {const a=argumentSchemas.binary_strings.parse(call.arguments);return this.binaryStrings(a.path,a.maxResults,a.minLength);}
      case 'binary_imports': {const a=argumentSchemas.binary_imports.parse(call.arguments);return this.binaryImports(a.path,a.maxResults);}
      case 'db_schema': {const a=argumentSchemas.db_schema.parse(call.arguments);return this.dbSchema(a.path,a.maxTables);}
      case 'db_sample_rows': {const a=argumentSchemas.db_sample_rows.parse(call.arguments);return this.dbSampleRows(a.path,a.table,a.limit);}
      case 'file_info': {const a=argumentSchemas.file_info.parse(call.arguments);return this.fileInfo(a.path);}
      case 'binary_read_range': {const a=argumentSchemas.binary_read_range.parse(call.arguments);return this.binaryReadRange(a.path,a.offset,a.length);}
      case 'pe_function_index': {const a=argumentSchemas.pe_function_index.parse(call.arguments);return this.peFunctionIndex(a.path,a.maxFunctions);}
      case 'pe_string_xrefs': {const a=argumentSchemas.pe_string_xrefs.parse(call.arguments);return this.peStringXrefs(a.path,a.stringOffset,a.maxResults);}
      case 'pe_disassemble': {const a=argumentSchemas.pe_disassemble.parse(call.arguments);return this.peDisassemble(a.path,a.rva,a.maxInstructions);}
      case 'mssql_schema': {const a=argumentSchemas.mssql_schema.parse(call.arguments);return this.mssqlSchema(a.path,a.maxObjects);}
      case 'mssql_object_definition': {const a=argumentSchemas.mssql_object_definition.parse(call.arguments);return this.mssqlObjectDefinition(a.path,a.name,a.maxChars);}
      case 'spf_index': {const a=argumentSchemas.spf_index.parse(call.arguments);return this.spfIndex(a.path,a.maxEntries);}
      case 'spf_entry_read_range': {const a=argumentSchemas.spf_entry_read_range.parse(call.arguments);return this.spfEntryReadRange(a.path,a.entryOffset,a.offset,a.length);}
      case 'ldt_table': {const a=argumentSchemas.ldt_table.parse(call.arguments);return this.ldtTable(a.path,a.table,a.limit);}
    }
  }
}
