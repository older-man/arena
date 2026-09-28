import { app, BrowserWindow, clipboard, dialog, ipcMain } from 'electron';
import { randomBytes } from 'node:crypto';
import { spawn, type ChildProcess } from 'node:child_process';
import { createBridge } from '../bridge.js';
import { ApprovalGate } from '../mcp.js';
import { ProjectTools } from '../tools.js';
import { probePublicMcp } from '../tunnel-probe.js';
import { DemoAuthFlow, type DemoAccountStore, type DemoAccount } from '../demo-auth.js';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';

type BridgeState = {workspace:string|null; localUrl:string|null; mcpUrl:string|null; tunnelUrl:string|null; bridge:'stopped'|'running'; tunnel:'stopped'|'starting'|'running'|'error'; message:string};
let windowRef: BrowserWindow|undefined;
let server: ReturnType<typeof createBridge>|undefined;
let tunnel: ChildProcess|undefined;
let token:string|undefined;
let approval: ApprovalGate|undefined;
let state: BridgeState={workspace:null,localUrl:null,mcpUrl:null,tunnelUrl:null,bridge:'stopped',tunnel:'stopped',message:'Choose a workspace to begin.'};
let demoFlow: DemoAuthFlow|undefined;
const demoStore=(file:string):DemoAccountStore=>({load:async()=>{try{return JSON.parse(await readFile(file,'utf8')) as DemoAccount;}catch{return null;}},save:async account=>{await mkdir(join(file,'..'),{recursive:true});await writeFile(file,JSON.stringify(account,null,2),'utf8');}});

function publish(next: Partial<BridgeState>={}) { state={...state,...next}; windowRef?.webContents.send('bridge:state',state); }
function createWindow() {
  windowRef=new BrowserWindow({width:1440,height:920,minWidth:960,minHeight:660,backgroundColor:'#0f172a',webPreferences:{preload:import.meta.dirname+'/preload.js',contextIsolation:true,nodeIntegration:false,webviewTag:true,sandbox:false}});
  void windowRef.loadFile(import.meta.dirname+'/../../desktop/index.html');
}
async function stopTunnel() {
  if (!tunnel) return;
  const active=tunnel; tunnel=undefined; active.kill('SIGTERM');
  publish({tunnel:'stopped',tunnelUrl:null,message:'Tunnel stopped. The local MCP service is still running.'});
}
async function stopBridge() {
  await stopTunnel(); approval?.rejectAll(); approval=undefined;
  if (server) { server.closeAllConnections(); await new Promise<void>(resolve=>server!.close(()=>resolve())); server=undefined; }
  token=undefined; publish({localUrl:null,mcpUrl:null,tunnelUrl:null,bridge:'stopped',tunnel:'stopped',message:'Bridge stopped.'});
}
async function startBridge(workspace: string) {
  await stopBridge();
  const project=await ProjectTools.create(workspace); token=randomBytes(32).toString('base64url'); approval=new ApprovalGate();
  approval.on('requested',request=>windowRef?.webContents.send('approval:requested',request));
  server=createBridge(project,token,undefined,approval);
  server.on('error',error=>publish({bridge:'stopped',message:`Bridge error: ${error.message}`}));
  await new Promise<void>((resolve,reject)=>server!.once('error',reject).listen(0,'127.0.0.1',resolve));
  const address=server.address(); if (!address || typeof address==='string') throw new Error('Bridge did not expose a local port');
  const localUrl=`http://127.0.0.1:${address.port}/mcp/${token}`;
  publish({workspace,localUrl,mcpUrl:localUrl,bridge:'running',tunnel:'stopped',message:'Local MCP service is running. Start a tunnel to let cloud-hosted connectors reach it.'});
}
async function demoAuth() {
  const root=app.getPath('userData'); const file=join(root,'demo-account.json');
  demoFlow ??= new DemoAuthFlow(demoStore(file)); await demoFlow.restore(); return demoFlow;
}
async function startTunnel() {
  if (!server || !token || !state.localUrl) throw new Error('Start the local MCP service first');
  await stopTunnel();
  const localBase=new URL(state.localUrl); const target=`http://127.0.0.1:${localBase.port}`;
  publish({tunnel:'starting',message:'Starting Cloudflare Quick Tunnel…'});
  try {
    const started=spawn('cloudflared',['tunnel','--url',target],{stdio:['ignore','pipe','pipe'],windowsHide:true});
    tunnel=started;
    let publicMcpUrl: string|undefined;
    const observe=(chunk:Buffer)=>{
      const line=String(chunk); const match=line.match(/https:\/\/[a-z0-9-]+\.trycloudflare\.com/i);
      if (match && token && !publicMcpUrl) {
        publicMcpUrl=`${match[0]}/mcp/${token}`;
        publish({tunnel:'running',tunnelUrl:match[0],mcpUrl:publicMcpUrl,message:'Tunnel is ready. Checking the public MCP endpoint…'});
        void probePublicMcp(publicMcpUrl).then(result=>{
          if (tunnel===started) publish({message:result.ready?'Tunnel is ready and the public MCP health check passed. Copy the MCP address into your AI connector.':`${result.message} You can retry by restarting the tunnel.`});
        });
      }
    };
    started.stdout.on('data',observe); started.stderr.on('data',observe);
    started.once('error',()=>publish({tunnel:'error',message:'cloudflared was not found. Install it, then start the tunnel again.'}));
    started.once('exit',code=>{if (tunnel===started) { tunnel=undefined; publish({tunnel:'error',tunnelUrl:null,mcpUrl:state.localUrl,message:`Cloudflare Tunnel stopped${code===0?'':` (exit ${code})`}.`}); }});
  } catch { publish({tunnel:'error',message:'cloudflared could not start. Install Cloudflare Tunnel and ensure it is on PATH.'}); return; }
}

app.whenReady().then(()=>{
  createWindow();
  ipcMain.handle('workspace:choose',async()=>{ const result=await dialog.showOpenDialog(windowRef!,{properties:['openDirectory','createDirectory']}); if (!result.canceled && result.filePaths[0]) publish({workspace:result.filePaths[0],message:'Workspace selected. Start the local MCP service when ready.'}); return state; });
  ipcMain.handle('bridge:start',async()=>{ if (!state.workspace) throw new Error('Choose a workspace first'); await startBridge(state.workspace); return state; });
  ipcMain.handle('bridge:stop',async()=>{await stopBridge(); return state;});
  ipcMain.handle('tunnel:start',async()=>{await startTunnel(); return state;});
  ipcMain.handle('tunnel:stop',async()=>{await stopTunnel(); return state;});
  ipcMain.handle('mcp:copy',()=>{if (!state.mcpUrl) throw new Error('No MCP address is available'); clipboard.writeText(state.mcpUrl); return state.mcpUrl;});
  ipcMain.handle('approval:respond',(_event,id:string,approved:boolean)=>{if (approved) approval?.approve(id); else approval?.reject(id);});
  ipcMain.handle('bridge:state',()=>state);
  ipcMain.handle('demo-auth:state',async()=>{const flow=await demoAuth();return flow.current;});
  ipcMain.handle('demo-auth:register',async()=>{const flow=await demoAuth();return flow.register();});
  ipcMain.handle('demo-auth:login',async()=>{const flow=await demoAuth();return flow.login();});
  app.on('activate',()=>{if (BrowserWindow.getAllWindows().length===0) createWindow();});
});
app.on('window-all-closed',()=>{ if (process.platform!=='darwin') app.quit(); });
app.on('before-quit',()=>{ void stopBridge(); });
