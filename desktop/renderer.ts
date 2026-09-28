type BridgeState={workspace:string|null;localUrl:string|null;mcpUrl:string|null;tunnelUrl:string|null;bridge:'stopped'|'running';tunnel:'stopped'|'starting'|'running'|'error';message:string}; type DemoAuthState={phase:'idle'|'registered'|'authenticated';account:{email:string;name:string}|null;message:string};
type Approval={id:string;tool:'apply_patch';arguments:{patch:string}};
declare global { interface Window { mcpStudio:{chooseWorkspace:()=>Promise<BridgeState>;startBridge:()=>Promise<BridgeState>;stopBridge:()=>Promise<BridgeState>;startTunnel:()=>Promise<BridgeState>;stopTunnel:()=>Promise<BridgeState>;copyMcpUrl:()=>Promise<string>;state:()=>Promise<BridgeState>;demoState:()=>Promise<DemoAuthState>;demoRegister:()=>Promise<DemoAuthState>;demoLogin:()=>Promise<DemoAuthState>;respondApproval:(id:string,approved:boolean)=>Promise<void>;onState:(listener:(state:BridgeState)=>void)=>void;onApproval:(listener:(request:Approval)=>void)=>void;} } }
const element=<T extends HTMLElement>(id:string)=>document.getElementById(id) as T;
const choose=element<HTMLButtonElement>('choose-workspace'); const startBridge=element<HTMLButtonElement>('start-bridge'); const startTunnel=element<HTMLButtonElement>('start-tunnel'); const stopTunnel=element<HTMLButtonElement>('stop-tunnel'); const copy=element<HTMLButtonElement>('copy-url');
const approval=element<HTMLDialogElement>('approval-dialog'); let activeApproval:Approval|undefined;
const demoStatus=element<HTMLElement>('demo-auth-status');
function busy(button:HTMLButtonElement,promise:()=>Promise<unknown>) { const original=button.textContent; button.disabled=true; button.textContent='处理中…'; return promise().catch(error=>render({...current,message:error instanceof Error?error.message:'操作失败'})).finally(()=>{button.disabled=false;button.textContent=original;}); }
let current:BridgeState={workspace:null,localUrl:null,mcpUrl:null,tunnelUrl:null,bridge:'stopped',tunnel:'stopped',message:'Choose a workspace to begin.'};
function render(state:BridgeState) {
  current=state;
  element('workspace-path').textContent=state.workspace??'尚未选择工作目录';
  element('message').textContent=state.message;
  const connection=element('connection'); connection.innerHTML=`<span class="dot ${state.tunnel==='running'?'running':state.bridge==='running'?'local':'stopped'}"></span><span>${state.tunnel==='running'?'Tunnel 已连接':state.bridge==='running'?'本地 MCP 已运行':'尚未启动'}</span>`;
  element('bridge-badge').textContent=state.bridge==='running'?'运行中':state.workspace?'准备就绪':'等待工作目录';
  element('tunnel-badge').textContent=state.tunnel==='running'?'已连接':state.tunnel==='starting'?'连接中':state.tunnel==='error'?'需处理':'未启动';
  element('url-badge').textContent=state.tunnel==='running'?'公网 MCP':'仅本地';
  element('mcp-url').textContent=state.mcpUrl??'先启动本地 MCP 服务';
  startBridge.disabled=!state.workspace || state.bridge==='running'; startBridge.textContent=state.bridge==='running'?'本地服务运行中':'启动本地服务';
  startTunnel.disabled=state.bridge!=='running'||state.tunnel==='running'||state.tunnel==='starting'; stopTunnel.disabled=state.tunnel!=='running'&&state.tunnel!=='starting'; copy.disabled=!state.mcpUrl;
}
choose.onclick=()=>void busy(choose,()=>window.mcpStudio.chooseWorkspace());
startBridge.onclick=()=>void busy(startBridge,()=>window.mcpStudio.startBridge());
startTunnel.onclick=()=>void busy(startTunnel,()=>window.mcpStudio.startTunnel());
stopTunnel.onclick=()=>void busy(stopTunnel,()=>window.mcpStudio.stopTunnel());
copy.onclick=()=>void busy(copy,async()=>{await window.mcpStudio.copyMcpUrl();render({...current,message:'MCP 地址已复制。请在网页 AI 的 Connector 设置中粘贴它。'});});
element<HTMLButtonElement>('reload-arena').onclick=()=>{const view=document.getElementById('arena') as HTMLElement & {reload:()=>void}; view.reload();};
element<HTMLButtonElement>('approve-approval').onclick=()=>{if(activeApproval) void window.mcpStudio.respondApproval(activeApproval.id,true); activeApproval=undefined;};
element<HTMLButtonElement>('reject-approval').onclick=()=>{if(activeApproval) void window.mcpStudio.respondApproval(activeApproval.id,false); activeApproval=undefined;};
window.mcpStudio.onState(render);
window.mcpStudio.onApproval(request=>{activeApproval=request;element('approval-patch').textContent=request.arguments.patch;approval.showModal();});
const renderDemo=(state:DemoAuthState)=>{demoStatus.textContent=state.account?`${state.message}（${state.account.email}）`:state.message;};
element<HTMLButtonElement>('demo-register').onclick=()=>void window.mcpStudio.demoRegister().then(renderDemo);
element<HTMLButtonElement>('demo-login').onclick=()=>void window.mcpStudio.demoLogin().then(renderDemo);
void window.mcpStudio.state().then(render);
void window.mcpStudio.demoState().then(renderDemo);
