import { ProjectTools } from './tools.js';
import { createBridge } from './bridge.js';
const root=process.env.PROJECT_ROOT;
if(!root) throw new Error('Set PROJECT_ROOT to an explicit absolute project directory');
const port=Number(process.env.BRIDGE_PORT??4318);
if(!Number.isInteger(port)||port<1024||port>65535) throw new Error('Invalid BRIDGE_PORT');
const server=createBridge(await ProjectTools.create(root),process.env.BRIDGE_TOKEN??'',process.env.EXTENSION_ID);
server.requestTimeout=10_000;server.headersTimeout=5000;
server.on('error',(error: NodeJS.ErrnoException)=>{
  if(error.code==='EADDRINUSE') console.error(`Bridge failed to listen: port ${port} is already in use; stop the existing Bridge or set BRIDGE_PORT to another port`);
  else console.error(`Bridge failed to listen on port ${port}: ${error.message}`);
  process.exitCode=1;
});
server.listen(port,'127.0.0.1',()=>console.info(`Bridge listening at http://127.0.0.1:${port}`));
for(const signal of ['SIGINT','SIGTERM'] as const) process.on(signal,()=>server.close());
