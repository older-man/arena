import { createHash, randomBytes } from 'node:crypto';

export type DemoAccount = { email:string; password:string; name:string; createdAt:string; verified:boolean };
export type DemoAuthState = { phase:'idle'|'registered'|'authenticated'; account:DemoAccount|null; message:string };

export interface DemoAccountStore { load(): Promise<DemoAccount|null>; save(account:DemoAccount): Promise<void>; }

export class MemoryDemoAccountStore implements DemoAccountStore {
  private account:DemoAccount|null=null;
  async load() { return this.account; }
  async save(account:DemoAccount) { this.account=account; }
}

export class DemoAuthFlow {
  private state:DemoAuthState={phase:'idle',account:null,message:'演示账号尚未创建'};
  constructor(private readonly store:DemoAccountStore, private readonly now=()=>new Date()) {}
  async restore():Promise<DemoAuthState> {
    const account=await this.store.load();
    this.state=account?{phase:'registered',account,message:'演示账号已保存，可自动登录'}:{phase:'idle',account:null,message:'演示账号尚未创建'};
    return this.state;
  }
  async register(name='Local Demo User'):Promise<DemoAuthState> {
    const existing=await this.store.load();
    if(existing) { this.state={phase:'registered',account:existing,message:'演示账号已存在，未重复创建'}; return this.state; }
    const account:DemoAccount={email:`demo-${randomBytes(5).toString('hex')}@local.test`,password:randomBytes(12).toString('base64url'),name,createdAt:this.now().toISOString(),verified:true};
    await this.store.save(account);
    this.state={phase:'registered',account,message:'演示账号已创建并保存'};
    return this.state;
  }
  async login(password?:string):Promise<DemoAuthState> {
    const account=await this.store.load();
    if(!account) { this.state={phase:'idle',account:null,message:'请先创建演示账号'}; return this.state; }
    if(password!==undefined && !safeEqual(password,account.password)) { this.state={phase:'registered',account,message:'演示账号密码不匹配'}; return this.state; }
    this.state={phase:'authenticated',account,message:`已自动登录演示账号 ${account.email}`};
    return this.state;
  }
  get current() { return this.state; }
}

function safeEqual(a:string,b:string) {
  return createHash('sha256').update(a).digest('hex')===createHash('sha256').update(b).digest('hex');
}
