# Local MCP Studio

Local MCP Studio 是一个桌面开发工具：在一个应用窗口中选择本地项目、启动标准 MCP 服务、建立 Cloudflare Tunnel，并打开 Arena Agent。目标是让支持 Custom MCP Connector 的网页 AI 原生调用本地工具，而不是通过浏览器扩展把 `tool_call` 与 `tool_result` JSON 发送回聊天框。

## 当前完成情况

| 能力 | 状态 | 说明 |
| --- | --- | --- |
| Electron 桌面窗口 | 已完成 | 包含工作区、Bridge、Tunnel、MCP 地址与 Arena 面板。 |
| 工作区隔离 | 已完成 | 拒绝绝对路径、父级跳转、符号链接和敏感文件。 |
| 标准 Streamable HTTP MCP | 已完成 | `initialize`、`notifications/initialized`、`ping`、`tools/list`、`tools/call`、会话 header，以及 SSE `GET` 保活端点。 |
| 本地工具 | 已完成 | 读文件、列目录、搜索、项目快照、Git 状态、单文件 Diff。 |
| 二进制证据工具 | 已完成 | `binary_metadata`、`binary_strings`、`binary_imports`；只读解析 PE 文件并限制大小与结果数量。 |
| 数据库证据工具 | 已完成 | `db_schema`、`db_sample_rows`；支持 SQLite、SQL DDL、CSV/JSON 样例；SQL Server MDF 需要外部 Windows/SQL Server 运行时。 |
| 函数级证据工具 | 已完成 | `file_info`、有界原始字节读取、PE 函数索引、字符串静态交叉引用和有界反汇编。 |
| S1 DDL 与数据容器工具 | 已完成 | MSSQL schema-only DDL 对象读取、SPF 有界原始块、以及文本 LDT/CSV/TSV/JSON 表读取。 |
| 补丁修改 | 已完成 | `apply_patch` 只接受受限 unified diff，并在桌面应用中等待本地批准。 |
| Cloudflare Quick Tunnel | 已完成 | 调用本机 `cloudflared`，自动解析 `trycloudflare.com` 地址。 |
| Arena 面板 | 已完成 | 应用内打开 `https://arena.ai/agent`，保留登录会话。 |
| Cloudflare 安装与诊断 | 已完成 | 应用在找不到 `cloudflared` 时给出明确提示；本机已安装官方 Cloudflare Tunnel CLI。 |
| Tunnel 公网健康检查 | 已完成 | Quick Tunnel 建立后会重试请求带 token 的 MCP 端点；仅 `404 Unknown MCP session` 才证明公网入口可达。 |
| 长时间任务与终端 | 待完成 | 第一版没有 shell、持久终端或进程管理。 |
| LSP / 编辑器 / Diff 审阅 | 待完成 | 当前有补丁批准文本；尚未提供完整代码编辑器与视觉 Diff。 |
| 分发安装包 | 待完成 | 当前可通过 Electron 开发模式运行，尚未配置 macOS / Windows 安装包。 |
| Arena MCP 兼容性验证 | 待验证 | Arena 是否能连接任意 Custom MCP URL 需用运行中的地址实测；不能仅根据页面或过往现象推断。 |
| 本地演示账号状态机 | 已完成 | JavaScript 版注册、持久化、恢复和自动登录，仅使用本机 `userData`，不连接第三方注册服务。 |

## 运行

需要 Node.js 22+，以及用于公网 Connector 的 `cloudflared`。只在同一台机器上使用本地 MCP Client 时无需 Cloudflare Tunnel。

```bash
npm install
npm run desktop
```

在应用中依次完成：

1. 选择项目工作目录。
2. 点击“启动本地服务”。应用生成一条仅在本机可访问的 MCP URL。
3. 点击“启动 Cloudflare Tunnel”。成功后 URL 切换为带随机 token 的临时 HTTPS 地址。
4. 点击“复制”，在 Arena 或其他支持 Custom MCP Connector 的网页 AI 中添加该地址。
5. 让模型读取、搜索和检查项目。模型请求补丁时，桌面应用会显示 diff，必须由本机用户批准才会应用。

Quick Tunnel 地址会在 Tunnel 停止或网络重连后改变；重新启动时必须复制新的 MCP 地址。

## MCP 端点与安全边界

桌面应用启动后生成的地址形式如下：

```text
http://127.0.0.1:<port>/mcp/<随机 token>
https://<随机子域>.trycloudflare.com/mcp/<随机 token>
```

随机 token 是 URL 路径的一部分，使不能设置 `Authorization` header 的网页 Connector 也能接入。不要把该地址发给无关人员，也不要在不允许将代码发送到网页 AI 的项目中启动 Tunnel。

工具不会访问工作目录以外的路径；`.env`、SSH/AWS 凭据、私钥、Git 元数据和符号链接均被排除。`apply_patch` 禁止二进制补丁与重命名，并始终需要应用内批准。第一版没有命令执行工具，因此模型不能运行 shell 命令、安装依赖或自行启动服务。

证据工具也不提供任意命令执行：PE 工具只读取文件头、节区、导入表、可打印字符串、静态机器码引用与有界指令；数据库工具以只读方式打开 SQLite，或解析 SQL DDL/数据文件。`.mdf`、`.ndf`、`.ldf` 不会被当作普通二进制猜测解析，而会明确提示需要 SQL Server 运行时。`spf_index` 也不会臆测私有游戏格式：在没有格式规范时，它只报告固定的有界原始块；`ldt_table` 只处理文本型 LDT/CSV/TSV/JSON。

## 架构

```text
Arena / 其他网页 AI 的 MCP Connector
                │ HTTPS
                ▼
Cloudflare Quick Tunnel（可选；云端 Connector 需要）
                │
                ▼
本机 Streamable HTTP MCP Server
                │
                ├── 受限工作区读取与 Git 工具
                └── 补丁批准窗口 → apply_patch
```

旧的 `extension/` 目录仍保留，供已有用户继续排查浏览器扩展版本；它使用 JSON 回填协议，不是桌面应用的推荐路径，也不会在 `npm run desktop` 中启用。

## 验证与开发

```bash
npm test
npm run build
```

测试覆盖路径隔离、敏感文件与符号链接、Git 外部 diff 防护、旧 Bridge 鉴权，以及 MCP 初始化、工具发现、调用、会话和 token 保护。

`npm run dev` 仍可单独启动旧的本地 Bridge，便于兼容性调试；桌面产品入口为 `npm run desktop`。
# arena
