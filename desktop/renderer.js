"use strict";
(() => {
  // desktop/renderer.ts
  var element = (id) => document.getElementById(id);
  var choose = element("choose-workspace");
  var startBridge = element("start-bridge");
  var startTunnel = element("start-tunnel");
  var stopTunnel = element("stop-tunnel");
  var copy = element("copy-url");
  var approval = element("approval-dialog");
  var activeApproval;
  var demoStatus = element("demo-auth-status");
  function busy(button, promise) {
    const original = button.textContent;
    button.disabled = true;
    button.textContent = "\u5904\u7406\u4E2D\u2026";
    return promise().catch((error) => render({ ...current, message: error instanceof Error ? error.message : "\u64CD\u4F5C\u5931\u8D25" })).finally(() => {
      button.disabled = false;
      button.textContent = original;
    });
  }
  var current = { workspace: null, localUrl: null, mcpUrl: null, tunnelUrl: null, bridge: "stopped", tunnel: "stopped", message: "Choose a workspace to begin." };
  function render(state) {
    current = state;
    element("workspace-path").textContent = state.workspace ?? "\u5C1A\u672A\u9009\u62E9\u5DE5\u4F5C\u76EE\u5F55";
    element("message").textContent = state.message;
    const connection = element("connection");
    connection.innerHTML = `<span class="dot ${state.tunnel === "running" ? "running" : state.bridge === "running" ? "local" : "stopped"}"></span><span>${state.tunnel === "running" ? "Tunnel \u5DF2\u8FDE\u63A5" : state.bridge === "running" ? "\u672C\u5730 MCP \u5DF2\u8FD0\u884C" : "\u5C1A\u672A\u542F\u52A8"}</span>`;
    element("bridge-badge").textContent = state.bridge === "running" ? "\u8FD0\u884C\u4E2D" : state.workspace ? "\u51C6\u5907\u5C31\u7EEA" : "\u7B49\u5F85\u5DE5\u4F5C\u76EE\u5F55";
    element("tunnel-badge").textContent = state.tunnel === "running" ? "\u5DF2\u8FDE\u63A5" : state.tunnel === "starting" ? "\u8FDE\u63A5\u4E2D" : state.tunnel === "error" ? "\u9700\u5904\u7406" : "\u672A\u542F\u52A8";
    element("url-badge").textContent = state.tunnel === "running" ? "\u516C\u7F51 MCP" : "\u4EC5\u672C\u5730";
    element("mcp-url").textContent = state.mcpUrl ?? "\u5148\u542F\u52A8\u672C\u5730 MCP \u670D\u52A1";
    startBridge.disabled = !state.workspace || state.bridge === "running";
    startBridge.textContent = state.bridge === "running" ? "\u672C\u5730\u670D\u52A1\u8FD0\u884C\u4E2D" : "\u542F\u52A8\u672C\u5730\u670D\u52A1";
    startTunnel.disabled = state.bridge !== "running" || state.tunnel === "running" || state.tunnel === "starting";
    stopTunnel.disabled = state.tunnel !== "running" && state.tunnel !== "starting";
    copy.disabled = !state.mcpUrl;
  }
  choose.onclick = () => void busy(choose, () => window.mcpStudio.chooseWorkspace());
  startBridge.onclick = () => void busy(startBridge, () => window.mcpStudio.startBridge());
  startTunnel.onclick = () => void busy(startTunnel, () => window.mcpStudio.startTunnel());
  stopTunnel.onclick = () => void busy(stopTunnel, () => window.mcpStudio.stopTunnel());
  copy.onclick = () => void busy(copy, async () => {
    await window.mcpStudio.copyMcpUrl();
    render({ ...current, message: "MCP \u5730\u5740\u5DF2\u590D\u5236\u3002\u8BF7\u5728\u7F51\u9875 AI \u7684 Connector \u8BBE\u7F6E\u4E2D\u7C98\u8D34\u5B83\u3002" });
  });
  element("reload-arena").onclick = () => {
    const view = document.getElementById("arena");
    view.reload();
  };
  element("approve-approval").onclick = () => {
    if (activeApproval) void window.mcpStudio.respondApproval(activeApproval.id, true);
    activeApproval = void 0;
  };
  element("reject-approval").onclick = () => {
    if (activeApproval) void window.mcpStudio.respondApproval(activeApproval.id, false);
    activeApproval = void 0;
  };
  window.mcpStudio.onState(render);
  window.mcpStudio.onApproval((request) => {
    activeApproval = request;
    element("approval-patch").textContent = request.arguments.patch;
    approval.showModal();
  });
  var renderDemo = (state) => {
    demoStatus.textContent = state.account ? `${state.message}\uFF08${state.account.email}\uFF09` : state.message;
  };
  element("demo-register").onclick = () => void window.mcpStudio.demoRegister().then(renderDemo);
  element("demo-login").onclick = () => void window.mcpStudio.demoLogin().then(renderDemo);
  void window.mcpStudio.state().then(render);
  void window.mcpStudio.demoState().then(renderDemo);
})();
