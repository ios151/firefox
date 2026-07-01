"""Local web control panel for fxproxy.

Run ``fxproxy web`` (or pick it from the interactive menu) to open a small
dashboard at http://127.0.0.1:8765 where you can start/stop the proxy,
switch egress country, and watch the quota — no command line needed.
"""
from __future__ import annotations

import asyncio
import json
import urllib.request
import webbrowser

from aiohttp import web

from . import config as cfgmod
from . import fxa_auth
from .guardian import GuardianClient, NotEnrolledError
from .proxyserver import NodePicker, ProxyServer

PAGE = """<!doctype html>
<html lang="zh">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>fxproxy 控制面板</title>
<style>
  :root { color-scheme: dark; }
  * { box-sizing: border-box; }
  body { margin:0; font-family: system-ui, "Segoe UI", "PingFang SC", sans-serif;
         background:#0e1116; color:#e6edf3; }
  .wrap { max-width:720px; margin:0 auto; padding:24px 18px 60px; }
  h1 { font-size:20px; margin:0 0 4px; }
  .sub { color:#8b949e; font-size:13px; margin-bottom:20px; }
  .card { background:#161b22; border:1px solid #30363d; border-radius:12px;
          padding:18px; margin-bottom:16px; }
  .row { display:flex; align-items:center; gap:12px; flex-wrap:wrap; }
  label { font-size:13px; color:#8b949e; }
  select, button, input { font-size:14px; border-radius:8px; border:1px solid #30363d;
          padding:9px 12px; background:#0d1117; color:#e6edf3; }
  input { min-width:200px; }
  input::placeholder { color:#6e7681; }
  button { cursor:pointer; border-color:#2ea043; }
  button.primary { background:#238636; border-color:#2ea043; color:#fff; font-weight:600; }
  button.stop { background:#da3633; border-color:#f85149; color:#fff; font-weight:600; }
  button:disabled { opacity:.5; cursor:not-allowed; }
  .pill { display:inline-block; padding:3px 10px; border-radius:999px; font-size:12px; font-weight:600; }
  .on { background:#238636; color:#fff; }
  .off { background:#484f58; color:#fff; }
  .kv { display:flex; justify-content:space-between; padding:6px 0;
        border-bottom:1px dashed #21262d; font-size:14px; }
  .kv:last-child { border-bottom:0; }
  .kv b { color:#e6edf3; font-weight:600; }
  .bar { height:8px; background:#21262d; border-radius:999px; overflow:hidden; margin-top:6px; }
  .bar > i { display:block; height:100%; background:#2ea043; }
  code { background:#0d1117; padding:2px 6px; border-radius:6px; font-size:13px; }
  .muted { color:#8b949e; font-size:12px; margin-top:8px; }
  .egress { font-size:15px; }
</style>
</head>
<body>
<div class="wrap">
  <h1>fxproxy 控制面板</h1>
  <div class="sub">Firefox IP Protection · 每月 50GB 落地代理（仅海外用途，非翻墙）</div>

  <div class="card" id="loginCard" style="display:none;">
    <div class="row" style="margin-bottom:10px;">
      <b>① 登录 / 入组</b>
      <span class="muted">还没凭证？用 Firefox 账号登录，成功后自动入组并保存。</span>
    </div>
    <div class="row">
      <label>方式</label>
      <select id="loginMode">
        <option value="token">直接粘贴 refresh_token（最稳）</option>
        <option value="password">邮箱 + 密码</option>
        <option value="session">sessionToken</option>
      </select>
    </div>
    <div id="rtFields" class="row" style="margin-top:10px;">
      <input id="refreshToken" placeholder="粘贴 refresh_token (hex)" style="width:100%;">
    </div>
    <div id="pwFields" class="row" style="margin-top:10px; display:none;">
      <input id="email" type="email" placeholder="FxA 邮箱">
      <input id="password" type="password" placeholder="FxA 密码">
    </div>
    <div id="stFields" class="row" style="margin-top:10px; display:none;">
      <input id="sessionToken" placeholder="粘贴 sessionToken (hex)" style="width:100%;">
    </div>
    <div class="row" style="margin-top:10px;">
      <label>默认出口</label>
      <input id="loginCountry" placeholder="US / GB / 留空=任意" style="width:140px;">
      <button id="loginBtn" class="primary">登录并保存</button>
      <button id="browserBtn">浏览器登录（推荐新用户）</button>
      <span id="loginMsg" class="muted"></span>
    </div>
    <div class="muted">提示：邮箱密码登录常被 Mozilla 风控拦（返回非 JSON / 406）。
        最省事是选「直接粘贴 refresh_token」——把已有的凭证贴进来即可，任意网络都能用。</div>
  </div>

  <div class="card">
    <div class="row">
      <span>状态：</span><span id="state" class="pill off">未运行</span>
      <span id="listen" class="muted"></span>
    </div>
    <div class="row" style="margin-top:14px;">
      <label>出口国家</label>
      <select id="country"><option value="">任意</option></select>
      <button id="startBtn" class="primary">启动</button>
      <button id="stopBtn" class="stop" disabled>停止</button>
      <button id="testBtn">测试出口 IP</button>
    </div>
    <div id="nodeWarn" style="display:none;margin-top:8px;color:#f0b400;font-size:13px;"></div>
    <div id="egress" class="egress muted"></div>
  </div>

  <div class="card">
    <div class="kv"><span>账号 uid</span><b id="uid">—</b></div>
    <div class="kv"><span>月度配额</span><b id="quota">—</b></div>
    <div class="kv"><span>剩余</span><b id="remain">—</b></div>
    <div class="bar"><i id="rembar" style="width:0"></i></div>
    <div class="kv" style="margin-top:8px;"><span>重置时间</span><b id="reset">—</b></div>
  </div>

  <div class="card">
    <div class="muted">在浏览器/系统里把代理设为：</div>
    <div style="margin-top:6px;">HTTP：<code id="httpAddr">127.0.0.1:8080</code>　
        SOCKS5：<code id="socksAddr">127.0.0.1:1080</code></div>
    <div class="row" style="margin-top:14px;">
      <button id="copyCfgBtn">复制配置（config.json）</button>
      <span id="copyMsg" class="muted"></span>
    </div>
    <div class="muted" style="margin-top:6px;font-size:12px;">
      含你的 refresh_token，可直接粘到服务器的 <code>~/.config/fxproxy/config.json</code>（对外用记得把 host 改成 0.0.0.0）。——凭证是私密信息，别外传。
    </div>
  </div>
</div>
<script>
const $ = id => document.getElementById(id);
function fmt(b){ if(b==null) return "—"; const u=["B","KiB","MiB","GiB","TiB"]; let i=0,v=b;
  while(v>=1024&&i<u.length-1){v/=1024;i++;} return v.toFixed(v<10&&i>0?2:0)+u[i]; }

let NODE_COUNTS = {};   // country code -> number of nodes
async function loadServers(){
  const r = await fetch("/api/servers"); const d = await r.json();
  const sel = $("country");
  d.countries.forEach(c => { const o=document.createElement("option");
    o.value=c.code; o.textContent=c.code+" — "+c.name+" ("+c.nodes+")"; sel.appendChild(o);
    NODE_COUNTS[c.code] = c.nodes; });
  updateNodeWarn();
}
function updateNodeWarn(){
  const code = $("country").value;
  const n = NODE_COUNTS[code];
  if(code && n === 1){
    $("nodeWarn").style.display = "block";
    $("nodeWarn").textContent = "⚠ 该国仅 1 个节点，偶发超时时无法自动切换，建议改用节点多的 US / GB / DE。";
  } else {
    $("nodeWarn").style.display = "none";
  }
}
async function loadStatus(){
  try{ const r = await fetch("/api/status"); const q = await r.json();
    if(q.error){ $("quota").textContent=q.error; return; }
    $("uid").textContent=q.uid; $("quota").textContent=fmt(q.max_bytes);
    if(q.remaining_bytes!=null){ const pct=100*q.remaining_bytes/q.max_bytes;
      $("remain").textContent=fmt(q.remaining_bytes)+" ("+pct.toFixed(1)+"%)";
      $("rembar").style.width=pct+"%"; }
    $("reset").textContent=q.reset||"—";
  }catch(e){}
}
let AUTHED = false;
let userPicked = false;
async function loadState(){
  const r = await fetch("/api/state"); const s = await r.json();
  AUTHED = !!s.authed;
  $("loginCard").style.display = AUTHED ? "none" : "block";
  $("state").className = "pill "+(s.running?"on":"off");
  $("state").textContent = s.running ? "运行中" : (AUTHED ? "未运行" : "未登录");
  // keep 启动 enabled while running so it can switch egress country (restart)
  $("startBtn").disabled = !AUTHED; $("stopBtn").disabled = !s.running;
  $("startBtn").textContent = s.running ? "切换/重启" : "启动";
  $("testBtn").disabled = !AUTHED;
  $("httpAddr").textContent = s.host+":"+s.http_port;
  $("socksAddr").textContent = s.host+":"+s.socks_port;
  $("listen").textContent = s.running ? ("出口："+(s.country||"任意")) : "";
  // only sync the dropdown to the running country until the user picks one,
  // otherwise the 5s poll would keep snapping their selection back.
  if(!userPicked && s.running && s.country){ $("country").value = s.country; updateNodeWarn(); }
}
$("loginMode").onchange = () => {
  const m = $("loginMode").value;
  $("rtFields").style.display = m === "token" ? "flex" : "none";
  $("pwFields").style.display = m === "password" ? "flex" : "none";
  $("stFields").style.display = m === "session" ? "flex" : "none";
};
$("loginBtn").onclick = async () => {
  $("loginBtn").disabled = true; $("loginMsg").textContent = "处理中，请稍候…";
  const body = { mode: $("loginMode").value, country: $("loginCountry").value,
    email: $("email").value, password: $("password").value,
    session_token: $("sessionToken").value,
    refresh_token: $("refreshToken").value };
  const r = await fetch("/api/login",{method:"POST",
    headers:{"Content-Type":"application/json"}, body:JSON.stringify(body)});
  const d = await r.json(); $("loginBtn").disabled = false;
  if(d.error){ $("loginMsg").textContent = "登录失败：" + d.error; return; }
  $("loginMsg").textContent = "登录成功，已保存凭证。";
  $("password").value = ""; $("sessionToken").value = "";
  await loadState(); await loadStatus();
};
$("browserBtn").onclick = async () => {
  $("browserBtn").disabled = true;
  $("loginMsg").textContent = "已请求打开浏览器，请在弹出的窗口里登录（或注册）你的 Firefox 账号，完成后自动保存 …";
  const r = await fetch("/api/login",{method:"POST",
    headers:{"Content-Type":"application/json"},
    body:JSON.stringify({mode:"browser", country:$("loginCountry").value})});
  const d = await r.json(); $("browserBtn").disabled = false;
  if(d.error){ $("loginMsg").textContent = "登录失败：" + d.error; return; }
  $("loginMsg").textContent = "登录成功，已保存凭证。";
  await loadState(); await loadStatus();
};
$("country").onchange = () => { userPicked = true; updateNodeWarn(); };
$("startBtn").onclick = async () => {
  $("startBtn").disabled=true; $("startBtn").textContent="启动中…";
  const r = await fetch("/api/start",{method:"POST",headers:{"Content-Type":"application/json"},
    body:JSON.stringify({country:$("country").value})});
  const d = await r.json();
  if(d.error){ alert("启动失败："+d.error); }
  userPicked = false;
  await loadState();
};
$("stopBtn").onclick = async () => { await fetch("/api/stop",{method:"POST"}); await loadState(); };
$("copyCfgBtn").onclick = async () => {
  const r = await fetch("/api/config"); const d = await r.json();
  if(d.error){ $("copyMsg").textContent = "失败："+d.error; return; }
  const text = d.config;
  try {
    await navigator.clipboard.writeText(text);
    $("copyMsg").textContent = "已复制到剪贴板✓";
  } catch(e) {
    // clipboard API needs https/localhost focus; fall back to a textarea select
    const ta = document.createElement("textarea");
    ta.value = text; document.body.appendChild(ta); ta.select();
    try { document.execCommand("copy"); $("copyMsg").textContent = "已复制到剪贴板✓"; }
    catch(_) { $("copyMsg").textContent = "复制失败，请手动选中："+text; }
    ta.remove();
  }
};
$("testBtn").onclick = async () => {
  $("egress").textContent="测试中…";
  const r = await fetch("/api/egress"); const d = await r.json();
  $("egress").textContent = d.ip ? ("当前出口 IP："+d.ip) : ("测试失败："+(d.error||"")); };
(async()=>{ await loadServers(); await loadState(); await loadStatus();
  setInterval(loadStatus, 15000); setInterval(loadState, 5000); })();
</script>
</body>
</html>"""


class Panel:
    def __init__(self, config_path=None):
        self.config_path = config_path
        self.cfg = cfgmod.load(config_path)
        self.client = None
        self.srv = None

    def _get_client(self):
        if self.client is None:
            rt = self.cfg.get("refresh_token")
            if not rt:
                raise RuntimeError("no refresh_token; 先在配置里填入凭证或运行 login")
            self.client = GuardianClient(rt)
        return self.client

    # ---- handlers ----
    async def index(self, req):
        return web.Response(text=PAGE, content_type="text/html")

    async def api_state(self, req):
        running = self.srv is not None
        return web.json_response({
            "authed": bool(self.cfg.get("refresh_token")),
            "running": running,
            "country": (self.srv.picker.country if running else self.cfg.get("country") or ""),
            "host": self.cfg.get("host", "127.0.0.1"),
            "http_port": self.cfg.get("http_port", 8080),
            "socks_port": self.cfg.get("socks_port", 1080),
        })

    async def api_status(self, req):
        try:
            q = await asyncio.to_thread(self._get_client().quota)
            return web.json_response(q)
        except NotEnrolledError as e:
            return web.json_response({"error": f"未入组: {e}"})
        except Exception as e:
            return web.json_response({"error": str(e)})

    async def api_servers(self, req):
        try:
            picker = NodePicker(self._get_client(), None)
            await asyncio.to_thread(picker.refresh)
            out = [{"code": c, "name": v.get("name", c), "nodes": len(v["nodes"])}
                   for c, v in sorted(picker._by_country.items())]
            return web.json_response({"countries": out})
        except Exception as e:
            return web.json_response({"countries": [], "error": str(e)})

    async def api_start(self, req):
        try:
            body = await req.json()
        except Exception:
            body = {}
        country = (body.get("country") or "").upper() or None
        if self.srv is not None:
            # already running: if the country is unchanged, no-op;
            # otherwise switch the egress country in place. We deliberately
            # do NOT stop/rebind the listeners here — closing and re-binding
            # the same ports races on Windows and can leave nothing listening
            # (WinError 10061 on the next request). Swapping the picker keeps
            # the sockets up; new connections use the new country immediately.
            if self.srv.picker.country == country:
                return web.json_response({"ok": True, "already": True})
            try:
                await self.srv.switch_country(country)
                return web.json_response({"ok": True, "switched": True})
            except Exception as e:
                return web.json_response({"error": str(e)})
        try:
            gc = self._get_client()
            picker = NodePicker(gc, country)
            srv = ProxyServer(
                gc, picker,
                host=self.cfg.get("host", "127.0.0.1"),
                http_port=self.cfg.get("http_port", 8080),
                socks_port=self.cfg.get("socks_port", 1080),
                failover=self.cfg.get("failover", 3),
            )
            await srv.start()
            self.srv = srv
            return web.json_response({"ok": True})
        except Exception as e:
            return web.json_response({"error": str(e)})

    async def api_stop(self, req):
        if self.srv is not None:
            await self.srv.stop()
            self.srv = None
        return web.json_response({"ok": True})

    async def api_login(self, req):
        try:
            body = await req.json()
        except Exception:
            body = {}
        mode = body.get("mode") or "token"
        country = (body.get("country") or "").upper()
        try:
            if mode == "token":
                rt = (body.get("refresh_token") or "").strip()
                if not rt:
                    return web.json_response({"error": "请粘贴 refresh_token"})
                # validate the token actually works before saving
                gc = GuardianClient(rt)
                await asyncio.to_thread(gc.quota)
                res = {"refresh_token": rt}
            elif mode == "browser":
                st = await asyncio.to_thread(fxa_auth.browser_login)
                res = await asyncio.to_thread(fxa_auth.bootstrap, session_token=st)
            elif mode == "session":
                st = (body.get("session_token") or "").strip()
                if not st:
                    return web.json_response({"error": "请粘贴 sessionToken"})
                res = await asyncio.to_thread(fxa_auth.bootstrap, session_token=st)
            else:
                email = (body.get("email") or "").strip()
                password = body.get("password") or ""
                if not (email and password):
                    return web.json_response({"error": "请填邮箱和密码"})
                res = await asyncio.to_thread(
                    fxa_auth.bootstrap, email=email, password=password)
            self.cfg["refresh_token"] = res["refresh_token"]
            if country:
                self.cfg["country"] = country
            await asyncio.to_thread(cfgmod.save, self.cfg, self.config_path)
            self.client = None  # rebuild with new token
            return web.json_response({"ok": True})
        except Exception as e:
            return web.json_response({"error": str(e)})

    async def api_config(self, req):
        if not self.cfg.get("refresh_token"):
            return web.json_response({"error": "尚未登录/无凭证"})
        cfg = {
            "refresh_token": self.cfg.get("refresh_token"),
            "country": (self.srv.picker.country if self.srv is not None
                        else self.cfg.get("country") or "US"),
            "host": self.cfg.get("host", "127.0.0.1"),
            "http_port": self.cfg.get("http_port", 8080),
            "socks_port": self.cfg.get("socks_port", 1080),
            "failover": self.cfg.get("failover", 3),
        }
        return web.json_response({"config": json.dumps(cfg, indent=2, ensure_ascii=False)})

    async def api_egress(self, req):
        if self.srv is None:
            return web.json_response({"error": "代理未运行"})
        host = self.cfg.get("host", "127.0.0.1")
        port = self.cfg.get("http_port", 8080)

        def _probe():
            proxy = f"http://{host}:{port}"
            op = urllib.request.build_opener(
                urllib.request.ProxyHandler({"http": proxy, "https": proxy})
            )
            return op.open("https://api.ipify.org", timeout=20).read().decode()

        try:
            ip = await asyncio.to_thread(_probe)
            return web.json_response({"ip": ip.strip()})
        except Exception as e:
            return web.json_response({"error": str(e)})


def run_web(config_path=None, web_host="127.0.0.1", web_port=8765, open_browser=True):
    panel = Panel(config_path)
    app = web.Application()
    app.add_routes([
        web.get("/", panel.index),
        web.get("/api/state", panel.api_state),
        web.get("/api/status", panel.api_status),
        web.get("/api/servers", panel.api_servers),
        web.post("/api/start", panel.api_start),
        web.post("/api/stop", panel.api_stop),
        web.post("/api/login", panel.api_login),
        web.get("/api/egress", panel.api_egress),
        web.get("/api/config", panel.api_config),
    ])
    url = f"http://{web_host}:{web_port}"
    print(f"[fxproxy] 控制面板: {url}  (Ctrl+C 退出)")
    if open_browser:
        try:
            webbrowser.open(url)
        except Exception:
            pass
    web.run_app(app, host=web_host, port=web_port, print=None)
