#!/usr/bin/env python3
"""Local web server, scheduler and password-protected admin panel for auto-vpnlink.

The scheduler, HTTP server, password hashing and timezone handling use Python's
standard library. The existing project dependencies are still required by the
scanner/health-check pipeline.

Security model:
- HOST/PORT are terminal/environment settings only.
- On first start a random administrator password is generated and printed once.
- The password is stored locally as a salted PBKDF2 hash in .auto_vpnlink_config.json.
- The admin panel can change the password, generate a new random password, and
  change the daily schedule/timezone.
- Admin authentication uses a random in-memory session cookie.
"""
from __future__ import annotations

import hashlib
import hmac
import http.cookies
import json
import os
import secrets
import subprocess
import sys
import threading
import time
from datetime import datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse
from zoneinfo import ZoneInfo

ROOT = Path(__file__).resolve().parent
CONFIG_FILE = ROOT / ".auto_vpnlink_config.json"
HOST = os.getenv("AUTO_VPN_HOST", "0.0.0.0")
PORT = int(os.getenv("AUTO_VPN_PORT", "8080"))
ENV_PASSWORD = os.getenv("AUTO_VPN_ADMIN_PASSWORD")
DEFAULT_TIME = "11:30"
DEFAULT_TZ = "Asia/Shanghai"
RUN_LOCK = threading.Lock()
STATE_LOCK = threading.Lock()
CONFIG_LOCK = threading.RLock()
SESSIONS = set()
STATE = {
    "running": False,
    "last_start": None,
    "last_finish": None,
    "last_ok": None,
    "last_error": None,
    "last_output": "",
}


def parse_time(value: str):
    try:
        h, m = value.split(":", 1)
        h, m = int(h), int(m)
    except Exception as exc:
        raise ValueError("时间必须使用 HH:MM 格式") from exc
    if not (0 <= h <= 23 and 0 <= m <= 59):
        raise ValueError("时间必须在 00:00 到 23:59 之间")
    return h, m


def valid_timezone(value: str):
    try:
        ZoneInfo(value)
    except Exception as exc:
        raise ValueError("无效的时区") from exc
    return value


def hash_password(password: str, salt: bytes | None = None):
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 310000)
    return salt.hex(), digest.hex()


def verify_password(password: str, salt_hex: str, digest_hex: str):
    try:
        salt = bytes.fromhex(salt_hex)
    except ValueError:
        return False
    _, digest = hash_password(password, salt)
    return hmac.compare_digest(digest, digest_hex)


def generate_password(length=20):
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789-_"
    return "".join(secrets.choice(alphabet) for _ in range(length))


def save_config(cfg):
    tmp = CONFIG_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(cfg, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.replace(tmp, CONFIG_FILE)


def load_config():
    if CONFIG_FILE.exists():
        try:
            cfg = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
            parse_time(cfg.get("schedule_time", DEFAULT_TIME))
            valid_timezone(cfg.get("timezone", DEFAULT_TZ))
            if cfg.get("password_salt") and cfg.get("password_hash"):
                return cfg
        except Exception:
            print("[config] 配置文件无效，将重新初始化。", flush=True)

    password = ENV_PASSWORD or generate_password()
    salt, digest = hash_password(password)
    cfg = {
        "schedule_time": DEFAULT_TIME,
        "timezone": DEFAULT_TZ,
        "password_salt": salt,
        "password_hash": digest,
        "created_at": datetime.now().astimezone().isoformat(),
    }
    save_config(cfg)
    print("=" * 64, flush=True)
    print("auto-vpnlink 首次运行已生成管理员密码", flush=True)
    print(f"管理员密码：{password}", flush=True)
    print("请立即保存此密码。之后密码不会再次显示。", flush=True)
    if ENV_PASSWORD:
        print("密码来自 AUTO_VPN_ADMIN_PASSWORD 环境变量。", flush=True)
    print("管理员面板：http://127.0.0.1:%s/admin" % PORT, flush=True)
    print("=" * 64, flush=True)
    return cfg


CONFIG = load_config()


def get_config():
    with CONFIG_LOCK:
        return dict(CONFIG)


def update_config(**changes):
    global CONFIG
    with CONFIG_LOCK:
        new_cfg = dict(CONFIG)
        new_cfg.update(changes)
        save_config(new_cfg)
        CONFIG = new_cfg
        return dict(CONFIG)


def set_state(**kwargs):
    with STATE_LOCK:
        STATE.update(kwargs)


def run_pipeline():
    if not RUN_LOCK.acquire(blocking=False):
        return False
    set_state(running=True, last_start=datetime.now().astimezone().isoformat(), last_error=None)
    commands = [
        [sys.executable, "scanner.py"],
        [sys.executable, "augment_protocols.py"],
        [sys.executable, "select_nodes.py"],
        [sys.executable, "healthcheck.py"],
        [sys.executable, "publish_outputs.py"],
    ]
    logs = []
    ok = False
    try:
        for cmd in commands:
            p = subprocess.run(cmd, cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            logs.append(f"$ {' '.join(cmd)}\n{p.stdout}")
            if p.returncode != 0:
                raise RuntimeError(f"command failed ({p.returncode}): {' '.join(cmd)}")
        ok = True
    except Exception as exc:
        logs.append(f"ERROR: {exc}")
        set_state(last_error=str(exc))
    finally:
        set_state(
            running=False,
            last_finish=datetime.now().astimezone().isoformat(),
            last_ok=ok,
            last_output="\n\n".join(logs)[-30000:],
        )
        RUN_LOCK.release()
    return ok


def next_run(now=None):
    cfg = get_config()
    tz = ZoneInfo(cfg["timezone"])
    now = now or datetime.now(tz)
    h, m = parse_time(cfg["schedule_time"])
    target = now.replace(hour=h, minute=m, second=0, microsecond=0)
    if target <= now:
        target += timedelta(days=1)
    return target


def scheduler_loop():
    while True:
        try:
            target = next_run()
            now = datetime.now(target.tzinfo)
            delay = max(1, (target - now).total_seconds())
            print(f"[scheduler] next run: {target.isoformat()}", flush=True)
            time.sleep(delay)
            threading.Thread(target=run_pipeline, daemon=True).start()
            time.sleep(2)
        except Exception as exc:
            print(f"[scheduler] error: {exc}", flush=True)
            time.sleep(60)


def authorized(handler):
    raw = handler.headers.get("Cookie", "")
    cookies = http.cookies.SimpleCookie()
    try:
        cookies.load(raw)
    except http.cookies.CookieError:
        return False
    token = cookies.get("auto_vpn_admin")
    return bool(token and token.value in SESSIONS)


def issue_session(handler):
    token = secrets.token_urlsafe(32)
    SESSIONS.add(token)
    cookie = http.cookies.SimpleCookie()
    cookie["auto_vpn_admin"] = token
    cookie["auto_vpn_admin"]["path"] = "/"
    cookie["auto_vpn_admin"]["httponly"] = True
    cookie["auto_vpn_admin"]["samesite"] = "Strict"
    handler.send_header("Set-Cookie", cookie.output(header="").strip())


def revoke_session(handler):
    raw = handler.headers.get("Cookie", "")
    cookies = http.cookies.SimpleCookie()
    try:
        cookies.load(raw)
        token = cookies.get("auto_vpn_admin")
        if token:
            SESSIONS.discard(token.value)
    except http.cookies.CookieError:
        pass
    handler.send_header("Set-Cookie", "auto_vpn_admin=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict")


LOGIN_HTML = r'''<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>管理员登录 - auto-vpnlink</title><style>*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;background:#f3f4f6;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI","Microsoft YaHei",sans-serif;color:#111827}.card{width:min(420px,calc(100% - 32px));background:#fff;padding:28px;border-radius:18px;box-shadow:0 12px 40px #0001}input,button{width:100%;padding:12px;margin-top:10px;border-radius:10px;border:1px solid #d1d5db;font-size:14px}button{background:#111827;color:#fff;border:0;cursor:pointer}.err{color:#dc2626;font-size:13px;margin-top:12px}</style></head><body><form class="card" method="post" action="/admin/login"><h1>🔐 管理员登录</h1><p>请输入管理员密码。</p><input type="password" name="password" autocomplete="current-password" autofocus required><button>登录</button>{{ERROR}}</form></body></html>'''


ADMIN_HTML = r'''<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>管理员面板 - auto-vpnlink</title><style>*{box-sizing:border-box}body{margin:0;background:#f3f4f6;color:#111827;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI","Microsoft YaHei",sans-serif}.wrap{max-width:960px;margin:30px auto;padding:18px}.card{background:#fff;border-radius:18px;padding:24px;margin-bottom:16px;box-shadow:0 10px 35px #0001}h1,h2{margin-top:0}.grid{display:grid;grid-template-columns:1fr 1fr;gap:12px}.item{padding:14px;border:1px solid #e5e7eb;border-radius:12px}.label{font-size:12px;color:#6b7280}.value{margin-top:5px;font-weight:700}label{display:block;font-size:13px;font-weight:600;margin-top:12px}input,select,button{width:100%;padding:11px;margin-top:6px;border:1px solid #d1d5db;border-radius:10px;font-size:14px;background:#fff}button{background:#111827;color:#fff;border:0;cursor:pointer}.danger{background:#991b1b}.msg{padding:11px;border-radius:10px;background:#f0fdf4;color:#166534;margin-bottom:14px}.warn{padding:11px;border-radius:10px;background:#fffbeb;color:#92400e;margin-bottom:14px}.actions{display:grid;grid-template-columns:1fr 1fr;gap:10px}.logout{display:block;text-align:center;margin-top:12px;color:#6b7280;text-decoration:none}@media(max-width:650px){.grid,.actions{grid-template-columns:1fr}}</style></head><body><div class="wrap"><div class="card"><h1>⚙️ auto-vpnlink 管理员面板</h1><div id="msg"></div><div class="grid"><div class="item"><div class="label">服务器</div><div class="value">{{HOST}}:{{PORT}}</div></div><div class="item"><div class="label">每日自动运行</div><div class="value" id="schedule">{{TIME}}</div></div><div class="item"><div class="label">时区</div><div class="value" id="timezone">{{TZ}}</div></div><div class="item"><div class="label">下一次运行</div><div class="value" id="next">读取中...</div></div><div class="item"><div class="label">当前状态</div><div class="value" id="running">读取中...</div></div><div class="item"><div class="label">上次结果</div><div class="value" id="result">-</div></div></div></div><div class="card"><h2>⏰ 自动任务设置</h2><form id="scheduleForm"><label>每天运行时间<input type="time" id="time" value="{{TIME}}" required></label><label>时区<select id="tzselect"></select></label><button>保存自动运行设置</button></form></div><div class="card"><h2>▶️ 手动更新</h2><p>立即执行一次完整扫描、健康检测和输出生成，不会改变每日自动运行时间。</p><button id="run">立即运行一次</button></div><div class="card"><h2>🔑 管理员密码</h2><div class="warn">密码只保存在服务器本地的哈希值中。新密码只会显示一次，请自行保存。</div><form id="passForm"><label>自定义固定密码<input type="password" id="newpass" minlength="8" autocomplete="new-password" placeholder="至少 8 位"></label><button>设置自定义密码</button></form><button id="random" style="margin-top:10px">生成新的随机密码</button><div id="newpassword"></div><a class="logout" href="/admin/logout">退出管理员登录</a></div></div><script>const zones=['Asia/Shanghai','Asia/Tokyo','Asia/Hong_Kong','Asia/Singapore','Asia/Seoul','UTC','Europe/London','Europe/Paris','America/Los_Angeles','America/New_York','Australia/Sydney','Asia/Bangkok','Asia/Kolkata'];const sel=document.querySelector('#tzselect');zones.forEach(z=>{const o=document.createElement('option');o.value=z;o.textContent=z;if(z==='{{TZ}}')o.selected=true;sel.appendChild(o)});function msg(t,bad=false){const e=document.querySelector('#msg');e.textContent=t;e.className=bad?'warn':'msg';setTimeout(()=>e.textContent='',5000)}async function refresh(){try{const s=await (await fetch('/api/admin/status?'+Date.now(),{cache:'no-store'})).json();document.querySelector('#schedule').textContent='每天 '+s.schedule_time;document.querySelector('#time').value=s.schedule_time;document.querySelector('#timezone').textContent=s.timezone;document.querySelector('#next').textContent=s.next_run;document.querySelector('#running').textContent=s.running?'运行中…':'空闲';document.querySelector('#result').textContent=s.last_ok===true?'成功':s.last_ok===false?'失败':'尚未运行';document.querySelector('#run').disabled=s.running}catch(e){msg('无法读取服务器状态',true)}}document.querySelector('#scheduleForm').onsubmit=async e=>{e.preventDefault();const r=await fetch('/api/admin/schedule',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({schedule_time:document.querySelector('#time').value,timezone:sel.value})});const d=await r.json();if(d.ok){msg('自动运行设置已保存');refresh()}else msg(d.error||'保存失败',true)};document.querySelector('#run').onclick=async()=>{const r=await fetch('/api/admin/run',{method:'POST'});const d=await r.json();msg(d.ok?'已开始手动更新':(d.error||'启动失败'),!d.ok);refresh()};document.querySelector('#passForm').onsubmit=async e=>{e.preventDefault();const password=document.querySelector('#newpass').value;const r=await fetch('/api/admin/password',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password})});const d=await r.json();msg(d.ok?'密码已修改，请记住新密码。':(d.error||'修改失败'),!d.ok);if(d.ok)document.querySelector('#newpass').value=''};document.querySelector('#random').onclick=async()=>{if(!confirm('确定生成新的随机管理员密码吗？当前密码会立即失效。'))return;const r=await fetch('/api/admin/password',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({generate_random:true})});const d=await r.json();if(d.ok){document.querySelector('#newpassword').innerHTML='<div class="warn" style="margin-top:12px"><b>新随机密码：</b><code>'+d.password+'</code><br>请立即保存。刷新或离开此页面后不会再次显示。</div>';msg('随机密码已生成，旧密码已经失效。')}else msg(d.error||'生成失败',true)};refresh();setInterval(refresh,5000)</script></body></html>'''


PUBLIC_HTML = r'''<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>auto-vpnlink 本地控制台</title><style>*{box-sizing:border-box}body{margin:0;background:#f3f4f6;color:#111827;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI","Microsoft YaHei",sans-serif}.wrap{max-width:900px;margin:40px auto;padding:20px}.card{background:#fff;border-radius:18px;padding:24px;box-shadow:0 10px 35px #0001}h1{margin-top:0}.grid{display:grid;grid-template-columns:repeat(2,1fr);gap:12px}.item{padding:15px;border:1px solid #e5e7eb;border-radius:12px}.label{font-size:12px;color:#6b7280}.value{margin-top:5px;font-weight:700}.actions{display:flex;gap:10px;margin:18px 0}button,a.btn{border:0;border-radius:10px;padding:11px 16px;background:#111827;color:#fff;cursor:pointer;text-decoration:none}button:disabled{opacity:.5}pre{white-space:pre-wrap;max-height:420px;overflow:auto;background:#111827;color:#e5e7eb;padding:14px;border-radius:12px;font-size:12px}.ok{color:#15803d}.bad{color:#dc2626}@media(max-width:650px){.grid{grid-template-columns:1fr}.actions{flex-wrap:wrap}}</style></head><body><div class="wrap"><div class="card"><h1>🚀 auto-vpnlink 本地控制台</h1><p>本页面由 Python 本地服务器提供。管理员设置请进入管理员面板。</p><div class="grid"><div class="item"><div class="label">自动更新时间</div><div class="value" id="schedule">读取中...</div></div><div class="item"><div class="label">时区</div><div class="value" id="tz">读取中...</div></div><div class="item"><div class="label">下一次运行</div><div class="value" id="next">读取中...</div></div><div class="item"><div class="label">运行状态</div><div class="value" id="running">读取中...</div></div><div class="item"><div class="label">上次运行</div><div class="value" id="last">-</div></div><div class="item"><div class="label">上次结果</div><div class="value" id="result">-</div></div></div><div class="actions"><button id="run">立即运行一次</button><a class="btn" href="/admin">管理员面板</a><a class="btn" href="/subscriptions.html">订阅网页</a></div><h3>最近运行日志</h3><pre id="log">管理员登录后可查看详细日志。</pre></div></div><script>async function refresh(){try{const s=await(await fetch('/api/status?'+Date.now(),{cache:'no-store'})).json();document.querySelector('#schedule').textContent='每天 '+s.schedule_time;document.querySelector('#tz').textContent=s.timezone;document.querySelector('#next').textContent=s.next_run;document.querySelector('#running').textContent=s.running?'运行中…':'空闲';document.querySelector('#last').textContent=s.last_finish||'-';document.querySelector('#result').textContent=s.last_ok===true?'成功':s.last_ok===false?'失败':'尚未运行';document.querySelector('#run').disabled=s.running}catch(e){}}document.querySelector('#run').onclick=async()=>{const r=await fetch('/api/run',{method:'POST'});if(r.status===401){location.href='/admin'}refresh()};refresh();setInterval(refresh,5000)</script></body></html>'''


class Handler(BaseHTTPRequestHandler):
    def send_bytes(self, status, content_type, data, extra_headers=None):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        if extra_headers:
            for key, value in extra_headers:
                self.send_header(key, value)
        self.end_headers()
        self.wfile.write(data)

    def json_response(self, status, obj, extra_headers=None):
        return self.send_bytes(status, "application/json; charset=utf-8", json.dumps(obj, ensure_ascii=False).encode(), extra_headers)

    def read_json(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
            return json.loads(self.rfile.read(length).decode("utf-8"))
        except Exception:
            return {}

    def do_GET(self):
        path = urlparse(self.path).path
        if path in ("/admin", "/admin/"):
            if not authorized(self):
                return self.send_bytes(200, "text/html; charset=utf-8", LOGIN_HTML.replace("{{ERROR}}", "" ).encode())
            cfg = get_config()
            html = ADMIN_HTML.replace("{{HOST}}", HOST).replace("{{PORT}}", str(PORT)).replace("{{TIME}}", cfg["schedule_time"]).replace("{{TZ}}", cfg["timezone"])
            return self.send_bytes(200, "text/html; charset=utf-8", html.encode())
        if path == "/admin/logout":
            headers=[]
            # Need a valid Set-Cookie header while redirecting.
            self.send_response(302); self.send_header("Location", "/admin"); revoke_session(self); self.end_headers(); return
        if path == "/api/admin/status":
            if not authorized(self): return self.json_response(401, {"ok": False, "error": "未登录"})
            cfg=get_config(); s=dict(STATE)
            s.update({"schedule_time":cfg["schedule_time"],"timezone":cfg["timezone"],"next_run":next_run().isoformat()})
            return self.json_response(200, s)
        if path == "/api/status":
            cfg=get_config(); s={k:v for k,v in STATE.items() if k not in ("last_output","last_error")}
            s.update({"schedule_time":cfg["schedule_time"],"timezone":cfg["timezone"],"next_run":next_run().isoformat()})
            return self.json_response(200, s)
        if path == "/api/admin/run" or path == "/api/admin/schedule" or path == "/api/admin/password":
            return self.json_response(405, {"ok":False,"error":"POST required"})
        if path == "/api/run":
            if not authorized(self): return self.json_response(401, {"ok":False,"error":"请先登录管理员面板"})
            if STATE["running"]: return self.json_response(409, {"ok":False,"error":"已经有任务正在运行"})
            threading.Thread(target=run_pipeline, daemon=True).start()
            return self.json_response(202, {"ok":True})
        target = ROOT / (path.lstrip("/") or "index.html")
        try:
            target = target.resolve()
            if ROOT not in target.parents and target != ROOT: raise FileNotFoundError
            data = target.read_bytes()
            ctype = "text/html; charset=utf-8" if target.suffix in (".html", ".htm") else "text/plain; charset=utf-8"
            if target.suffix == ".json": ctype = "application/json; charset=utf-8"
            if target.suffix in (".yaml", ".yml"): ctype = "text/yaml; charset=utf-8"
            return self.send_bytes(200, ctype, data)
        except Exception:
            return self.send_bytes(404, "text/plain; charset=utf-8", b"404 Not Found")

    def do_POST(self):
        path = urlparse(self.path).path
        if path == "/admin/login":
            form = parse_qs(self.rfile.read(int(self.headers.get("Content-Length", "0"))).decode("utf-8"))
            password = form.get("password", [""])[0]
            cfg = get_config()
            if verify_password(password, cfg["password_salt"], cfg["password_hash"]):
                self.send_response(302); self.send_header("Location", "/admin"); issue_session(self); self.end_headers(); return
            return self.send_bytes(200, "text/html; charset=utf-8", LOGIN_HTML.replace("{{ERROR}}", '<div class="err">密码错误，请重试。</div>').encode())
        if path not in ("/api/admin/run", "/api/admin/schedule", "/api/admin/password"):
            return self.send_bytes(404, "text/plain; charset=utf-8", b"404 Not Found")
        if not authorized(self): return self.json_response(401, {"ok":False,"error":"未登录"})
        data = self.read_json()
        if path == "/api/admin/run":
            if STATE["running"]: return self.json_response(409, {"ok":False,"error":"已经有任务正在运行"})
            threading.Thread(target=run_pipeline, daemon=True).start()
            return self.json_response(202, {"ok":True})
        if path == "/api/admin/schedule":
            try:
                schedule_time = str(data.get("schedule_time", ""))
                timezone = str(data.get("timezone", ""))
                parse_time(schedule_time); valid_timezone(timezone)
                update_config(schedule_time=schedule_time, timezone=timezone)
                return self.json_response(200, {"ok":True})
            except ValueError as exc:
                return self.json_response(400, {"ok":False,"error":str(exc)})
        if path == "/api/admin/password":
            if data.get("generate_random"):
                password = generate_password()
            else:
                password = str(data.get("password", ""))
                if len(password) < 8:
                    return self.json_response(400, {"ok":False,"error":"自定义密码至少需要 8 位。"})
            salt, digest = hash_password(password)
            update_config(password_salt=salt, password_hash=digest)
            # Revoke all existing sessions so the password change takes effect immediately.
            SESSIONS.clear()
            if data.get("generate_random"):
                # Keep this response authenticated for the current browser by issuing a new session.
                token = secrets.token_urlsafe(32); SESSIONS.add(token)
                cookie = http.cookies.SimpleCookie(); cookie["auto_vpn_admin"] = token; cookie["auto_vpn_admin"]["path"] = "/"; cookie["auto_vpn_admin"]["httponly"] = True; cookie["auto_vpn_admin"]["samesite"] = "Strict"
                return self.json_response(200, {"ok":True,"password":password}, [("Set-Cookie", cookie.output(header="").strip())])
            return self.json_response(200, {"ok":True})

    def log_message(self, fmt, *args):
        print(f"[{self.address_string()}] {fmt % args}")


def main():
    cfg = get_config()
    parse_time(cfg["schedule_time"]); valid_timezone(cfg["timezone"])
    threading.Thread(target=scheduler_loop, daemon=True).start()
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"auto-vpnlink local server: http://127.0.0.1:{PORT}/local", flush=True)
    print(f"admin panel: http://127.0.0.1:{PORT}/admin", flush=True)
    print(f"listening on: {HOST}:{PORT}", flush=True)
    print(f"daily schedule: {cfg['schedule_time']} ({cfg['timezone']})", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nserver stopped", flush=True)
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
