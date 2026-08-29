#!/usr/bin/env python3
"""Local web dashboard and daily scheduler for auto-vpnlink.

Uses only Python standard-library modules for the scheduler/web server itself.
The existing project dependencies are still required by the scanner/health-check scripts.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time
from datetime import datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse
from zoneinfo import ZoneInfo

ROOT = Path(__file__).resolve().parent
HOST = os.getenv("AUTO_VPN_HOST", "0.0.0.0")
PORT = int(os.getenv("AUTO_VPN_PORT", "8080"))
SCHEDULE_TIME = os.getenv("AUTO_VPN_TIME", "11:30")
SCHEDULE_TZ = os.getenv("AUTO_VPN_TIMEZONE", "Asia/Shanghai")
RUN_LOCK = threading.Lock()
STATE_LOCK = threading.Lock()
STATE = {
    "running": False,
    "last_start": None,
    "last_finish": None,
    "last_ok": None,
    "last_error": None,
    "last_output": "",
}


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


def parse_time(value: str):
    h, m = value.split(":", 1)
    h, m = int(h), int(m)
    if not (0 <= h <= 23 and 0 <= m <= 59):
        raise ValueError
    return h, m


def next_run(now=None):
    tz = ZoneInfo(SCHEDULE_TZ)
    now = now or datetime.now(tz)
    h, m = parse_time(SCHEDULE_TIME)
    target = now.replace(hour=h, minute=m, second=0, microsecond=0)
    if target <= now:
        target += timedelta(days=1)
    return target


def scheduler_loop():
    while True:
        try:
            target = next_run()
            delay = max(1, (target - datetime.now(ZoneInfo(SCHEDULE_TZ))).total_seconds())
            print(f"[scheduler] next run: {target.isoformat()}", flush=True)
            time.sleep(delay)
            threading.Thread(target=run_pipeline, daemon=True).start()
            time.sleep(2)
        except Exception as exc:
            print(f"[scheduler] error: {exc}", flush=True)
            time.sleep(60)


HTML = r'''<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>auto-vpnlink 本地控制台</title>
<style>*{box-sizing:border-box}body{margin:0;background:#f3f4f6;color:#111827;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI","Microsoft YaHei",sans-serif}.wrap{max-width:900px;margin:40px auto;padding:20px}.card{background:#fff;border-radius:18px;padding:24px;box-shadow:0 10px 35px #0001}h1{margin-top:0}.grid{display:grid;grid-template-columns:repeat(2,1fr);gap:12px}.item{padding:15px;border:1px solid #e5e7eb;border-radius:12px}.label{font-size:12px;color:#6b7280}.value{margin-top:5px;font-weight:700}.actions{display:flex;gap:10px;margin:18px 0}button{border:0;border-radius:10px;padding:11px 16px;background:#111827;color:#fff;cursor:pointer}button:disabled{opacity:.5}pre{white-space:pre-wrap;max-height:420px;overflow:auto;background:#111827;color:#e5e7eb;padding:14px;border-radius:12px;font-size:12px}.ok{color:#15803d}.bad{color:#dc2626}@media(max-width:650px){.grid{grid-template-columns:1fr}.actions{flex-wrap:wrap}}</style></head>
<body><div class="wrap"><div class="card"><h1>🚀 auto-vpnlink 本地控制台</h1><p>本页面由 Python 本地服务器提供。关闭终端/服务器后，定时任务也会停止。</p><div class="grid"><div class="item"><div class="label">自动更新时间</div><div class="value" id="schedule">读取中...</div></div><div class="item"><div class="label">时区</div><div class="value" id="tz">读取中...</div></div><div class="item"><div class="label">下一次运行</div><div class="value" id="next">读取中...</div></div><div class="item"><div class="label">运行状态</div><div class="value" id="running">读取中...</div></div><div class="item"><div class="label">上次运行</div><div class="value" id="last">-</div></div><div class="item"><div class="label">上次结果</div><div class="value" id="result">-</div></div></div><div class="actions"><button id="run">立即运行一次</button><a href="/subscriptions.html"><button type="button">订阅网页</button></a><a href="/"><button type="button">项目首页</button></a></div><h3>最近运行日志</h3><pre id="log">读取中...</pre></div></div>
<script>async function refresh(){try{const r=await fetch('/api/status?'+Date.now(),{cache:'no-store'}),s=await r.json();document.querySelector('#schedule').textContent='每天 '+s.schedule_time;document.querySelector('#tz').textContent=s.timezone;document.querySelector('#next').textContent=s.next_run;document.querySelector('#running').textContent=s.running?'运行中…':'空闲';document.querySelector('#running').className='value '+(s.running?'':'ok');document.querySelector('#last').textContent=s.last_finish||'-';document.querySelector('#result').textContent=s.last_ok===true?'成功':s.last_ok===false?'失败':'尚未运行';document.querySelector('#result').className='value '+(s.last_ok===true?'ok':s.last_ok===false?'bad':'');document.querySelector('#log').textContent=s.last_output||'暂无运行日志';document.querySelector('#run').disabled=s.running}catch(e){document.querySelector('#log').textContent='无法连接本地服务器：'+e}}document.querySelector('#run').onclick=async()=>{await fetch('/api/run',{method:'POST'});refresh()};refresh();setInterval(refresh,5000)</script></body></html>'''


class Handler(BaseHTTPRequestHandler):
    def send_bytes(self, status, content_type, data):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/local" or path == "/local/":
            return self.send_bytes(200, "text/html; charset=utf-8", HTML.encode())
        if path == "/api/status":
            with STATE_LOCK:
                s = dict(STATE)
            s.update({"schedule_time": SCHEDULE_TIME, "timezone": SCHEDULE_TZ, "next_run": next_run().isoformat()})
            return self.send_bytes(200, "application/json; charset=utf-8", json.dumps(s, ensure_ascii=False).encode())
        if path == "/api/run":
            return self.send_bytes(405, "text/plain; charset=utf-8", b"POST required")
        target = ROOT / (path.lstrip("/") or "index.html")
        try:
            target = target.resolve()
            if ROOT not in target.parents and target != ROOT:
                raise FileNotFoundError
            data = target.read_bytes()
            ctype = "text/html; charset=utf-8" if target.suffix in (".html", ".htm") else "text/plain; charset=utf-8"
            if target.suffix == ".json": ctype = "application/json; charset=utf-8"
            if target.suffix in (".yaml", ".yml"): ctype = "text/yaml; charset=utf-8"
            return self.send_bytes(200, ctype, data)
        except Exception:
            return self.send_bytes(404, "text/plain; charset=utf-8", b"404 Not Found")

    def do_POST(self):
        if urlparse(self.path).path != "/api/run":
            return self.send_bytes(404, "text/plain; charset=utf-8", b"404 Not Found")
        if STATE["running"]:
            return self.send_bytes(409, "application/json; charset=utf-8", b'{"ok":false,"error":"already running"}')
        threading.Thread(target=run_pipeline, daemon=True).start()
        return self.send_bytes(202, "application/json; charset=utf-8", b'{"ok":true}')

    def log_message(self, fmt, *args):
        print(f"[{self.address_string()}] {fmt % args}")


def main():
    parse_time(SCHEDULE_TIME)
    ZoneInfo(SCHEDULE_TZ)
    threading.Thread(target=scheduler_loop, daemon=True).start()
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"auto-vpnlink local server: http://127.0.0.1:{PORT}/local", flush=True)
    print(f"listening on: {HOST}:{PORT}", flush=True)
    print(f"daily schedule: {SCHEDULE_TIME} ({SCHEDULE_TZ})", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nserver stopped", flush=True)
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
