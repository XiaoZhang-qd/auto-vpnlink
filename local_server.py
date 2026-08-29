#!/usr/bin/env python3
from __future__ import annotations
import hashlib,hmac,http.cookies,json,os,secrets,subprocess,sys,threading,time
from datetime import datetime,timedelta
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs,urlparse
from zoneinfo import ZoneInfo,available_timezones

ROOT=Path(__file__).resolve().parent
CONFIG_FILE=ROOT/'.auto_vpnlink_config.json'
HOST=os.getenv('AUTO_VPN_HOST','0.0.0.0')
PORT=int(os.getenv('AUTO_VPN_PORT','8080'))
DEFAULT_TIME='11:30'; DEFAULT_TZ='Asia/Shanghai'
LOCK=threading.Lock(); CFG_LOCK=threading.RLock(); SESSIONS=set()
STATE={'running':False,'last_start':None,'last_finish':None,'last_ok':None,'last_error':None,'last_output':''}

def parse_time(v):
    try:h,m=map(int,v.split(':',1))
    except Exception as e:raise ValueError('时间必须使用 HH:MM 格式') from e
    if not(0<=h<=23 and 0<=m<=59):raise ValueError('时间必须在 00:00 到 23:59 之间')
    return h,m

def valid_tz(v):
    try:ZoneInfo(v)
    except Exception as e:raise ValueError('无效的 IANA 时区') from e
    return v

def hpw(p,s=None):
    s=s or secrets.token_bytes(16); d=hashlib.pbkdf2_hmac('sha256',p.encode(),s,310000); return s.hex(),d.hex()
def vpw(p,s,d):
    try:_,x=hpw(p,bytes.fromhex(s)); return hmac.compare_digest(x,d)
    except Exception:return False

def random_password(n=20):
    a='ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789-_';return ''.join(secrets.choice(a) for _ in range(n))

def save(c):
    t=CONFIG_FILE.with_suffix('.tmp');t.write_text(json.dumps(c,ensure_ascii=False,indent=2)+'\n',encoding='utf-8');os.replace(t,CONFIG_FILE)

def load():
    if CONFIG_FILE.exists():
        try:
            c=json.loads(CONFIG_FILE.read_text(encoding='utf-8'));parse_time(c.get('schedule_time',DEFAULT_TIME));valid_tz(c.get('timezone',DEFAULT_TZ))
            if c.get('password_salt') and c.get('password_hash'):return c
        except Exception:print('[config] 配置无效，将重新初始化。',flush=True)
    p=os.getenv('AUTO_VPN_ADMIN_PASSWORD') or random_password();s,d=hpw(p)
    c={'schedule_time':DEFAULT_TIME,'timezone':DEFAULT_TZ,'password_salt':s,'password_hash':d,'created_at':datetime.now().astimezone().isoformat()};save(c)
    print('='*60,flush=True);print('auto-vpnlink 首次运行管理员密码：'+p,flush=True);print('请立即保存；之后不会再次显示。',flush=True);print(f'管理员面板：http://127.0.0.1:{PORT}/admin',flush=True);print('='*60,flush=True);return c
CFG=load()
def cfg():
    with CFG_LOCK:return dict(CFG)
def update(**x):
    global CFG
    with CFG_LOCK: CFG={**CFG,**x};save(CFG);return dict(CFG)

def run_pipeline():
    if not LOCK.acquire(False):return False
    STATE.update(running=True,last_start=datetime.now().astimezone().isoformat(),last_error=None);logs=[];ok=False
    try:
        for f in ('scanner.py','augment_protocols.py','select_nodes.py','healthcheck.py','publish_outputs.py'):
            p=subprocess.run([sys.executable,f],cwd=ROOT,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT);logs.append(f'$ {f}\n{p.stdout}')
            if p.returncode:raise RuntimeError(f'{f} exited with {p.returncode}')
        ok=True
    except Exception as e:STATE['last_error']=str(e);logs.append('ERROR: '+str(e))
    finally:
        STATE.update(running=False,last_finish=datetime.now().astimezone().isoformat(),last_ok=ok,last_output='\n\n'.join(logs)[-30000:]);LOCK.release()
    return ok

def next_run():
    c=cfg();z=ZoneInfo(c['timezone']);now=datetime.now(z);h,m=parse_time(c['schedule_time']);t=now.replace(hour=h,minute=m,second=0,microsecond=0)
    return t if t>now else t+timedelta(days=1)

def scheduler():
    while True:
        try:
            t=next_run();time.sleep(max(1,(t-datetime.now(t.tzinfo)).total_seconds()));threading.Thread(target=run_pipeline,daemon=True).start();time.sleep(2)
        except Exception as e:print('[scheduler]',e,flush=True);time.sleep(30)

def auth(h):
    c=http.cookies.SimpleCookie();
    try:c.load(h.headers.get('Cookie',''))
    except Exception:return False
    x=c.get('auto_vpn_admin');return bool(x and x.value in SESSIONS)

def cookie_session(h):
    t=secrets.token_urlsafe(32);SESSIONS.add(t);c=http.cookies.SimpleCookie();c['auto_vpn_admin']=t;c['auto_vpn_admin']['path']='/';c['auto_vpn_admin']['httponly']=True;c['auto_vpn_admin']['samesite']='Strict';h.send_header('Set-Cookie',c.output(header='').strip())

def jsons(h,o,status=200,headers=()):
    b=json.dumps(o,ensure_ascii=False).encode();h.send_response(status);h.send_header('Content-Type','application/json; charset=utf-8');h.send_header('Content-Length',str(len(b)));h.send_header('Cache-Control','no-store')
    for k,v in headers:h.send_header(k,v)
    h.end_headers();h.wfile.write(b)

LOGIN='''<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>管理员登录</title><style>body{font-family:system-ui;max-width:420px;margin:15vh auto;padding:24px;background:#f5f5f5}.c{background:white;padding:28px;border-radius:16px}input,button{width:100%;padding:12px;margin-top:10px;box-sizing:border-box}button{background:#111;color:white;border:0;border-radius:8px}</style><div class="c"><h1>🔐 管理员登录</h1><form method="post" action="/admin/login"><input type="password" name="password" placeholder="管理员密码" autofocus required><button>登录</button>{{E}}</form></div>'''
ADMIN='''<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>auto-vpnlink 管理员面板</title><style>*{box-sizing:border-box}body{font-family:system-ui;background:#f3f4f6;margin:0;color:#111827}.w{max-width:960px;margin:30px auto;padding:18px}.c{background:white;padding:24px;border-radius:16px;margin-bottom:16px;box-shadow:0 8px 25px #0001}.g{display:grid;grid-template-columns:1fr 1fr;gap:12px}.i{border:1px solid #ddd;border-radius:10px;padding:12px}label{display:block;font-weight:600;margin-top:12px}input,select,button{width:100%;padding:11px;margin-top:6px;border:1px solid #ccc;border-radius:9px;background:white}button{background:#111;color:white;border:0;cursor:pointer}.msg{padding:10px;background:#ecfdf5;color:#166534;border-radius:8px;margin:10px 0}.warn{padding:10px;background:#fffbeb;color:#92400e;border-radius:8px;margin:10px 0}@media(max-width:650px){.g{grid-template-columns:1fr}}</style><body><div class="w"><div class="c"><h1>⚙️ 管理员面板</h1><div class="g"><div class="i">服务器：{{HOST}}:{{PORT}}</div><div class="i">每日：<b id="sch">{{TIME}}</b></div><div class="i">时区：<b id="tz">{{TZ}}</b></div><div class="i">下次运行：<b id="next">-</b></div><div class="i">状态：<b id="runstate">-</b></div><div class="i">上次结果：<b id="result">-</b></div></div></div><div class="c"><h2>⏰ 自动任务</h2><form id="sf"><label>每天运行时间<input id="time" type="time" value="{{TIME}}" required></label><label>完整 IANA 时区<select id="zone"></select></label><button>保存设置</button></form></div><div class="c"><h2>▶️ 手动更新</h2><button id="run">立即运行一次</button></div><div class="c"><h2>🔑 管理员密码</h2><div class="warn">密码只保存哈希。新随机密码只显示一次。</div><form id="pf"><label>固定密码<input id="pass" type="password" minlength="8" placeholder="至少 8 位"></label><button>设置固定密码</button></form><button id="rand">生成新的随机密码</button><div id="new"></div><p><a href="/admin/logout">退出登录</a></p></div></div><script>
const current='{{TZ}}';const sel=document.querySelector('#zone');let zones=[];try{zones=Intl.supportedValuesOf('timeZone')}catch(e){zones=[]}if(!zones.length)zones=['UTC','Asia/Shanghai','Asia/Tokyo'];if(!zones.includes(current))zones.push(current);zones.sort().forEach(z=>{let o=document.createElement('option');o.value=z;o.textContent=z;if(z===current)o.selected=true;sel.appendChild(o)});
async function refresh(){let s=await (await fetch('/api/admin/status?'+Date.now(),{cache:'no-store'})).json();if(s.ok===false){location='/admin';return}document.querySelector('#sch').textContent=s.schedule_time;document.querySelector('#tz').textContent=s.timezone;document.querySelector('#time').value=s.schedule_time;document.querySelector('#next').textContent=s.next_run;document.querySelector('#runstate').textContent=s.running?'运行中…':'空闲';document.querySelector('#result').textContent=s.last_ok===true?'成功':s.last_ok===false?'失败':'尚未运行'}
function message(t){document.querySelector('#new').innerHTML='<div class="msg">'+t+'</div>'}document.querySelector('#sf').onsubmit=async e=>{e.preventDefault();let r=await fetch('/api/admin/schedule',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({schedule_time:time.value,timezone:zone.value})});let d=await r.json();message(d.ok?'设置已保存':d.error);refresh()};document.querySelector('#run').onclick=async()=>{let d=await (await fetch('/api/admin/run',{method:'POST'})).json();message(d.ok?'已开始更新':d.error);refresh()};document.querySelector('#pf').onsubmit=async e=>{e.preventDefault();let d=await (await fetch('/api/admin/password',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:pass.value})})).json();message(d.ok?'密码已修改，请记住新密码':d.error);if(d.ok)pass.value=''};document.querySelector('#rand').onclick=async()=>{if(!confirm('生成新随机密码并使旧密码失效？'))return;let d=await (await fetch('/api/admin/password',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({generate_random:true})})).json();if(d.ok)document.querySelector('#new').innerHTML='<div class="warn">新随机密码：<b>'+d.password+'</b><br>请立即保存。</div>';else message(d.error)};refresh();setInterval(refresh,5000)</script></html>'''

class H(BaseHTTPRequestHandler):
    def out(self,b,typ='text/html; charset=utf-8',status=200,headers=()):
        self.send_response(status);self.send_header('Content-Type',typ);self.send_header('Content-Length',str(len(b)));self.send_header('Cache-Control','no-store')
        for k,v in headers:self.send_header(k,v)
        self.end_headers();self.wfile.write(b)
    def data(self):
        try:return json.loads(self.rfile.read(int(self.headers.get('Content-Length','0'))).decode())
        except:return {}
    def do_GET(self):
        p=urlparse(self.path).path
        if p in ('/admin','/admin/'):
            if not auth(self):return self.out(LOGIN.replace('{{E}}','').encode())
            c=cfg();return self.out(ADMIN.replace('{{HOST}}',HOST).replace('{{PORT}}',str(PORT)).replace('{{TIME}}',c['schedule_time']).replace('{{TZ}}',c['timezone']).encode())
        if p=='/admin/logout':SESSIONS.clear();self.send_response(302);self.send_header('Location','/admin');self.send_header('Set-Cookie','auto_vpn_admin=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict');self.end_headers();return
        if p=='/api/admin/status':
            if not auth(self):return jsons(self,{'ok':False,'error':'未登录'},401)
            c=cfg();return jsons(self,{**STATE,'ok':True,'schedule_time':c['schedule_time'],'timezone':c['timezone'],'next_run':next_run().isoformat()})
        if p=='/api/status':
            c=cfg();return jsons(self,{k:v for k,v in STATE.items() if k not in ('last_output','last_error')}|{'schedule_time':c['schedule_time'],'timezone':c['timezone'],'next_run':next_run().isoformat()})
        if p=='/api/run':
            if not auth(self):return jsons(self,{'ok':False,'error':'请先登录'},401)
            if STATE['running']:return jsons(self,{'ok':False,'error':'任务正在运行'},409)
            threading.Thread(target=run_pipeline,daemon=True).start();return jsons(self,{'ok':True},202)
        if p.startswith('/api/admin/'):return jsons(self,{'ok':False,'error':'POST required'},405)
        target=(ROOT/(p.lstrip('/') or 'index.html')).resolve()
        try:
            if ROOT not in target.parents and target!=ROOT:raise FileNotFoundError
            b=target.read_bytes();ext=target.suffix.lower();typ='text/html; charset=utf-8' if ext in ('.html','.htm') else 'text/plain; charset=utf-8'
            if ext=='.json':typ='application/json; charset=utf-8'
            return self.out(b,typ)
        except:return self.out(b'404 Not Found','text/plain; charset=utf-8',404)
    def do_POST(self):
        p=urlparse(self.path).path
        if p=='/admin/login':
            q=parse_qs(self.rfile.read(int(self.headers.get('Content-Length','0'))).decode());c=cfg()
            if vpw(q.get('password',[''])[0],c['password_salt'],c['password_hash']):self.send_response(302);self.send_header('Location','/admin');cookie_session(self);self.end_headers();return
            return self.out(LOGIN.replace('{{E}}','<p style="color:red">密码错误</p>').encode())
        if p not in ('/api/admin/run','/api/admin/schedule','/api/admin/password') or not auth(self):return jsons(self,{'ok':False,'error':'未登录'},401)
        d=self.data()
        if p=='/api/admin/run':
            if STATE['running']:return jsons(self,{'ok':False,'error':'任务正在运行'},409)
            threading.Thread(target=run_pipeline,daemon=True).start();return jsons(self,{'ok':True},202)
        if p=='/api/admin/schedule':
            try:parse_time(d['schedule_time']);valid_tz(d['timezone']);update(schedule_time=d['schedule_time'],timezone=d['timezone']);return jsons(self,{'ok':True})
            except Exception as e:return jsons(self,{'ok':False,'error':str(e)},400)
        if p=='/api/admin/password':
            pw=random_password() if d.get('generate_random') else str(d.get('password',''))
            if not d.get('generate_random') and len(pw)<8:return jsons(self,{'ok':False,'error':'密码至少 8 位'},400)
            s,h=hpw(pw);update(password_salt=s,password_hash=h);SESSIONS.clear();t=secrets.token_urlsafe(32);SESSIONS.add(t);co=http.cookies.SimpleCookie();co['auto_vpn_admin']=t;co['auto_vpn_admin']['path']='/';co['auto_vpn_admin']['httponly']=True;co['auto_vpn_admin']['samesite']='Strict';return jsons(self,{'ok':True,**({'password':pw} if d.get('generate_random') else {})},200,[('Set-Cookie',co.output(header='').strip())])
    def log_message(self,f,*a):print(f'[web] {f%a}',flush=True)

def main():
    threading.Thread(target=scheduler,daemon=True).start();s=ThreadingHTTPServer((HOST,PORT),H);print(f'Web: http://127.0.0.1:{PORT}/local',flush=True);print(f'Admin: http://127.0.0.1:{PORT}/admin',flush=True);print(f'Listen: {HOST}:{PORT}',flush=True)
    try:s.serve_forever()
    except KeyboardInterrupt:pass
    finally:s.server_close()
if __name__=='__main__':main()
