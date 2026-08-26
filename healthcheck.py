#!/usr/bin/env python3
"""Stable real-egress health check for CFW-compatible candidates."""
import hashlib,ipaddress,json,os,socket,subprocess,tempfile,time
from pathlib import Path
import requests,yaml
import converter
ROOT=Path(__file__).resolve().parent; OUT=ROOT/'output'; INPUT=OUT/'verified-nodes.txt'
HEALTHY=OUT/os.getenv('HEALTHCHECK_OUTPUT','health-checked-nodes.txt'); REPORT=OUT/os.getenv('HEALTHCHECK_REPORT','healthcheck.json')
MAX=max(1,int(os.getenv('HEALTHCHECK_MAX','120'))); SUCCESS_TARGET=max(0,int(os.getenv('HEALTHCHECK_SUCCESS_TARGET','0'))); TIMEOUT=int(os.getenv('HEALTHCHECK_TIMEOUT','12'))
MIHOMO=os.getenv('MIHOMO_BIN',str(ROOT/'.bin/mihomo')); ROUNDS=max(1,int(os.getenv('HEALTHCHECK_ROUNDS','2'))); DELAY=float(os.getenv('HEALTHCHECK_ROUND_DELAY','1')); MIN_TESTS=max(1,int(os.getenv('HEALTHCHECK_MIN_PUBLIC_TESTS','2')))
TEST_URLS=[x.strip() for x in os.getenv('HEALTHCHECK_URLS','https://www.gstatic.com/generate_204,https://cp.cloudflare.com/generate_204,https://www.google.com/generate_204').split(',') if x.strip()]; IP_URLS=['https://api.ipify.org','https://ifconfig.me/ip']
# These are the protocols published to the legacy Clash-for-Windows compatible profile.
# VLESS/Hysteria2/TUIC remain available in their protocol-specific outputs and are not
# falsely counted as CFW candidates.
ALLOWED={'ss','trojan','vmess'}; START=17890
BAD_HOSTS={'example.com','example.org','example.net','localhost','localhost.localdomain','invalid','test','test.local'}; BAD_WORDS=('placeholder','example','changeme','your-server','your_server','server_ip','<server>','${','{{','}}')
def free_port():
 for p in range(START,START+500):
  try:
   with socket.socket() as s:s.bind(('127.0.0.1',p));return p
  except OSError:pass
 raise RuntimeError('no free local port')
def stop(p):
 if p:
  try:p.terminate();p.wait(3)
  except Exception:
   try:p.kill()
   except Exception:pass
def pub(v):
 try:
  x=ipaddress.ip_address(v.strip());return not(x.is_private or x.is_loopback or x.is_reserved or x.is_link_local or x.is_multicast)
 except:return False
def direct_ip():
 for u in IP_URLS:
  try:
   x=requests.get(u,timeout=8).text.strip().split()[0]
   if pub(x):return x
  except:pass
 return None
def proxy_ip(port):
 p={'http':f'http://127.0.0.1:{port}','https':f'http://127.0.0.1:{port}'}
 for u in IP_URLS:
  try:
   x=requests.get(u,proxies=p,timeout=TIMEOUT).text.strip().split()[0]
   if pub(x):return x
  except:pass
 return None
def web_round(port):
 p={'http':f'http://127.0.0.1:{port}','https':f'http://127.0.0.1:{port}'};ok=[]
 for u in TEST_URLS:
  try:
   r=requests.get(u,proxies=p,timeout=TIMEOUT,allow_redirects=False)
   if r.status_code in (200,204):ok.append(u)
  except:pass
 return ok
def test(n,runner):
 host=str(n.get('server','')).lower().strip('[]')
 if host in BAD_HOSTS or any(w in host for w in BAD_WORDS):return False,'placeholder_endpoint'
 if any(w in str(n.get('name','')).lower() for w in BAD_WORDS):return False,'placeholder_name'
 port=free_port();proc=None
 with tempfile.TemporaryDirectory(prefix='avh-') as td:
  log=None
  try:
   cfg={'mixed-port':port,'allow-lan':False,'mode':'rule','log-level':'error','ipv6':False,'proxies':[n],'rules':['MATCH,'+n['name']]};cp=Path(td)/'config.yaml';cp.write_text(yaml.safe_dump(cfg,allow_unicode=True,sort_keys=False),encoding='utf-8');log=open(Path(td)/'mihomo.log','w')
   proc=subprocess.Popen([MIHOMO,'-d',td,'-f',str(cp)],stdout=log,stderr=subprocess.STDOUT);end=time.time()+10
   while time.time()<end:
    try:
     with socket.create_connection(('127.0.0.1',port),.3):break
    except OSError:time.sleep(.15)
   else:return False,'core_not_ready'
   ips=[]
   for r in range(ROUNDS):
    x=proxy_ip(port)
    if not x:return False,'no_proxied_public_ip'
    if runner and x==runner:return False,'proxy_equals_runner_ip'
    ips.append(x);checks=web_round(port)
    if len(checks)<min(MIN_TESTS,len(TEST_URLS)):return False,f'round_{r+1}_public_test_failed'
    if r+1<ROUNDS:time.sleep(DELAY)
   if len(set(ips))!=1:return False,'egress_ip_changed'
   return True,'internet_stable_real_egress'
  except Exception as e:return False,type(e).__name__
  finally:
   stop(proc)
   if log:log.close()
def fp(n):return hashlib.sha256('|'.join(str(n.get(k,'')) for k in ('type','server','port','uuid','password','cipher','sni','flow','net','path','host')).encode()).hexdigest()
def main():
 if not Path(MIHOMO).exists():raise SystemExit('Mihomo not found')
 raw=[x.strip() for x in INPUT.read_text(encoding='utf-8',errors='ignore').splitlines() if x.strip()] if INPUT.exists() else [];runner=direct_ip()
 if not runner:raise SystemExit('Cannot determine runner public IP')
 good=[];seen=set();results=[];skipped=0;limit=min(len(raw),MAX)
 for i,u in enumerate(raw[:limit],1):
  n=converter.parse(u,i)
  if not n:skipped+=1;continue
  typ=n.get('type','').lower()
  if typ not in ALLOWED:skipped+=1;continue
  # Do not maintain a second SS-cipher allow-list here. Mihomo/converter is the
  # authoritative parser; a cipher that parses and passes the real-egress test
  # must not be rejected by a stale hard-coded list.
  f=fp(n)
  if f in seen:skipped+=1;continue
  seen.add(f);p=converter.clash(n);ok,reason=test(p,runner);results.append({'uri':u,'name':p['name'],'type':p['type'],'server':p['server'],'port':p['port'],'ok':ok,'reason':reason})
  if ok:
   good.append(u);print(f'[{len(results)}/{limit}] PASS {p["name"]} [{p["type"]}]',flush=True)
   if SUCCESS_TARGET>0 and len(good)>=SUCCESS_TARGET:
    print(f'HEALTHCHECK success target reached: {len(good)}/{SUCCESS_TARGET}',flush=True);break
  else:print(f'[{len(results)}/{limit}] FAIL {p["name"]} [{p["type"]}] ({reason})',flush=True)
 HEALTHY.write_text('\n'.join(good)+'\n' if good else '',encoding='utf-8');REPORT.write_text(json.dumps({'candidate_limit':limit,'tested':len(results),'skipped':skipped,'healthy':len(good),'failed':len(results)-len(good),'success_target':SUCCESS_TARGET,'target_reached':SUCCESS_TARGET>0 and len(good)>=SUCCESS_TARGET,'runner_public_ip':runner,'allowed_types':sorted(ALLOWED),'rounds':ROUNDS,'results':results},ensure_ascii=False,indent=2),encoding='utf-8')
 print(f'HEALTHCHECK output={HEALTHY.name} tested={len(results)} skipped={skipped} healthy={len(good)} target={SUCCESS_TARGET}',flush=True)
 # An empty CFW pool is a valid result of the current search sources. Do not turn
 # it into an Action failure; protocol-specific outputs are still published.
 if not good: print('WARNING: no stable healthy CFW node found; CFW output will be empty for this run.',flush=True)
if __name__=='__main__':main()
