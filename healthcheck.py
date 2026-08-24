#!/usr/bin/env python3
"""Real protocol-level internet health check.

A TCP connect is not enough. Each candidate is converted to its exact Clash/Mihomo
proxy configuration and Mihomo is asked to proxy real HTTPS requests. A node is
published only when at least one independent public HTTPS endpoint succeeds.
"""
import json, os, socket, subprocess, tempfile, time
from pathlib import Path
import requests, yaml
import converter

ROOT=Path(__file__).resolve().parent; OUT=ROOT/'output'; INPUT=OUT/'verified-nodes.txt'; HEALTHY=OUT/'health-checked-nodes.txt'; REPORT=OUT/'healthcheck.json'
MAX=int(os.getenv('HEALTHCHECK_MAX','150')); TIMEOUT=int(os.getenv('HEALTHCHECK_TIMEOUT','12')); MIHOMO=os.getenv('MIHOMO_BIN',str(ROOT/'mihomo'))
TEST_URLS=[x.strip() for x in os.getenv('HEALTHCHECK_URLS','https://www.gstatic.com/generate_204,https://cp.cloudflare.com/generate_204,https://www.google.com/generate_204').split(',') if x.strip()]
START_PORT=17890

def free_port():
 for p in range(START_PORT,START_PORT+200):
  with socket.socket() as s:
   try:s.bind(('127.0.0.1',p));return p
   except OSError:pass
 raise RuntimeError('no free local port')

def stop(proc):
 if not proc:return
 try:proc.terminate();proc.wait(timeout=3)
 except Exception:
  try:proc.kill();proc.wait(timeout=2)
  except Exception:pass

def test_proxy(proxy):
 port=free_port()
 with tempfile.TemporaryDirectory(prefix='auto-vpnlink-health-') as td:
  cfg={'mixed-port':port,'allow-lan':False,'mode':'global','log-level':'error','ipv6':False,'proxies':[proxy],'rules':['MATCH,'+proxy['name']]}
  cp=Path(td)/'config.yaml';cp.write_text(yaml.safe_dump(cfg,allow_unicode=True,sort_keys=False),encoding='utf-8')
  log=open(Path(td)/'mihomo.log','w',encoding='utf-8');proc=None
  try:
   proc=subprocess.Popen([MIHOMO,'-d',td,'-f',str(cp)],stdout=log,stderr=subprocess.STDOUT)
   deadline=time.time()+8;ready=False
   while time.time()<deadline:
    try:
     with socket.create_connection(('127.0.0.1',port),timeout=.3):ready=True;break
    except OSError:time.sleep(.15)
   if not ready:return False,'mihomo_not_ready',[]
   passed=[]
   for url in TEST_URLS:
    try:
     r=requests.get(url,proxies={'http':f'http://127.0.0.1:{port}','https':f'http://127.0.0.1:{port}'},timeout=TIMEOUT,allow_redirects=False,headers={'User-Agent':'auto-vpnlink-health/1.0'})
     if r.status_code in (200,204):passed.append({'url':url,'status':r.status_code})
    except Exception:pass
   if passed:return True,'internet_ok',passed
   return False,'internet_failed',[]
  except Exception as e:return False,type(e).__name__,[]
  finally:stop(proc);log.close()

def main():
 if not Path(MIHOMO).exists():raise SystemExit(f'Mihomo binary not found: {MIHOMO}')
 raw=[x.strip() for x in INPUT.read_text(encoding='utf-8',errors='ignore').splitlines() if x.strip()] if INPUT.exists() else []
 results=[];good=[];seen_fp=set()
 for i,uri in enumerate(raw[:MAX],1):
  n=converter.parse(uri,i)
  if not n:
   results.append({'uri':uri,'ok':False,'reason':'parse_failed'});continue
  # Exact credential/transport identity: never match a different node that only
  # happens to share the same server and port.
  fp=converter.fingerprint(n) if hasattr(converter,'fingerprint') else None
  if fp and fp in seen_fp:
   results.append({'uri':uri,'ok':False,'reason':'duplicate_credentials'});continue
  if fp:seen_fp.add(fp)
  proxy=converter.clash(n)
  ok,reason,checks=test_proxy(proxy)
  item={'uri':uri,'name':proxy['name'],'type':proxy['type'],'server':proxy['server'],'port':proxy['port'],'ok':ok,'reason':reason,'checks':checks}
  results.append(item)
  if ok:good.append(uri)
  print(f'[{i}/{min(len(raw),MAX)}] {proxy["name"]} [{proxy["type"]}]: {"PASS" if ok else "FAIL"} ({reason})',flush=True)
 HEALTHY.write_text('\n'.join(good)+('\n' if good else ''),encoding='utf-8')
 REPORT.write_text(json.dumps({'tested':len(results),'healthy':len(good),'failed':len(results)-len(good),'internet_test_urls':TEST_URLS,'results':results},ensure_ascii=False,indent=2),encoding='utf-8')
 print(f'HEALTHCHECK tested={len(results)} healthy={len(good)} failed={len(results)-len(good)}')
 if raw and not good:raise SystemExit('No node passed real internet health check; refusing to publish unverified nodes.')
if __name__=='__main__':main()
