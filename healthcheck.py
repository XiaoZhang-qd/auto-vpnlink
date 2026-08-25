#!/usr/bin/env python3
"""Conservative real-internet health check for publishable proxy nodes.

A node is publishable only when the selected proxy core can repeatedly proxy
real HTTPS traffic and the traffic exits through a different public IP.
"""
import hashlib, ipaddress, json, os, socket, subprocess, tempfile, time
from pathlib import Path
import requests, yaml
import converter

ROOT=Path(__file__).resolve().parent
OUT=ROOT/'output'
INPUT=OUT/'verified-nodes.txt'
HEALTHY=OUT/os.getenv('HEALTHCHECK_OUTPUT','health-checked-nodes.txt')
REPORT=OUT/os.getenv('HEALTHCHECK_REPORT','healthcheck.json')
MAX=int(os.getenv('HEALTHCHECK_MAX','120'))
TIMEOUT=int(os.getenv('HEALTHCHECK_TIMEOUT','12'))
MIHOMO=os.getenv('MIHOMO_BIN',str(ROOT/'.bin/mihomo'))
TEST_URLS=[x.strip() for x in os.getenv('HEALTHCHECK_URLS','https://www.gstatic.com/generate_204,https://cp.cloudflare.com/generate_204,https://www.google.com/generate_204').split(',') if x.strip()]
IP_URLS=['https://api.ipify.org','https://ifconfig.me/ip']
ROUNDS=int(os.getenv('HEALTHCHECK_ROUNDS','3'))
ROUND_DELAY=float(os.getenv('HEALTHCHECK_ROUND_DELAY','2'))
MIN_PUBLIC_TESTS=int(os.getenv('HEALTHCHECK_MIN_PUBLIC_TESTS','2'))
ALLOWED_TYPES={x.strip().lower() for x in os.getenv('HEALTHCHECK_TYPES','').split(',') if x.strip()}
START_PORT=17890
PLACEHOLDER_HOSTS={'example.com','example.org','example.net','localhost','localhost.localdomain','invalid','test','test.local'}
PLACEHOLDER_WORDS=('placeholder','example','changeme','your-server','your_server','server_ip','<server>','${','{{','}}')

def free_port():
    for p in range(START_PORT,START_PORT+500):
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

def is_public_ip(value):
    try:
        ip=ipaddress.ip_address(value.strip());return not(ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_link_local or ip.is_multicast)
    except Exception:return False

def direct_public_ip():
    for url in IP_URLS:
        try:
            r=requests.get(url,timeout=8,headers={'User-Agent':'auto-vpnlink-direct/5.0'});ip=r.text.strip().split()[0]
            if is_public_ip(ip):return ip
        except Exception:pass
    return None

def proxied_public_ip(port):
    proxies={'http':f'http://127.0.0.1:{port}','https':f'http://127.0.0.1:{port}'}
    for url in IP_URLS:
        try:
            r=requests.get(url,proxies=proxies,timeout=TIMEOUT,headers={'User-Agent':'auto-vpnlink-proxy/5.0'});ip=r.text.strip().split()[0]
            if is_public_ip(ip):return ip
        except Exception:pass
    return None

def public_round(port):
    passed=[];proxies={'http':f'http://127.0.0.1:{port}','https':f'http://127.0.0.1:{port}'}
    for url in TEST_URLS:
        try:
            r=requests.get(url,proxies=proxies,timeout=TIMEOUT,allow_redirects=False,headers={'User-Agent':'auto-vpnlink-health/5.0'})
            if r.status_code in (200,204):passed.append({'url':url,'status':r.status_code})
        except Exception:pass
    return passed

def test_proxy(proxy,direct_ip):
    host=str(proxy.get('server','')).lower().strip('[]')
    if host in PLACEHOLDER_HOSTS or any(w in host for w in PLACEHOLDER_WORDS):return False,'placeholder_endpoint',[]
    if any(w in str(proxy.get('name','')).lower() for w in PLACEHOLDER_WORDS):return False,'placeholder_name',[]
    port=free_port()
    with tempfile.TemporaryDirectory(prefix='auto-vpnlink-health-') as td:
        cfg={'mixed-port':port,'allow-lan':False,'mode':'rule','log-level':'error','ipv6':False,'proxies':[proxy],'rules':['MATCH,'+proxy['name']]}
        cp=Path(td)/'config.yaml';cp.write_text(yaml.safe_dump(cfg,allow_unicode=True,sort_keys=False),encoding='utf-8')
        log=open(Path(td)/'mihomo.log','w',encoding='utf-8');proc=None
        try:
            proc=subprocess.Popen([MIHOMO,'-d',td,'-f',str(cp)],stdout=log,stderr=subprocess.STDOUT)
            deadline=time.time()+10;ready=False
            while time.time()<deadline:
                try:
                    with socket.create_connection(('127.0.0.1',port),timeout=.3):ready=True;break
                except OSError:time.sleep(.15)
            if not ready:return False,'core_not_ready',[]
            time.sleep(.3);pip=proxied_public_ip(port)
            if not pip:return False,'no_proxied_public_ip',[]
            if direct_ip and pip==direct_ip:return False,'proxy_equals_runner_ip',[]
            all_checks=[];stable_ips=[]
            for round_no in range(ROUNDS):
                rip=proxied_public_ip(port)
                if not rip or (direct_ip and rip==direct_ip):return False,f'round_{round_no+1}_bad_egress_ip',all_checks
                stable_ips.append(rip);checks=public_round(port);all_checks.extend(checks)
                if len(checks)<min(MIN_PUBLIC_TESTS,len(TEST_URLS)):return False,f'round_{round_no+1}_only_{len(checks)}_public_tests',all_checks
                if round_no+1<ROUNDS:time.sleep(ROUND_DELAY)
            if len(set(stable_ips))!=1:return False,'egress_ip_changed_during_check',all_checks
            return True,'internet_stable_real_egress',all_checks
        except Exception as e:return False,type(e).__name__,[]
        finally:stop(proc);log.close()

def stable_fingerprint(n):
    keys=('type','server','port','uuid','password','cipher','sni','security','pbk','sid','flow','net','path','host','aid')
    return hashlib.sha256('|'.join(str(n.get(k,'')) for k in keys).encode()).hexdigest()

def main():
    if not Path(MIHOMO).exists():raise SystemExit(f'Proxy core not found: {MIHOMO}')
    raw=[x.strip() for x in INPUT.read_text(encoding='utf-8',errors='ignore').splitlines() if x.strip()] if INPUT.exists() else []
    direct_ip=direct_public_ip()
    if not direct_ip:raise SystemExit('Cannot determine runner public IP; refusing to publish unverified nodes.')
    results=[];good=[];seen_fp=set();tested=0
    for i,uri in enumerate(raw[:MAX],1):
        n=converter.parse(uri,i)
        if not n:continue
        if ALLOWED_TYPES and n.get('type','').lower() not in ALLOWED_TYPES:continue
        fp=stable_fingerprint(n)
        if fp in seen_fp:continue
        seen_fp.add(fp);tested+=1
        proxy=converter.clash(n);ok,reason,checks=test_proxy(proxy,direct_ip)
        results.append({'uri':uri,'name':proxy['name'],'type':proxy['type'],'server':proxy['server'],'port':proxy['port'],'ok':ok,'reason':reason,'checks':checks})
        if ok:good.append(uri)
        print(f'[{tested}/{min(len(raw),MAX)}] {proxy["name"]} [{proxy["type"]}]: {"PASS" if ok else "FAIL"} ({reason})',flush=True)
    HEALTHY.write_text('\n'.join(good)+('\n' if good else ''),encoding='utf-8')
    REPORT.write_text(json.dumps({'tested':len(results),'healthy':len(good),'failed':len(results)-len(good),'core':MIHOMO,'allowed_types':sorted(ALLOWED_TYPES),'stable_required':True,'rounds':ROUNDS,'round_delay':ROUND_DELAY,'runner_public_ip':direct_ip,'internet_test_urls':TEST_URLS,'results':results},ensure_ascii=False,indent=2),encoding='utf-8')
    print(f'HEALTHCHECK output={HEALTHY.name} tested={len(results)} healthy={len(good)} failed={len(results)-len(good)}')
    if raw and ALLOWED_TYPES and not good:raise SystemExit('No node passed the client-specific health check.')
    if raw and not ALLOWED_TYPES and not good:raise SystemExit('No node passed stable real-egress health check; refusing to publish unverified nodes.')
if __name__=='__main__':main()
