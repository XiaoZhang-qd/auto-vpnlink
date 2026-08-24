#!/usr/bin/env python3
"""Real, conservative protocol-level internet health check.

A TCP connect is not enough. Each candidate is converted to its exact
Clash/Mihomo proxy configuration and Mihomo proxies real HTTPS requests.
A node is published only after it passes a multi-endpoint check and a
second independent stability check. TCP proxy protocols are preferred;
QUIC-only protocols must pass the same stricter test.
"""
import json, os, socket, subprocess, tempfile, time, hashlib
from pathlib import Path
import requests, yaml
import converter

ROOT=Path(__file__).resolve().parent
OUT=ROOT/'output'
INPUT=OUT/'verified-nodes.txt'
HEALTHY=OUT/'health-checked-nodes.txt'
REPORT=OUT/'healthcheck.json'
MAX=int(os.getenv('HEALTHCHECK_MAX','150'))
TIMEOUT=int(os.getenv('HEALTHCHECK_TIMEOUT','12'))
MIHOMO=os.getenv('MIHOMO_BIN',str(ROOT/'mihomo'))
TEST_URLS=[x.strip() for x in os.getenv('HEALTHCHECK_URLS','https://www.gstatic.com/generate_204,https://cp.cloudflare.com/generate_204,https://www.google.com/generate_204').split(',') if x.strip()]
MIN_FIRST=int(os.getenv('HEALTHCHECK_MIN_FIRST','2'))
MIN_SECOND=int(os.getenv('HEALTHCHECK_MIN_SECOND','2'))
START_PORT=17890

# TCP-capable protocols are preferred for Windows desktop clients. UDP/QUIC
# protocols are still allowed, but only after the stricter two-round test.
TCP_TYPES={'ss','vless','vmess','trojan'}
UDP_TYPES={'hysteria2','hy2','tuic'}

def free_port():
    for p in range(START_PORT,START_PORT+400):
        with socket.socket() as s:
            try:
                s.bind(('127.0.0.1',p)); return p
            except OSError:
                pass
    raise RuntimeError('no free local port')

def stop(proc):
    if not proc:return
    try:
        proc.terminate(); proc.wait(timeout=3)
    except Exception:
        try: proc.kill(); proc.wait(timeout=2)
        except Exception: pass

def request_round(port, urls):
    passed=[]
    for url in urls:
        try:
            r=requests.get(
                url,
                proxies={'http':f'http://127.0.0.1:{port}','https':f'http://127.0.0.1:{port}'},
                timeout=TIMEOUT,
                allow_redirects=False,
                headers={'User-Agent':'auto-vpnlink-health/2.0'},
            )
            if r.status_code in (200,204):
                passed.append({'url':url,'status':r.status_code})
        except Exception:
            pass
    return passed

def test_proxy(proxy):
    port=free_port()
    with tempfile.TemporaryDirectory(prefix='auto-vpnlink-health-') as td:
        cfg={
            'mixed-port':port,
            'allow-lan':False,
            'mode':'global',
            'log-level':'error',
            'ipv6':False,
            'proxies':[proxy],
            'rules':['MATCH,'+proxy['name']],
        }
        cp=Path(td)/'config.yaml'
        cp.write_text(yaml.safe_dump(cfg,allow_unicode=True,sort_keys=False),encoding='utf-8')
        log=open(Path(td)/'mihomo.log','w',encoding='utf-8')
        proc=None
        try:
            proc=subprocess.Popen([MIHOMO,'-d',td,'-f',str(cp)],stdout=log,stderr=subprocess.STDOUT)
            deadline=time.time()+8
            ready=False
            while time.time()<deadline:
                try:
                    with socket.create_connection(('127.0.0.1',port),timeout=.3):
                        ready=True; break
                except OSError:
                    time.sleep(.15)
            if not ready:
                return False,'mihomo_not_ready',[]

            # First round: require at least 2 independent public endpoints.
            first=request_round(port,TEST_URLS)
            if len(first) < min(MIN_FIRST,len(TEST_URLS)):
                return False,f'internet_first_only_{len(first)}',first

            # Second round after a short pause. This removes transient/free-node
            # false positives that work once on a GitHub runner and immediately die.
            time.sleep(1.0)
            second_urls=TEST_URLS[:2] if len(TEST_URLS)>2 else TEST_URLS
            second=request_round(port,second_urls)
            if len(second) < min(MIN_SECOND,len(second_urls)):
                return False,f'internet_second_only_{len(second)}',first+second

            return True,'internet_stable',first+second
        except Exception as e:
            return False,type(e).__name__,[]
        finally:
            stop(proc); log.close()

def stable_fingerprint(n):
    try:
        fp=converter.fingerprint(n) if hasattr(converter,'fingerprint') else None
        if fp:return fp
    except Exception:
        pass
    keys=('type','server','port','uuid','password','cipher','sni','security','pbk','sid','flow','net','path','host','aid')
    return hashlib.sha256('|'.join(str(n.get(k,'')) for k in keys).encode()).hexdigest()

def main():
    if not Path(MIHOMO).exists():
        raise SystemExit(f'Mihomo binary not found: {MIHOMO}')
    raw=[x.strip() for x in INPUT.read_text(encoding='utf-8',errors='ignore').splitlines() if x.strip()] if INPUT.exists() else []
    results=[]; good=[]; seen_fp=set()
    for i,uri in enumerate(raw[:MAX],1):
        n=converter.parse(uri,i)
        if not n:
            results.append({'uri':uri,'ok':False,'reason':'parse_failed'}); continue

        fp=stable_fingerprint(n)
        if fp in seen_fp:
            results.append({'uri':uri,'ok':False,'reason':'duplicate_credentials'}); continue
        seen_fp.add(fp)

        proxy=converter.clash(n)
        ok,reason,checks=test_proxy(proxy)
        item={
            'uri':uri,
            'name':proxy['name'],
            'type':proxy['type'],
            'server':proxy['server'],
            'port':proxy['port'],
            'ok':ok,
            'reason':reason,
            'checks':checks,
        }
        results.append(item)
        if ok: good.append(uri)
        print(f'[{i}/{min(len(raw),MAX)}] {proxy["name"]} [{proxy["type"]}]: {"PASS" if ok else "FAIL"} ({reason})',flush=True)

    HEALTHY.write_text('\n'.join(good)+('\n' if good else ''),encoding='utf-8')
    REPORT.write_text(json.dumps({
        'tested':len(results),
        'healthy':len(good),
        'failed':len(results)-len(good),
        'stable_required':True,
        'first_round_min_success':MIN_FIRST,
        'second_round_min_success':MIN_SECOND,
        'internet_test_urls':TEST_URLS,
        'results':results,
    },ensure_ascii=False,indent=2),encoding='utf-8')
    print(f'HEALTHCHECK tested={len(results)} healthy={len(good)} failed={len(results)-len(good)}')
    if raw and not good:
        raise SystemExit('No node passed stable real internet health check; refusing to publish unverified nodes.')

if __name__=='__main__':
    main()
