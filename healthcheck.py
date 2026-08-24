#!/usr/bin/env python3
"""Protocol-level health check for generated Clash/Mihomo proxies.

A TCP connect only proves that an endpoint answers on a port. This checker
starts Mihomo with one proxy at a time and performs a real HTTPS request
through the proxy. Only proxies that complete that request are published as
healthy nodes.
"""
import json, os, signal, socket, subprocess, tempfile, time
from pathlib import Path
import requests, yaml

ROOT = Path(__file__).resolve().parent
OUT = ROOT / 'output'
CLASH = OUT / 'clash.yaml'
INPUT = OUT / 'verified-nodes.txt'
HEALTHY = OUT / 'health-checked-nodes.txt'
REPORT = OUT / 'healthcheck.json'
MAX = int(os.getenv('HEALTHCHECK_MAX', '150'))
START_PORT = 17890
URL = os.getenv('HEALTHCHECK_URL', 'https://www.gstatic.com/generate_204')
TIMEOUT = int(os.getenv('HEALTHCHECK_TIMEOUT', '10'))
MIHOMO = os.getenv('MIHOMO_BIN', str(ROOT / 'mihomo'))

def free_port(start=START_PORT):
    for p in range(start, start + 100):
        with socket.socket() as s:
            try:
                s.bind(('127.0.0.1', p)); return p
            except OSError: pass
    raise RuntimeError('no free local port')

def stop(proc):
    if not proc: return
    try:
        proc.terminate(); proc.wait(timeout=3)
    except Exception:
        try: proc.kill(); proc.wait(timeout=2)
        except Exception: pass

def test_proxy(proxy):
    port = free_port()
    with tempfile.TemporaryDirectory(prefix='auto-vpnlink-health-') as td:
        cfg = {
            'mixed-port': port,
            'allow-lan': False,
            'mode': 'global',
            'log-level': 'error',
            'ipv6': True,
            'proxies': [proxy],
            'rules': ['MATCH,' + proxy['name']],
        }
        cp = Path(td) / 'config.yaml'
        cp.write_text(yaml.safe_dump(cfg, allow_unicode=True, sort_keys=False), encoding='utf-8')
        log = open(Path(td) / 'mihomo.log', 'w', encoding='utf-8')
        proc = None
        try:
            proc = subprocess.Popen([MIHOMO, '-d', td, '-f', str(cp)], stdout=log, stderr=subprocess.STDOUT)
            deadline = time.time() + 6
            ready = False
            while time.time() < deadline:
                try:
                    with socket.create_connection(('127.0.0.1', port), timeout=0.3):
                        ready = True; break
                except OSError: time.sleep(0.15)
            if not ready: return False, 'mihomo_not_ready'
            r = requests.get(URL, proxies={'http': f'http://127.0.0.1:{port}', 'https': f'http://127.0.0.1:{port}'}, timeout=TIMEOUT, allow_redirects=False)
            if r.status_code in (200, 204): return True, f'http_{r.status_code}'
            return False, f'http_{r.status_code}'
        except Exception as e:
            return False, type(e).__name__
        finally:
            stop(proc); log.close()

def main():
    if not Path(MIHOMO).exists(): raise SystemExit(f'Mihomo binary not found: {MIHOMO}')
    data = yaml.safe_load(CLASH.read_text(encoding='utf-8')) or {}
    proxies = data.get('proxies') or []
    raw = [x.strip() for x in INPUT.read_text(encoding='utf-8').splitlines() if x.strip()] if INPUT.exists() else []
    by_key = {(p.get('server'), int(p.get('port', 0)), p.get('name')): p for p in proxies}
    results=[]; good=[]
    for i, uri in enumerate(raw[:MAX], 1):
        # Converter-generated Clash names correspond to the URI fragment. Match
        # by server/port first, then consume the first matching proxy to preserve duplicates.
        import urllib.parse as up
        try:
            q=up.parse_qs(up.urlparse(uri).query); u=up.urlparse(uri)
            host=u.hostname; port=u.port or 443
            candidates=[p for p in proxies if p.get('server')==host and int(p.get('port',0))==port and p.get('name') not in {x['proxy'].get('name') for x in results if x.get('ok')}]
        except Exception:
            candidates=[]
        if not candidates:
            results.append({'uri':uri,'ok':False,'reason':'proxy_not_found'}); continue
        p=candidates[0]
        ok,reason=test_proxy(p)
        results.append({'uri':uri,'name':p['name'],'server':p.get('server'),'port':p.get('port'),'ok':ok,'reason':reason,'proxy':p})
        if ok: good.append(uri)
        print(f'[{i}/{min(len(raw),MAX)}] {p["name"]}: {"PASS" if ok else "FAIL"} ({reason})', flush=True)
    HEALTHY.write_text('\n'.join(good) + ('\n' if good else ''), encoding='utf-8')
    REPORT.write_text(json.dumps({'tested':len(results),'healthy':len(good),'failed':len(results)-len(good),'results':results}, ensure_ascii=False, indent=2), encoding='utf-8')
    print(f'HEALTHCHECK tested={len(results)} healthy={len(good)} failed={len(results)-len(good)}')
    if raw and not good:
        raise SystemExit('No node passed protocol-level health check; refusing to publish unverified nodes.')

if __name__ == '__main__': main()
