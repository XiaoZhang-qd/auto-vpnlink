#!/usr/bin/env python3
"""Finalize Clash output without collapsing it to only a few health checks.

Health checks are a ranking signal, not a hard inclusion gate. All nodes that
are already present in the generated Clash config and pass basic Mihomo-safe
shape checks are retained; nodes proven healthy are moved to the front.
Legacy/unsupported ciphers have already been removed by publish_outputs.py.
"""
import json
from pathlib import Path
import yaml
import converter

OUT=Path('output')
healthy_file=OUT/'health-checked-nodes.txt'
clash_file=OUT/'clash.yaml'
if not clash_file.exists():
    raise SystemExit('clash.yaml not found')

# Build the set of proxy names that the real-egress health check confirmed.
healthy=set()
if healthy_file.exists():
    for i,u in enumerate(healthy_file.read_text(encoding='utf-8',errors='ignore').splitlines(),1):
        u=u.strip()
        if not u: continue
        try:
            n=converter.parse(u,i)
            if n:
                p=converter.clash(n)
                if p and p.get('name'): healthy.add(str(p['name']))
        except Exception:
            pass

cfg=yaml.safe_load(clash_file.read_text(encoding='utf-8')) or {}
all_proxies=cfg.get('proxies') or []

def basic_ok(p):
    if not isinstance(p,dict): return False
    t=str(p.get('type','')).lower()
    if t not in {'ss','ssr','vless','vmess','trojan','hysteria','hysteria2','tuic'}:
        return False
    if not p.get('server'): return False
    try:
        port=int(p.get('port',0))
        if not 1 <= port <= 65535: return False
    except Exception:
        return False
    if t=='ss':
        cipher=str(p.get('cipher','')).lower()
        allowed={'aes-128-gcm','aes-192-gcm','aes-256-gcm','chacha20-ietf-poly1305','xchacha20-ietf-poly1305'}
        if cipher not in allowed or not p.get('password'): return False
    if t in {'vless','vmess','tuic'} and not p.get('uuid'): return False
    if t in {'trojan','hysteria2'} and not p.get('password'): return False
    return True

# Keep every syntactically compatible proxy, but put verified proxies first.
compatible=[p for p in all_proxies if basic_ok(p)]
verified=[p for p in compatible if str(p.get('name','')) in healthy]
unverified=[p for p in compatible if str(p.get('name','')) not in healthy]
kept=verified+unverified
names=[p.get('name') for p in kept]
for g in cfg.get('proxy-groups') or []:
    if g.get('name') in {'AUTO','自动选择'}:
        g['proxies']=names
cfg['proxies']=kept
if not kept:
    raise SystemExit('No compatible Clash nodes found')
clash_file.write_text(yaml.safe_dump(cfg,allow_unicode=True,sort_keys=False),encoding='utf-8')

summary_path=OUT/'publish-summary.json'
summary=json.loads(summary_path.read_text(encoding='utf-8')) if summary_path.exists() else {}
summary['clash_proxies']=len(kept)
summary['clash_verified_kept']=len(verified)
summary['clash_unverified_kept']=len(unverified)
summary['clash_incompatible_removed']=len(all_proxies)-len(compatible)
summary_path.write_text(json.dumps(summary,ensure_ascii=False,indent=2),encoding='utf-8')
print(f'CLASH FINAL: before={len(all_proxies)} compatible={len(compatible)} verified_first={len(verified)} unverified_kept={len(unverified)} removed_incompatible={len(all_proxies)-len(compatible)}')
