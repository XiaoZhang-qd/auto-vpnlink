#!/usr/bin/env python3
"""Keep the complete node pool in raw feeds, but make clash.yaml usable.

Clash is a runtime configuration, so untested/dead nodes are not placed in it.
They remain available in all-nodes and protocol-specific feeds. Health-checked
nodes are matched by the converter-generated proxy name and placed in Clash.
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
kept=[p for p in all_proxies if str(p.get('name','')) in healthy]
# Stable order: verified nodes first, preserving the generated order.
names=[p.get('name') for p in kept]
for g in cfg.get('proxy-groups') or []:
    if g.get('name')=='AUTO':
        g['proxies']=names
if kept:
    cfg['proxies']=kept
else:
    cfg['proxies']=[]
    cfg['proxy-groups']=[]
    cfg['rules']=['MATCH,DIRECT']
clash_file.write_text(yaml.safe_dump(cfg,allow_unicode=True,sort_keys=False),encoding='utf-8')
summary_path=OUT/'publish-summary.json'
summary=json.loads(summary_path.read_text(encoding='utf-8')) if summary_path.exists() else {}
summary['clash_proxies']=len(kept)
summary['clash_unverified_removed']=len(all_proxies)-len(kept)
summary['clash_verified_names']=len(healthy)
summary_path.write_text(json.dumps(summary,ensure_ascii=False,indent=2),encoding='utf-8')
print(f'CLASH VERIFIED FILTER: before={len(all_proxies)} healthy_names={len(healthy)} after={len(kept)} removed_unverified={len(all_proxies)-len(kept)}')
if not kept and all_proxies:
    raise SystemExit('No health-checked node could be matched into Clash; refusing to publish a misleading Clash config.')
