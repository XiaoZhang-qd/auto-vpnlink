#!/usr/bin/env python3
"""Merge all valid discovered nodes with health-check results.

Healthy nodes are placed first; all other syntactically valid, deduplicated
nodes are retained so a temporary GitHub Runner/network failure does not erase
the published node pool.
"""
import hashlib, json, re
from pathlib import Path
import converter

OUT=Path('output')
raw_path=OUT/'discovered-nodes.txt'
healthy_path=OUT/'health-checked-nodes.txt'
out_path=OUT/'publish-nodes.txt'
pat=re.compile(r"(?i)(?:vless|vmess|ssr?|trojan|hysteria2?|hy2|tuic|relay)://[^\s<>\"'\\]+")

def clean(u): return u.strip().rstrip('.,;!?)]}')
def key_for(u, idx):
    n=converter.parse(u, idx)
    if n:
        try: return 'parsed:' + converter.fingerprint(n)
        except Exception: pass
    return 'raw:' + hashlib.sha256(clean(u).encode('utf-8')).hexdigest()
def collect(path):
    if not path.exists(): return []
    out=[]
    for line in path.read_text(encoding='utf-8', errors='ignore').splitlines():
        for u in pat.findall(line):
            u=clean(u)
            if u: out.append(u)
    return out
all_nodes=collect(raw_path); healthy=collect(healthy_path)
seen=set(); ordered=[]; stats={}
for group in (healthy, all_nodes):
    for i,u in enumerate(group,1):
        k=key_for(u,i)
        if k in seen: continue
        seen.add(k); ordered.append(u)
        scheme=u.split('://',1)[0].lower(); stats[scheme]=stats.get(scheme,0)+1
out_path.write_text(('\n'.join(ordered)+'\n') if ordered else '', encoding='utf-8')
summary={'discovered_raw':len(all_nodes),'healthy_raw':len(healthy),'published_unique':len(ordered),'protocols':stats}
(OUT/'publish-summary.json').write_text(json.dumps(summary,ensure_ascii=False,indent=2),encoding='utf-8')
print('PUBLISH MERGE:',json.dumps(summary,ensure_ascii=False))
if all_nodes and not ordered: raise SystemExit('No valid discovered nodes found.')
