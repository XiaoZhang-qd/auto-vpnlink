#!/usr/bin/env python3
"""Merge only nodes that passed the real-egress health check.

The scanner may discover thousands of syntactically valid URLs, but a node is
not useful to a client unless it can actually proxy public HTTPS traffic.
Healthy results are therefore the publish gate; the raw/protocol feeds remain
available separately for debugging/source inspection.
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
# Only health-checked nodes enter the publish pool. This prevents clients from
# receiving thousands of dead endpoints and showing them as Error.
for i,u in enumerate(healthy,1):
    k=key_for(u,i)
    if k in seen: continue
    seen.add(k); ordered.append(u)
    scheme=u.split('://',1)[0].lower(); stats[scheme]=stats.get(scheme,0)+1
out_path.write_text(('\n'.join(ordered)+'\n') if ordered else '', encoding='utf-8')
summary={'discovered_raw':len(all_nodes),'healthy_raw':len(healthy),'published_unique':len(ordered),'protocols':stats,'unverified_discovered_not_published':max(0,len(all_nodes)-len(ordered))}
(OUT/'publish-summary.json').write_text(json.dumps(summary,ensure_ascii=False,indent=2),encoding='utf-8')
print('PUBLISH MERGE:',json.dumps(summary,ensure_ascii=False))
if all_nodes and not ordered: raise SystemExit('No node passed the real-egress health check; refusing to publish dead endpoints.')
