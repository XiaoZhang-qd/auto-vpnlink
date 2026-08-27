#!/usr/bin/env python3
"""Publish every node that passed the current health check, with protocol-specific outputs."""
import base64,json,re
from pathlib import Path
import yaml
import converter
OUT=Path('output'); CFW_TYPES={'ss','ssr','vmess','trojan'}
def clean(u): return u.strip().rstrip('.,;!?)]}')
def safe_name(value,fallback):
    value=re.sub(r'[\x00-\x1f\x7f]','',str(value or '')).strip(); return value[:100] or fallback
# Always consume the result produced by THIS run. Never prefer a stale
# health-checked-cfw.txt left by an older workflow execution.
health_file=OUT/'health-checked-all.txt'
if not health_file.exists(): health_file=OUT/'health-checked-nodes.txt'
raw=[clean(x) for x in health_file.read_text(encoding='utf-8',errors='ignore').splitlines() if x.strip()] if health_file.exists() else []
nodes=[];uris=[];rejected=[];seen=set();name_count={}
for i,u in enumerate(raw,1):
    n=converter.parse(u,i)
    if not n:
        rejected.append({'uri':u,'reason':'parse_failed'}); continue
    key='|'.join(str(n.get(k,'')) for k in ('type','server','port','uuid','password','cipher','sni'))
    if key in seen: continue
    seen.add(key)
    base=safe_name(n.get('name'),f"{n['type']}-{n['server']}:{n['port']}")
    lk=base.casefold();name_count[lk]=name_count.get(lk,0)+1
    n['name']=base if name_count[lk]==1 else f'{base} [{name_count[lk]}]'
    nodes.append(n);uris.append(u)

proxies=[]; cfw_uris=[]
for u,n in zip(uris,nodes):
    if n.get('type') not in CFW_TYPES: continue
    try:
        p=converter.clash(n)
        if p and p.get('type') in CFW_TYPES:
            proxies.append(p); cfw_uris.append(u)
        else: rejected.append({'uri':u,'reason':'cfw_conversion_rejected'})
    except Exception as e: rejected.append({'uri':u,'reason':'cfw_conversion_error:'+type(e).__name__})

names=[p['name'] for p in proxies]
cfg={'mixed-port':7890,'allow-lan':False,'mode':'rule','log-level':'info','proxies':proxies,'proxy-groups':[{'name':'AUTO','type':'url-test','proxies':names,'url':'https://www.gstatic.com/generate_204','interval':300,'tolerance':50}] if names else [],'rules':['MATCH,AUTO'] if names else ['MATCH,DIRECT']}
for fn in ('clash.yaml','stash.yaml'): (OUT/fn).write_text(yaml.safe_dump(cfg,allow_unicode=True,sort_keys=False),encoding='utf-8')
# Generic feeds contain ALL healthy nodes; CFW feed contains only classic CFW-compatible healthy nodes.
all_text='\n'.join(uris)+'\n' if uris else ''
cfw_text='\n'.join(cfw_uris)+'\n' if cfw_uris else ''
for fn in ('nodes.txt','all-nodes.txt','health-checked-all.txt'): (OUT/fn).write_text(all_text,encoding='utf-8')
(OUT/'health-checked-cfw.txt').write_text(cfw_text,encoding='utf-8')
(OUT/'shadowrocket.txt').write_text(all_text,encoding='utf-8')
(OUT/'base64.txt').write_text((base64.b64encode(all_text.encode()).decode()+'\n') if all_text else '',encoding='utf-8')
by={}
for u,n in zip(uris,nodes): by.setdefault(n['type'],[]).append(u)
for p in ('ss','ssr','vmess','trojan','vless','hysteria2','tuic'):
    vals=by.get(p,[]); (OUT/f'{p}.txt').write_text('\n'.join(vals)+'\n' if vals else '',encoding='utf-8')
summary={'health_input':len(raw),'healthy_total':len(nodes),'cfw_healthy_parsed':len(cfw_uris),'clash_proxies':len(proxies),'rejected_after_health':len(rejected),'protocols':{k:len(v) for k,v in by.items()},'cfw_types':sorted(CFW_TYPES)}
(OUT/'publish-summary.json').write_text(json.dumps(summary,ensure_ascii=False,indent=2),encoding='utf-8')
print('PUBLISH:',json.dumps(summary,ensure_ascii=False))
if nodes and not proxies and any(n.get('type') in CFW_TYPES for n in nodes): raise SystemExit('Healthy CFW-compatible nodes could not be converted; refusing to publish an empty CFW profile.')
