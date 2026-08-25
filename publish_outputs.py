#!/usr/bin/env python3
"""Publish only nodes that passed the CFW-specific real-egress health check.

The previous publisher re-added the entire raw pool after health checking. That
made server-side PASS nodes and untested/dead nodes mix together and it also
used a second, different URI parser. This version uses the exact same
converter.py parser used by healthcheck.py and publishes only the health-check
output for the CFW feed.
"""
import base64, json, re
from pathlib import Path
import yaml
import converter

OUT=Path('output')
CFW_TYPES={'ss','ssr','vmess','trojan'}
CFW_SS_CIPHERS={'aes-128-gcm','aes-192-gcm','aes-256-gcm','chacha20-ietf-poly1305','xchacha20-ietf-poly1305'}

def clean(u): return u.strip().rstrip('.,;!?)]}')

def safe_name(value,fallback):
    value=re.sub(r'[\x00-\x1f\x7f]','',str(value or '')).strip()
    return value[:100] or fallback

def cfw_proxy(n):
    if n.get('type') not in CFW_TYPES:return None
    if n.get('type')=='ss' and str(n.get('cipher','')).lower() not in CFW_SS_CIPHERS:return None
    p=converter.clash(n)
    if not p:return None
    # Classic CFW/Clash is safest with these fields only.
    p={k:v for k,v in p.items() if v not in (None,'')}
    return p

health_file=OUT/'health-checked-cfw.txt'
if not health_file.exists():
    health_file=OUT/'health-checked-nodes.txt'
raw=[clean(x) for x in health_file.read_text(encoding='utf-8',errors='ignore').splitlines() if x.strip()]
nodes=[];uris=[];rejected=[];seen=set();name_count={}
for i,u in enumerate(raw,1):
    n=converter.parse(u,i)
    if not n or n.get('type') not in CFW_TYPES:
        rejected.append({'uri':u,'reason':'not_cfw_or_parse_failed'});continue
    fp=converter.parse(u,i)
    key='|'.join(str(fp.get(k,'')) for k in ('type','server','port','uuid','password','cipher'))
    if key in seen:continue
    seen.add(key)
    base=safe_name(n.get('name'),f"{n['type']}-{n['server']}:{n['port']}")
    lk=base.casefold();name_count[lk]=name_count.get(lk,0)+1
    n['name']=base if name_count[lk]==1 else f'{base} [{name_count[lk]}]'
    nodes.append(n);uris.append(u)

proxies=[]
for n in nodes:
    p=cfw_proxy(n)
    if p:proxies.append(p)
    else:rejected.append({'uri':next((u for u,nn in zip(uris,nodes) if nn is n),''),'reason':'cfw_conversion_rejected'})

names=[p['name'] for p in proxies]
cfg={'mixed-port':7890,'allow-lan':False,'mode':'rule','log-level':'info','proxies':proxies,'proxy-groups':[{'name':'AUTO','type':'url-test','proxies':names,'url':'https://www.gstatic.com/generate_204','interval':300,'tolerance':50}] if names else [],'rules':['MATCH,AUTO'] if names else ['MATCH,DIRECT']}
(OUT/'clash.yaml').write_text(yaml.safe_dump(cfg,allow_unicode=True,sort_keys=False),encoding='utf-8')
(OUT/'stash.yaml').write_text(yaml.safe_dump(cfg,allow_unicode=True,sort_keys=False),encoding='utf-8')

text='\n'.join(uris)+'\n' if uris else ''
(OUT/'nodes.txt').write_text(text,encoding='utf-8')
(OUT/'shadowrocket.txt').write_text(text,encoding='utf-8')
(OUT/'all-nodes.txt').write_text(text,encoding='utf-8')
(OUT/'base64.txt').write_text((base64.b64encode(text.encode()).decode()+'\n') if text else '',encoding='utf-8')
by={}
for u,n in zip(uris,nodes):by.setdefault(n['type'],[]).append(u)
for p in ('ss','ssr','vmess','trojan','vless','hysteria2','tuic'):
    vals=by.get(p,[]);(OUT/f'{p}.txt').write_text('\n'.join(vals)+'\n' if vals else '',encoding='utf-8')
summary={'health_input':len(raw),'cfw_healthy_parsed':len(nodes),'clash_proxies':len(proxies),'rejected_after_health':len(rejected),'protocols':{k:len(v) for k,v in by.items()},'cfw_types':sorted(CFW_TYPES)}
(OUT/'publish-summary.json').write_text(json.dumps(summary,ensure_ascii=False,indent=2),encoding='utf-8')
print('CFW PUBLISH:',json.dumps(summary,ensure_ascii=False))
if raw and not proxies:raise SystemExit('No CFW-compatible health-checked nodes could be converted; refusing to publish an empty CFW profile.')
