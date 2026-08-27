#!/usr/bin/env python3
import hashlib,json,re,base64,os
from pathlib import Path
from urllib.parse import urlparse,parse_qs,unquote
SCHEMES=('vless','vmess','trojan','ss','hysteria2','hysteria','hy2','tuic')
SEARCH_LIMIT=max(1,int(os.getenv('SEARCH_LIMIT','5000')))
HEALTH_CANDIDATES=max(1,int(os.getenv('HEALTH_CANDIDATES','300')))
QUOTAS={'ss':.15,'trojan':.15,'vmess':.10,'vless':.20,'hysteria2':.30,'hysteria':.05,'tuic':.05}
raw=Path('output/discovered-nodes.txt').read_text(encoding='utf-8',errors='ignore').splitlines()[:SEARCH_LIMIT]
pat=re.compile(r"(?i)(?:vless|vmess|trojan|ss|hysteria2?|hy2|tuic)://[^\s<>\"'\\]+")
def b64(s):
 s=''.join(s.split()).replace('-','+').replace('_','/');return base64.b64decode(s+'='*(-len(s)%4)).decode('utf-8','ignore')
def parse(u):
 try:
  p=urlparse(u);s=p.scheme.lower();q={k:v[-1] for k,v in parse_qs(p.query,keep_blank_values=True).items()}
  if s=='vmess':
   d=json.loads(b64(u.split('://',1)[1]));return {'type':'vmess','server':str(d.get('add','')).lower(),'port':int(d.get('port',0)),'cred':str(d.get('id','')).lower(),'sni':str(d.get('sni') or d.get('host') or '').lower()}
  if s=='trojan':return {'type':'trojan','server':(p.hostname or '').lower(),'port':p.port or 443,'cred':unquote(p.username or ''),'sni':q.get('sni') or p.hostname or ''}
  if s=='ss':
   r=unquote(u.split('://',1)[1].split('#',1)[0]);r=b64(r) if '@' not in r else r;a,h=r.rsplit('@',1);m,pw=a.split(':',1);host,port=h.rsplit(':',1);return {'type':'ss','server':host.strip('[]').lower(),'port':int(port),'cred':m+':'+pw,'cipher':m.lower()}
  if s=='vless':return {'type':'vless','server':(p.hostname or '').lower(),'port':p.port or 443,'cred':unquote(p.username or ''),'sni':q.get('sni') or p.hostname or ''}
  if s in ('hysteria2','hysteria','hy2'):return {'type':'hysteria2','server':(p.hostname or '').lower(),'port':p.port or 443,'cred':unquote(p.username or ''),'sni':q.get('sni') or p.hostname or ''}
  if s=='tuic':return {'type':'tuic','server':(p.hostname or '').lower(),'port':p.port or 443,'cred':unquote(p.username or '')+':'+unquote(p.password or '')}
 except Exception:return None

def fingerprint(n):
 if not n or not n.get('server') or not n.get('port') or not n.get('cred'):return None
 return hashlib.sha256(json.dumps(sorted((k,str(v)) for k,v in n.items()),ensure_ascii=False).encode()).hexdigest()
def spread_pick(items,limit):
 if limit<=0 or not items:return []
 if len(items)<=limit:return items
 if limit==1:return [items[0]]
 step=(len(items)-1)/(limit-1);return [items[round(i*step)] for i in range(limit)]
buckets={s:[] for s in SCHEMES};seen=set();rejected=0
for line in raw:
 for u in pat.findall(line):
  u=u.strip().rstrip('.,;!?)]}')
  n=parse(u)
  if not n or n['type'] not in buckets:rejected+=1;continue
  f=fingerprint(n)
  if not f or f in seen:continue
  seen.add(f);buckets[n['type']].append((u,n,f))
selected=[];used=set()
for s,q in QUOTAS.items():
 want=min(len(buckets[s]),round(HEALTH_CANDIDATES*q))
 chosen=spread_pick(buckets[s],want);selected.extend(chosen);used.update(x[2] for x in chosen)
remaining=HEALTH_CANDIDATES-len(selected)
if remaining>0:
 pool=[x for s in SCHEMES for x in buckets[s] if x[2] not in used]
 selected.extend(spread_pick(pool,remaining))
selected=selected[:HEALTH_CANDIDATES]
Path('output/health-candidates.txt').write_text('\n'.join(x[0] for x in selected)+('\n' if selected else ''),encoding='utf-8')
summary={'search_limit':SEARCH_LIMIT,'discovered_lines_considered':len(raw),'rejected_malformed':rejected,'unique_candidates':len(seen),'protocol_candidates':{s:len(buckets[s]) for s in SCHEMES},'health_candidate_limit':HEALTH_CANDIDATES,'selected':len(selected),'selected_protocols':{s:sum(1 for _,n,_ in selected if n['type']==s) for s in SCHEMES}}
Path('output/candidate-summary.json').write_text(json.dumps(summary,ensure_ascii=False,indent=2),encoding='utf-8')
print('search_limit:',SEARCH_LIMIT);print('protocol candidates:',summary['protocol_candidates']);print('selected:',summary['selected_protocols']);print('health candidates:',len(selected))
if not selected:raise SystemExit('No parseable proxy candidates found.')
