#!/usr/bin/env python3
"""Select diverse candidates, prioritizing protocols supported by CFW."""
import hashlib,json,re,base64
from pathlib import Path
from urllib.parse import urlparse,parse_qs,unquote
SCHEMES=('vless','vmess','trojan','ss','hysteria2','hysteria','hy2','tuic')
# CFW-compatible protocols are given the majority of health-check slots.
MAX=600
QUOTAS={'ss':220,'trojan':160,'vmess':100,'vless':60,'hysteria2':60,'tuic':0}
raw=Path('output/discovered-nodes.txt').read_text(encoding='utf-8',errors='ignore').splitlines()
pat=re.compile(r"(?i)(?:vless|vmess|ss|trojan|hysteria2?|hy2|tuic)://[^\s<>\"'\\]+")
def b64(s):
 s=''.join(s.split()).replace('-','+').replace('_','/');return base64.b64decode(s+'='*(-len(s)%4)).decode('utf-8','ignore')
def parse(u):
 try:
  p=urlparse(u);s=p.scheme.lower();q={k:v[-1] for k,v in parse_qs(p.query,keep_blank_values=True).items()}
  if s=='vmess':
   d=json.loads(b64(u.split('://',1)[1]));return {'type':'vmess','server':str(d.get('add','')).lower(),'port':int(d.get('port',0)),'cred':str(d.get('id','')).lower(),'sni':str(d.get('sni') or d.get('host') or '').lower()}
  if s=='vless':return {'type':'vless','server':(p.hostname or '').lower(),'port':p.port or 443,'cred':unquote(p.username or ''),'sni':q.get('sni') or p.hostname or ''}
  if s=='trojan':return {'type':'trojan','server':(p.hostname or '').lower(),'port':p.port or 443,'cred':unquote(p.username or ''),'sni':q.get('sni') or p.hostname or ''}
  if s=='ss':
   r=unquote(u.split('://',1)[1].split('#',1)[0]);r=b64(r) if '@' not in r else r;a,h=r.rsplit('@',1);m,pw=a.split(':',1);host,port=h.rsplit(':',1);return {'type':'ss','server':host.strip('[]').lower(),'port':int(port),'cred':m+':'+pw}
  if s in ('hysteria2','hysteria','hy2'):return {'type':'hysteria2','server':(p.hostname or '').lower(),'port':p.port or 443,'cred':unquote(p.username or '')}
  if s=='tuic':return {'type':'tuic','server':(p.hostname or '').lower(),'port':p.port or 443,'cred':unquote(p.username or '')+':'+unquote(p.password or '')}
 except Exception:return None
def fingerprint(n):
 if not n or not n.get('server') or not n.get('port') or not n.get('cred'):return None
 return hashlib.sha256(json.dumps(sorted((k,str(v)) for k,v in n.items()),ensure_ascii=False).encode()).hexdigest()
def spread_pick(items,limit):
 if len(items)<=limit:return items
 step=(len(items)-1)/(limit-1);return [items[round(i*step)] for i in range(limit)]
buckets={s:[] for s in SCHEMES};seen=set();rejected=0
for line in raw:
 for u in pat.findall(line):
  u=u.strip().rstrip('.,;!?)]}')
  n=parse(u)
  if not n or n['type'] not in buckets:rejected+=1;continue
  fp=fingerprint(n)
  if not fp or fp in seen:continue
  seen.add(fp);buckets[n['type']].append((u,n,fp))
selected=[]
for s,q in QUOTAS.items():selected.extend(spread_pick(buckets[s],q))
selected=selected[:MAX]
Path('output/health-candidates.txt').write_text('\n'.join(x[0] for x in selected)+('\n' if selected else ''),encoding='utf-8')
Path('output/candidate-summary.json').write_text(json.dumps({'discovered_lines':len(raw),'rejected_malformed':rejected,'unique_by_credentials':len(seen),'protocol_candidates':{s:len(buckets[s]) for s in SCHEMES},'selected':len(selected),'selected_protocols':{s:sum(1 for _,n,_ in selected if n['type']==s) for s in SCHEMES}},ensure_ascii=False,indent=2),encoding='utf-8')
print('protocol candidates:',{s:len(buckets[s]) for s in SCHEMES});print('selected:',{s:sum(1 for _,n,_ in selected if n['type']==s) for s in SCHEMES});print('health candidates:',len(selected))
if not selected:raise SystemExit('No clean, unique protocol candidates found.')
