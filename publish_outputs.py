#!/usr/bin/env python3
"""Publish all deduplicated valid nodes; healthy nodes are first.

Clash output contains protocols supported by the current converter. Every
requested protocol also gets its own raw URI feed so unsupported-by-Clash
protocols are not silently discarded.
"""
import base64,hashlib,json,re
from pathlib import Path
from urllib.parse import urlparse,parse_qs,unquote
import yaml
OUT=Path('output')
SCHEMES=('ss','ssr','vless','vmess','relay','trojan','hysteria','hysteria2','hy2','tuic')
PAT=re.compile(r'(?i)^([a-z0-9_-]+)://')
def clean(u): return u.strip().rstrip('.,;!?)]}')
def b64d(s):
    s=''.join(s.split()).replace('-','+').replace('_','/')
    return base64.b64decode(s+'='*(-len(s)%4)).decode('utf-8','ignore')
def qd(q): return {k:v[-1] for k,v in parse_qs(q,keep_blank_values=True).items()}
def parse(u,i):
    try:
        s=u.split('://',1)[0].lower(); p=urlparse(u); q=qd(p.query)
        if s not in SCHEMES:return None
        name=unquote(p.fragment or q.get('remarks') or q.get('name') or f'{s}-{i}')[:100]
        if s=='ssr':
            d=b64d(u.split('://',1)[1]); main,*tail=d.split('/?',1); a=main.split(':')
            if len(a)<6:return None
            pp=qd(tail[0] if tail else ''); return {'type':'ssr','name':name,'server':a[0],'port':int(a[1]),'protocol':a[2],'cipher':a[3],'obfs':a[4],'password':b64d(a[5]),'protocol-param':pp.get('protoparam',''),'obfs-param':pp.get('obfsparam','')}
        if s=='vmess':
            d=json.loads(b64d(u.split('://',1)[1]));return {'type':'vmess','name':unquote(d.get('ps') or name),'server':d.get('add'),'port':int(d.get('port',0)),'uuid':d.get('id'),'tls':str(d.get('tls','')).lower() in ('tls','1','true'),'sni':d.get('sni') or d.get('host'),'net':d.get('net') or 'tcp','path':d.get('path') or '','host':d.get('host') or '','aid':int(d.get('aid',0))}
        if s=='vless':return {'type':s,'name':name,'server':p.hostname,'port':p.port or 443,'uuid':unquote(p.username or ''),'tls':q.get('security','') in ('tls','reality'),'security':q.get('security',''),'sni':q.get('sni') or p.hostname,'net':q.get('type','tcp'),'path':q.get('path',''),'host':q.get('host',''),'flow':q.get('flow',''),'pbk':q.get('pbk',''),'sid':q.get('sid','')}
        if s=='trojan':return {'type':s,'name':name,'server':p.hostname,'port':p.port or 443,'password':unquote(p.username or ''),'sni':q.get('sni') or p.hostname,'net':q.get('type','tcp'),'path':q.get('path',''),'host':q.get('host','')}
        if s=='ss':
            raw=unquote(u.split('://',1)[1].split('#',1)[0]);raw=b64d(raw) if '@' not in raw else raw;a,h=raw.rsplit('@',1);cipher,password=a.split(':',1);server,port=h.rsplit(':',1);return {'type':'ss','name':name,'server':server.strip('[]'),'port':int(port),'cipher':cipher,'password':password}
        if s in ('hysteria2','hy2'):return {'type':'hysteria2','name':name,'server':p.hostname,'port':p.port or 443,'password':unquote(p.username or ''),'sni':q.get('sni') or p.hostname,'insecure':q.get('insecure','0').lower() in ('1','true'),'obfs':q.get('obfs',''),'obfs-password':q.get('obfs-password',''),'alpn':q.get('alpn','')}
        if s=='hysteria':return {'type':'hysteria','name':name,'server':p.hostname,'port':p.port or 443,'auth-str':q.get('auth') or q.get('auth-str') or unquote(p.username or ''),'sni':q.get('sni') or p.hostname,'insecure':q.get('insecure','0').lower() in ('1','true'),'protocol':q.get('protocol','udp')}
        if s=='tuic':return {'type':'tuic','name':name,'server':p.hostname,'port':p.port or 443,'uuid':unquote(p.username or ''),'password':unquote(p.password or ''),'sni':q.get('sni') or p.hostname,'cc':q.get('congestion_control','bbr')}
        if s=='relay':return {'type':'relay','name':name,'raw':u}
    except Exception:return None

def fp(n):
    if n.get('type')=='relay':return 'relay:'+hashlib.sha256(n['raw'].encode()).hexdigest()
    keys=('type','server','port','uuid','password','cipher','protocol','obfs','sni','protocol-param','obfs-param','auth-str','flow','net','path','host','aid')
    return hashlib.sha256('|'.join(str(n.get(k,'')) for k in keys).encode()).hexdigest()
def valid(n):
    if not n:return False
    if n['type']=='relay':return True
    if not n.get('server') or not isinstance(n.get('port'),int) or not 1<=n['port']<=65535:return False
    if n['type'] in ('vless','vmess') and not n.get('uuid'):return False
    if n['type'] in ('trojan','hysteria2') and not n.get('password'):return False
    if n['type']=='ss' and not n.get('cipher') or n.get('type')=='ss' and not n.get('password'):return False
    if n['type']=='ssr' and (not n.get('cipher') or not n.get('password')):return False
    if n['type']=='tuic' and (not n.get('uuid') or not n.get('password')):return False
    return True

def safe_name(x,f):return re.sub(r'[\x00-\x1f\x7f]','',str(x or f)).strip()[:100] or f
def clash(n):
    t=n['type'];o={'name':n['name'],'type':t,'server':n['server'],'port':n['port']}
    if t=='ss':o.update(cipher=n['cipher'],password=n['password'],udp=True)
    elif t=='ssr':o.update(cipher=n['cipher'],password=n['password'],protocol=n['protocol'],obfs=n['obfs'],udp=True,**({'protocol-param':n['protocol-param']} if n.get('protocol-param') else {}),**({'obfs-param':n['obfs-param']} if n.get('obfs-param') else {}))
    elif t=='vless':o.update(uuid=n['uuid'],tls=n['tls'],udp=True,**({'servername':n['sni']} if n.get('sni') else {}))
    elif t=='vmess':o.update(uuid=n['uuid'],cipher='auto',alterId=n['aid'],tls=n['tls'],udp=True,**({'servername':n['sni']} if n.get('sni') else {}))
    elif t=='trojan':o.update(password=n['password'],sni=n['sni'],udp=True)
    elif t=='hysteria2':o.update(password=n['password'],sni=n['sni'],udp=True,**{'skip-cert-verify':n['insecure']})
    elif t=='tuic':o.update(uuid=n['uuid'],password=n['password'],udp=True,**{'congestion-controller':n['cc']})
    return o
raw=[clean(x) for x in (OUT/'publish-nodes.txt').read_text(encoding='utf-8',errors='ignore').splitlines() if x.strip()]
healthy=[clean(x) for x in (OUT/'health-checked-nodes.txt').read_text(encoding='utf-8',errors='ignore').splitlines()] if (OUT/'health-checked-nodes.txt').exists() else []
ordered=[];seen=set();healthy_keys=set()
for i,u in enumerate(healthy,1):
 n=parse(u,i)
 if n and valid(n):healthy_keys.add(fp(n))
for group in (healthy,raw):
 for i,u in enumerate(group,1):
  n=parse(u,i)
  if not valid(n):continue
  k=fp(n)
  if k in seen:continue
  seen.add(k);ordered.append((u,n,k))
nodes=[n for _,n,_ in ordered]
used={}
for n in nodes:
 b=safe_name(n.get('name'),f"{n['type']}-{n.get('server','relay')}");k=b.casefold();used[k]=used.get(k,0)+1;n['name']=b if used[k]==1 else f'{b} [{used[k]}]'
proxies=[clash(n) for n in nodes if n['type'] in ('ss','ssr','vless','vmess','trojan','hysteria2','tuic')]
names=[p['name'] for p in proxies]
cfg={'proxies':proxies,'proxy-groups':[{'name':'AUTO','type':'url-test','proxies':names,'url':'https://www.gstatic.com/generate_204','interval':300}],'rules':['MATCH,AUTO']} if proxies else {'proxies':[],'proxy-groups':[],'rules':['MATCH,DIRECT']}
for fn in ('clash.yaml','stash.yaml'):(OUT/fn).write_text(yaml.safe_dump(cfg,allow_unicode=True,sort_keys=False),encoding='utf-8')
by={}
for u,n,k in ordered:by.setdefault(n['type'],[]).append(u)
for scheme in SCHEMES:
 vals=by.get(scheme,[]);(OUT/f'{scheme}.txt').write_text(('\n'.join(vals)+'\n') if vals else '',encoding='utf-8')
(OUT/'all-nodes.txt').write_text(('\n'.join(u for u,_,_ in ordered)+'\n') if ordered else '',encoding='utf-8')
(OUT/'nodes.txt').write_text(('\n'.join(u for u,_,_ in ordered)+'\n') if ordered else '',encoding='utf-8')
text='\n'.join(u for u,_,_ in ordered)+'\n' if ordered else ''; (OUT/'shadowrocket.txt').write_text(text,encoding='utf-8');(OUT/'base64.txt').write_text((base64.b64encode(text.encode()).decode()+'\n') if text else '',encoding='utf-8')
summary={'discovered':len(raw),'healthy_first':len(healthy_keys),'published_unique':len(ordered),'clash_proxies':len(proxies),'protocols':{k:len(v) for k,v in by.items()}}
(OUT/'publish-summary.json').write_text(json.dumps(summary,ensure_ascii=False,indent=2),encoding='utf-8');print('PUBLISH:',json.dumps(summary,ensure_ascii=False))
if raw and not ordered:raise SystemExit('No valid nodes to publish')
