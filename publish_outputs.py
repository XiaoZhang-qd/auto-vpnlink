#!/usr/bin/env python3
"""Publish deduplicated VPN nodes and generate a legacy Clash-for-Windows config.

Raw protocol feeds keep every syntactically valid URI. The main clash.yaml is
intentionally limited to proxy types supported by classic Clash for Windows:
SS, SSR, VMess and Trojan. Modern-only types such as VLESS/Hysteria2/TUIC are
still written to their own protocol files and are not allowed to make the CFW
profile fail to load.
"""
import base64, hashlib, ipaddress, json, re
from pathlib import Path
from urllib.parse import urlparse, parse_qs, unquote
import yaml

OUT=Path('output')
SCHEMES=('ss','ssr','vless','vmess','relay','trojan','hysteria','hysteria2','hy2','tuic')
CFW_TYPES=frozenset({'ss','ssr','vmess','trojan'})
CLASH_SS_CIPHERS=frozenset({'aes-128-gcm','aes-192-gcm','aes-256-gcm','chacha20-ietf-poly1305','xchacha20-ietf-poly1305'})
BAD_HOSTS=frozenset({'host.com','cdn.example.com','example.com','localhost','127.0.0.1','uuid'})
BAD_VALUES=re.compile(r'(?i)^(?:\$\{|\$|uuid$|password$|changeme$|example(?:\.com)?$|host\.com$)')

def clean(u): return u.strip().rstrip('.,;!?)]}')
def b64d(s):
    s=''.join(s.split()).replace('-','+').replace('_','/')
    return base64.b64decode(s+'='*(-len(s)%4)).decode('utf-8','ignore')
def qd(q): return {k:v[-1] for k,v in parse_qs(q,keep_blank_values=True).items()}

def parse(u,i):
    try:
        s=u.split('://',1)[0].lower(); p=urlparse(u); q=qd(p.query)
        if s not in SCHEMES: return None
        name=unquote(p.fragment or q.get('remarks') or q.get('name') or f'{s}-{i}')[:100]
        if s=='ssr':
            d=b64d(u.split('://',1)[1]); main,*tail=d.split('/?',1); a=main.split(':')
            if len(a)<6:return None
            pp=qd(tail[0] if tail else '')
            return {'type':'ssr','name':name,'server':a[0],'port':int(a[1]),'protocol':a[2],'cipher':a[3].lower(),'obfs':a[4],'password':b64d(a[5]),'protocol-param':pp.get('protoparam',''),'obfs-param':pp.get('obfsparam','')}
        if s=='vmess':
            d=json.loads(b64d(u.split('://',1)[1]));return {'type':'vmess','name':unquote(d.get('ps') or name),'server':d.get('add'),'port':int(d.get('port',0)),'uuid':d.get('id'),'tls':str(d.get('tls','')).lower() in ('tls','1','true'),'sni':d.get('sni') or d.get('host'),'net':d.get('net') or 'tcp','path':d.get('path') or '','host':d.get('host') or '','aid':int(d.get('aid',0))}
        if s=='vless':return {'type':s,'name':name,'server':p.hostname,'port':p.port or 443,'uuid':unquote(p.username or ''),'tls':q.get('security','') in ('tls','reality'),'security':q.get('security',''),'sni':q.get('sni') or p.hostname}
        if s=='trojan':return {'type':s,'name':name,'server':p.hostname,'port':p.port or 443,'password':unquote(p.username or ''),'sni':q.get('sni') or p.hostname}
        if s=='ss':
            raw=unquote(u.split('://',1)[1].split('#',1)[0]);raw=b64d(raw) if '@' not in raw else raw;a,h=raw.rsplit('@',1);cipher,password=a.split(':',1);server,port=h.rsplit(':',1);return {'type':'ss','name':name,'server':server.strip('[]'),'port':int(port),'cipher':cipher.lower(),'password':password}
        if s in ('hysteria2','hy2'):return {'type':'hysteria2','name':name,'server':p.hostname,'port':p.port or 443,'password':unquote(p.username or ''),'sni':q.get('sni') or p.hostname}
        if s=='hysteria':return {'type':'hysteria','name':name,'server':p.hostname,'port':p.port or 443,'auth-str':q.get('auth') or q.get('auth-str') or unquote(p.username or ''),'sni':q.get('sni') or p.hostname}
        if s=='tuic':return {'type':'tuic','name':name,'server':p.hostname,'port':p.port or 443,'uuid':unquote(p.username or ''),'password':unquote(p.password or ''),'sni':q.get('sni') or p.hostname}
        if s=='relay':return {'type':'relay','name':name,'raw':u}
    except Exception:return None

def fp(n):
    if n.get('type')=='relay':return 'relay:'+hashlib.sha256(n['raw'].encode()).hexdigest()
    keys=('type','server','port','uuid','password','cipher','protocol','obfs','sni','protocol-param','obfs-param','auth-str')
    return hashlib.sha256('|'.join(str(n.get(k,'')) for k in keys).encode()).hexdigest()

def valid(n):
    if not n or n.get('type')=='relay': return bool(n and n.get('raw'))
    host=str(n.get('server') or '').strip().lower()
    if not host or host in BAD_HOSTS or BAD_VALUES.match(host): return False
    if not isinstance(n.get('port'),int) or not 1<=n['port']<=65535:return False
    try:
        if host.replace('.','').isdigit(): ipaddress.ip_address(host)
    except ValueError:return False
    if n['type'] in ('vless','vmess') and (not n.get('uuid') or str(n['uuid']).lower() in BAD_HOSTS):return False
    if n['type'] in ('trojan','hysteria2') and (not n.get('password') or BAD_VALUES.match(str(n['password']))):return False
    if n['type'] in ('ss','ssr') and (not n.get('cipher') or not n.get('password')):return False
    if n['type']=='tuic' and (not n.get('uuid') or not n.get('password')):return False
    return True

def safe_name(x,f): return re.sub(r'[\x00-\x1f\x7f]','',str(x or f)).strip()[:100] or f

def clash(n):
    t=n['type']
    if t not in CFW_TYPES:return None
    if t=='ss' and n.get('cipher','').lower() not in CLASH_SS_CIPHERS:return None
    o={'name':n['name'],'type':t,'server':n['server'],'port':n['port']}
    if t=='ss':o.update(cipher=n['cipher'],password=n['password'],udp=True)
    elif t=='ssr':o.update(cipher=n['cipher'],password=n['password'],protocol=n['protocol'],obfs=n['obfs'],udp=True,**({'protocol-param':n['protocol-param']} if n.get('protocol-param') else {}),**({'obfs-param':n['obfs-param']} if n.get('obfs-param') else {}))
    elif t=='vmess':o.update(uuid=n['uuid'],cipher='auto',alterId=n['aid'],tls=n['tls'],udp=True,**({'servername':n['sni']} if n.get('sni') else {}))
    elif t=='trojan':o.update(password=n['password'],sni=n['sni'],udp=True)
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
proxies=[];filtered=0
for n in nodes:
    p=clash(n)
    if p is None:
        if n['type'] in CFW_TYPES: filtered+=1
        continue
    proxies.append(p)
names=[p['name'] for p in proxies]
cfg={'proxies':proxies,'proxy-groups':[{'name':'AUTO','type':'url-test','proxies':names,'url':'https://www.gstatic.com/generate_204','interval':300}],'rules':['MATCH,AUTO']} if proxies else {'proxies':[],'proxy-groups':[],'rules':['MATCH,DIRECT']}
for fn in ('clash.yaml','stash.yaml'):
    (OUT/fn).write_text(yaml.safe_dump(cfg,allow_unicode=True,sort_keys=False),encoding='utf-8')
by={}
for u,n,k in ordered:by.setdefault(n['type'],[]).append(u)
for scheme in SCHEMES:
    vals=by.get(scheme,[]);(OUT/f'{scheme}.txt').write_text(('\n'.join(vals)+'\n') if vals else '',encoding='utf-8')
all_text='\n'.join(u for u,_,_ in ordered)+'\n' if ordered else ''
for fn in ('all-nodes.txt','nodes.txt','shadowrocket.txt'):(OUT/fn).write_text(all_text,encoding='utf-8')
(OUT/'base64.txt').write_text((base64.b64encode(all_text.encode()).decode()+'\n') if all_text else '',encoding='utf-8')
summary={'discovered':len(raw),'healthy_first':len(healthy_keys),'published_unique':len(ordered),'clash_proxies':len(proxies),'clash_filtered_cfw_incompatible':filtered,'clash_supported_types':sorted(CFW_TYPES),'protocols':{k:len(v) for k,v in by.items()}}
(OUT/'publish-summary.json').write_text(json.dumps(summary,ensure_ascii=False,indent=2),encoding='utf-8')
print('PUBLISH:',json.dumps(summary,ensure_ascii=False))
if raw and not ordered:raise SystemExit('No valid nodes to publish')
