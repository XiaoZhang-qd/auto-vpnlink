#!/usr/bin/env python3
"""Convert verified VPN URIs into conservative, Clash-safe client outputs."""
import base64,json,os,re
from urllib.parse import urlparse,parse_qs,unquote
import yaml
OUT='output';os.makedirs(OUT,exist_ok=True)
SUPPORTED={'vless','vmess','trojan','ss','hysteria2','hy2','tuic'}

def b64(s):
 s=''.join(s.split()).replace('-','+').replace('_','/');return base64.b64decode(s+'='*(-len(s)%4)).decode('utf-8','ignore')
def qd(q):return {k:v[-1] for k,v in parse_qs(q,keep_blank_values=True).items()}
def valid(n):
 if not n or n.get('type') not in SUPPORTED or not n.get('server') or not isinstance(n.get('port'),int) or not 1<=n['port']<=65535:return False
 if n['type'] in ('vless','vmess') and not n.get('uuid'):return False
 if n['type'] in ('trojan','hysteria2','hy2') and not n.get('password'):return False
 if n['type']=='tuic' and (not n.get('uuid') or not n.get('password')):return False
 if n['type']=='ss' and (not n.get('cipher') or not n.get('password')):return False
 return True

def parse(u,i):
 try:
  p=urlparse(u);s=p.scheme.lower();q=qd(p.query)
  if s not in SUPPORTED:return None
  name=unquote(p.fragment or q.get('remarks') or q.get('name') or f'{s}-{i}')[:120]
  if s=='vmess':
   d=json.loads(b64(u.split('://',1)[1]));n={'type':'vmess','name':unquote(d.get('ps') or name),'server':d.get('add'),'port':int(d.get('port',0)),'uuid':d.get('id'),'tls':str(d.get('tls','')).lower() in ('tls','1','true'),'sni':d.get('sni') or d.get('host'),'net':(d.get('net') or 'tcp').lower(),'path':d.get('path') or '','host':d.get('host') or '','aid':int(d.get('aid',0))}
  elif s=='vless':n={'type':'vless','name':name,'server':p.hostname,'port':p.port or 443,'uuid':unquote(p.username or ''),'tls':q.get('security','') in ('tls','reality'),'security':q.get('security',''),'sni':q.get('sni') or p.hostname,'net':q.get('type','tcp').lower(),'path':q.get('path') or '','host':q.get('host') or '','flow':q.get('flow') or '','pbk':q.get('pbk') or '','sid':q.get('sid') or ''}
  elif s=='trojan':n={'type':'trojan','name':name,'server':p.hostname,'port':p.port or 443,'password':unquote(p.username or ''),'sni':q.get('sni') or p.hostname,'net':q.get('type','tcp').lower(),'path':q.get('path') or '','host':q.get('host') or ''}
  elif s=='ss':
   raw=unquote(u.split('://',1)[1].split('#',1)[0]);raw=b64(raw) if '@' not in raw else raw;a,h=raw.rsplit('@',1);method,password=a.split(':',1);host,port=h.rsplit(':',1);n={'type':'ss','name':name,'server':host.strip('[]'),'port':int(port),'cipher':method,'password':password}
  elif s in ('hysteria2','hy2'):n={'type':'hysteria2','name':name,'server':p.hostname,'port':p.port or 443,'password':unquote(p.username or ''),'sni':q.get('sni') or p.hostname,'insecure':q.get('insecure','0').lower() in ('1','true'),'alpn':q.get('alpn') or 'h3','obfs':q.get('obfs') or '','obfs_password':q.get('obfs-password') or ''}
  else:n={'type':'tuic','name':name,'server':p.hostname,'port':p.port or 443,'uuid':unquote(p.username or ''),'password':unquote(p.password or ''),'sni':q.get('sni') or p.hostname,'cc':q.get('congestion_control','bbr')}
  return n if valid(n) else None
 except Exception:return None

def safe_name(value,fallback):
 value=re.sub(r'[\x00-\x1f\x7f]','',str(value or '')).strip()
 return value[:100] or fallback

def unique_names(nodes):
 """Clash/Mihomo requires every proxy name to be unique.
    Some public subscriptions reuse the same remark (for example a country label),
    so add a deterministic suffix instead of letting Clash Verge reject the whole file.
 """
 used={}
 for n in nodes:
  base=safe_name(n.get('name'),f"{n['type']}-{n['server']}:{n['port']}")
  key=base.casefold();count=used.get(key,0)+1;used[key]=count
  n['name']=base if count==1 else f'{base} [{count}]'
 return nodes

def transport(o,n):
 if n.get('net') in ('ws','websocket'):
  o['network']='ws';o['ws-opts']={'path':n.get('path') or '/','headers':({'Host':n['host']} if n.get('host') else {})}
 elif n.get('net')=='grpc':o['network']='grpc';o['grpc-opts']={'grpc-service-name':n.get('path') or ''}
 return o

def clash(n):
 t=n['type'];o={'name':n['name'],'type':('hysteria2' if t=='hy2' else t),'server':n['server'],'port':n['port']}
 if t=='vmess':o.update(uuid=n['uuid'],cipher='auto',alterId=n['aid'],tls=n['tls'],udp=True)
 elif t=='vless':o.update(uuid=n['uuid'],tls=n['tls'],udp=True)
 elif t=='trojan':o.update(password=n['password'],sni=n['sni'],udp=True)
 elif t=='ss':o.update(cipher=n['cipher'],password=n['password'],udp=True)
 elif t in ('hysteria2','hy2'):
  o.update(password=n['password'],sni=n['sni'],udp=True,**{'skip-cert-verify':n['insecure']})
  if n.get('alpn'):o['alpn']=[x.strip() for x in n['alpn'].split(',') if x.strip()]
  if n.get('obfs'):o.update(obfs=n['obfs'],**({'obfs-password':n['obfs_password']} if n.get('obfs_password') else {}))
 elif t=='tuic':o.update(uuid=n['uuid'],password=n['password'],udp=True,**{'congestion-controller':n['cc']})
 if n.get('sni') and t in ('vmess','vless'):o['servername']=n['sni']
 if t in ('vless','vmess','trojan'):transport(o,n)
 if n.get('flow') and t=='vless':o['flow']=n['flow']
 if n.get('security')=='reality' and n.get('pbk'):o['reality-opts']={'public-key':n['pbk'],'short-id':n.get('sid','')}
 return o

def sing(n):
 t=n['type'];o={'tag':n['name'],'server':n['server'],'server_port':n['port']}
 if t=='ss':o.update(type='shadowsocks',method=n['cipher'],password=n['password'])
 elif t=='trojan':o.update(type='trojan',password=n['password'],tls={'enabled':True,'server_name':n['sni'],'insecure':True})
 elif t=='vless':
  o.update(type='vless',uuid=n['uuid'])
  if n['tls']:
   tls={'enabled':True,'server_name':n['sni'],'insecure':True}
   if n.get('security')=='reality' and n.get('pbk'):tls['reality']={'enabled':True,'public_key':n['pbk'],'short_id':n.get('sid','')}
   o['tls']=tls
  if n.get('flow'):o['flow']=n['flow']
 elif t=='vmess':
  o.update(type='vmess',uuid=n['uuid'],security='auto',alter_id=n['aid'])
  if n['tls']:o['tls']={'enabled':True,'server_name':n.get('sni',''),'insecure':True}
 elif t in ('hysteria2','hy2'):
  o.update(type='hysteria2',password=n['password'],tls={'enabled':True,'server_name':n['sni'],'insecure':n['insecure']})
  if n.get('obfs'):o['obfs']={'type':n['obfs'],'password':n.get('obfs_password','')}
 elif t=='tuic':o.update(type='tuic',uuid=n['uuid'],password=n['password'],congestion_control=n['cc'],tls={'enabled':True,'server_name':n['sni'],'insecure':True})
 return o

def xray(n):
 t=n['type'];o={'tag':n['name']}
 if t=='vmess':o.update(protocol='vmess',settings={'vnext':[{'address':n['server'],'port':n['port'],'users':[{'id':n['uuid'],'alterId':n['aid'],'security':'auto'}]}]})
 elif t=='vless':o.update(protocol='vless',settings={'vnext':[{'address':n['server'],'port':n['port'],'users':[{'id':n['uuid'],'encryption':'none',**({'flow':n['flow']} if n.get('flow') else {})}]}]})
 elif t=='trojan':o.update(protocol='trojan',settings={'servers':[{'address':n['server'],'port':n['port'],'password':n['password']}]})
 elif t=='ss':o.update(protocol='shadowsocks',settings={'servers':[{'address':n['server'],'port':n['port'],'method':n['cipher'],'password':n['password']}]})
 return o

def put(name,text):
 with open(os.path.join(OUT,name),'w',encoding='utf-8') as f:f.write(text)

def main():
 raw=[x.strip() for x in open(os.path.join(OUT,'verified-nodes.txt'),encoding='utf-8') if x.strip()];nodes=[];uris=[];bad=[]
 for i,u in enumerate(raw,1):
  n=parse(u,i)
  if n:nodes.append(n);uris.append(u)
  else:bad.append(u)
 nodes=unique_names(nodes)
 text='\n'.join(uris)+'\n' if uris else '';put('nodes.txt',text);put('shadowrocket.txt',text);enc=base64.b64encode(text.encode()).decode()+'\n' if text else '';put('base64.txt',enc);put('v2ray.txt',enc);put('rejected-nodes.txt','\n'.join(bad)+'\n' if bad else '')
 proxies=[clash(n) for n in nodes];names=[x['name'] for x in proxies]
 cfg={'proxies':proxies,'proxy-groups':[{'name':'AUTO','type':'url-test','proxies':names,'url':'https://www.gstatic.com/generate_204','interval':300}],'rules':['MATCH,AUTO']} if proxies else {'proxies':[],'proxy-groups':[],'rules':['MATCH,DIRECT']}
 for name in ('clash.yaml','stash.yaml'):
  with open(os.path.join(OUT,name),'w',encoding='utf-8') as f:yaml.safe_dump(cfg,f,allow_unicode=True,sort_keys=False)
 sb=[sing(n) for n in nodes];sbcfg={'log':{'level':'warn'},'outbounds':sb+[{'type':'selector','tag':'AUTO','outbounds':[x['tag'] for x in sb]}]} if sb else {'outbounds':[{'type':'direct','tag':'direct'}]}
 with open(os.path.join(OUT,'sing-box.json'),'w',encoding='utf-8') as f:json.dump(sbcfg,f,ensure_ascii=False,indent=2)
 xo=[xray(n) for n in nodes if n['type'] in ('vless','vmess','trojan','ss')]
 with open(os.path.join(OUT,'xray-outbounds.json'),'w',encoding='utf-8') as f:json.dump({'outbounds':xo},f,ensure_ascii=False,indent=2)
 by={}
 for n,u in zip(nodes,uris):by.setdefault(n['type'],[]).append(u)
 for p in ('vless','vmess','trojan','ss','hysteria2','tuic'):put(p+'.txt','\n'.join(by.get(p,[]))+'\n' if by.get(p) else '')
 summary={'verified_input':len(raw),'parsed':len(nodes),'rejected':len(bad),'protocols':{k:len(v) for k,v in by.items()},'clash_proxies':len(proxies),'singbox_outbounds':len(sb),'xray_outbounds':len(xo),'unique_proxy_names':len({x['name'].casefold() for x in nodes})}
 with open(os.path.join(OUT,'conversion.json'),'w',encoding='utf-8') as f:json.dump(summary,f,ensure_ascii=False,indent=2)
 print('CONVERT',summary)
 if raw and not nodes:raise SystemExit('No verified nodes could be parsed safely; refusing to publish client configs.')
if __name__=='__main__':main()
