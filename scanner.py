#!/usr/bin/env python3
import base64, ipaddress, json, os, re, socket, time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, parse_qs, unquote
import requests, yaml
ROOT=os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(ROOT,'sources.yaml'),encoding='utf-8') as f: CFG=yaml.safe_load(f) or {}
C=CFG.get('scan',{}); MAX_REPOS=int(C.get('max_repositories_per_topic',15)); MAX_FILES=int(C.get('max_files_per_repository',20)); MAX_SIZE=int(C.get('max_file_size',800000)); TIMEOUT=int(C.get('request_timeout',8)); WORKERS=max(2,min(int(C.get('workers',8)),8)); MAX_CHECKS=int(C.get('max_subscription_checks',300)); MAX_NODES=int(C.get('max_aggregate_nodes',5000)); NODE_CHECKS=int(C.get('max_node_checks',150))
OUT=os.path.join(ROOT,'output'); os.makedirs(OUT,exist_ok=True); S=requests.Session(); S.headers.update({'User-Agent':'auto-vpnlink/6.0'}); GH='https://api.github.com'
NODE_RE=re.compile(r'(?:vless|vmess|ss|trojan|hysteria2?|tuic)://[^\s<>"\'\\]+',re.I); URL_RE=re.compile(r'https?://[^\s<>"\'\\]+',re.I); EXT={'.txt','.md','.yaml','.yml','.json','.conf','.config','.list','.ini','.toml','.csv','.html','.xml'}; HINT=('sub','subscription','proxy','vpn','clash','sing','vless','vmess','trojan','hysteria','ss'); BROAD={'devops','automation','networking','self-hosted'}; REPO_HINT=re.compile(r'(vpn|proxy|clash|sing.?box|v2ray|vless|vmess|shadow.?socks|trojan|hysteria)',re.I)
def gh(path,params=None):
 h={'Accept':'application/vnd.github+json','User-Agent':'auto-vpnlink/6.0'}
 if os.getenv('GITHUB_TOKEN'): h['Authorization']='Bearer '+os.getenv('GITHUB_TOKEN')
 r=S.get(GH+path,params=params,headers=h,timeout=TIMEOUT); r.raise_for_status(); return r.json()
def discover():
 out={}
 for topic in CFG.get('github_topics',[]):
  try:
   d=gh('/search/repositories',{'q':f'topic:{topic}','sort':'updated','order':'desc','per_page':MAX_REPOS})
   for x in d.get('items',[]):
    text=f"{x.get('name','')} {x.get('description') or ''}"
    if x.get('fork') or x.get('archived') or (topic in BROAD and not REPO_HINT.search(text)): continue
    out[x['full_name']]={'full_name':x['full_name'],'url':x['html_url'],'branch':x.get('default_branch') or 'main','source':f'github-topic:{topic}'}
  except Exception as e: print('[GitHub]',topic,e)
 for topic in CFG.get('gitlab_topics',[]):
  try:
   r=S.get('https://gitlab.com/api/v4/projects',params={'topic':topic,'order_by':'last_activity_at','sort':'desc','per_page':MAX_REPOS},timeout=TIMEOUT); r.raise_for_status()
   for x in r.json():
    text=f"{x.get('name','')} {x.get('description') or ''}"
    if x.get('archived') or (topic in BROAD and not REPO_HINT.search(text)): continue
    out[x['path_with_namespace']]={'full_name':x['path_with_namespace'],'url':x['web_url'],'clone':x['http_url_to_repo'],'branch':x.get('default_branch') or 'main','source':f'gitlab-topic:{topic}'}
  except Exception as e: print('[GitLab]',topic,e)
 for u in CFG.get('extra_repositories',[]): out[u]={'full_name':u,'url':u,'clone':u,'branch':'main','source':'extra'}
 return out
def clean(u): return u.rstrip('.,;:!?)]}\'"')
def safe_url(u):
 try:
  p=urlparse(u)
  if p.scheme not in ('http','https') or not p.hostname:return False
  try:
   ip=ipaddress.ip_address(p.hostname)
   if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified:return False
  except ValueError: pass
  return True
 except Exception:return False
def decode_b64(t):
 z=re.sub(r'\s+','',t)
 if len(z)<20 or len(z)>2000000 or not re.fullmatch(r'[A-Za-z0-9+/=_-]+',z):return ''
 try:return base64.urlsafe_b64decode(z+'='*(-len(z)%4)).decode('utf-8','ignore')
 except Exception:return ''
def extract(t):
 u={clean(x) for x in URL_RE.findall(t)}; n={clean(x) for x in NODE_RE.findall(t)}; d=decode_b64(t)
 if d:n|={clean(x) for x in NODE_RE.findall(d)}
 return {x for x in u if safe_url(x)},n
def scan_repo(r):
 U=set();N=set();files=0
 try:
  if 'clone' in r:
   import tarfile,io; q=S.get(r['clone'].replace('.git',f"/-/archive/{r['branch']}/repo.tar.gz"),timeout=TIMEOUT)
   if q.status_code==200 and len(q.content)<=20000000:
    with tarfile.open(fileobj=io.BytesIO(q.content),mode='r:gz') as t:
     a=[]
     for m in t.getmembers():
      if not m.isfile() or m.size>MAX_SIZE:continue
      n=os.path.basename(m.name).lower();e=os.path.splitext(n)[1];score=(100 if n.startswith('readme') else 0)+(50 if any(k in n for k in HINT) else 0)+(10 if e in EXT else 0)
      if score:a.append((score,m))
     for _,m in sorted(a,key=lambda x:x[0],reverse=True)[:MAX_FILES]:
      try:u,n=extract(t.extractfile(m).read().decode('utf-8','ignore'));U|=u;N|=n;files+=1
      except Exception:pass
  else:
   tree=gh(f"/repos/{r['full_name']}/git/trees/{r['branch']}",{'recursive':'1'}).get('tree',[]);a=[]
   for i in tree:
    if i.get('type')!='blob' or i.get('size',0)>MAX_SIZE:continue
    p=i.get('path','');n=os.path.basename(p).lower();e=os.path.splitext(n)[1];score=(100 if n.startswith('readme') else 0)+(50 if any(k in n for k in HINT) else 0)+(10 if e in EXT else 0)
    if score:a.append((score,p))
   for _,p in sorted(a,reverse=True)[:MAX_FILES]:
    try:
     q=S.get(f"https://raw.githubusercontent.com/{r['full_name']}/{r['branch']}/{p}",timeout=TIMEOUT)
     if q.status_code==200:u,n=extract(q.text[:MAX_SIZE]);U|=u;N|=n;files+=1
    except Exception:pass
 except Exception as e:print('[scan]',r['full_name'],e)
 return r,U,N,files
def inspect(u):
 x={'url':u,'ok':False,'status':None,'type':'unknown','nodes':[]}
 try:
  r=S.get(u,timeout=TIMEOUT,allow_redirects=True,stream=True,headers={'Accept':'*/*','User-Agent':'Mozilla/5.0'});x['status']=r.status_code
  if r.status_code>=400:return x
  data=b''
  for c in r.iter_content(8192):
   data+=c
   if len(data)>=MAX_SIZE:break
  t=data.decode('utf-8','ignore').lstrip('\ufeff');urls,nodes=extract(t);low=t.lower()
  if nodes:x.update(ok=True,type='node-list',nodes=sorted(nodes))
  elif 'proxies:' in low and 'proxy-groups:' in low:x.update(ok=True,type='clash')
  elif len(urls)>=2:x.update(ok=True,type='subscription')
  return x
 except Exception as e:x['error']=str(e)[:160];return x
def endpoint(u):
 try:
  p=urlparse(u);s=p.scheme.lower();host=p.hostname;port=p.port
  if s=='vmess':
   z=u.split('://',1)[1];d=json.loads(base64.urlsafe_b64decode(z+'='*(-len(z)%4)).decode('utf-8','ignore'));host=d.get('add');port=int(d.get('port',0))
  elif s in ('vless','trojan','ss','hysteria','hysteria2','tuic'):port=port or 443
  else:return False
  if not host or not 1<=int(port)<=65535:return False
  try:
   ip=ipaddress.ip_address(host)
   if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved:return False
  except ValueError:pass
  for fam,typ,proto,_,sa in socket.getaddrinfo(host,int(port),type=socket.SOCK_STREAM)[:2]:
   sck=socket.socket(fam,typ,proto);sck.settimeout(2.5)
   try:sck.connect(sa);return True
   except Exception:pass
   finally:sck.close()
 except Exception:pass
 return False
def parse_node(u,i):
 try:
  p=urlparse(u);q={k:v[-1] for k,v in parse_qs(p.query).items()};s=p.scheme.lower()
  if s=='vmess':
   z=u.split('://',1)[1];d=json.loads(base64.urlsafe_b64decode(z+'='*(-len(z)%4)).decode('utf-8','ignore'));return {'scheme':'vmess','name':unquote(d.get('ps') or f'vmess-{i}'),'server':d.get('add'),'port':int(d.get('port',0)),'uuid':d.get('id'),'tls':str(d.get('tls','')).lower() in ('tls','1','true'),'sni':d.get('sni') or d.get('host'),'network':d.get('net') or 'tcp','path':d.get('path'),'host':d.get('host'),'alterId':int(d.get('aid',0))}
  if s=='vless':return {'scheme':'vless','name':unquote(q.get('remarks') or q.get('name') or f'vless-{i}'),'server':p.hostname,'port':p.port or 443,'uuid':unquote(p.username or ''),'tls':q.get('security') in ('tls','reality'),'sni':q.get('sni') or p.hostname,'network':q.get('type','tcp'),'path':q.get('path'),'host':q.get('host'),'flow':q.get('flow')}
  if s=='trojan':return {'scheme':'trojan','name':unquote(q.get('remarks') or q.get('name') or f'trojan-{i}'),'server':p.hostname,'port':p.port or 443,'password':unquote(p.username or ''),'sni':q.get('sni') or p.hostname,'network':q.get('type','tcp'),'path':q.get('path'),'host':q.get('host')}
  if s=='ss':
   raw=unquote(u.split('://',1)[1].split('#',1)[0]); raw=base64.urlsafe_b64decode(raw+'='*(-len(raw)%4)).decode('utf-8','ignore') if '@' not in raw else raw;auth,hp=raw.rsplit('@',1);method,password=auth.split(':',1);host,port=hp.rsplit(':',1);return {'scheme':'ss','name':unquote(q.get('remarks') or q.get('name') or f'ss-{i}'),'server':host,'port':int(port),'cipher':method,'password':password}
 except Exception:return None
 return None
def clash_node(n):
 s=n['scheme'];o={'name':n['name'],'type':s,'server':n['server'],'port':n['port']}
 if s=='vless':o.update(uuid=n['uuid'],tls=n.get('tls',False),udp=True,**({'servername':n['sni']} if n.get('sni') else {}),**({'network':n['network']} if n.get('network') not in (None,'tcp') else {}),**({'flow':n['flow']} if n.get('flow') else {}))
 elif s=='vmess':o.update(uuid=n['uuid'],cipher='auto',alterId=n.get('alterId',0),tls=n.get('tls',False),udp=True,**({'servername':n['sni']} if n.get('sni') else {}))
 elif s=='trojan':o.update(password=n['password'],sni=n.get('sni',n['server']),udp=True)
 elif s=='ss':o.update(cipher=n['cipher'],password=n['password'],udp=True)
 return o
def singbox_node(n):
 s=n['scheme']
 if s=='ss':return {'type':'shadowsocks','tag':n['name'],'server':n['server'],'server_port':n['port'],'method':n['cipher'],'password':n['password']}
 if s=='trojan':return {'type':'trojan','tag':n['name'],'server':n['server'],'server_port':n['port'],'password':n['password'],'tls':{'enabled':True,'server_name':n.get('sni',n['server']),'insecure':True}}
 if s=='vless':
  o={'type':'vless','tag':n['name'],'server':n['server'],'server_port':n['port'],'uuid':n['uuid']};
  if n.get('flow'):o['flow']=n['flow']
  if n.get('tls'):o['tls']={'enabled':True,'server_name':n.get('sni',n['server']),'insecure':True}
  return o
 if s=='vmess':
  o={'type':'vmess','tag':n['name'],'server':n['server'],'server_port':n['port'],'uuid':n['uuid'],'security':'auto','alter_id':n.get('alterId',0)}
  if n.get('tls'):o['tls']={'enabled':True,'server_name':n.get('sni',n['server']),'insecure':True}
  return o
def write_outputs(verified,sources,discovered,results):
 verified=sorted(set(verified));parsed=[]
 for i,u in enumerate(verified,1):
  n=parse_node(u,i)
  if n and n.get('server') and n.get('port'):parsed.append(n)
 parsed_uris=[]
 for i,u in enumerate(verified,1):
  if parse_node(u,i):parsed_uris.append(u)
 def put(name,data):open(os.path.join(OUT,name),'w',encoding='utf-8').write(data)
 put('subscriptions.txt','\n'.join(sorted(x['url'] for x in sources))+'\n' if sources else '');put('discovered-nodes.txt','\n'.join(discovered)+'\n' if discovered else '');put('verified-nodes.txt','\n'.join(verified)+'\n' if verified else '');put('nodes.txt','\n'.join(parsed_uris)+'\n' if parsed_uris else '');put('shadowrocket.txt','\n'.join(parsed_uris)+'\n' if parsed_uris else '')
 b=base64.b64encode(('\n'.join(parsed_uris)+'\n').encode()).decode();put('base64.txt',b+'\n' if parsed_uris else '')
 put('v2ray.txt',b+'\n' if parsed_uris else '')
 proxies=[clash_node(n) for n in parsed];names=[p['name'] for p in proxies];cfg={'proxies':proxies,'proxy-groups':[{'name':'AUTO','type':'url-test','proxies':names,'url':'https://www.gstatic.com/generate_204','interval':300}],'rules':['MATCH,AUTO']} if proxies else {'proxies':[],'proxy-groups':[],'rules':['MATCH,DIRECT']}
 with open(os.path.join(OUT,'clash.yaml'),'w',encoding='utf-8') as f:yaml.safe_dump(cfg,f,allow_unicode=True,sort_keys=False)
 with open(os.path.join(OUT,'stash.yaml'),'w',encoding='utf-8') as f:yaml.safe_dump(cfg,f,allow_unicode=True,sort_keys=False)
 sing=[singbox_node(n) for n in parsed];tags=[n['tag'] for n in sing];scfg={'log':{'level':'warn'},'outbounds':sing+[{'type':'selector','tag':'AUTO','outbounds':tags}]} if sing else {'outbounds':[{'type':'direct','tag':'direct'}]}
 with open(os.path.join(OUT,'sing-box.json'),'w',encoding='utf-8') as f:json.dump(scfg,f,ensure_ascii=False,indent=2)
 v2=[]
 for n in parsed:
  if n['scheme']=='vless':v2.append({'protocol':'vless','settings':{'vnext':[{'address':n['server'],'port':n['port'],'users':[{'id':n['uuid'],'encryption':'none','flow':n.get('flow','')}]}]}})
  elif n['scheme']=='vmess':v2.append({'protocol':'vmess','settings':{'vnext':[{'address':n['server'],'port':n['port'],'users':[{'id':n['uuid'],'alterId':n.get('alterId',0),'security':'auto'}]}]}})
  elif n['scheme']=='trojan':v2.append({'protocol':'trojan','settings':{'servers':[{'address':n['server'],'port':n['port'],'password':n['password']}]}})
  elif n['scheme']=='ss':v2.append({'protocol':'shadowsocks','settings':{'servers':[{'address':n['server'],'port':n['port'],'method':n['cipher'],'password':n['password']}]}})
 with open(os.path.join(OUT,'xray-outbounds.json'),'w',encoding='utf-8') as f:json.dump({'outbounds':v2},f,ensure_ascii=False,indent=2)
 providers={f'source_{i}':{'type':'http','url':x['url'],'interval':86400,'health-check':{'enable':True,'interval':300,'url':'https://www.gstatic.com/generate_204'}} for i,x in enumerate(sources,1) if x['type'] in ('clash','subscription')}
 with open(os.path.join(OUT,'clash-providers.yaml'),'w',encoding='utf-8') as f:yaml.safe_dump({'proxy-providers':providers},f,allow_unicode=True,sort_keys=False)
 counts={'repositories':len(results),'candidate_urls':sum(len(r['urls']) for r in results),'valid_sources':len(sources),'discovered_nodes':len(discovered),'verified_endpoints':len(verified),'parsed_nodes':len(parsed),'clash_proxies':len(proxies),'singbox_outbounds':len(sing)}
 with open(os.path.join(OUT,'sources.json'),'w',encoding='utf-8') as f:json.dump({'generated_at':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'counts':counts,'repositories':results,'checked':sources},f,ensure_ascii=False,indent=2)
 with open(os.path.join(OUT,'summary.md'),'w',encoding='utf-8') as f:f.write('# Auto VPNLink\n\n'+''.join(f'- **{k}:** {v}\n' for k,v in counts.items())+f'- **Generated:** {time.strftime("%Y-%m-%d %H:%M:%S UTC",time.gmtime())}\n')
def main():
 print('== auto-vpnlink 6.0 ==');repos=discover();print('repositories:',len(repos));results=[];all_urls=set();all_nodes=set()
 with ThreadPoolExecutor(max_workers=WORKERS) as ex:
  fs=[ex.submit(scan_repo,r) for r in repos.values()]
  for f in as_completed(fs):
   r,u,n,files=f.result();results.append({'repository':r['full_name'],'source':r['source'],'url':r['url'],'files':files,'urls':sorted(u),'nodes':sorted(n)});all_urls|=u;all_nodes|=n
 cand=sorted(all_urls)[:MAX_CHECKS];print('candidate URLs:',len(all_urls),'checking:',len(cand));checked=[]
 with ThreadPoolExecutor(max_workers=WORKERS) as ex:
  fs=[ex.submit(inspect,u) for u in cand]
  for f in as_completed(fs):checked.append(f.result())
 sources=[x for x in checked if x['ok']];discovered=[];seen=set()
 for n in sorted(all_nodes)+[n for x in sources for n in x.get('nodes',[])]:
  if n not in seen:seen.add(n);discovered.append(n)
 discovered=discovered[:MAX_NODES]
 with ThreadPoolExecutor(max_workers=WORKERS) as ex:
  fs={ex.submit(endpoint,n):n for n in discovered[:NODE_CHECKS]};verified=sorted({fs[f] for f in as_completed(fs) if f.result()})
 write_outputs(verified,sources,discovered,results);print('RESULT',{'repositories':len(results),'candidate_urls':len(all_urls),'valid_sources':len(sources),'discovered_nodes':len(discovered),'verified_endpoints':len(verified)})
if __name__=='__main__':main()
