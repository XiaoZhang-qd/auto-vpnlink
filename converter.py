#!/usr/bin/env python3
"""Turn verified node URIs into usable client subscription/config files."""
import base64,json,os
from urllib.parse import urlparse,parse_qs,unquote
import yaml
OUT='output'; os.makedirs(OUT,exist_ok=True)

def b64(s):
    s=''.join(s.split()); return base64.urlsafe_b64decode(s+'='*(-len(s)%4)).decode('utf-8','ignore')

def parse(u,i):
    try:
        p=urlparse(u); q={k:v[-1] for k,v in parse_qs(p.query).items()}; s=p.scheme.lower(); name=unquote(p.fragment or '') or f'{s}-{i}'
        if s=='vmess':
            d=json.loads(b64(u.split('://',1)[1])); return {'type':'vmess','name':unquote(d.get('ps') or name),'server':d.get('add'),'port':int(d.get('port',0)),'uuid':d.get('id'),'tls':str(d.get('tls','')).lower() in ('tls','1','true'),'sni':d.get('sni') or d.get('host'),'net':d.get('net') or 'tcp','path':d.get('path'),'host':d.get('host'),'aid':int(d.get('aid',0))}
        if s=='vless': return {'type':'vless','name':name,'server':p.hostname,'port':p.port or 443,'uuid':unquote(p.username or ''),'tls':q.get('security') in ('tls','reality'),'sni':q.get('sni') or p.hostname,'net':q.get('type','tcp'),'path':q.get('path'),'host':q.get('host'),'flow':q.get('flow'),'pbk':q.get('pbk'),'sid':q.get('sid')}
        if s=='trojan': return {'type':'trojan','name':name,'server':p.hostname,'port':p.port or 443,'password':unquote(p.username or ''),'sni':q.get('sni') or p.hostname}
        if s=='ss':
            raw=unquote(u.split('://',1)[1].split('#',1)[0]); raw=b64(raw) if '@' not in raw else raw
            a,h=raw.rsplit('@',1); method,password=a.split(':',1); host,port=h.rsplit(':',1)
            return {'type':'ss','name':name,'server':host,'port':int(port),'cipher':method,'password':password}
        if s in ('hysteria2','hy2'): return {'type':'hysteria2','name':name,'server':p.hostname,'port':p.port or 443,'password':unquote(p.username or ''),'sni':q.get('sni') or p.hostname}
        if s=='tuic': return {'type':'tuic','name':name,'server':p.hostname,'port':p.port or 443,'uuid':unquote(p.username or ''),'password':unquote(p.password or ''),'sni':q.get('sni') or p.hostname,'cc':q.get('congestion_control','bbr')}
    except Exception: return None

def clash(n):
    o={'name':n['name'],'type':n['type'],'server':n['server'],'port':n['port']}; t=n['type']
    if t=='vmess': o.update(uuid=n['uuid'],cipher='auto',alterId=n['aid'],tls=n['tls'],udp=True)
    elif t=='vless': o.update(uuid=n['uuid'],tls=n['tls'],udp=True)
    elif t=='trojan': o.update(password=n['password'],sni=n['sni'],udp=True)
    elif t=='ss': o.update(cipher=n['cipher'],password=n['password'],udp=True)
    elif t=='hysteria2': o.update(password=n['password'],sni=n['sni'],skip-cert-verify=True)
    elif t=='tuic': o.update(uuid=n['uuid'],password=n['password'],congestion-controller=n['cc'],udp=True)
    if n.get('sni') and t in ('vmess','vless'): o['servername']=n['sni']
    if n.get('net') not in (None,'tcp') and t in ('vmess','vless'): o['network']=n['net']
    if n.get('flow'): o['flow']=n['flow']
    if n.get('pbk'): o['reality-opts']={'public-key':n['pbk'],'short-id':n.get('sid','')}
    return o

def sing(n):
    t=n['type']; o={'tag':n['name'],'server':n['server'],'server_port':n['port']}
    if t=='ss': o.update(type='shadowsocks',method=n['cipher'],password=n['password'])
    elif t=='trojan': o.update(type='trojan',password=n['password'],tls={'enabled':True,'server_name':n['sni'],'insecure':True})
    elif t=='vless':
        o.update(type='vless',uuid=n['uuid']);
        if n['tls']: o['tls']={'enabled':True,'server_name':n['sni'],'insecure':True}
        if n.get('flow'): o['flow']=n['flow']
    elif t=='vmess': o.update(type='vmess',uuid=n['uuid'],security='auto',alter_id=n['aid'],tls={'enabled':n['tls'],'server_name':n.get('sni',''),'insecure':True})
    elif t=='hysteria2': o.update(type='hysteria2',password=n['password'],tls={'enabled':True,'server_name':n['sni'],'insecure':True})
    elif t=='tuic': o.update(type='tuic',uuid=n['uuid'],password=n['password'],congestion_control=n['cc'],tls={'enabled':True,'server_name':n['sni'],'insecure':True})
    return o

def main():
    raw=[x.strip() for x in open(os.path.join(OUT,'verified-nodes.txt'),encoding='utf-8') if x.strip()]
    nodes=[]; parsed=[]
    for i,u in enumerate(raw,1):
        n=parse(u,i)
        if n and n.get('server') and n.get('port'): nodes.append(n); parsed.append(u)
    # Keep only parsed, verified URIs in client-ready text subscriptions.
    text='\n'.join(parsed)+'\n' if parsed else ''
    open(os.path.join(OUT,'nodes.txt'),'w',encoding='utf-8').write(text)
    open(os.path.join(OUT,'shadowrocket.txt'),'w',encoding='utf-8').write(text)
    encoded=base64.b64encode(text.encode()).decode()+'\n' if text else ''
    open(os.path.join(OUT,'base64.txt'),'w',encoding='utf-8').write(encoded)
    open(os.path.join(OUT,'v2ray.txt'),'w',encoding='utf-8').write(encoded)
    proxies=[clash(n) for n in nodes]; names=[x['name'] for x in proxies]
    cfg={'proxies':proxies,'proxy-groups':[{'name':'AUTO','type':'url-test','proxies':names,'url':'https://www.gstatic.com/generate_204','interval':300}],'rules':['MATCH,AUTO']}
    with open(os.path.join(OUT,'clash.yaml'),'w',encoding='utf-8') as f: yaml.safe_dump(cfg,f,allow_unicode=True,sort_keys=False)
    with open(os.path.join(OUT,'stash.yaml'),'w',encoding='utf-8') as f: yaml.safe_dump(cfg,f,allow_unicode=True,sort_keys=False)
    sb= [sing(n) for n in nodes]
    sbcfg={'log':{'level':'warn'},'outbounds':sb+[{'type':'selector','tag':'AUTO','outbounds':[x['tag'] for x in sb]}]} if sb else {'outbounds':[{'type':'direct','tag':'direct'}]}
    json.dump(sbcfg,open(os.path.join(OUT,'sing-box.json'),'w',encoding='utf-8'),ensure_ascii=False,indent=2)
    json.dump({'outbounds':[]},open(os.path.join(OUT,'xray-outbounds.json'),'w',encoding='utf-8'),indent=2)
    print('CONVERT',{'verified':len(raw),'parsed_nodes':len(nodes),'clash_proxies':len(proxies),'singbox_outbounds':len(sb)})
if __name__=='__main__': main()
