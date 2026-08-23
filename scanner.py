#!/usr/bin/env python3
import base64, ipaddress, json, os, re, socket, time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
import requests
import yaml

ROOT = os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(ROOT, 'sources.yaml'), encoding='utf-8') as f:
    CFG = yaml.safe_load(f) or {}
SCAN = CFG.get('scan', {})
MAX_REPOS = int(SCAN.get('max_repositories_per_topic', 15))
MAX_FILES = int(SCAN.get('max_files_per_repository', 20))
MAX_SIZE = int(SCAN.get('max_file_size', 800000))
TIMEOUT = int(SCAN.get('request_timeout', 8))
WORKERS = max(1, min(int(SCAN.get('workers', 8)), 8))
MAX_CHECKS = int(SCAN.get('max_subscription_checks', 300))
OUT = os.path.join(ROOT, 'output')
os.makedirs(OUT, exist_ok=True)

S = requests.Session()
S.headers.update({'User-Agent': 'auto-vpnlink/2.0'})
GH = 'https://api.github.com'
NODE_RE = re.compile(r'(?:vless|vmess|ss|trojan|hysteria2?|tuic)://[^\s<>"\'\\]+', re.I)
URL_RE = re.compile(r'https?://[^\s<>"\'\\]+', re.I)
TEXT_EXT = {'.txt','.md','.yaml','.yml','.json','.conf','.config','.list','.ini','.toml','.csv','.html','.xml'}
SKIP = {'package-lock.json','yarn.lock','pnpm-lock.yaml'}
NAME_HINTS = ('sub','subscription','proxy','vpn','clash','sing','vless','vmess','trojan','hysteria','ss')

# Broad topics such as devops/networking are useful, but scanning every repository
# under them creates huge workloads. Require a VPN/proxy hint in the repo metadata.
BROAD_TOPICS = {'devops','automation','networking','self-hosted'}
REPO_HINTS = re.compile(r'(vpn|proxy|clash|sing.?box|v2ray|vless|vmess|shadow.?socks|trojan|hysteria)', re.I)

def gh(path, params=None):
    h={'Accept':'application/vnd.github+json','User-Agent':'auto-vpnlink/2.0'}
    if os.getenv('GITHUB_TOKEN'): h['Authorization']='Bearer '+os.getenv('GITHUB_TOKEN')
    r=S.get(GH+path, params=params, headers=h, timeout=TIMEOUT)
    r.raise_for_status()
    return r.json()

def github_topics():
    out={}
    for topic in CFG.get('github_topics', []):
        try:
            data=gh('/search/repositories', {'q':f'topic:{topic}','sort':'updated','order':'desc','per_page':MAX_REPOS})
            for x in data.get('items', []):
                if x.get('fork') or x.get('archived'): continue
                text=' '.join([x.get('name',''), x.get('description') or ''])
                if topic in BROAD_TOPICS and not REPO_HINTS.search(text): continue
                out[x['full_name']]={'full_name':x['full_name'],'url':x['html_url'],'branch':x.get('default_branch') or 'main','source':f'github-topic:{topic}'}
        except Exception as e: print('[GitHub]', topic, e)
    return out

def gitlab_topics():
    out={}
    for topic in CFG.get('gitlab_topics', []):
        try:
            r=S.get('https://gitlab.com/api/v4/projects', params={'topic':topic,'order_by':'last_activity_at','sort':'desc','per_page':MAX_REPOS}, timeout=TIMEOUT)
            r.raise_for_status()
            for x in r.json():
                if x.get('archived'): continue
                text=' '.join([x.get('name',''), x.get('description') or ''])
                if topic in BROAD_TOPICS and not REPO_HINTS.search(text): continue
                out[x['path_with_namespace']]={'full_name':x['path_with_namespace'],'url':x['web_url'],'clone':x['http_url_to_repo'],'branch':x.get('default_branch') or 'main','source':f'gitlab-topic:{topic}'}
        except Exception as e: print('[GitLab]', topic, e)
    return out

def safe_url(u):
    try:
        p=urlparse(u)
        if p.scheme not in ('http','https') or not p.hostname: return False
        # Only validate literal IPs here. Hostnames are allowed because normal public
        # subscription hosts can legitimately resolve through DNS at request time.
        try:
            ip=ipaddress.ip_address(p.hostname)
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified: return False
        except ValueError:
            pass
        return True
    except Exception: return False

def clean(u): return u.rstrip('.,;:!?)]}\'"')

def extract(text):
    urls={clean(x) for x in URL_RE.findall(text)}
    nodes={clean(x) for x in NODE_RE.findall(text)}
    compact=re.sub(r'\s+','',text)
    if len(compact)>=20 and len(compact)<=2_000_000 and re.fullmatch(r'[A-Za-z0-9+/=_-]+',compact):
        try:
            d=base64.urlsafe_b64decode(compact+'='*(-len(compact)%4)).decode('utf-8','ignore')
            nodes.update(clean(x) for x in NODE_RE.findall(d))
        except Exception: pass
    return {u for u in urls if safe_url(u)}, nodes

def candidate_files(tree):
    items=[]
    for item in tree:
        if item.get('type')!='blob' or item.get('size',0)>MAX_SIZE: continue
        p=item.get('path',''); name=os.path.basename(p).lower(); ext=os.path.splitext(name)[1]
        score=0
        if name in ('readme.md','readme.txt','readme'): score+=100
        if any(k in name for k in NAME_HINTS): score+=50
        if ext in TEXT_EXT: score+=10
        if score: items.append((score,p,item.get('size',0)))
    items.sort(reverse=True)
    return items[:MAX_FILES]

def github_scan(repo):
    full=repo['full_name']; branch=repo['branch']; found_u=set(); found_n=set(); files=0
    try: tree=gh(f'/repos/{full}/git/trees/{branch}', {'recursive':'1'}).get('tree',[])
    except Exception as e: print('[tree]',full,e); return repo,found_u,found_n,files
    for _,p,_ in candidate_files(tree):
        try:
            url=f'https://raw.githubusercontent.com/{full}/{branch}/{p}'
            r=S.get(url,timeout=TIMEOUT)
            if r.status_code!=200: continue
            u,n=extract(r.text[:MAX_SIZE]); found_u|=u; found_n|=n; files+=1
        except Exception: pass
    return repo,found_u,found_n,files

def gitlab_scan(repo):
    found_u=set(); found_n=set(); files=0
    try:
        url=repo['clone'].replace('.git', f'/-/archive/{repo["branch"]}/repo.tar.gz')
        r=S.get(url,timeout=TIMEOUT)
        if r.status_code==200 and len(r.content)<=20_000_000:
            import tarfile, io
            with tarfile.open(fileobj=io.BytesIO(r.content),mode='r:gz') as t:
                members=[]
                for m in t.getmembers():
                    if not m.isfile() or m.size>MAX_SIZE: continue
                    name=os.path.basename(m.name).lower(); ext=os.path.splitext(name)[1]
                    score=(100 if name.startswith('readme') else 0)+(50 if any(k in name for k in NAME_HINTS) else 0)+(10 if ext in TEXT_EXT else 0)
                    if score: members.append((score,m))
                members.sort(key=lambda x:x[0], reverse=True)
                for _,m in members[:MAX_FILES]:
                    try:
                        text=t.extractfile(m).read().decode('utf-8','ignore'); u,n=extract(text); found_u|=u; found_n|=n; files+=1
                    except Exception: pass
    except Exception as e: print('[GitLab scan]',repo['full_name'],e)
    return repo,found_u,found_n,files

def check(u):
    x={'url':u,'ok':False,'status':None,'type':'unknown','nodes':0}
    try:
        r=S.get(u,timeout=TIMEOUT,allow_redirects=True,stream=True)
        x['status']=r.status_code
        if r.status_code>=400: return x
        data=b''
        for c in r.iter_content(8192):
            data+=c
            if len(data)>=MAX_SIZE: break
        text=data.decode('utf-8','ignore'); urls,nodes=extract(text); low=text.lower()
        if nodes: x.update(ok=True,type='node-list',nodes=len(nodes))
        elif 'proxies:' in low or 'proxy-groups:' in low or 'mixed-port:' in low or 'socks-port:' in low: x.update(ok=True,type='clash')
        elif urls: x.update(ok=True,type='subscription',nodes=len(urls))
    except Exception: pass
    return x

def main():
    print('== auto-vpnlink 2.0 ==')
    repos={}; repos.update(github_topics()); repos.update(gitlab_topics())
    for u in CFG.get('extra_repositories',[]): repos[u]={'full_name':u,'url':u,'clone':u,'branch':'main','source':'extra'}
    print('repositories:',len(repos))
    results=[]; all_urls=set(); all_nodes=set(); tasks=list(repos.values())
    with ThreadPoolExecutor(max_workers=WORKERS) as ex:
        fs=[ex.submit(gitlab_scan if 'clone' in r else github_scan,r) for r in tasks]
        for f in as_completed(fs):
            repo,urls,nodes,files=f.result(); results.append({'repository':repo['full_name'],'source':repo['source'],'url':repo['url'],'files':files,'urls':sorted(urls),'nodes':sorted(nodes)}); all_urls|=urls; all_nodes|=nodes
    candidates=sorted(all_urls)[:MAX_CHECKS]
    if len(all_urls)>MAX_CHECKS: print(f'limiting URL checks to {MAX_CHECKS}/{len(all_urls)}')
    checked=[]
    with ThreadPoolExecutor(max_workers=WORKERS) as ex:
        fs=[ex.submit(check,u) for u in candidates]
        for f in as_completed(fs): checked.append(f.result())
    alive=sorted(x['url'] for x in checked if x['ok'])
    open(os.path.join(OUT,'subscriptions.txt'),'w',encoding='utf-8').write('\n'.join(alive)+'\n' if alive else '')
    open(os.path.join(OUT,'nodes.txt'),'w',encoding='utf-8').write('\n'.join(sorted(all_nodes))+'\n' if all_nodes else '')
    with open(os.path.join(OUT,'sources.json'),'w',encoding='utf-8') as f: json.dump({'generated_at':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'repositories':results,'checked':checked},f,ensure_ascii=False,indent=2)
    with open(os.path.join(OUT,'summary.md'),'w',encoding='utf-8') as f:
        f.write('# Auto VPNLink\n\n'); f.write(f'- Repositories scanned: {len(results)}\n- Candidate URLs: {len(all_urls)}\n- URLs checked: {len(candidates)}\n- Reachable subscription sources: {len(alive)}\n- Extracted node URIs: {len(all_nodes)}\n- Generated: {time.strftime("%Y-%m-%d %H:%M:%S UTC",time.gmtime())}\n')
    print('candidate URLs:',len(all_urls),'checked:',len(candidates),'alive:',len(alive),'nodes:',len(all_nodes))
if __name__=='__main__': main()
