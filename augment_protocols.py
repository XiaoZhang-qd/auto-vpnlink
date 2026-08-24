#!/usr/bin/env python3
"""Widen protocol extraction from discovered subscription URLs.

Supplements the scanner's legacy URI matcher with SSR/Relay/Hysteria v1/v2.
"""
import base64,re
from pathlib import Path
import requests
OUT=Path('output'); OUT.mkdir(exist_ok=True)
SCHEMES=('vless','vmess','ss','ssr','trojan','hysteria','hysteria2','hy2','tuic','relay')
PAT=re.compile(r'(?i)(?:'+'|'.join(map(re.escape,SCHEMES))+r')://[^\s<>"\'\\]+')
B64_RE=re.compile(r'^[A-Za-z0-9+/=_-]{20,}$')
def clean(x): return x.strip().rstrip('.,;!?)]}')
def decode(text):
    z=''.join(text.split())
    if not B64_RE.fullmatch(z): return ''
    try: return base64.urlsafe_b64decode(z.replace('-','+').replace('_','/')+'='*(-len(z)%4)).decode('utf-8','ignore')
    except Exception: return ''
def extract(text):
    out=set()
    for blob in (text,decode(text)):
        if blob: out.update(clean(x) for x in PAT.findall(blob))
    return out
sub=OUT/'subscriptions.txt'; urls=[]
if sub.exists(): urls=[x.strip() for x in sub.read_text(encoding='utf-8',errors='ignore').splitlines() if x.strip().startswith(('http://','https://'))]
found=set()
disc=OUT/'discovered-nodes.txt'
if disc.exists(): found.update(extract(disc.read_text(encoding='utf-8',errors='ignore')))
s=requests.Session(); s.headers.update({'User-Agent':'auto-vpnlink/7.0'})
for u in urls[:1000]:
    try:
        r=s.get(u,timeout=10,allow_redirects=True)
        if r.ok: found.update(extract(r.text[:2_000_000]))
    except Exception: pass
disc.write_text(('\n'.join(sorted(found))+'\n') if found else '',encoding='utf-8')
print(f'WIDE_EXTRACT subscriptions={len(urls)} nodes={len(found)}')
