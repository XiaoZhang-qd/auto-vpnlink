#!/usr/bin/env python3
"""Select a diverse, clean sample for protocol-level health checking."""
import re
from pathlib import Path
SCHEMES=('vless','vmess','trojan','ss','hysteria2','hysteria','hy2','tuic')
MAX=200
raw=Path('output/discovered-nodes.txt').read_text(encoding='utf-8',errors='ignore').splitlines()
# Extract complete URIs and reject glued protocol boundaries / control chars.
pat=re.compile(r'(?i)(?:vless|vmess|ss|trojan|hysteria2?|hy2|tuic)://[^\s<>"\'\\]+')
seen=set(); buckets={s:[] for s in SCHEMES}
for line in raw:
    for u in pat.findall(line):
        u=u.strip().rstrip('.,;!?)]}')
        if any(x in u.lower()[u.find('://')+3:] for x in ('vless://','vmess://','ss://','trojan://','hysteria2://','hysteria://','hy2://','tuic://')):
            continue
        s=u.split('://',1)[0].lower()
        if s in buckets and u not in seen:
            seen.add(u); buckets[s].append(u)
# Prefer TCP-capable protocols first. Keep Hysteria2/TUIC as well, but do not let
# hundreds of UDP-only nodes crowd out VLESS/VMess/Trojan/SS.
order=('vless','vmess','trojan','ss','hysteria2','hysteria','hy2','tuic')
selected=[]
for s in order:
    selected.extend(buckets[s][:30])
    if len(selected)>=MAX: break
selected=selected[:MAX]
Path('output/health-candidates.txt').write_text('\n'.join(selected)+ ('\n' if selected else ''),encoding='utf-8')
print('protocol candidates:', {s:len(buckets[s]) for s in order})
print('health candidates:', len(selected))
if not selected: raise SystemExit('No clean protocol candidates found.')
