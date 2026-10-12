"""Subscription parsing and name classification. No old project dependencies."""
import base64
import hashlib
import json
import re
import unicodedata
from urllib.parse import parse_qs, unquote, urlsplit
import yaml
from network_identity import advertised_home

COUNTRIES = {
    'JP': ('日本', '东京', '大阪', 'japan', 'tokyo', 'osaka'),
    'SG': ('新加坡', '狮城', 'singapore'), 'US': ('美国', '美國', '洛杉矶', '圣何塞', '美西', '美东', 'united states', 'america'),
    'HK': ('香港', 'hong kong'), 'TW': ('台湾', '台灣', 'taiwan'),
    'KR': ('韩国', '韓國', '首尔', 'korea', 'seoul'), 'GB': ('英国', '英國', '伦敦', 'united kingdom', 'britain'),
    'DE': ('德国', '德國', 'germany'), 'FR': ('法国', '法國', 'france'), 'CA': ('加拿大', 'canada'),
    'AU': ('澳大利亚', '澳洲', 'australia'), 'IN': ('印度', 'india'), 'RU': ('俄罗斯', 'russia'),
    'NL': ('荷兰', 'netherlands'), 'TR': ('土耳其', 'turkey'), 'TH': ('泰国', 'thailand'),
    'VN': ('越南', 'vietnam'), 'MY': ('马来西亚', 'malaysia'), 'ID': ('印尼', '印度尼西亚', 'indonesia'),
    'PH': ('菲律宾', 'philippines'), 'BR': ('巴西', 'brazil'), 'ZA': ('南非', 'south africa'),
    'AE': ('阿联酋', '迪拜', 'dubai'), 'CH': ('瑞士', 'switzerland'), 'IT': ('意大利', 'italy'),
    'ES': ('西班牙', 'spain'), 'SE': ('瑞典', 'sweden'), 'FI': ('芬兰', 'finland'),
    'NO': ('挪威', 'norway'), 'PL': ('波兰', 'poland'), 'NZ': ('新西兰', 'new zealand'),
    'IE': ('爱尔兰', 'ireland'), 'IL': ('以色列', 'israel'), 'MO': ('澳门', '澳門', 'macao'),
    'AR': ('阿根廷', 'argentina'), 'MX': ('墨西哥', 'mexico'), 'CL': ('智利', 'chile'),
    'BE': ('比利时', 'belgium'), 'AT': ('奥地利', 'austria'), 'PT': ('葡萄牙', 'portugal'),
}

def name_country(name):
    s = unicodedata.normalize('NFKC', str(name)).lower()
    # Flags are unambiguous; otherwise take the longest name match (印度尼西亚 != 印度).
    for code in COUNTRIES:
        flag = ''.join(chr(127397 + ord(c)) for c in code)
        if flag in s:
            return code
    matches = [(len(alias), code) for code, aliases in COUNTRIES.items() for alias in aliases if alias in s]
    if matches:
        return max(matches)[1]
    for code in COUNTRIES:
        if re.search(r'(?<![a-z])' + code.lower() + r'(?![a-z])', s):
            return code
    return None

def multiplier(name):
    s = unicodedata.normalize('NFKC', str(name)).lower()
    values = re.findall(r'(\d+(?:\.\d+)?)\s*(?:[x×*]|倍)', s)
    values += re.findall(r'[x×*]\s*(\d+(?:\.\d+)?)', s)
    return max(map(float, values), default=1.0)

def b64(s):
    return base64.urlsafe_b64decode(s + '=' * (-len(s) % 4)).decode('utf-8')

def uri_node(line):
    scheme = line.split('://', 1)[0].lower()
    if scheme == 'vmess':
        d = json.loads(b64(line.split('://', 1)[1]))
        p = {'name':d.get('ps',''), 'type':'vmess', 'server':d['add'], 'port':int(d['port']), 'uuid':d['id'],
             'alterId':int(d.get('aid',0)), 'cipher':d.get('scy','auto'), 'udp':True}
        if d.get('tls') == 'tls': p.update(tls=True, servername=d.get('sni') or d.get('host') or d['add'])
        if d.get('net') == 'ws': p.update(network='ws', **{'ws-opts':{'path':d.get('path','/'),'headers':{'Host':d.get('host',d['add'])}}})
        return p
    if scheme == 'ss':
        u = urlsplit(line)
        if not u.hostname:
            u = urlsplit('ss://' + b64(u.netloc) + '#' + u.fragment)
        raw = unquote(u.username or '')
        if u.password is not None: raw += ':' + unquote(u.password)
        elif ':' not in raw: raw = b64(raw)
        cipher, password = raw.split(':',1)
        p = {'name':unquote(u.fragment), 'type':'ss', 'server':u.hostname,'port':u.port,'cipher':cipher,'password':password,'udp':True}
        q = parse_qs(u.query)
        if q.get('plugin'): raise ValueError('UNSUPPORTED_SS_PLUGIN')
        return p
    u = urlsplit(line); q = {k:v[0] for k,v in parse_qs(u.query).items()}
    p = {'name':unquote(u.fragment), 'type':{'hy2':'hysteria2'}.get(scheme,scheme), 'server':u.hostname, 'port':u.port or 443,'udp':True}
    if scheme in ('hysteria2','hy2','trojan'):
        p.update(password=unquote(u.username or '') + (':' + unquote(u.password) if u.password else ''))
        p['sni'] = q.get('sni') or q.get('peer') or u.hostname
        if q.get('obfs'): p.update(obfs=q['obfs'], **{'obfs-password':q.get('obfs-password','')})
    elif scheme == 'vless':
        p['uuid'] = unquote(u.username or '')
        if q.get('security') in ('tls','reality'):
            p.update(tls=True, servername=q.get('sni',u.hostname))
        if q.get('security') == 'reality': p['reality-opts'] = {'public-key':q.get('pbk',''),'short-id':q.get('sid','')}
        if q.get('fp'): p['client-fingerprint'] = q['fp']
        if q.get('flow'): p['flow'] = q['flow']
    else: raise ValueError('UNSUPPORTED_PROTOCOL')
    if q.get('type') == 'ws': p.update(network='ws', **{'ws-opts':{'path':q.get('path','/'),'headers':{'Host':q.get('host',u.hostname)}}})
    elif q.get('type') == 'grpc': p.update(network='grpc', **{'grpc-opts':{'grpc-service-name':q.get('serviceName','')}})
    p['skip-cert-verify'] = False
    return p

def parse_subscription(body):
    text = body.decode('utf-8-sig').strip()
    if text.startswith(('proxies:', 'port:', 'mixed-port:', '#', '{')) or '\nproxies:' in text:
        d = yaml.safe_load(text)
        if isinstance(d,dict) and isinstance(d.get('proxies'), list): return d['proxies'], 0
    if '://' not in text: text = b64(text)
    result, errors = [], 0
    for line in text.splitlines():
        if not line.strip(): continue
        try: result.append(uri_node(line.strip()))
        except Exception: errors += 1
    if not result: raise ValueError('NO_PARSEABLE_NODES')
    return result, errors

def classify(nodes, source):
    result = []; counts = {'input':len(nodes), 'excluded_high_rate':0, 'unknown_country':0, 'unsupported_rate':0, 'invalid':0}
    seen = set()
    for original in nodes:
        p = dict(original)
        if not p.get('name') or not p.get('server') or not p.get('port') or not p.get('type'):
            counts['invalid'] += 1; continue
        rate = multiplier(p['name']) if source == 'residential' else 1
        if source == 'residential' and rate >= 6:
            counts['excluded_high_rate'] += 1; continue
        if source == 'residential' and rate not in (1,3):
            counts['unsupported_rate'] += 1; continue
        country = name_country(p['name'])
        if not country: counts['unknown_country'] += 1; continue
        identity = {k:v for k,v in p.items() if k != 'name'}
        ident = hashlib.sha256((source + json.dumps(identity,sort_keys=True,ensure_ascii=False)).encode()).hexdigest()[:24]
        if ident in seen:
            # Aliases of the same exact binding cannot discard a declared-home tag.
            previous=next(n for n in result if n['id']==ident)
            previous['advertised_residential'] |= source=='residential' and advertised_home(p['name'])
            continue
        seen.add(ident)
        group = ('dc' if source == 'datacenter' else 'home' + str(int(rate))) + '-' + country.lower()
        p['name'] = 'n-' + ident
        # Do not inherit a provider's insecure TLS bypass or chaining/global settings.
        p['skip-cert-verify'] = False
        p.pop('dialer-proxy',None)
        result.append({'id':ident, 'group':group, 'country':country, 'rate':rate, 'source':source, 'proxy':p,
                       'advertised_residential':source=='residential' and advertised_home(original['name'])})
    counts['candidates'] = len(result)
    return result, counts
