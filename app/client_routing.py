"""Client-only routing/DNS; does not configure the host or Gateway."""
from pathlib import Path
import json
import re
from urllib.parse import quote

RULE_FILES = {'cn-domain': 'domain', 'foreign-domain': 'domain', 'cn-ip': 'ipcidr',
              'google-domain': 'domain', 'gemini-domain': 'domain', 'google-ip': 'ipcidr'}
MAX_RULE_BYTES = 2 * 1024 * 1024
COUNTRY_ORDER = ('JP', 'HK', 'TW', 'SG', 'US', 'KR')

def subscription_layout(proxies, bindings=None):
    """Country selectors are presentation only; the server owns actual failover."""
    from nodes import COUNTRIES
    countries = {}
    if bindings is not None and len(bindings)!=len(proxies):raise ValueError('INVALID_PUBLIC_BINDINGS')
    for index,proxy in enumerate(proxies):
        group=bindings[index] if bindings is not None else proxy['ws-opts']['path'].rsplit('/', 1)[1]
        tier, country = group.split('-')
        code = country.upper()
        suffix = ('HY2' if tier == 'hy' else
                  '3× 家宽' if tier == 'home3' else
                  '1× 家宽' if tier == 'home1' else
                  '1× 机房' if tier == 'dc' else '1× 普通机房')
        # Mihomo names are globally unique, including across country groups.
        # A stable short numeric identifier avoids repeating country/flag on
        # every mobile card without relying on invisible Unicode characters.
        number = list(COUNTRIES).index(code) + 1
        # Mutate only newly-generated public proxy objects, never source records.
        proxy['name'] = suffix + ' · ' + str(number).zfill(2) + (' HY2' if proxy['type']=='hysteria2' and tier!='hy' else '')
        countries.setdefault(code, []).append((tier, proxy['name']))
    order = sorted(countries, key=lambda c: (COUNTRY_ORDER.index(c) if c in COUNTRY_ORDER else len(COUNTRY_ORDER), c))
    groups = []
    common, other = [], []
    priority = {'home3': 0, 'dc': 1, 'dc1': 2, 'hy': 2, 'home1': 3}
    for code in order:
        flag = ''.join(chr(127397 + ord(c)) for c in code)
        name = COUNTRIES[code][0] + ' ' + flag
        members = [name for tier, name in sorted(countries[code], key=lambda row: (priority[row[0]], row[1]))]
        groups.append({'name': name, 'type': 'select', 'proxies': members})
        (common if code in COUNTRY_ORDER else other).append(name)
    if other:
        groups.append({'name': '其他地区 🌐', 'type': 'select', 'proxies': other})
    return [{'name': '出口选择', 'type': 'select', 'proxies': common + (['其他地区 🌐'] if other else [])}] + groups
OVERSEAS = ('openai.com', 'chatgpt.com', 'oaistatic.com', 'oaiusercontent.com',
            'anthropic.com', 'claude.ai', 'github.com', 'githubusercontent.com',
            'githubassets.com', 'google.com', 'gstatic.com', 'googleapis.com',
            'googleusercontent.com', 'youtube.com', 'ytimg.com', 'ipify.org', 'ippure.com',
            'antigravity.google', 'gemini.google', 'gvt1.com', 'gvt2.com', 'googlevideo.com')
LOCAL_DOMAINS = ('lan', 'local', 'localhost', 'home.arpa')
# Campus authentication/split-horizon zones need the client's current network
# resolver. Never substitute the relay's DNS or hardcode a school's portal IP.
CAMPUS_DOMAINS = ('edu.cn',)
# Covers conventional STUN/TURN labels (including numbered servers) without
# matching unrelated labels such as "turnip" or "return". This is routing,
# not packet inspection: opaque endpoints on arbitrary ports remain outside
# this bounded protection, and host ICE addresses require client controls.
WEBRTC_DOMAIN_REGEX = r'(?i)(^|[.])(stun|turn|turns)[0-9]*([.-]|$)'
WEBRTC_MATCHERS = (
    'DOMAIN-REGEX,' + WEBRTC_DOMAIN_REGEX,
    'AND,((NETWORK,UDP),(DST-PORT,3478/5349/19302-19309))',
    'AND,((NETWORK,TCP),(DST-PORT,3478/5349))',
)

def webrtc_rules():
    # Mihomo may skip a proxy rule when the chosen outbound lacks UDP support.
    # An identical reject rule prevents falling through into China DIRECT.
    return [matcher + ',' + policy for matcher in WEBRTC_MATCHERS
            for policy in ('出口选择', 'REJECT')]

def bundle_revision(root):
    path=Path(root)/'rules/current.json'
    if not path.exists():return None
    revision=json.loads(path.read_text())['revision']
    if not re.fullmatch('[a-f0-9]{16}',revision):raise ValueError('INVALID_RULE_REVISION')
    return revision

def rule_body(root, name, revision=None):
    if name not in RULE_FILES:
        raise ValueError('UNKNOWN_RULE')
    revision=revision or bundle_revision(root)
    if revision and not re.fullmatch('[a-f0-9]{16}',revision):raise ValueError('INVALID_RULE_REVISION')
    directory=Path(root)/'rules'
    if revision:directory=directory/'bundles'/revision
    path = directory / (name + '.mrs')
    size = path.stat().st_size
    if not 0 < size <= MAX_RULE_BYTES:
        raise ValueError('INVALID_RULE_SIZE')
    return path.read_bytes()

def settings(subscription_token, revision=None):
    if revision and not re.fullmatch('[a-f0-9]{16}',revision):raise ValueError('INVALID_RULE_REVISION')
    domestic = ['https://dns.alidns.com/dns-query#DIRECT', 'https://doh.pub/dns-query#DIRECT']
    # No native IPv6 route exists on the relay. Keep domestic IPv6, but do not
    # hand clients overseas AAAA destinations that this path cannot carry.
    overseas = ['https://1.1.1.1/dns-query#出口选择&disable-ipv6=true',
                'https://8.8.8.8/dns-query#出口选择&disable-ipv6=true']
    # Ordered matching stops at the first rule-set. Specific exceptions must
    # precede broad matchers such as cn-domain's +.cn, including on DIRECT.
    dns_policy = {'+.'+domain:['system'] for domain in CAMPUS_DOMAINS+LOCAL_DOMAINS+('arpa',)}
    dns_policy.update({'+.gw.sync-api.xyz':domestic,'+.sub.sync-api.xyz':domestic})
    dns_policy.update({'+.' + domain: overseas for domain in OVERSEAS})
    dns_policy.update({'rule-set:gemini-domain': overseas, 'rule-set:google-domain': overseas,
                  'rule-set:foreign-domain': overseas, 'rule-set:cn-domain': domestic,
                  })
    providers = {name: {'type': 'http', 'behavior': behavior, 'format': 'mrs',
        'url': 'https://sub.sync-api.xyz/s/' + quote(subscription_token, safe='') + '/rules/' +
               (revision+'/' if revision else '') + name + '.mrs',
        'path': './rules/node-dispatch/' + (revision+'/' if revision else '') + name + '.mrs', 'proxy': 'DIRECT',
        'interval': 86400, 'size-limit': MAX_RULE_BYTES} for name, behavior in RULE_FILES.items()}
    rules = ['DOMAIN,gw.sync-api.xyz,DIRECT', 'DOMAIN,sub.sync-api.xyz,DIRECT', 'DOMAIN,localhost,DIRECT']
    rules += ['DOMAIN-SUFFIX,' + domain + ',DIRECT' for domain in LOCAL_DOMAINS]
    rules += ['IP-CIDR,' + cidr + ',DIRECT,no-resolve' for cidr in
              ('0.0.0.0/8', '127.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10',
               '169.254.0.0/16', '172.16.0.0/12', '192.168.0.0/16', '224.0.0.0/4')]
    rules += ['IP-CIDR6,' + cidr + ',DIRECT,no-resolve' for cidr in
              ('::1/128', 'fc00::/7', 'fe80::/10', 'ff00::/8')]
    # Keep local/private traffic local; public STUN/TURN privacy takes priority
    # over both China domain rules and China-IP fallback. No ISP IP hardcoding.
    rules += webrtc_rules()
    # Educational services retain the client's authenticated network identity;
    # public STUN/TURN privacy rules still take precedence.
    rules += ['DOMAIN-SUFFIX,' + domain + ',DIRECT' for domain in CAMPUS_DOMAINS]
    rules += ['DOMAIN-SUFFIX,' + domain + ',出口选择' for domain in OVERSEAS]
    # Overseas domains precede China IP fallback, protecting sites on shared CDNs.
    rules += ['RULE-SET,gemini-domain,出口选择', 'RULE-SET,google-domain,出口选择',
              'RULE-SET,google-ip,出口选择,no-resolve',
              'RULE-SET,foreign-domain,出口选择', 'RULE-SET,cn-domain,DIRECT',
              'RULE-SET,cn-ip,DIRECT', 'MATCH,出口选择']
    return {'ipv6': True, 'unified-delay': True, 'tcp-concurrent': True,
        # Recover hostname for real-IP HTTPS/QUIC without replacing destination
        # addresses or intercepting TLS. Known Google IPs also match without SNI.
        'sniffer': {'enable': True, 'parse-pure-ip': True, 'force-dns-mapping': True,
                    'override-destination': False,
                    'sniff': {'HTTP': {'ports': [80, 8080]}, 'TLS': {'ports': [443]},
                              'QUIC': {'ports': [443]}}},
        'profile': {'store-selected': True, 'store-fake-ip': True},
        'dns': {'enable': True, 'ipv6': True, 'enhanced-mode': 'fake-ip',
            'fake-ip-range': '198.18.0.1/16', 'cache-algorithm': 'arc', 'prefer-h3': False,
            'default-nameserver': ['223.5.5.5', '119.29.29.29'],
            'proxy-server-nameserver': domestic, 'direct-nameserver': domestic,
            # A second DIRECT-side resolution must not undo the campus policy.
            'direct-nameserver-follow-policy': True,
            'nameserver': overseas, 'nameserver-policy': dns_policy,
            'fake-ip-filter': ['localhost', '+.lan', '+.local', '+.home.arpa',
                               'rule-set:cn-domain', '+.stun.*.*'] +
                              ['+.' + domain for domain in CAMPUS_DOMAINS]},
        'rule-providers': providers, 'rules': rules}
