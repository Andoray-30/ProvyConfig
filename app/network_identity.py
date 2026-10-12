"""Conservative actual-egress labels, not an ASN-to-residential certification."""
import ipaddress
import json
import re
import time
import hashlib

NETWORK_TTL = 7200
# Network operator roles reviewed against their own service documentation.
# ISP_NETWORK only identifies an access-network operator, NOT a household circuit.
HOSTING_ASNS = {197540, 154177, 205548, 62240, 26666, 30058}
ACCESS_ASNS = {4760, 2856, 7018, 23473, 852, 2527, 3462}

def advertised_home(name):
    return bool(re.search(r'家宽|住宅|residential|\bhome\b', str(name), re.I))

def from_body(body, now=None):
    d=json.loads(body); ipaddress.ip_address(d['ip'])
    country=d.get('countryCode') or d.get('country_code') or d.get('country')
    if not isinstance(country,str) or not re.fullmatch('[A-Za-z]{2}',country):raise ValueError('INVALID_COUNTRY')
    org=d.get('org') or ''
    if not org and d.get('asn') and d.get('asOrganization'):
        org='AS'+str(d['asn'])+' '+str(d['asOrganization'])
    if not org and isinstance(d.get('connection'),dict):
        c=d['connection'];org='AS'+str(c.get('asn',''))+' '+str(c.get('org') or c.get('isp') or '')
    match=re.match(r'^AS(\d+)\b',org)
    asn=int(match.group(1)) if match else None
    kind='HOSTING' if asn in HOSTING_ASNS else 'ISP_NETWORK' if asn in ACCESS_ASNS else 'UNKNOWN'
    residential=d.get('isResidential')
    if isinstance(residential,bool):
        if residential:
            # Conflicting hosting ownership is not upgraded by a single database bit.
            kind='CONFLICT' if kind=='HOSTING' or re.search(r'\bhosting\b|\bvirtual machines\b',org,re.I) else 'RESIDENTIAL_CLASSIFIED'
        elif kind!='HOSTING':kind='NON_RESIDENTIAL'
    # Keep only sanctioned metadata. Never persist the exit IP/body here.
    return country.upper(), {'kind':kind,'asn':asn,'operator':org[:160],
                            'exit_fingerprint':hashlib.sha256(str(ipaddress.ip_address(d['ip'])).encode()).hexdigest(),
                            'checked_at':time.time() if now is None else now,
                            'residential_proven':False,'residential_classified':residential if isinstance(residential,bool) else None,
                            'country':country.upper(),'basis':'IPPURE_PUBLIC_CLASSIFICATION' if isinstance(residential,bool) else 'ACTUAL_EGRESS_OPERATOR_ROLE'}

def merge_evidence(previous, current, now):
    """Operator-only fallback may not renew or erase a same-exit strong verdict."""
    previous=previous or {}
    same_exit=(previous.get('exit_fingerprint') and
               previous['exit_fingerprint']==current.get('exit_fingerprint') and
               previous.get('country')==current.get('country') and
               previous.get('asn')==current.get('asn'))
    strong=previous.get('residential_classified') is not None
    weak=current.get('residential_classified') is None
    explicit_conflict=current.get('kind') in ('HOSTING','CONFLICT','NON_RESIDENTIAL')
    if (same_exit and strong and weak and not explicit_conflict and
            previous.get('checked_at',0)+NETWORK_TTL>now):
        return dict(previous)
    return dict(current)

def kind(node, now):
    evidence=(node or {}).get('network_identity') or {}
    if evidence.get('checked_at',0)+NETWORK_TTL<=now:return 'UNKNOWN'
    return evidence.get('kind','UNKNOWN')

def preference(node, now):
    """Prefer declared-home access ISP; never turn a BGP/hosting node into home."""
    k=kind(node,now)
    if k=='RESIDENTIAL_CLASSIFIED':return 0
    if node.get('advertised_residential') and k=='ISP_NETWORK':return 1
    if node.get('advertised_residential') and k=='UNKNOWN':return 2
    return 3

def pool_group(node, now):
    """Classification never changes source identity, country or price tier."""
    country=node['country'].lower()
    if node['source']=='datacenter':return 'dc-'+country
    rate=str(int(node['rate']))
    if kind(node,now) in ('HOSTING','CONFLICT','NON_RESIDENTIAL'):
        return ('dc' if rate=='1' else 'dc'+rate)+'-'+country
    previous=node.get('group','')
    if kind(node,now)=='UNKNOWN' and previous.startswith(('dc-','dc1-','dc3-')):
        return 'dc-'+country if rate=='1' else 'dc'+rate+'-'+country
    return 'home'+rate+'-'+country

def pool_eligible(node, now):
    group=node.get('group','')
    # Product decision: three-times hosting/non-residential exits are withdrawn.
    # Keep their identity/rate/classification, never relabel them as rate one.
    if group.startswith('dc3-'):return False
    if node.get('source')=='datacenter':return group=='dc-'+node['country'].lower()
    if not node.get('source'):return True
    if group=='dc-'+node['country'].lower():
        return (node.get('source')=='residential' and node.get('rate')==1 and
                kind(node,now) in ('HOSTING','CONFLICT','NON_RESIDENTIAL'))
    if group.startswith('home'):
        return (group=='home'+str(int(node['rate']))+'-'+node['country'].lower() and
                kind(node,now)=='RESIDENTIAL_CLASSIFIED')
    return False
