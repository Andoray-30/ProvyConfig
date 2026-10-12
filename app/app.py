"""Small independent dispatcher: subscriptions -> verified countries -> sticky winners."""
import argparse
import hmac
import hashlib
import json
import os
import secrets
import signal
import socket
import statistics
import subprocess
import threading
import time
import uuid
from collections import Counter, defaultdict
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import quote, urlsplit
import yaml
from httpio import request, RequestFailure, atomic, write_json
from nodes import COUNTRIES, classify, parse_subscription
from network_identity import (from_body as network_from_body, kind as network_kind,
                             pool_group, pool_eligible, merge_evidence, NETWORK_TTL)
from client_routing import settings as client_settings, rule_body, subscription_layout, bundle_revision, RULE_FILES
from policy import (REFRESH_SECONDS, SAMPLE_SECONDS, QUALIFICATION_TTL, PRIMARY_SECONDS,
                    record_sample, score, select, eligible, metrics, RTT_SECONDS, quality, standby_ready)

ROOT = Path(__file__).resolve().parent
MIHOMO = '/usr/local/bin/mihomo'
CONTROLLER = 'http://127.0.0.1:19190'
PROBE_PROXY = 'http://127.0.0.1:18190'
HEALTH_URL = 'https://www.gstatic.com/generate_204'
RELEASE_ID='RESIDENTIAL-HY2-20261012T122524Z'
HY2_RATES=(1,)
SECONDARY_HEALTH_URL='https://cp.cloudflare.com/generate_204'

# Capture once at import, before serving or scheduling. This is independent of
# __main__ vs imported-module bytecode serialization, and cannot claim a later
# on-disk edit has already been loaded by the running process.
_CODE_FILES=('app.py','client_routing.py','policy.py','scheduler.py','network_identity.py','nodes.py','httpio.py')
_LOADED_CODE_SHA256=hashlib.sha256(json.dumps({name:hashlib.sha256((ROOT/name).read_bytes()).hexdigest()
    for name in _CODE_FILES},sort_keys=True,separators=(',',':')).encode()).hexdigest()

def loaded_identity():
    return _LOADED_CODE_SHA256

def country_from_body(body):
    text = body.decode('utf-8').strip()
    if len(text)==2 and text.isalpha(): return text.upper()
    d = json.loads(text)
    c = d.get('country_code') or d.get('country')
    return c.upper() if isinstance(c,str) and len(c)==2 else None

def label(group, node=None, now=None):
    tier, country = group.split('-')
    display = COUNTRIES[country.upper()][0]
    if tier=='hy':return display+'｜HY2'
    if tier=='dc':return display+'｜机房节点'
    if tier in ('dc1','dc3'):
        rate='普通' if tier=='dc1' else '3倍'
        suffix='非家宽出口' if network_kind(node,time.time() if now is None else now)=='NON_RESIDENTIAL' else '机房出口'
        return display+'｜'+rate+suffix
    rate='普通' if tier=='home1' else '3倍'
    k=network_kind(node,time.time() if now is None else now)
    if k=='HOSTING':suffix='机房出口'
    elif k=='NON_RESIDENTIAL':suffix='非家宽出口'
    elif k=='RESIDENTIAL_CLASSIFIED':suffix='家宽（IP检测）'
    elif node and node.get('advertised_residential') and k=='ISP_NETWORK':suffix='家宽候选'
    elif k=='ISP_NETWORK':suffix='运营商出口'
    else:suffix='未核实出口'
    return display+'｜'+rate+suffix

class Dispatcher:
    def __init__(self, root=ROOT):
        self.root = Path(root); self.runtime = self.root/'runtime'
        self.runtime.mkdir(exist_ok=True,mode=0o700)
        private = self.root/'secrets/access.json'
        if private.exists(): self.access = json.loads(private.read_text())
        else:
            self.access = {'controller':secrets.token_urlsafe(32),'subscription':secrets.token_urlsafe(32),'bindings':{}}
            write_json(private,self.access)
        self.nodes = json.loads((self.runtime/'candidates.json').read_text()) if (self.runtime/'candidates.json').exists() else []
        self.state = json.loads((self.runtime/'state.json').read_text()) if (self.runtime/'state.json').exists() else {'groups':{},'last_refresh':0,'last_sample':0}
        self.proc = None; self.stop = threading.Event(); self.lock = threading.RLock()
        self.summary = json.loads((self.runtime/'source-summary.json').read_text()) if (self.runtime/'source-summary.json').exists() else {}
        self.health = {'phase':'STARTING','updated_at':time.time()}
        self.config_dirty=False
        self.actual_targets={}
        path=self.root/'secrets/hy2.json'
        self.hy2=json.loads(path.read_text()) if path.exists() else {'enabled':False}
        if self.hy2.get('enabled'):
            if self.hy2.get('listen')!='172.17.16.64' or self.hy2.get('port')!=443:
                raise RequestFailure('INVALID_HY2_BINDING')
            certdir=Path('/var/lib/caddy/certificates/acme-v02.api.letsencrypt.org-directory/gw.sync-api.xyz')
            for key,filename in [('certificate','gw.sync-api.xyz.crt'),('private-key','gw.sync-api.xyz.key')]:
                if Path(self.hy2.get(key,''))!=certdir/filename:raise RequestFailure('INVALID_HY2_CERT_PATH')
        self.load_network_evidence()

    def hy2_password(self,group):
        return hmac.new(self.access['controller'].encode(),('node-dispatch-hy2-v1:'+group).encode(),hashlib.sha256).hexdigest()

    @staticmethod
    def hy2_candidate(node):
        # Source is the configured subscription role, not a name/ASN heuristic.
        # This one predicate gates native membership, public entries, actual
        # admission and scheduling; old HY2 credentials cannot bypass it.
        return (node.get('source')=='residential' and
                node.get('proxy',{}).get('type')=='hysteria2' and node.get('rate') in HY2_RATES)

    def route_members(self,group):
        if group.startswith('hy-'):
            return [n for n in self.nodes if n['country'].lower()==group.split('-')[1] and self.hy2_candidate(n)]
        return [n for n in self.nodes if n['group']==group]

    def route_admissible(self,group,node,now):
        if not node:return False
        matched=(self.hy2_candidate(node) and node['country'].lower()==group.split('-')[1]
                 if group.startswith('hy-') else node['group']==group)
        return matched and node.get('qualified_at',0)+QUALIFICATION_TTL>now and pool_eligible(node,now)

    def route_eligible(self,group,node,now):
        return self.route_admissible(group,node,now) and eligible(node,now)

    def gateway_environment(self):
        env=dict(os.environ)
        if self.hy2.get('enabled'):
            env['SAFE_PATHS']=str(Path(self.hy2['certificate']).parent)
        return env

    def listeners_ready(self):
        if not self.proc or self.proc.poll() is not None:return False
        cfg=yaml.safe_load((self.runtime/'gateway.yaml').read_text())
        for listener in cfg['listeners']:
            if listener['type']=='hysteria2':continue
            try:
                with socket.create_connection((listener['listen'],listener['port']),timeout=.2):pass
            except OSError:return False
        if self.hy2.get('enabled'):
            owned=set()
            try:
                for fd in (Path('/proc')/str(self.proc.pid)/'fd').iterdir():
                    try:target=os.readlink(fd)
                    except OSError:continue
                    if target.startswith('socket:['):owned.add(target[8:-1])
                rows=(Path('/proc')/str(self.proc.pid)/'net/udp').read_text().splitlines()[1:]
                if not any(row.split()[9] in owned and int(row.split()[1].split(':')[1],16)==self.hy2['port']
                           and socket.inet_ntoa(bytes.fromhex(row.split()[1].split(':')[0])[::-1])==self.hy2['listen']
                           for row in rows):return False
            except OSError:return False
        return True

    def load_network_evidence(self):
        # Upgrade the existing cache without a source refetch or credential rotation.
        if any('advertised_residential' not in n for n in self.nodes):
            for source in {n['source'] for n in self.nodes}:
                path=self.runtime/('input-'+source+'.txt')
                if not path.exists() or path.stat().st_size>8*1024*1024:continue
                try:classified,_=classify(parse_subscription(path.read_bytes())[0],source)
                except Exception:continue
                indexed={n['id']:n for n in classified}
                for n in self.nodes:
                    if n['source']==source:
                        n['advertised_residential']=indexed.get(n['id'],{}).get('advertised_residential',False)
        path=self.runtime/'network-evidence.json'
        evidence=json.loads(path.read_text()) if path.exists() and path.stat().st_size<=131072 else {}
        for n in self.nodes:
            e=evidence.get(n['id'])
            if e and e.get('checked_at',0)>n.get('network_identity',{}).get('checked_at',0):
                n['network_identity']=e
                if e.get('country') and e['country']!=n['country']:
                    n['qualified_at']=0;n['country_result']='MISMATCH'
        self.reconcile(initial=True)

    def reconcile(self,initial=False,compare=False,now=None,compare_groups=None):
        now=time.time() if now is None else now
        with self.lock:
            grouped=defaultdict(list)
            for n in self.nodes:
                n.setdefault('source_group',('dc' if n['source']=='datacenter' else 'home'+str(int(n['rate'])))+'-'+n['country'].lower())
                n['group']=pool_group(n,now)
                if 'legacy_samples' not in n:n['legacy_samples']=list(n.get('samples',[]))
                grouped[n['group']].append(n)
            # Retire the separate ordinary-machine selection owner. Seed only
            # an empty canonical pool; never displace its healthy winner merely
            # because sources have been merged. Preserve per-node evidence.
            for name in list(self.state['groups']):
                if not name.startswith('dc1-'):continue
                previous=self.state['groups'].pop(name)
                canonical='dc-'+name.split('-')[1]
                current=self.state['groups'].setdefault(canonical,{})
                if not current.get('selected') and previous.get('selected'):
                    current.update(previous)
            if self.hy2.get('enabled'):
                # An independent, country-only HY2 route owner; observations
                # remain on the original nodes and are never double-counted.
                for country in COUNTRIES:
                    name='hy-'+country.lower()
                    grouped[name]=self.route_members(name)
            for name in set(grouped)|set(self.state['groups']):
                g=self.state['groups'].setdefault(name,{})
                select(g,grouped[name],now,require_recent=not initial,
                       compare=compare and (compare_groups is None or name in compare_groups))

    @staticmethod
    def port_for(group):
        tier,country=group.split('-');index=sorted(COUNTRIES).index(country.upper())
        if tier in ('dc1','dc3'):return 18600+index*2+['dc1','dc3'].index(tier)
        return 18400+index*3+['dc','home1','home3'].index(tier)

    def api(self, path, method='GET', data=None, seconds=5):
        status,body=request(CONTROLLER+path,seconds=seconds,method=method,data=data,headers={'Authorization':'Bearer '+self.access['controller']},limit=2*1024*1024)
        if status>=300: raise RequestFailure('CONTROLLER_STATUS_'+str(status))
        return json.loads(body) if body else {}

    def binding(self, group):
        port=self.port_for(group)
        if group not in self.access['bindings']:
            self.access['bindings'][group]={'uuid':str(uuid.uuid4()),'port':port}
            write_json(self.root/'secrets/access.json',self.access)
        elif self.access['bindings'][group]['port']!=port:
            self.access['bindings'][group]['port']=port
            write_json(self.root/'secrets/access.json',self.access)
        return self.access['bindings'][group]

    def config(self):
        grouped=defaultdict(list)
        for n in self.nodes: grouped[n['group']].append(n)
        groups=[{'name':'PROBE','type':'select','proxies':['REJECT']+[n['proxy']['name'] for n in self.nodes]}]
        listeners=[{'name':'probe','type':'http','listen':'127.0.0.1','port':18190,'proxy':'PROBE'}]
        if len(self.nodes)>1000:raise RequestFailure('PROBE_PORT_CAPACITY')
        used={n['probe_port'] for n in self.nodes if 21000<=n.get('probe_port',0)<22000}
        free=iter(p for p in range(21000,22000) if p not in used)
        claimed=set()
        for n in sorted(self.nodes,key=lambda n:n['id']):
            if not 21000<=n.get('probe_port',0)<22000:n['probe_port']=next(free)
            if n['probe_port'] in claimed:n['probe_port']=next(free)
            claimed.add(n['probe_port'])
            # Name the endpoint by its stable socket, not its shifting position
            # in the candidate list. Port reuse then updates one listener only.
            listeners.append({'name':'health-port-'+str(n['probe_port']),'type':'http','listen':'127.0.0.1',
                              'port':n['probe_port'],'proxy':n['proxy']['name']})
        now=time.time()
        namespaces={name for name in set(grouped)|set(self.access['bindings']) if not name.startswith('hy-')}
        namespaces.update('dc-'+name.split('-')[1] for name in list(namespaces) if name.startswith('dc1-'))
        for name in sorted(namespaces):
            # Both type-specific selectors have fixed same-country/same-rate
            # membership. Admission and actual selection remain type-gated.
            # A classification renewal no longer reloads every active tunnel.
            tier,country=name.split('-')
            ns=[n for n in self.nodes if n['country'].lower()==country and
                ((tier=='dc' and (n['source']=='datacenter' or
                                  (n['source']=='residential' and n['rate']==1))) or
                 (tier in ('home1','dc1') and n['source']=='residential' and n['rate']==1) or
                 (tier in ('home3','dc3') and n['source']=='residential' and n['rate']==3))]
            b=self.binding(name)
            # Eligibility belongs to the single selector. Fixed ordering prevents
            # evidence renewal/selection changes from rewriting the entire config.
            # Old ordinary-machine VLESS credentials remain internal aliases
            # to the canonical machine pool. HY2 aliases are handled below
            # and can route only to the same-country HY2-only owner.
            names=['dc-'+country] if tier=='dc1' else ['REJECT']+[n['proxy']['name'] for n in sorted(ns,key=lambda n:n['id'])]
            groups.append({'name':name,'type':'select','proxies':names})
            listeners.append({'name':'in-'+name,'type':'vless','listen':'127.0.0.1','port':b['port'],
                              'users':[{'username':name,'uuid':b['uuid']}], 'ws-path':'/dispatch/'+name,
                              'allow-insecure':True,'proxy':name})
        rules=[]
        if self.hy2.get('enabled'):
            countries=sorted(COUNTRIES)
            for country in countries:
                name='hy-'+country.lower()
                groups.append({'name':name,'type':'select','proxies':['REJECT']+
                    [n['proxy']['name'] for n in sorted(self.route_members(name),key=lambda n:n['id'])]})
            names=[g['name'] for g in groups if g['name']!='PROBE' and not g['name'].startswith('dc3-')]
            listeners.append({'name':'hy2-gateway','type':'hysteria2','listen':self.hy2['listen'],
                'port':self.hy2['port'],'users':{'hy2-'+g:self.hy2_password(g) for g in names},
                'certificate':self.hy2['certificate'],'private-key':self.hy2['private-key'],
                'alpn':['h3'],'ignore-client-bandwidth':True})
            # Old per-tier HY2 credentials are same-country aliases to the HY2
            # owner, never routes back into the mixed-protocol VLESS pools.
            rules=['AND,((IN-NAME,hy2-gateway),(IN-USER,hy2-'+g+')),hy-'+g.split('-')[1] for g in names]
        return {'mode':'rule','log-level':'silent','ipv6':False,'unified-delay':True,'allow-lan':False,'bind-address':'127.0.0.1',
                'external-controller':'127.0.0.1:19190','secret':self.access['controller'],
                'profile':{'store-selected':False}, 'proxies':[n['proxy'] for n in self.nodes],
                'proxy-groups':groups,'listeners':listeners,'rules':rules+['MATCH,REJECT']}

    def save(self):
        with self.lock:
            write_json(self.runtime/'candidates.json',self.nodes)
            write_json(self.runtime/'state.json',self.state)
            write_json(self.runtime/'source-summary.json',self.summary)
            write_json(self.runtime/'status.json',self.status())

    def status(self):
        groups={}
        now=time.time()
        for name,g in self.state['groups'].items():
            ns=self.route_members(name); chosen=next((n for n in ns if n['id']==g.get('selected')),None)
            backup=next((n for n in ns if n['id']==g.get('backup')),None)
            groups[name]={'label':label(name,chosen,now),'candidates':len(ns),
                          'network_type':network_kind(chosen,now),'residential_proven':False,
                          'country_verified':sum(n.get('qualified_at',0)+QUALIFICATION_TTL>now for n in ns),
                          'ready':bool(chosen and self.route_eligible(name,chosen,now)),
                          'routing_mode':'HY2_FIXED_BINDING' if name.startswith('hy-') and len(ns)==1 else 'HY2_ONLY_SELECTION' if name.startswith('hy-') else 'MIXED_UPSTREAM_SELECTION',
                          'latency_ms':metrics(chosen)['median_ms'] if chosen else None,
                          'measurement':metrics(chosen) if chosen else None,
                          'stability':quality(chosen) if chosen else None,
                          'stability_reason':chosen.get('stability_reason') if chosen else None,
                          'backup_ready':bool(backup and eligible(backup,now) and standby_ready(backup,now)),
                          'backup_measurement':metrics(backup) if backup else None,
                          'primary_check_overdue':bool(chosen and now-chosen.get('last_checked_at',0)>PRIMARY_SECONDS+10),
                          'selected_since':g.get('selected_at'),'selection_reason':g.get('reason'),
                          'switch_count':g.get('switch_count',0)}
        return {'updated_at':now,'health':dict(self.health),'gateway_running':bool(self.proc and self.proc.poll() is None),
                'refresh_interval_seconds':REFRESH_SECONDS,'sample_interval_seconds':SAMPLE_SECONDS,
                'last_refresh':self.state.get('last_refresh'),'last_sample':self.state.get('last_sample'),
                'sources':self.summary,'groups':groups}

    def write_config(self):
        path=self.runtime/'gateway.yaml'
        candidate=self.runtime/'gateway-next.yaml'
        body=yaml.safe_dump(self.config(),allow_unicode=True,sort_keys=False).encode()
        if path.exists() and path.read_bytes()==body:return False
        atomic(candidate,body)
        result=subprocess.run([MIHOMO,'-t','-d',str(self.runtime),'-f',str(candidate)],env=self.gateway_environment(),stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=15)
        if result.returncode: raise RequestFailure('CONFIG_VALIDATION_FAILED')
        if path.exists(): atomic(self.runtime/'gateway-previous.yaml',path.read_bytes())
        atomic(path,candidate.read_bytes())
        if self.proc and self.proc.poll() is None:
            try:
                self.api('/configs?force=true','PUT',{'path':str(path)},seconds=15)
                self.apply_selections()
                if not self.listeners_ready():raise RequestFailure('LISTENER_READY_CHECK_FAILED')
            except Exception:
                previous=self.runtime/'gateway-previous.yaml'
                if previous.exists():
                    atomic(path,previous.read_bytes())
                    self.api('/configs?force=true','PUT',{'path':str(path)},seconds=15)
                raise
        return True

    def start_gateway(self):
        self.write_config()
        self.proc=subprocess.Popen([MIHOMO,'-d',str(self.runtime),'-f',str(self.runtime/'gateway.yaml')],env=self.gateway_environment(),stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        deadline=time.monotonic()+15
        while time.monotonic()<deadline:
            if self.proc.poll() is not None: raise RequestFailure('GATEWAY_EXITED')
            try:
                self.api('/version');self.apply_selections()
                if self.listeners_ready():return
            except RequestFailure: time.sleep(0.2)
            time.sleep(.05)
        raise RequestFailure('GATEWAY_START_TIMEOUT')

    def apply_selections(self):
        now=time.time(); indexed={n['id']:n for n in self.nodes}
        observed_groups=self.api('/proxies').get('proxies',{})
        self.actual_targets={name:p.get('now') for name,p in observed_groups.items()
                             if name in self.state['groups']}
        for name,g in self.state['groups'].items():
            # Removed groups might not exist after source replacement.
            n=indexed.get(g.get('selected'))
            target=n['proxy']['name'] if self.route_eligible(name,n,now) else 'REJECT'
            observed=observed_groups.get(name,{})
            if not observed:continue
            if observed.get('now')!=target:
                self.api('/proxies/'+quote(name,safe=''),'PUT',{'name':target})
                self.actual_targets[name]=target

    def actual_admission_safe(self,now):
        """Control outages must not silently retain a revoked country/type."""
        by_name={n['proxy']['name']:n for n in self.nodes}
        for group,target in self.actual_targets.items():
            if target=='REJECT':continue
            n=by_name.get(target)
            if not self.route_admissible(group,n,now):
                return False
        return True

    def fetch(self):
        for source,url in json.loads((self.root/'secrets/providers.json').read_text()).items():
            try:self.accept_source(source,self.fetch_source(source,url))
            except Exception as e:self.summary.setdefault(source,{}).update(fetch_status='FAIL',failure_type=type(e).__name__)
        self.save()

    def fetch_source(self,source,url):
        routes=['http://127.0.0.1:7890',None] if source=='datacenter' else [None,'http://127.0.0.1:7890']
        last=None
        for route in routes:
            try:
                code,body=request(url,seconds=25,limit=8*1024*1024,proxy=route)
                if code!=200:raise RequestFailure('SOURCE_STATUS')
                parsed,errors=parse_subscription(body);ns,counts=classify(parsed,source)
                counts.update(parse_errors=errors,fetch_at=time.time(),fetch_status='PASS')
                return {'nodes':ns,'counts':counts,'body':body}
            except Exception as e:last=e
        raise last

    def accept_source(self,source,result):
        import copy
        with self.lock:
            old_nodes=self.nodes;old_state=copy.deepcopy(self.state);old={n['id']:n for n in old_nodes}
            for n in result['nodes']:
                previous=old.get(n['id'],{})
                old_source_group=previous.get('source_group',previous.get('group'))
                if old_source_group==n['group']:
                    for field in ('samples','legacy_samples','observations','last_checked_at','last_success_at','last_rtt_checked_at','failures','qualified_at','country_result','network_identity','cooldown_until','recovery_required','recovery_successes','probe_port',
                                  'last_recovery_success_at','incident_level','last_incident_at',
                                  'last_recovered_at','recovery_confirmations_required','stability_reason',
                                  'qualification_attempt_at','qualification_next_at','qualification_failures'):
                        if field in previous:n[field]=previous[field]
            self.nodes=[n for n in old_nodes if n['source']!=source]+result['nodes']
            self.reconcile();self.summary[source]=result['counts']
            try:self.write_config()
            except Exception:
                self.nodes=old_nodes;self.state=old_state;self.summary[source].update(fetch_status='FAIL_CONFIG');raise
            atomic(self.runtime/('input-'+source+'.txt'),result['body'])

    def qualify_node(self,node):
        """One worker owns PROBE; other worker only uses per-node delay API."""
        if self.summary.get(node['source'],{}).get('fetch_status','PASS').startswith('FAIL'):
            return {'reason':'SOURCE_UNCONFIRMED'}
        self.api('/proxies/PROBE','PUT',{'name':node['proxy']['name']})
        endpoints=('https://my.ippure.com/v1/info','https://ipinfo.io/json') if node['source']=='residential' else ('https://ipinfo.io/country','https://api.country.is/')
        for endpoint in endpoints:
            try:
                code,body=request(endpoint,proxy=PROBE_PROXY,seconds=7,limit=32*1024)
                if code!=200:continue
                if endpoint in ('https://my.ippure.com/v1/info','https://ipinfo.io/json'):
                    country,evidence=network_from_body(body)
                else:country,evidence=country_from_body(body),None
                if country:return {'country':country,'evidence':evidence,'reason':'MATCH' if country==node['country'] else 'MISMATCH'}
            except Exception:continue
        return {'reason':'UNREACHABLE'}

    def accept_qualification(self,node,result):
        now=time.time();node['country_result']=result['reason']
        node['qualification_attempt_at']=now
        if result.get('evidence'):
            node['network_identity']=merge_evidence(node.get('network_identity'),result['evidence'],now)
        if result['reason']=='MATCH':node['qualified_at']=now
        elif result['reason']=='MISMATCH':node['qualified_at']=0
        # A failed lookup retains only the unrenewed bounded evidence, not a new PASS.
        old=node['group'];self.reconcile()
        evidence=node.get('network_identity') or {}
        fresh_type=(node['source']=='datacenter' or
                    (result.get('evidence') or {}).get('residential_classified') is not None)
        if result['reason']=='MATCH' and fresh_type:
            node['qualification_failures']=0
            node['qualification_next_at']=now+QUALIFICATION_TTL-900
        else:
            failures=min(5,node.get('qualification_failures',0)+1)
            node['qualification_failures']=failures
            node['qualification_next_at']=now+min(300,30*2**(failures-1))
        # write_config is byte-stable for established type namespaces. Only
        # genuinely new bindings/nodes require an apply, batched by the owner.
        if old!=node['group']:self.config_dirty=True

    def probe_node(self,node):
        start=time.monotonic()
        try:
            with socket.create_connection(('127.0.0.1',node['probe_port']),timeout=.3):pass
        except OSError:
            return {'ok':False,'infrastructure_error':True,'failure_class':'LOCAL_PROBE_UNAVAILABLE'}
        try:
            # This installed engine ignores the newer expected= query parameter.
            # Validate the actual status via an isolated per-node loopback listener.
            proxy='http://127.0.0.1:'+str(node['probe_port'])
            primary_failed=False;target=HEALTH_URL
            try:
                status,_=request(HEALTH_URL,proxy=proxy,seconds=5,limit=1024)
            except RequestFailure:
                status=0
            if status!=204:
                primary_failed=True;target=SECONDARY_HEALTH_URL
                attempt_start=time.monotonic()
                status,_=request(target,proxy=proxy,seconds=5,limit=1024)
            http_ms=round((time.monotonic()-locals().get('attempt_start',start))*1000)
            connection_ms=max(1,round((time.monotonic()-start)*1000))
            if status!=204:return {'ok':False,'delay_ms':None,'probe_wall_ms':http_ms,'request_ms':http_ms,'http_status':status,'failure_class':'EXPECTED_204'}
            # Availability/quality always use the actual request. The separate
            # displayed RTT need not incur a second TLS request every minute.
            if time.time()-node.get('last_rtt_checked_at',0)<RTT_SECONDS:
                return {'ok':True,'delay_ms':None,'request_ms':http_ms,'http_status':204,
                        'probe_wall_ms':http_ms,'failure_class':None,'rtt_sampling':'NOT_DUE',
                        'health_target':'SECONDARY' if primary_failed else 'PRIMARY',
                        'connection_ms':connection_ms,
                        'primary_target_failed':primary_failed}
            rtt_at=time.time()
            repeat_ok=None
            try:
                data=self.api('/proxies/'+quote(node['proxy']['name'],safe='')+'/delay?timeout=4500&expected=204&url='+quote(target,safe=''),seconds=6)
                if isinstance(data.get('delay'),(int,float)) and data['delay']>0:repeat_ok=True
            except RequestFailure as e:
                # Only a completed node-test error is endpoint evidence.
                # A controller transport outage remains UNKNOWN, not a node failure.
                if str(e) not in ('CONTROLLER_STATUS_503','CONTROLLER_STATUS_504'):raise
                data={};repeat_ok=False
            delay=data.get('delay');ok=isinstance(delay,(int,float)) and delay>0
            # A missing RTT is not a failed webpage request; record availability separately.
            return {'ok':True,'delay_ms':delay if ok else None,'request_ms':http_ms,'http_status':204,
                    'probe_wall_ms':round((time.monotonic()-start)*1000),'failure_class':None if ok else 'RTT_UNAVAILABLE',
                    'rtt_checked_at':rtt_at,'rtt_sampling':'CHECKED',
                    'repeat_request_ok':repeat_ok,
                    'connection_ms':connection_ms,
                    'health_target':'SECONDARY' if primary_failed else 'PRIMARY',
                    'primary_target_failed':primary_failed}
        except Exception:
            if 'http_ms' in locals() and status==204:
                return {'ok':True,'delay_ms':None,'request_ms':http_ms,'http_status':204,
                        'probe_wall_ms':round((time.monotonic()-start)*1000),'failure_class':'RTT_UNAVAILABLE',
                        'rtt_checked_at':locals().get('rtt_at'),'rtt_sampling':'FAILED',
                        'connection_ms':locals().get('connection_ms'),
                        'health_target':'SECONDARY' if primary_failed else 'PRIMARY',
                        'primary_target_failed':primary_failed}
            return {'ok':False,'delay_ms':None,'probe_wall_ms':round((time.monotonic()-start)*1000),'failure_class':'REQUEST_FAILED'}

    def qualify(self):
        counts=Counter()
        for i,n in enumerate(self.nodes):
            if self.stop.is_set():return
            if self.summary.get(n['source'],{}).get('fetch_status','PASS').startswith('FAIL'):
                counts['SOURCE_UNCONFIRMED']+=1
                continue
            self.health.update(phase='COUNTRY_VERIFICATION',position=i+1,total=len(self.nodes),updated_at=time.time())
            measured=None;reason='COUNTRY_REQUEST_FAILED'
            try:
                self.api('/proxies/PROBE','PUT',{'name':n['proxy']['name']})
                endpoints=('https://my.ippure.com/v1/info','https://ipinfo.io/json') if n['source']=='residential' else ('https://ipinfo.io/country','https://api.country.is/')
                # Type and country come from the same node's actual egress, not its entrance.
                if n['source']=='residential':n.pop('network_identity',None)
                for endpoint in endpoints:
                    try:
                        code,body=request(endpoint,proxy=PROBE_PROXY,seconds=7,limit=32*1024)
                        if code==200:
                            if endpoint in ('https://my.ippure.com/v1/info','https://ipinfo.io/json'):
                                measured,evidence=network_from_body(body);n['network_identity']=evidence
                            else:measured=country_from_body(body)
                        if measured: break
                    except Exception: continue
                if measured==n['country']:
                    n['qualified_at']=time.time();reason='MATCH'
                elif measured:
                    n['qualified_at']=0;reason='MISMATCH'
                else:
                    # An unsuccessful recheck must not renew evidence. Existing bounded evidence expires normally.
                    reason='UNREACHABLE'
            except Exception: reason='PROBE_REQUEST_FAILED'
            n['country_result']=reason;counts[reason]+=1
            if i%2==0:self.save()
        self.api('/proxies/PROBE','PUT',{'name':'REJECT'})
        self.state['last_refresh']=time.time();self.state['country_verification_counts']=dict(counts)
        self.write_config();self.save()

    def sample(self):
        """Compatibility one-shot; production uses the priority queue instead."""
        from policy import record_observation
        for n in self.nodes:
            if self.stop.is_set():return
            if n.get('qualified_at',0)+QUALIFICATION_TTL<=time.time() or not pool_eligible(n,time.time()):continue
            record_observation(n,self.probe_node(n),time.time());self.reconcile(compare=True);self.apply_selections()
        self.state['last_sample']=time.time();self.save()

    def client_profile(self, tier=None):
        now=time.time();indexed={n['id']:n for n in self.nodes};proxies=[];bindings=[]
        for group,g in sorted(self.state['groups'].items(),key=lambda kv:('jp' not in kv[0],kv[0])):
            if group.startswith(('dc1-','dc3-','hy-')):continue
            if tier and group!=tier and group.split('-')[0]!=tier:continue
            selected=indexed.get(g.get('selected'))
            if not selected or selected['group']!=group or not eligible(selected,now):continue
            b=self.binding(group)
            proxies.append({'name':label(group,selected,now),'type':'vless','server':'gw.sync-api.xyz','port':443,'uuid':b['uuid'],
                            'udp':True,'tls':True,'servername':'gw.sync-api.xyz','skip-cert-verify':False,'network':'ws',
                            'ws-opts':{'path':'/dispatch/'+group,'headers':{'Host':'gw.sync-api.xyz'}}})
            bindings.append(group)
        if self.hy2.get('enabled') and (not tier or tier=='hy' or tier.startswith('hy-')):
            for group,g in sorted(self.state['groups'].items()):
                if not group.startswith('hy-') or (tier and tier!='hy' and group!=tier):continue
                selected=indexed.get(g.get('selected'))
                if not self.route_eligible(group,selected,now):continue
                proxies.append({'name':label(group,selected,now),'type':'hysteria2',
                    'server':'gw.sync-api.xyz','port':443,'password':self.hy2_password(group),
                    'sni':'gw.sync-api.xyz','skip-cert-verify':False,'alpn':['h3'],'udp':True})
                bindings.append(group)
        if not proxies:raise RequestFailure('NO_READY_GROUPS')
        groups=subscription_layout(proxies,bindings)
        return yaml.safe_dump({'mixed-port':7890,'allow-lan':False,'mode':'rule','log-level':'warning',
            'proxies':proxies,'proxy-groups':groups,
            **client_settings(self.access['subscription'],bundle_revision(self.root))},allow_unicode=True,sort_keys=False).encode()

    def caddy_fragment(self):
        lines=['gw.sync-api.xyz {','    bind 172.17.16.64']
        # Fixed path/port namespace, including future countries: refresh never needs a Caddy reload.
        for group in sorted(tier+'-'+country.lower() for country in COUNTRIES for tier in ('dc','home1','home3','dc1','dc3')):
            lines += ['    handle /dispatch/'+group+' {','        reverse_proxy 127.0.0.1:'+str(self.port_for(group)),'    }']
        lines+=['    respond 404','}','sub.sync-api.xyz {','    bind 172.17.16.64','    reverse_proxy 127.0.0.1:18192',
                '    handle_errors {','        respond "Subscription temporarily unavailable" 503','    }','}']
        return '\n'.join(lines)+'\n'

    def serve(self, address=('127.0.0.1',18192)):
        dispatch=self
        class Handler(BaseHTTPRequestHandler):
            def log_message(self,*args):pass
            def do_GET(self):
                self.connection.settimeout(5)
                parts=urlsplit(self.path).path.split('/')
                if len(self.path)>256 or len(parts) not in (3,4,5,6) or parts[1]!='s' or not hmac.compare_digest(parts[2],dispatch.access['subscription']):
                    self.send_error(404);return
                if len(parts) in (5,6):
                    if parts[3]!='rules' or parts[-1] not in tuple(n+'.mrs' for n in RULE_FILES):
                        self.send_error(404);return
                    try:body=rule_body(dispatch.root,parts[-1][:-4],parts[4] if len(parts)==6 else None)
                    except (OSError,ValueError):self.send_error(503);return
                    self.send_response(200);self.send_header('Content-Type','application/octet-stream')
                    self.send_header('Cache-Control','private, max-age=3600')
                    self.send_header('Content-Length',str(len(body)))
                    self.end_headers();self.wfile.write(body);return
                try:
                    with dispatch.lock:body=dispatch.client_profile(parts[3] if len(parts)==4 else None)
                except RequestFailure:self.send_error(503);return
                self.send_response(200);self.send_header('Content-Type','application/yaml; charset=utf-8')
                self.send_header('Cache-Control','no-store');self.send_header('Content-Length',str(len(body)))
                self.end_headers();self.wfile.write(body)
        class LimitedServer(HTTPServer):
            def get_request(self):
                connection,address=super().get_request()
                connection.settimeout(5)
                return connection,address
        self.server=LimitedServer(address,Handler)
        self.server.timeout=1
        self.server.socket.settimeout(5)
        while not self.stop.is_set():
            try:self.server.handle_request()
            except OSError:pass
        self.server.server_close()

    def run(self, initial_only=False):
        self.start_gateway()
        thread=threading.Thread(target=self.serve,daemon=True);thread.start()
        from scheduler import AdaptiveScheduler
        scheduler=AdaptiveScheduler(self)
        self.health.update(release_id=RELEASE_ID,loaded_code_sha256=loaded_identity())
        try:
            while not self.stop.is_set():
                if self.proc.poll() is not None:raise RequestFailure('GATEWAY_EXITED')
                scheduler.tick()
                if initial_only and scheduler.completed_refresh:break
                self.stop.wait(.25)
        finally:
            self.stop.set();scheduler.close()
            if self.proc and self.proc.poll() is None:
                self.proc.terminate()
                try:self.proc.wait(timeout=5)
                except subprocess.TimeoutExpired:self.proc.kill();self.proc.wait()
            thread.join(timeout=6)

def main():
    parser=argparse.ArgumentParser();parser.add_argument('command',choices=['run','initial','status','caddy','handoff']);args=parser.parse_args()
    d=Dispatcher()
    signal.signal(signal.SIGTERM,lambda *_:d.stop.set());signal.signal(signal.SIGINT,lambda *_:d.stop.set())
    if args.command in ('run','initial'):d.run(initial_only=args.command=='initial')
    elif args.command=='status':print((ROOT/'runtime/status.json').read_text())
    elif args.command=='caddy':atomic(ROOT/'runtime/caddy-fragment.conf',d.caddy_fragment().encode())
    elif args.command=='handoff':
        directory=ROOT/'secrets/handoff';directory.mkdir(exist_ok=True,mode=0o700)
        atomic(directory/'subscription-url.txt',('https://sub.sync-api.xyz/s/'+d.access['subscription']+'\n').encode())
        print('HANDOFF_PATH='+str(directory/'subscription-url.txt'))

if __name__=='__main__':
    try:main()
    except Exception as e:
        # Known RequestFailure codes contain no URL, token or credential.
        code=str(e) if isinstance(e,RequestFailure) and str(e).replace('_','').isalnum() else 'UNCLASSIFIED'
        print(json.dumps({'status':'FAILED','exception_type':type(e).__name__,'failure_code':code[:96]}),flush=True)
        raise SystemExit(1)
