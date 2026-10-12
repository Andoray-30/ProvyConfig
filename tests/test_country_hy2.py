"""One HY2-only owner per country; no changes to the VLESS quality policy."""
import copy
from concurrent.futures import Future
import json
import os
from pathlib import Path
import subprocess
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from urllib.parse import quote
from app import Dispatcher
from httpio import request
from policy import record_observation
from scheduler import AdaptiveScheduler
from test_adaptive import node
import test_hy2_gateway as hy_fixture
import yaml


class CountryHY2Tests(unittest.TestCase):
    def dispatch(self,enabled=True):
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup)
        d=Dispatcher(Path(tmp.name))
        if enabled:hy_fixture.GatewayChanges().enable_hy2(d)
        return d

    def upstream(self,ident,protocol='hysteria2',country='JP',now=None,ms=100):
        now=time.time() if now is None else now
        n=node(ident,ms=ms,group='dc-'+country.lower(),now=now)
        n['proxy']['type']=protocol
        n.update(source='residential',network_identity={'kind':'HOSTING','checked_at':now},
            last_checked_at=now,last_success_at=now)
        return n

    def test_single_hy2_is_bound_no_vless_or_other_country_fallback(self):
        d=self.dispatch();now=time.time()
        hy=self.upstream('hy',now=now)
        d.nodes=[hy,self.upstream('fast','vless',now=now,ms=10),self.upstream('hk',country='HK',now=now)]
        d.reconcile(initial=True,now=now)
        self.assertEqual(d.state['groups']['hy-jp']['selected'],'hy')
        self.assertEqual(d.status()['groups']['hy-jp']['routing_mode'],'HY2_FIXED_BINDING')
        self.assertEqual(d.state['groups']['dc-jp']['selected'],'fast')
        record_observation(hy,{'ok':False},now+1);record_observation(hy,{'ok':False},now+16)
        d.reconcile(now=now+16)
        self.assertIsNone(d.state['groups']['hy-jp']['selected'])
        self.assertEqual(d.state['groups']['dc-jp']['selected'],'fast')
        self.assertFalse(d.route_admissible('hy-jp',d.nodes[1],now+16))
        self.assertFalse(d.route_admissible('hy-jp',d.nodes[2],now+16))

    def test_multiple_hy2_choose_and_fail_over_with_original_confirmations(self):
        d=self.dispatch();now=time.time()
        a=self.upstream('a',now=now,ms=100);b=self.upstream('b',now=now,ms=130)
        d.nodes=[a,b,self.upstream('not-hy2','vless',now=now,ms=5)]
        d.reconcile(initial=True,now=now)
        self.assertEqual(d.state['groups']['hy-jp']['selected'],'a')
        record_observation(a,{'ok':False},now+1)
        d.reconcile(now=now+1)
        self.assertEqual(d.state['groups']['hy-jp']['selected'],'a')
        record_observation(a,{'ok':False},now+16)
        d.reconcile(now=now+16)
        self.assertEqual(d.state['groups']['hy-jp']['selected'],'b')
        self.assertEqual(d.state['groups']['dc-jp']['selected'],'not-hy2')

    def test_hy2_not_enabled_leaves_vless_state_and_membership_identical(self):
        d=self.dispatch(enabled=False);now=time.time()
        d.nodes=[self.upstream('v','vless',now=now),self.upstream('h',now=now)]
        d.state['groups']={'dc-jp':{'selected':'v','selected_at':now}}
        d.reconcile(initial=True,now=now)
        state=copy.deepcopy(d.state['groups']['dc-jp']);old=d.config()
        hy_fixture.GatewayChanges().enable_hy2(d);d.reconcile(initial=True,now=now)
        self.assertEqual(d.state['groups']['dc-jp'],state)
        new=d.config()
        self.assertEqual(next(g for g in old['proxy-groups'] if g['name']=='dc-jp'),
                         next(g for g in new['proxy-groups'] if g['name']=='dc-jp'))
        self.assertEqual([l for l in old['listeners'] if l['type']=='vless'],
                         [l for l in new['listeners'] if l['type']=='vless'])

    def test_profile_has_one_hy2_per_country_and_preserves_vless(self):
        d=self.dispatch(enabled=False);now=time.time()
        d.nodes=[self.upstream('h1',now=now),self.upstream('h2',now=now),
            self.upstream('v','vless',now=now),self.upstream('hk',country='HK',now=now)]
        d.reconcile(initial=True,now=now)
        old=yaml.safe_load(d.client_profile())
        hy_fixture.GatewayChanges().enable_hy2(d);d.reconcile(initial=True,now=now)
        new=yaml.safe_load(d.client_profile())
        self.assertEqual([p for p in new['proxies'] if p['type']=='vless'],old['proxies'])
        self.assertEqual(sum(p['type']=='hysteria2' for p in new['proxies']),2)
        self.assertEqual(len({p['name'] for p in new['proxies']}),len(new['proxies']))
        self.assertEqual(new['dns'],old['dns']);self.assertEqual(new['rules'],old['rules'])
        country=next(g for g in new['proxy-groups'] if g['name']=='日本 🇯🇵')
        self.assertEqual(sum(name.startswith('HY2') for name in country['proxies']),1)

    def test_empty_country_or_bad_evidence_does_not_borrow_mixed_pool(self):
        d=self.dispatch();now=time.time()
        n=self.upstream('v','vless',now=now);d.nodes=[n];d.reconcile(initial=True,now=now)
        self.assertIsNone(d.state['groups']['hy-jp']['selected'])
        self.assertFalse(any(p['type']=='hysteria2' for p in yaml.safe_load(d.client_profile())['proxies']))
        n=self.upstream('h',now=now)
        n.update(source='residential',group='home1-jp',network_identity={'kind':'UNKNOWN','checked_at':now})
        d.nodes.append(n);d.reconcile(initial=True,now=now)
        self.assertIsNone(d.state['groups']['hy-jp']['selected'])
        n.update(qualified_at=0)
        self.assertFalse(d.route_admissible('hy-jp',n,now))

    def test_onefold_policy_cannot_silently_choose_threefold(self):
        d=self.dispatch();now=time.time()
        n=self.upstream('h',now=now)
        n.update(source='residential',rate=3,group='home3-jp',network_identity={'kind':'RESIDENTIAL_CLASSIFIED','checked_at':now})
        d.nodes=[n];d.reconcile(initial=True,now=now)
        self.assertIsNone(d.state['groups']['hy-jp']['selected'])
        self.assertFalse(d.hy2_candidate(n))

    def test_expiry_for_hy2_is_hard_revoked_even_if_vless_healthy(self):
        d=self.dispatch();now=time.time()
        n=self.upstream('h',now=now);d.nodes=[n];d.reconcile(initial=True,now=now)
        d.actual_targets={'hy-jp':'n-h'}
        self.assertFalse(d.actual_admission_safe(now+7201))
        self.assertFalse(d.route_admissible('hy-hk',n,now))
        d.reconcile(now=now+7201)
        self.assertIsNone(d.state['groups']['hy-jp']['selected'])

    def test_failure_refreshes_backups_of_both_owners_once_per_observation(self):
        d=self.dispatch();now=time.time()
        a=self.upstream('a',now=now);b=self.upstream('b',now=now,ms=120)
        d.nodes=[a,b];d.reconcile(initial=True,now=now)
        s=AdaptiveScheduler(d);self.addCleanup(s.close)
        f=Future();f.set_result({'ok':False})
        s.pending[f]=('probe','a','dc-jp');s._complete(now+1)
        self.assertEqual(len(a['observations']),1)
        self.assertEqual(b['health_due_at'],now+1)

    def test_old_hy2_credentials_map_only_to_country_hy2_owner(self):
        d=self.dispatch();now=time.time()
        d.nodes=[self.upstream('v','vless',now=now),self.upstream('h',now=now)]
        d.binding('dc1-jp');d.binding('home3-jp');d.reconcile(initial=True,now=now)
        cfg=d.config();g={g['name']:g for g in cfg['proxy-groups']}
        self.assertEqual(g['hy-jp']['proxies'],['REJECT','n-h'])
        for old in ('dc-jp','dc1-jp','home3-jp'):
            self.assertIn('AND,((IN-NAME,hy2-gateway),(IN-USER,hy2-'+old+')),hy-jp',cfg['rules'])
        self.assertEqual(g['dc1-jp']['proxies'],['dc-jp'])
        self.assertEqual(cfg['rules'][-1],'MATCH,REJECT')

    def test_refresh_comparison_excludes_unassessed_hy2_pool(self):
        d=self.dispatch();now=time.time();d.nodes=[self.upstream('h',now=now)]
        d.reconcile(initial=True,now=now)
        s=AdaptiveScheduler(d);self.addCleanup(s.close)
        s.refresh_active=True;s.scan_queue.append('h')
        self.assertNotIn('hy-jp',s._comparison_groups())
        s.scan_queue.clear();self.assertIn('hy-jp',s._comparison_groups())

    def test_native_hy2_front_uses_hy2_upstream_and_never_vless_fallback(self):
        from test_hy2_engine import port,core,stop
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);cert=root/'cert.pem';key=root/'key.pem'
            subprocess.run(['openssl','req','-x509','-newkey','ec','-pkeyopt','ec_paramgen_curve:P-256',
                '-nodes','-keyout',str(key),'-out',str(cert),'-days','1','-subj','/CN=country.fixture.test',
                '-addext','subjectAltName=DNS:country.fixture.test','-addext','basicConstraints=critical,CA:TRUE'],
                stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=True,timeout=10)
            key.chmod(0o600)
            env={k:v for k,v in os.environ.items() if 'proxy' not in k.lower()}
            env.update(SAFE_PATHS=str(root),SSL_CERT_FILE=str(cert))
            class Handler(BaseHTTPRequestHandler):
                def log_message(self,*a):pass
                def do_GET(self):self.send_response(204);self.end_headers()
            http=ThreadingHTTPServer(('127.0.0.1',0),Handler)
            thread=threading.Thread(target=http.serve_forever,daemon=True);thread.start()
            up_h,up_v,up_a=port(),port(),port()
            fixture_uuid='11111111-1111-4111-8111-111111111111'
            upper={'external-controller':'127.0.0.1:'+str(up_a),'log-level':'silent',
                'listeners':[{'name':'upper-h','type':'hysteria2','listen':'127.0.0.1','port':up_h,
                    'users':{'fixture':'upper-password'},'certificate':str(cert),'private-key':str(key),
                    'ignore-client-bandwidth':True,'proxy':'DIRECT'},
                    {'name':'upper-v','type':'vless','listen':'127.0.0.1','port':up_v,
                    'users':[{'username':'fixture','uuid':fixture_uuid}],
                    'allow-insecure':True,'ws-path':'/fixture','proxy':'DIRECT'}],
                'rules':['MATCH,REJECT']}
            d=self.dispatch();now=time.time()
            v=self.upstream('v','vless',now=now,ms=10)
            v['proxy'].update(server='127.0.0.1',port=up_v,uuid=fixture_uuid,
                network='ws',**{'ws-opts':{'path':'/fixture'}})
            h=self.upstream('h',now=now)
            h['proxy'].update(server='127.0.0.1',port=up_h,password='upper-password',
                sni='country.fixture.test',udp=True,**{'skip-cert-verify':False})
            machine=copy.deepcopy(h);machine.update(id='machine',source='datacenter',samples=[1]*3,legacy_samples=[1]*3)
            machine['proxy']['name']='n-machine'
            d.nodes=[v,h,machine];d.state['groups']={'dc-jp':{'selected':'v','selected_at':now}}
            d.reconcile(initial=True,now=now)
            self.assertEqual(d.state['groups']['hy-jp']['selected'],'h')
            d.binding('dc1-jp')
            config=d.config()
            self.assertEqual(next(g for g in config['proxy-groups'] if g['name']=='hy-jp')['proxies'],['REJECT','n-h'])
            ga,ca=port(),port()
            config['external-controller']='127.0.0.1:'+str(ga)
            incoming_h=incoming_v=None
            for listener in config['listeners']:
                listener['listen']='127.0.0.1';listener['port']=port()
                if listener['type']=='hysteria2':
                    listener.update(certificate=str(cert),**{'private-key':str(key)})
                    incoming_h=listener['port']
                elif listener['name']=='in-dc-jp':incoming_v=listener['port']
            front={'external-controller':'127.0.0.1:'+str(ca),'log-level':'silent',
                'proxies':[{'name':'hy','type':'hysteria2','server':'127.0.0.1','port':incoming_h,
                    'password':d.hy2_password('hy-jp'),'sni':'country.fixture.test','skip-cert-verify':False},
                    {'name':'old-hy','type':'hysteria2','server':'127.0.0.1','port':incoming_h,
                    'password':d.hy2_password('dc1-jp'),'sni':'country.fixture.test','skip-cert-verify':False},
                    {'name':'vless','type':'vless','server':'127.0.0.1','port':incoming_v,
                    'uuid':d.access['bindings']['dc-jp']['uuid'],'network':'ws','ws-opts':{'path':'/dispatch/dc-jp'}}],
                'rules':['MATCH,REJECT']}
            upper_child=gateway_child=client_child=None
            try:
                upper_child,_,_=core(root/'upper',upper,env)
                gateway_child,_,gateway_api=core(root/'gateway',config,env)
                d.api=lambda path,method='GET',data=None,seconds=3:json.loads(request(gateway_api+path,
                    method=method,data=data,seconds=seconds,headers={'Authorization':'Bearer '+d.access['controller']})[1] or b'{}')
                d.apply_selections()
                client_child,_,client_api=core(root/'client',front,env)
                target='http://127.0.0.1:'+str(http.server_port)+'/'
                for name in ('hy','old-hy','vless'):
                    code,_=request(client_api+'/proxies/'+name+'/delay?timeout=2000&url='+quote(target,safe=''),seconds=3)
                    self.assertEqual(code,200,name)
                record_observation(h,{'ok':False},now+1)
                record_observation(h,{'ok':False},now+16)
                d.reconcile(now=now+16);d.apply_selections()
                self.assertIsNone(d.state['groups']['hy-jp']['selected'])
                self.assertEqual(d.state['groups']['dc-jp']['selected'],'v')
                for name in ('hy','old-hy','vless'):
                    code,_=request(client_api+'/proxies/'+name+'/delay?timeout=1200&url='+quote(target,safe=''),seconds=2)
                    self.assertEqual(code==200,name=='vless',name)
            finally:
                if client_child:stop(client_child)
                if gateway_child:stop(gateway_child)
                if upper_child:stop(upper_child)
                http.shutdown();http.server_close();thread.join(2)


if __name__=='__main__':unittest.main()
