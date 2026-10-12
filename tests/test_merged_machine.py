"""Canonical machine pools retain evidence, boundaries and one route owner."""
import copy
import os
import subprocess
import threading
import tempfile
import time
from pathlib import Path
import unittest
from unittest.mock import patch
import yaml
from app import Dispatcher
from network_identity import pool_group,pool_eligible
from scheduler import AdaptiveScheduler
from test_adaptive import node
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from httpio import request
from urllib.parse import quote


class MergedMachineTests(unittest.TestCase):
    def dispatch(self):
        tmp=tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        return Dispatcher(Path(tmp.name))

    def residential(self,ident,kind='HOSTING',country='JP',rate=1,now=None):
        now=time.time() if now is None else now
        n=node(ident,group='home'+str(rate)+'-'+country.lower(),now=now)
        n.update(source='residential',rate=rate,country=country,last_success_at=now,
            network_identity={'kind':kind,'checked_at':now})
        return n

    def test_all_verified_nonhome_onefold_kinds_enter_machine(self):
        for kind in ('HOSTING','CONFLICT','NON_RESIDENTIAL'):
            n=self.residential(kind,kind,now=10000)
            before=copy.deepcopy(n)
            n['group']=pool_group(n,10001)
            self.assertEqual(n['group'],'dc-jp')
            self.assertTrue(pool_eligible(n,10001))
            for field in ('id','source','rate','country','proxy','network_identity','samples'):
                self.assertEqual(n[field],before[field])

    def test_home_unknown_expired_and_threefold_cannot_enter_machine(self):
        for kind in ('RESIDENTIAL_CLASSIFIED','UNKNOWN','ISP_NETWORK'):
            n=self.residential(kind,kind,now=10000)
            n['group']='dc-jp'
            self.assertFalse(pool_eligible(n,10001))
        n=self.residential('expired',now=10000)
        n['group']='dc-jp'
        self.assertEqual(pool_group(n,18000),'dc-jp')
        self.assertFalse(pool_eligible(n,18000))
        n=self.residential('threefold',rate=3,now=10000)
        n['group']=pool_group(n,10001)
        self.assertEqual(n['group'],'dc3-jp')
        self.assertFalse(pool_eligible(n,10001))
        n['group']='dc-jp'
        self.assertFalse(pool_eligible(n,10001))

    def test_one_owner_keeps_canonical_winner_and_candidate_histories(self):
        d=self.dispatch()
        now=time.time()
        a=node('dc',now=now)
        b=self.residential('ordinary',now=now)
        b.update(group='dc1-jp',failures=1,observations=[{'at':now,'ok':False}],probe_port=21101)
        before=copy.deepcopy(b)
        d.nodes=[a,b]
        d.state['groups']={'dc-jp':{'selected':'dc','selected_at':now},
            'dc1-jp':{'selected':'ordinary','selected_at':now}}
        d.reconcile(initial=True,now=now)
        self.assertNotIn('dc1-jp',d.state['groups'])
        self.assertEqual(d.state['groups']['dc-jp']['selected'],'dc')
        self.assertEqual([n['group'] for n in d.nodes],['dc-jp','dc-jp'])
        for field in ('id','failures','observations','samples','qualified_at','probe_port','network_identity'):
            self.assertEqual(b[field],before[field])

    def test_empty_canonical_seeds_legacy_winner_not_another_country(self):
        d=self.dispatch()
        now=time.time()
        n=self.residential('legacy',now=now)
        n['group']='dc1-jp'
        d.nodes=[n]
        d.state['groups']={'dc1-jp':{'selected':'legacy','selected_at':now}}
        d.reconcile(initial=True,now=now)
        self.assertEqual(d.state['groups']['dc-jp']['selected'],'legacy')
        self.assertNotIn('dc1-jp',d.state['groups'])
        self.assertNotIn('dc-us',d.state['groups'])

    def test_canonical_native_membership_has_both_sources_same_country_rate(self):
        d=self.dispatch()
        now=time.time()
        a=node('dc',now=now)
        b=self.residential('new',now=now)
        wrong_country=self.residential('us',country='US',now=now)
        wrong_rate=self.residential('3x',rate=3,now=now)
        d.nodes=[a,b,wrong_country,wrong_rate]
        d.reconcile(initial=True,now=now)
        groups={g['name']:g for g in d.config()['proxy-groups']}
        self.assertEqual(set(groups['dc-jp']['proxies']),{'REJECT','n-dc','n-new'})

    def test_old_credentials_are_single_pool_aliases_and_not_published(self):
        d=self.dispatch()
        now=time.time()
        d.nodes=[node('dc',now=now),self.residential('ordinary',now=now)]
        d.state['groups']={'dc-jp':{'selected':'dc','selected_at':now}}
        old=copy.deepcopy(d.binding('dc1-jp'))
        old_password=d.hy2_password('dc1-jp')
        from test_hy2_gateway import GatewayChanges
        GatewayChanges().enable_hy2(d)
        d.reconcile(initial=True,now=now)
        config=d.config()
        groups={g['name']:g for g in config['proxy-groups']}
        self.assertEqual(groups['dc1-jp']['proxies'],['dc-jp'])
        self.assertEqual(d.binding('dc1-jp'),old)
        self.assertEqual(d.hy2_password('dc1-jp'),old_password)
        hy=next(l for l in config['listeners'] if l['type']=='hysteria2')
        self.assertEqual(hy['users']['hy2-dc1-jp'],old_password)
        profile=yaml.safe_load(d.client_profile())
        self.assertEqual(len(profile['proxies']),1)
        self.assertFalse(any('普通机房' in p['name'] for p in profile['proxies']))
        self.assertEqual({p['type'] for p in profile['proxies']},{'vless'})
        self.assertNotIn('dc1-jp',d.state['groups'])
        self.assertEqual(config['rules'][-1],'MATCH,REJECT')

    def test_classification_refresh_keeps_static_membership_and_withdraws_home(self):
        d=self.dispatch()
        now=time.time()
        n=self.residential('r',now=now)
        d.nodes=[n]
        d.binding('dc-jp')
        d.binding('home1-jp')
        d.binding('dc1-jp')
        d.reconcile(initial=True,now=now)
        before=d.config()
        n['network_identity']={'kind':'RESIDENTIAL_CLASSIFIED','checked_at':now+1}
        d.reconcile(initial=True,now=now+1)
        self.assertEqual(n['group'],'home1-jp')
        self.assertEqual(before,d.config())
        self.assertIsNone(d.state['groups']['dc-jp']['selected'])
        self.assertNotIn('dc1-jp',d.state['groups'])

    def test_refresh_blocks_comparison_until_all_merged_candidates_assessed(self):
        d=self.dispatch()
        now=time.time()
        d.nodes=[node('dc',now=now),self.residential('new',now=now)]
        d.reconcile(initial=True,now=now)
        s=AdaptiveScheduler(d)
        self.addCleanup(s.close)
        s.refresh_active=True
        s.qualify_queue.append('new')
        self.assertNotIn('dc-jp',s._comparison_groups())
        self.assertNotIn('home1-jp',s._comparison_groups())
        s.qualify_queue.clear()
        self.assertIn('dc-jp',s._comparison_groups())

    def test_expired_merged_candidate_is_revoked_by_single_canonical_owner(self):
        d=self.dispatch()
        n=self.residential('r',now=10000)
        n['group']='dc-jp'
        d.nodes=[n]
        d.state['groups']={'dc-jp':{'selected':'r'}}
        d.actual_targets={'dc-jp':'n-r'}
        self.assertFalse(d.actual_admission_safe(18000))
        d.reconcile(now=18000)
        self.assertIsNone(d.state['groups']['dc-jp']['selected'])
        self.assertNotIn('dc1-jp',d.state['groups'])

    def test_native_both_protocols_and_old_alias_follow_one_owner(self):
        from test_hy2_engine import core,port,stop
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            cert=root/'cert.pem'
            key=root/'key.pem'
            subprocess.run(['openssl','req','-x509','-newkey','ec','-pkeyopt','ec_paramgen_curve:P-256',
                '-nodes','-keyout',str(key),'-out',str(cert),'-days','1','-subj','/CN=merge.fixture.test',
                '-addext','subjectAltName=DNS:merge.fixture.test','-addext','basicConstraints=critical,CA:TRUE'],
                stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=True,timeout=10)
            key.chmod(0o600)
            env={k:v for k,v in os.environ.items() if 'proxy' not in k.lower()}
            env.update(SAFE_PATHS=str(root),SSL_CERT_FILE=str(cert))
            class Handler(BaseHTTPRequestHandler):
                def log_message(self,*a):pass
                def do_GET(self):self.send_response(204);self.end_headers()
            http=ThreadingHTTPServer(('127.0.0.1',0),Handler)
            thread=threading.Thread(target=http.serve_forever,daemon=True)
            thread.start()
            hp,vp,oldvp,sa,ca=port(),port(),port(),port(),port()
            uuids=['11111111-1111-4111-8111-111111111111','22222222-2222-4222-8222-222222222222']
            server={'external-controller':'127.0.0.1:'+str(sa),'log-level':'silent','mode':'rule',
                'listeners':[{'name':'hy2-gateway','type':'hysteria2','listen':'127.0.0.1','port':hp,
                    'users':{'hy2-dc-jp':'canonical','hy2-dc1-jp':'legacy','hy2-dc-kr':'unmapped'},
                    'certificate':str(cert),'private-key':str(key),'ignore-client-bandwidth':True}],
                'proxy-groups':[{'name':'dc-jp','type':'select','proxies':['DIRECT','REJECT']},
                    {'name':'dc1-jp','type':'select','proxies':['dc-jp']}],
                'rules':['AND,((IN-NAME,hy2-gateway),(IN-USER,hy2-dc-jp)),dc-jp',
                    'AND,((IN-NAME,hy2-gateway),(IN-USER,hy2-dc1-jp)),dc1-jp','MATCH,REJECT']}
            proxies=[]
            for name,password in [('canonical-hy2','canonical'),('legacy-hy2','legacy'),('other-country','unmapped')]:
                proxies.append({'name':name,'type':'hysteria2','server':'127.0.0.1','port':hp,
                    'password':password,'sni':'merge.fixture.test','skip-cert-verify':False,'udp':True})
            for index,(group,p) in enumerate([('dc-jp',vp),('dc1-jp',oldvp)]):
                server['listeners'].append({'name':'in-'+group,'type':'vless','listen':'127.0.0.1','port':p,
                    'users':[{'username':group,'uuid':uuids[index]}],'ws-path':'/dispatch/'+group,
                    'allow-insecure':True,'proxy':group})
                proxies.append({'name':group+'-vless','type':'vless','server':'127.0.0.1','port':p,
                    'uuid':uuids[index],'network':'ws','ws-opts':{'path':'/dispatch/'+group},'udp':True})
            client={'external-controller':'127.0.0.1:'+str(ca),'log-level':'silent',
                'proxies':proxies,'rules':['MATCH,REJECT']}
            server_child=client_child=None
            try:
                server_child,_,server_api=core(root/'server',server,env)
                client_child,_,client_api=core(root/'client',client,env)
                target='http://127.0.0.1:'+str(http.server_port)+'/'
                allowed=[p['name'] for p in proxies if p['name']!='other-country']
                for name in allowed:
                    code,_=request(client_api+'/proxies/'+name+'/delay?timeout=2000&url='+quote(target,safe=''),seconds=3)
                    self.assertEqual(code,200,name)
                code,_=request(client_api+'/proxies/other-country/delay?timeout=1200&url='+quote(target,safe=''),seconds=2)
                self.assertNotEqual(code,200)
                self.assertEqual(request(server_api+'/proxies/dc-jp',method='PUT',data={'name':'REJECT'},seconds=2)[0],204)
                for name in allowed:
                    code,_=request(client_api+'/proxies/'+name+'/delay?timeout=1200&url='+quote(target,safe=''),seconds=2)
                    self.assertNotEqual(code,200,name)
            finally:
                if client_child:stop(client_child)
                if server_child:stop(server_child)
                http.shutdown();http.server_close();thread.join(2)


if __name__=='__main__':unittest.main()
