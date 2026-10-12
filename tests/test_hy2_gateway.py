import copy
from concurrent.futures import Future
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch
import yaml

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from app import Dispatcher
from client_routing import settings
import test_adaptive as fixture


class GatewayChanges(unittest.TestCase):
    def dispatch(self):
        temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup)
        return Dispatcher(Path(temporary.name))

    def enable_hy2(self,d):
        d.hy2={'enabled':True,'listen':'172.17.16.64','port':443,
            'certificate':'/var/lib/caddy/certificates/acme-v02.api.letsencrypt.org-directory/gw.sync-api.xyz/gw.sync-api.xyz.crt',
            'private-key':'/var/lib/caddy/certificates/acme-v02.api.letsencrypt.org-directory/gw.sync-api.xyz/gw.sync-api.xyz.key'}

    def test_dns_exception_precedes_all_broad_rule_sets_in_real_yaml(self):
        cfg=settings('fixture');encoded=yaml.safe_dump(cfg,sort_keys=False)
        keys=list(yaml.safe_load(encoded)['dns']['nameserver-policy'])
        for key in keys:
            if key.startswith('rule-set:'):
                self.assertLess(keys.index('+.edu.cn'),keys.index(key))
                self.assertLess(keys.index('+.gw.sync-api.xyz'),keys.index(key))
        self.assertEqual(cfg['dns']['nameserver-policy']['+.edu.cn'],['system'])
        for ip in ('202.204.193.9','202.204.193.153','202.204.193.154'):
            self.assertNotIn(ip,encoded)

    def test_probe_names_stay_bound_to_ports_after_insertion_and_reorder(self):
        d=self.dispatch();d.nodes=[fixture.node('bbb',now=time.time()),fixture.node('ddd',now=time.time())]
        before={l['port']:l for l in d.config()['listeners'] if l['type']=='http'}
        d.nodes=[fixture.node('aaa',now=time.time())]+list(reversed(d.nodes))
        after={l['port']:l for l in d.config()['listeners'] if l['type']=='http'}
        for port,listener in before.items():self.assertEqual(listener,after[port])
        self.assertTrue(all(l['name']=='health-port-'+str(l['port']) for l in after.values() if l['name']!='probe'))

    def test_port_reuse_keeps_same_listener_name_and_changes_only_target(self):
        d=self.dispatch();n=fixture.node('aaa',now=time.time());n['probe_port']=21000;d.nodes=[n]
        old=d.config();replacement=fixture.node('zzz',now=time.time());replacement['probe_port']=21000;d.nodes=[replacement]
        new=d.config();a=next(l for l in old['listeners'] if l['port']==21000);b=next(l for l in new['listeners'] if l['port']==21000)
        self.assertEqual(a['name'],b['name']);self.assertNotEqual(a['proxy'],b['proxy'])

    def test_duplicate_probe_ports_are_repaired_uniquely(self):
        d=self.dispatch();d.nodes=[fixture.node('a',now=time.time()),fixture.node('b',now=time.time())]
        for n in d.nodes:n['probe_port']=21000
        d.config();self.assertEqual(len({n['probe_port'] for n in d.nodes}),2)

    def test_missing_local_port_never_calls_upstream(self):
        d=self.dispatch()
        with patch('app.socket.create_connection',side_effect=ConnectionRefusedError()),patch('app.request') as req:
            result=d.probe_node({'probe_port':21106,'proxy':{'name':'fixture'}})
        self.assertTrue(result['infrastructure_error']);req.assert_not_called()

    def test_infrastructure_failure_preserves_history_and_scan_coverage(self):
        setup=fixture.SchedulerTests();d,s,clock,e=setup.setup(count=0);self.addCleanup(setup.doCleanups)
        n=d.nodes[0];old=copy.deepcopy(n);f=Future()
        f.set_result({'ok':False,'infrastructure_error':True,'failure_class':'LOCAL_PROBE_UNAVAILABLE'})
        s.pending[f]=('scan',n['id'],n['group']);s._complete(clock[0])
        self.assertIn(n['id'],s.scan_queue);self.assertFalse(s.scan_results)
        self.assertEqual(n['samples'],old['samples']);self.assertEqual(n['failures'],old['failures'])
        self.assertEqual(n['qualified_at'],old['qualified_at']);self.assertEqual(n['probe_infra_retry_at'],clock[0]+10)
        self.assertFalse(s._probe_due(clock[0]))

    def test_hy2_credentials_are_distinct_and_stable_without_rotation(self):
        d=self.dispatch();old=copy.deepcopy(d.access);first=d.hy2_password('home1-jp')
        self.assertEqual(first,d.hy2_password('home1-jp'));self.assertNotEqual(first,d.hy2_password('home1-hk'))
        self.assertEqual(len(first),64);self.assertEqual(d.access,old)

    def test_one_udp_listener_authenticated_routing_no_direct_fallback(self):
        d=self.dispatch();d.nodes=[fixture.node('a',now=time.time())];self.enable_hy2(d)
        cfg=d.config();hy=[l for l in cfg['listeners'] if l['type']=='hysteria2']
        self.assertEqual(len(hy),1);self.assertEqual(hy[0]['port'],443)
        self.assertEqual(hy[0]['listen'],'172.17.16.64');self.assertTrue(hy[0]['ignore-client-bandwidth'])
        self.assertIn('hy2-dc-jp',hy[0]['users'])
        self.assertIn('AND,((IN-NAME,hy2-gateway),(IN-USER,hy2-dc-jp)),hy-jp',cfg['rules'])
        self.assertEqual(cfg['rules'][-1],'MATCH,REJECT');self.assertFalse(any(',DIRECT' in r for r in cfg['rules']))

    def test_no_threefold_datacenter_hy2_credentials_or_routes(self):
        d=self.dispatch();d.binding('dc3-jp');self.enable_hy2(d);cfg=d.config()
        hy=next(l for l in cfg['listeners'] if l['type']=='hysteria2')
        self.assertNotIn('hy2-dc3-jp',hy['users']);self.assertFalse(any('hy2-dc3-jp' in r for r in cfg['rules']))

    def test_public_protocols_have_independent_pools_and_keep_vless_identity(self):
        d=self.dispatch();n=fixture.node('a',now=time.time());d.nodes=[n];d.state['groups']={'dc-jp':{'selected':'a'}}
        before=yaml.safe_load(d.client_profile());self.enable_hy2(d)
        upstream=fixture.node('b',now=time.time());upstream['proxy']['type']='hysteria2'
        upstream.update(source='residential',network_identity={'kind':'HOSTING','checked_at':time.time()});d.nodes.append(upstream)
        d.reconcile(initial=True);after=yaml.safe_load(d.client_profile())
        vless=next(p for p in after['proxies'] if p['type']=='vless');self.assertEqual(vless,before['proxies'][0])
        hy=next(p for p in after['proxies'] if p['type']=='hysteria2')
        self.assertEqual(hy['password'],d.hy2_password('hy-jp'));self.assertFalse(hy['skip-cert-verify'])
        self.assertEqual(hy['sni'],'gw.sync-api.xyz');self.assertTrue(hy['name'].startswith('HY2 · '))
        self.assertNotIn('uuid',hy);self.assertNotIn('ws-opts',hy)
        country=next(g for g in after['proxy-groups'] if g['name']=='日本 🇯🇵')
        self.assertEqual(set(country['proxies']),{vless['name'],hy['name']})
        self.assertEqual(after['rules'],before['rules']);self.assertEqual(after['dns'],before['dns'])

    def test_disabled_hy2_leaves_old_reject_only_gateway(self):
        d=self.dispatch();cfg=d.config()
        self.assertFalse(any(l['type']=='hysteria2' for l in cfg['listeners']))
        self.assertEqual(cfg['rules'],['MATCH,REJECT'])


if __name__=='__main__':unittest.main()
