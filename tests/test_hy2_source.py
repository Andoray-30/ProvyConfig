"""HY2 source provenance is enforced at every route gate, not just display."""
import copy
import tempfile
import time
from pathlib import Path
import unittest
import yaml
from app import Dispatcher
from scheduler import AdaptiveScheduler
from test_adaptive import node
import test_hy2_gateway as hy_fixture


class HY2SourceTests(unittest.TestCase):
    def dispatch(self):
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup)
        d=Dispatcher(Path(tmp.name));hy_fixture.GatewayChanges().enable_hy2(d)
        return d

    def candidate(self,ident,source='residential',now=None,ms=100):
        now=time.time() if now is None else now
        n=node(ident,ms=ms,now=now)
        n['proxy']['type']='hysteria2'
        n.update(source=source,network_identity={'kind':'HOSTING','checked_at':now},
            last_success_at=now,last_checked_at=now)
        return n

    def test_only_role_protocol_and_rate_match_not_names_or_ip_classification(self):
        d=self.dispatch();now=time.time()
        home=self.candidate('home',now=now)
        machine=self.candidate('machine','datacenter',now=now)
        self.assertTrue(d.hy2_candidate(home));self.assertFalse(d.hy2_candidate(machine))
        machine['advertised_residential']=True
        machine['network_identity']['kind']='RESIDENTIAL_CLASSIFIED'
        self.assertFalse(d.hy2_candidate(machine))
        for source in ('unknown','',None):
            x=copy.deepcopy(home);x['source']=source;self.assertFalse(d.hy2_candidate(x))
        for protocol in ('vless','trojan','ss'):
            x=copy.deepcopy(home);x['proxy']['type']=protocol;self.assertFalse(d.hy2_candidate(x))
        for rate in (3,6,10):
            x=copy.deepcopy(home);x['rate']=rate;self.assertFalse(d.hy2_candidate(x))

    def test_fast_machine_stays_in_vless_pool_but_not_hy2_members(self):
        d=self.dispatch();now=time.time()
        home=self.candidate('home',now=now,ms=120)
        machine=self.candidate('machine','datacenter',now=now,ms=5)
        d.nodes=[home,machine];d.reconcile(initial=True,now=now)
        self.assertEqual(d.state['groups']['hy-jp']['selected'],'home')
        self.assertEqual(d.state['groups']['dc-jp']['selected'],'machine')
        groups={g['name']:g for g in d.config()['proxy-groups']}
        self.assertEqual(groups['hy-jp']['proxies'],['REJECT','n-home'])
        self.assertIn('n-machine',groups['dc-jp']['proxies'])

    def test_cached_machine_hy2_route_is_unsafe_and_replaced_without_history_reset(self):
        d=self.dispatch();now=time.time()
        home=self.candidate('home',now=now);machine=self.candidate('machine','datacenter',now=now)
        d.nodes=[home,machine]
        d.state['groups']={'hy-jp':{'selected':'machine','selected_at':now},'dc-jp':{'selected':'machine','selected_at':now}}
        d.actual_targets={'hy-jp':'n-machine','dc-jp':'n-machine'}
        before=copy.deepcopy(d.nodes)
        self.assertFalse(d.actual_admission_safe(now))
        d.reconcile(initial=True,now=now)
        self.assertEqual(d.state['groups']['hy-jp']['selected'],'home')
        self.assertEqual(d.state['groups']['dc-jp']['selected'],'machine')
        for a,b in zip(before,d.nodes):
            for field in ('id','source','proxy','qualified_at','samples','network_identity'):
                self.assertEqual(a[field],b[field])

    def test_machine_only_country_has_no_public_hy2_entry_or_fallback(self):
        d=self.dispatch();now=time.time();machine=self.candidate('machine','datacenter',now=now)
        d.nodes=[machine];d.reconcile(initial=True,now=now)
        self.assertIsNone(d.state['groups']['hy-jp']['selected'])
        self.assertFalse(d.route_admissible('hy-jp',machine,now))
        self.assertFalse(any(p['type']=='hysteria2' for p in yaml.safe_load(d.client_profile())['proxies']))
        self.assertEqual(next(g for g in d.config()['proxy-groups'] if g['name']=='hy-jp')['proxies'],['REJECT'])

    def test_old_hy2_auth_maps_to_same_source_restricted_country_pool(self):
        d=self.dispatch();now=time.time()
        d.nodes=[self.candidate('home',now=now),self.candidate('machine','datacenter',now=now)]
        d.binding('dc1-jp');d.binding('home3-jp');d.reconcile(initial=True,now=now)
        cfg=d.config()
        for old in ('dc-jp','dc1-jp','home3-jp'):
            self.assertIn('AND,((IN-NAME,hy2-gateway),(IN-USER,hy2-'+old+')),hy-jp',cfg['rules'])
        self.assertEqual(next(g for g in cfg['proxy-groups'] if g['name']=='hy-jp')['proxies'],['REJECT','n-home'])

    def test_machine_refresh_does_not_block_independent_residential_hy2_comparison(self):
        d=self.dispatch();now=time.time()
        d.nodes=[self.candidate('home',now=now),self.candidate('machine','datacenter',now=now)]
        d.reconcile(initial=True,now=now)
        s=AdaptiveScheduler(d);self.addCleanup(s.close)
        s.refresh_active=True;s.qualify_queue.append('machine')
        self.assertIn('hy-jp',s._comparison_groups());self.assertNotIn('dc-jp',s._comparison_groups())
        s.qualify_queue.append('home');self.assertNotIn('hy-jp',s._comparison_groups())


if __name__=='__main__':unittest.main()
