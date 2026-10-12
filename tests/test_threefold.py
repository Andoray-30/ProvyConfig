import copy,json,sys,time,unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from app import Dispatcher
from client_routing import subscription_layout,settings
from policy import quality,rank,record_observation,select,RTT_SECONDS
import test_adaptive as fixtures
node=fixtures.node

def history(n,values,start=9900):
    n['observations']=[]
    for i,ms in enumerate(values):
        record_observation(n,{'ok':ms is not None,'delay_ms':100 if ms else None,
                             'request_ms':ms,'probe_wall_ms':ms,'failure_class':None},start+i)

class ThreefoldPolicyTests(unittest.TestCase):
    def test_fast_reliable_beats_slow_perfect_despite_one_old_failure(self):
        a,b=node('slow'),node('fast')
        history(a,[2000]*10);history(b,[800]*4+[None]+[800]*5)
        self.assertLess(rank(b),rank(a))
        g={'selected':'slow','selected_at':9000}
        for at in (10000,10061,10122):
            record_observation(a,{'ok':True,'delay_ms':100,'request_ms':2000},at)
            record_observation(b,{'ok':True,'delay_ms':100,'request_ms':800},at)
            select(g,[a,b],at,require_recent=True)
        self.assertEqual(g['selected'],'fast')
    def test_historical_failure_no_longer_blocks_recent_recovery(self):
        a,b=node('slow'),node('fast')
        history(a,[2000]*30);history(b,[None]*20+[800]*10)
        self.assertEqual(quality(b)['rate'],1);self.assertLess(rank(b),rank(a))
    def test_fast_half_failing_does_not_replace_reliable(self):
        a,b=node('slow'),node('fast')
        history(a,[2000]*10);history(b,[None,100]*5)
        self.assertLess(rank(a),rank(b))
        self.assertEqual(select({'selected':'slow','selected_at':9000},[a,b],10000),'slow')
    def test_recent_failure_and_tail_regression_do_not_drive_healthy_switch(self):
        a,b=node('slow'),node('fast')
        history(a,[2000]*10);history(b,[800]*9+[None])
        self.assertFalse(quality(b)['stable'])
        self.assertEqual(select({'selected':'slow','selected_at':9000},[a,b],10000),'slow')
        history(b,[800]*7+[5000,5000,800])
        self.assertEqual(select({'selected':'slow','selected_at':9000},[a,b],10000),'slow')
    def test_repeated_same_pair_no_confirmation_inflation(self):
        a,b=node('slow'),node('fast');history(a,[2000]*10);history(b,[800]*10)
        g={'selected':'slow','selected_at':9000}
        for _ in range(5):select(g,[a,b],10000)
        self.assertEqual(g['confirmations'],1);self.assertEqual(g['selected'],'slow')

class ProbeCostTests(unittest.TestCase):
    def setUp(self):
        # Unit fixtures mock the new local-listener readiness boundary too.
        mock=patch('app.socket.create_connection');mock.start();self.addCleanup(mock.stop)
    def test_actual_https_checked_without_duplicate_rtt(self):
        d=Dispatcher.__new__(Dispatcher);d.api=lambda *a,**k:self.fail('extra RTT request')
        n={'proxy':{'name':'fixture'},'probe_port':12345,'last_rtt_checked_at':time.time()}
        with patch('app.request',return_value=(204,b'')) as req:
            result=d.probe_node(n)
        self.assertEqual(req.call_count,1);self.assertTrue(result['ok']);self.assertIsNone(result['delay_ms'])
        self.assertEqual(result['rtt_sampling'],'NOT_DUE')
    def test_failed_actual_request_never_masked_by_cached_rtt(self):
        d=Dispatcher.__new__(Dispatcher);n={'proxy':{'name':'fixture'},'probe_port':12345,'last_rtt_checked_at':time.time()}
        with patch('app.request',return_value=(200,b'')):
            result=d.probe_node(n)
        self.assertFalse(result['ok']);self.assertEqual(result['http_status'],200)
    def test_rtt_due_is_measured_and_recorded(self):
        d=Dispatcher.__new__(Dispatcher);d.api=lambda *a,**k:{'delay':150}
        n={'proxy':{'name':'fixture'},'probe_port':12345,'last_rtt_checked_at':time.time()-RTT_SECONDS-1}
        with patch('app.request',return_value=(204,b'')):
            result=d.probe_node(n)
        self.assertEqual(result['delay_ms'],150);record_observation(n,result,time.time())
        self.assertEqual(n['last_rtt_checked_at'],result['rtt_checked_at'])
    def test_failed_rtt_is_not_a_failed_successful_https(self):
        d=Dispatcher.__new__(Dispatcher);d.api=lambda *a,**k:(_ for _ in ()).throw(TimeoutError())
        n={'proxy':{'name':'fixture'},'probe_port':12345}
        with patch('app.request',return_value=(204,b'')):
            result=d.probe_node(n)
        self.assertTrue(result['ok']);self.assertEqual(result['rtt_sampling'],'FAILED')

class LayoutTests(unittest.TestCase):
    def proxy(self,group):
        return {'name':'old','type':'vless','uuid':'fixture','server':'gateway.test',
                'tls':True,'skip-cert-verify':False,'ws-opts':{'path':'/dispatch/'+group}}
    def test_country_manual_groups_threefold_first_and_other_regions(self):
        proxies=[self.proxy(g) for g in ['home1-jp','dc-jp','home3-jp','home3-hk','dc1-jp','home3-gb']]
        original=copy.deepcopy(proxies);groups=subscription_layout(proxies);by_name={g['name']:g for g in groups}
        self.assertTrue(all(g['type']=='select' for g in groups))
        self.assertEqual(groups[0]['name'],'出口选择');self.assertEqual(groups[0]['proxies'][0],'日本 🇯🇵')
        self.assertEqual(len(by_name['日本 🇯🇵']['proxies']),4)
        self.assertTrue(by_name['日本 🇯🇵']['proxies'][0].startswith('3× 家宽'))
        self.assertEqual(by_name['其他地区 🌐']['proxies'],['英国 🇬🇧'])
        for p,old in zip(proxies,original):
            self.assertEqual({k:v for k,v in p.items() if k!='name'},{k:v for k,v in old.items() if k!='name'})
        for group in groups[1:]:
            if group['name']!='其他地区 🌐':
                self.assertTrue(all('🇯🇵' not in x and '🇬🇧' not in x for x in group['proxies']))
        self.assertEqual(len({p['name'] for p in proxies}),len(proxies))
        self.assertTrue(all(len(p['name']) <= 14 for p in proxies))
        self.assertEqual(settings('fixture')['rules'][-1],'MATCH,出口选择')
    def test_single_minor_country_has_reachable_top_selector(self):
        groups=subscription_layout([self.proxy('home3-ca')])
        self.assertEqual(groups[0]['proxies'],['其他地区 🌐'])
        self.assertEqual(groups[-1]['proxies'],['加拿大 🇨🇦'])

    def test_names_unique_for_all_country_tiers_and_independent_of_subset(self):
        from nodes import COUNTRIES
        proxies=[self.proxy(tier+'-'+code.lower()) for code in COUNTRIES
                 for tier in ('home3','home1','dc','dc1')]
        subscription_layout(proxies)
        self.assertEqual(len({p['name'] for p in proxies}),len(proxies))
        for p in proxies:
            subset=copy.deepcopy(p);subscription_layout([subset])
            self.assertEqual(subset['name'],p['name'])
            self.assertFalse(any(alias[0] in p['name'] for alias in COUNTRIES.values()))

class ThreefoldSchedulerTests(unittest.TestCase):
    def test_threefold_backup_checked_each_minute_same_worker_limit(self):
        fixture=fixtures.SchedulerTests();d,s,clock,executor=fixture.setup(count=0)
        self.addCleanup(fixture.doCleanups)
        for n in d.nodes:
            n.update(group='home3-jp',source='residential',rate=3,network_identity={'kind':'RESIDENTIAL_CLASSIFIED','checked_at':clock[0]})
        d.nodes[0]['last_checked_at']=clock[0]
        d.nodes[1]['last_checked_at']=clock[0]-61
        d.state['groups']={'home3-jp':{'selected':'a','backup':'b','selected_at':clock[0]}}
        self.assertEqual(s._probe_due(clock[0])[3]['id'],'b')
        s.tick();self.assertLessEqual(len(s.pending),2)

if __name__=='__main__':unittest.main()
