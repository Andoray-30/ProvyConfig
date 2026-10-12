import copy,sys,time,unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import test_adaptive as fixtures
from app import Dispatcher
from httpio import RequestFailure
from policy import record_observation,eligible,quality,rank,select,choose_backup,standby_ready

def observe(n,at,ok=True,repeat=None,ms=200):
    record_observation(n,{'ok':ok,'request_ms':ms if ok else None,'delay_ms':100 if ok else None,
                          'repeat_request_ok':repeat,'failure_class':None if ok else 'REQUEST_FAILED'},at)

class StabilityPolicyTests(unittest.TestCase):
    def test_alternating_failure_cannot_escape_quarantine(self):
        n=fixtures.node('a')
        for i,ok in enumerate([True,False]*3):observe(n,10000+i*30,ok)
        self.assertEqual(n['failures'],1)
        self.assertEqual(n['stability_reason'],'INTERMITTENT_FAILURE')
        self.assertFalse(eligible(n,10150));self.assertEqual(n['recovery_confirmations_required'],3)
    def test_flapping_failover_bypasses_healthy_dwell(self):
        a,b=fixtures.node('a'),fixtures.node('b');g={'selected':'a','selected_at':10140}
        for i,ok in enumerate([True,False]*3):
            observe(a,10000+i*30,ok);observe(b,10000+i*30)
        self.assertEqual(select(g,[a,b],10150,require_recent=True),'b')
        self.assertEqual(g['switch_count'],1)
    def test_one_failure_does_not_discard_current(self):
        a,b=fixtures.node('a'),fixtures.node('b');g={'selected':'a','selected_at':10000}
        observe(a,10000);observe(b,10000);observe(a,10015,False)
        self.assertEqual(select(g,[a,b],10015,require_recent=True),'a')
        self.assertFalse(a.get('recovery_required',False))
    def test_old_alternating_failures_do_not_quarantine_fresh_good_route(self):
        n=fixtures.node('a')
        for i,ok in enumerate([True,False]*2):observe(n,10000+i,ok)
        observe(n,10400);observe(n,10415,False)
        self.assertFalse(n.get('recovery_required',False))
    def test_flapping_recovery_needs_three_spaced_successes(self):
        n=fixtures.node('a')
        for i,ok in enumerate([True,False]*3):observe(n,10000+i*30,ok)
        at=n['cooldown_until'];observe(n,at);observe(n,at)
        self.assertEqual(n['recovery_successes'],1);self.assertFalse(eligible(n,at))
        observe(n,at+15);self.assertFalse(eligible(n,at+15))
        observe(n,at+30);self.assertTrue(eligible(n,at+30))
    def test_early_success_cannot_shorten_cooldown(self):
        n=fixtures.node('a');observe(n,10000,False);observe(n,10015,False)
        until=n['cooldown_until'];observe(n,10016);observe(n,10031)
        self.assertEqual(n['cooldown_until'],until);self.assertEqual(n['recovery_successes'],0)
    def test_failure_during_recovery_resets_success_count(self):
        n=fixtures.node('a');observe(n,10000,False);observe(n,10015,False)
        observe(n,10045);observe(n,10060,False)
        self.assertEqual(n['recovery_successes'],0);self.assertTrue(n['recovery_required'])
    def test_repeat_failure_is_soft_quality_not_hard_transport_failure(self):
        n=fixtures.node('a');observe(n,10000,repeat=False)
        self.assertTrue(eligible(n,10000));self.assertEqual(quality(n)['transport_rate'],1)
        self.assertEqual(quality(n)['rate'],0);self.assertEqual(quality(n)['repeat_failures'],1)
    def test_unknown_controller_measurement_never_penalizes_quality(self):
        n=fixtures.node('a');observe(n,10000,repeat=None)
        self.assertEqual(quality(n)['rate'],1);self.assertEqual(quality(n)['repeat_failures'],0)
    def test_reliable_slower_route_beats_fast_eighty_percent(self):
        a,b=fixtures.node('fast'),fixtures.node('steady')
        for i in range(10):observe(a,10000+i,ok=i not in (3,8),ms=100);observe(b,10000+i,ms=140)
        self.assertLess(rank(b),rank(a))
    def test_unstable_new_node_cannot_become_ready_backup_on_one_hit(self):
        a,b=fixtures.node('a'),fixtures.node('b');b['legacy_samples']=[];b['samples']=[]
        observe(a,10000);observe(b,10000);g={'selected':'a'}
        choose_backup(g,[a,b],10000)
        self.assertIsNone(g['backup']);self.assertEqual(g['backup_candidate'],'b')
        observe(b,10015);choose_backup(g,[a,b],10015);self.assertEqual(g['backup'],'b')
    def test_stale_backup_remains_verification_candidate(self):
        a,b=fixtures.node('a'),fixtures.node('b');observe(b,10000);g={'selected':'a'}
        choose_backup(g,[a,b],10091)
        self.assertIsNone(g['backup']);self.assertEqual(g['backup_candidate'],'b')
    def test_empty_selection_cannot_bypass_failover_confirmation(self):
        a,b=fixtures.node('a'),fixtures.node('b');g={'selected':'a'}
        observe(a,10000,False);observe(a,10015,False)
        b['legacy_samples']=[];b['samples']=[];observe(b,10015)
        self.assertIsNone(select(g,[a,b],10015,require_recent=True))
        self.assertIsNone(select(g,[a,b],10016,require_recent=True))
        observe(b,10030);self.assertEqual(select(g,[a,b],10030,require_recent=True),'b')
    def test_failed_recent_backup_is_not_ready(self):
        n=fixtures.node('a');observe(n,10000);observe(n,10015,False)
        self.assertFalse(standby_ready(n,10015));observe(n,10030)
        self.assertFalse(standby_ready(n,10030));observe(n,10045)
        self.assertTrue(standby_ready(n,10045))
    def test_ordinary_success_cannot_erase_unconfirmed_repeat_failure(self):
        n=fixtures.node('a');observe(n,10000,repeat=False)
        observe(n,10015);observe(n,10030)
        self.assertFalse(standby_ready(n,10030))
        observe(n,10045,repeat=True);self.assertTrue(standby_ready(n,10045))
    def test_fallback_wait_is_counted_in_connection_quality(self):
        n=fixtures.node('a')
        record_observation(n,{'ok':True,'request_ms':200,'connection_ms':5200,
                             'primary_target_failed':True},10000)
        self.assertEqual(quality(n)['median_ms'],5200)
        self.assertEqual(quality(n)['transport_rate'],1)

class StabilityProbeTests(unittest.TestCase):
    def setUp(self):
        mock=patch('app.socket.create_connection');mock.start();self.addCleanup(mock.stop)
    def probe(self,api):
        d=Dispatcher.__new__(Dispatcher);d.api=api
        with patch('app.request',return_value=(204,b'')):
            return d.probe_node({'proxy':{'name':'fixture'},'probe_port':12345})
    def test_completed_node_test_timeout_is_quality_evidence(self):
        for code in (503,504):
            with self.subTest(code=code):
                result=self.probe(lambda *a,**k:(_ for _ in ()).throw(RequestFailure('CONTROLLER_STATUS_'+str(code))))
                self.assertTrue(result['ok']);self.assertIs(result['repeat_request_ok'],False)
    def test_controller_transport_failure_is_not_node_evidence(self):
        result=self.probe(lambda *a,**k:(_ for _ in ()).throw(RequestFailure('TRANSPORT_FAILURE_28')))
        self.assertTrue(result['ok']);self.assertIsNone(result.get('repeat_request_ok'))
    def test_zero_or_missing_rtt_is_not_node_evidence(self):
        for value in (0,None):
            result=self.probe(lambda *a,**k:{'delay':value})
            self.assertIsNone(result['repeat_request_ok'])
    def test_good_repeat_is_preserved(self):
        self.assertTrue(self.probe(lambda *a,**k:{'delay':100})['repeat_request_ok'])

class StabilitySchedulerTests(unittest.TestCase):
    def setup(self):
        f=fixtures.SchedulerTests();d,s,c,e=f.setup(count=0);self.addCleanup(f.doCleanups)
        return d,s,c,e
    def test_ordinary_backup_checked_each_minute(self):
        d,s,c,e=self.setup();d.nodes[0]['last_checked_at']=c[0];d.nodes[1]['last_checked_at']=c[0]-61
        self.assertEqual(s._probe_due(c[0])[3]['id'],'b')
    def test_stale_backup_candidate_is_not_starved_as_background(self):
        d,s,c,e=self.setup();d.nodes[0]['last_checked_at']=c[0]
        d.state['groups']['dc-jp'].update(backup=None,backup_candidate='b')
        d.nodes[1]['last_checked_at']=c[0]-100
        self.assertEqual(s._probe_due(c[0])[3]['id'],'b')
    def test_repeat_failure_gets_fast_recheck(self):
        d,s,c,e=self.setup();observe(d.nodes[0],c[0]-16,repeat=False)
        self.assertEqual(s._probe_due(c[0])[3]['id'],'a')
    def test_primary_failure_queues_backup_verification(self):
        d,s,c,e=self.setup();s.tick();c[0]+=6;e.advance();s._complete(c[0])
        self.assertEqual(d.nodes[1].get('health_due_at'),c[0])

if __name__=='__main__':unittest.main()
