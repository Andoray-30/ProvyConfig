import copy,json,sys,time,unittest
from pathlib import Path
from unittest.mock import patch
from collections import deque
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import test_adaptive as fixtures
from app import Dispatcher
from scheduler import AdaptiveScheduler
from policy import record_observation,select,eligible,quality
from network_identity import from_body,merge_evidence,pool_eligible
from httpio import RequestFailure

def evidence(ip='192.0.2.10',residential=True,now=10000,country='HK',asn=4760):
    body={'ip':ip,'countryCode':country,'asn':asn,'asOrganization':'HKT'}
    if residential is not None:body['isResidential']=residential
    return from_body(json.dumps(body).encode(),now=now)[1]

class EvidenceTests(unittest.TestCase):
    def test_same_exit_weak_does_not_erase_or_renew_strong(self):
        old=evidence();new=evidence(residential=None,now=10030)
        merged=merge_evidence(old,new,10030)
        self.assertEqual(merged,old);self.assertEqual(merged['checked_at'],10000)
    def test_new_exit_not_allowed_to_borrow_old_house_verdict(self):
        old=evidence();new=evidence(ip='192.0.2.11',residential=None,now=10030)
        self.assertEqual(merge_evidence(old,new,10030)['kind'],'ISP_NETWORK')
    def test_missing_legacy_exit_fingerprint_cannot_preserve_positive(self):
        old=evidence();old.pop('exit_fingerprint')
        self.assertEqual(merge_evidence(old,evidence(residential=None),10030)['kind'],'ISP_NETWORK')
    def test_no_raw_ip_in_metadata(self):
        e=evidence();self.assertNotIn('192.0.2.10',json.dumps(e));self.assertEqual(len(e['exit_fingerprint']),64)
    def test_expired_verdict_cannot_survive_weak_refresh(self):
        old=evidence();new=evidence(residential=None,now=18000)
        self.assertEqual(merge_evidence(old,new,18000),new)
    def test_explicit_nonhouse_country_and_asn_change_override(self):
        old=evidence()
        for new in (evidence(residential=False),evidence(residential=None,country='US'),evidence(residential=None,asn=154177)):
            self.assertEqual(merge_evidence(old,new,10030),new)

class BalancePolicyTests(unittest.TestCase):
    def observe(self,n,at,ms=100):
        record_observation(n,{'ok':ms is not None,'request_ms':ms,'delay_ms':ms},at)
    def test_reliability_can_promote_slightly_slower_after_confirmation(self):
        a,b=fixtures.node('a'),fixtures.node('b');g={'selected':'a','selected_at':9000}
        for i,ms in enumerate([100,None,100,100,None,100,100,None,100,100]):
            self.observe(a,9900+i,ms);self.observe(b,9900+i,120)
        for at in (10000,10060):
            self.observe(a,at);self.observe(b,at,120);select(g,[a,b],at,require_recent=True)
        self.assertEqual(g['selected'],'b');self.assertEqual(g['reason'],'SUSTAINED_RELIABILITY_IMPROVEMENT')
    def test_same_reliability_evidence_cannot_repeat_votes(self):
        a,b=fixtures.node('a'),fixtures.node('b');g={'selected':'a','selected_at':9000}
        for i,ms in enumerate([100,None,100,None,100,100,100,None,100,100]):
            self.observe(a,9990+i,ms);self.observe(b,9990+i,120)
        for _ in range(8):select(g,[a,b],10000,require_recent=True)
        self.assertEqual(g['selected'],'a');self.assertEqual(g['confirmations'],1)
    def test_no_reliability_switch_to_extremely_slow_route(self):
        a,b=fixtures.node('a'),fixtures.node('b');g={'selected':'a','selected_at':9000}
        # Test soft reliability promotion, not the newly confirmed hard flapping path.
        for i,ms in enumerate([100,None,100,100,None,100,100,None,100,100]):self.observe(a,9990+i,ms);self.observe(b,9990+i,2000)
        self.observe(a,10000);self.observe(b,10000,2000)
        select(g,[a,b],10000,require_recent=True);self.assertEqual(g['selected'],'a')
    def test_progressive_cooldown_and_spaced_recovery(self):
        n=fixtures.node('a');at=10000
        for duration in (30,60,120,240,300):
            self.observe(n,at,None);self.observe(n,at+15,None)
            self.assertEqual(n['cooldown_until'],at+15+duration)
            at=n['cooldown_until'];self.observe(n,at)
            self.assertFalse(eligible(n,at));self.observe(n,at+15)
            self.assertTrue(eligible(n,at+15));at+=30
    def test_no_cross_country_tier_type_migration_by_recovery(self):
        n=fixtures.node('a',group='home3-hk');n.update(source='residential',rate=3,network_identity=evidence(),qualified_at=10000)
        for at in (10000,10015,10045,10060):self.observe(n,at,None if at<10030 else 100)
        self.assertEqual(n['group'],'home3-hk');self.assertEqual(n['rate'],3)
        n['network_identity']=evidence(residential=False,now=10060)
        self.assertFalse(pool_eligible(n,10061))

class BalancedSchedulerTests(unittest.TestCase):
    def setup(self,refresh=False,count=0):
        fixture=fixtures.SchedulerTests();d,s,c,e=fixture.setup(count=count,refresh=refresh);self.addCleanup(fixture.doCleanups)
        d.accept_source=lambda *a:None
        return d,s,c,e
    def test_transient_control_error_does_not_exit_or_penalize_nodes(self):
        d,s,c,e=self.setup();d.reconcile(now=c[0]);before=copy.deepcopy(d.nodes)
        d.apply_selections=lambda:(_ for _ in ()).throw(RequestFailure('TRANSPORT_FAILURE_28'))
        s.tick();self.assertEqual(d.health['phase'],'DEGRADED');self.assertEqual(s.control_failures,1)
        self.assertEqual(d.nodes,before)
        d.apply_selections=lambda:None;c[0]+=2;e.advance();s.tick()
        self.assertEqual(d.health['phase'],'READY');self.assertEqual(s.control_failures,0)
    def test_hard_revoke_not_silently_retained_when_control_unavailable(self):
        d,s,c,e=self.setup();d.actual_admission_safe=lambda at:False
        d.apply_selections=lambda:(_ for _ in ()).throw(RequestFailure('TRANSPORT_FAILURE_28'))
        with self.assertRaisesRegex(RequestFailure,'CONTROL_HARD_REVOCATION'):s.tick()
    def test_hard_revoke_bypasses_control_retry_delay(self):
        d,s,c,e=self.setup();d.actual_admission_safe=lambda at:False
        s.control_retry_at=c[0]+15;s.last_apply=c[0]
        d.apply_selections=lambda:(_ for _ in ()).throw(RequestFailure('TRANSPORT_FAILURE_28'))
        with self.assertRaisesRegex(RequestFailure,'CONTROL_HARD_REVOCATION'):s.tick()
    def test_unknown_qualification_retried_without_source_refresh(self):
        d,s,c,e=self.setup();n=d.nodes[0];n['qualified_at']=0;n['qualification_next_at']=c[0]
        called=[];d.qualify_node=lambda node:(called.append(node['id']) or {'reason':'MATCH'})
        d.accept_qualification=lambda n,r:n.update(qualified_at=c[0],qualification_next_at=c[0]+6300)
        s.tick();c[0]+=6;e.advance();s.tick()
        self.assertIn(n['id'],called);self.assertFalse(s.refresh_active)
        self.assertTrue(any(job[0]=='probe' and job[1]==n['id'] for job in s.pending.values()))
    def test_qualification_renewal_scheduled_before_evidence_expires(self):
        d,s,c,e=self.setup();n=d.nodes[0];n['qualified_at']=c[0]-6400
        self.assertEqual(s._qualification_due(c[0])['id'],n['id'])
    def test_interrupted_full_round_restarts_coverage_not_wait_90_minutes(self):
        d,s,c,e=self.setup();d.state['full_scan']={'phase':'RUNNING','candidates':2}
        restarted=AdaptiveScheduler(d,clock=lambda:c[0],executor=e)
        restarted.tick();self.assertTrue(restarted.refresh_active)
    def test_first_upgrade_immediately_validates_new_round(self):
        d,s,c,e=self.setup();d.state.pop('scheduler_schema')
        restarted=AdaptiveScheduler(d,clock=lambda:c[0],executor=e)
        restarted.tick();self.assertTrue(restarted.refresh_active);self.assertTrue(d.state['refresh_session_active'])
    def test_restart_during_source_phase_cannot_lose_refresh_intent(self):
        d,s,c,e=self.setup();d.state['refresh_session_active']=True
        restarted=AdaptiveScheduler(d,clock=lambda:c[0],executor=e)
        restarted.tick();self.assertTrue(restarted.refresh_active)
    def test_due_retries_do_not_prevent_full_round_finishing(self):
        d,s,c,e=self.setup(refresh=True,count=8)
        d.qualify_node=lambda n:{'reason':'UNREACHABLE'}
        def accept(n,result):
            n.update(qualified_at=0,qualification_attempt_at=c[0],qualification_next_at=c[0]+30)
        d.accept_qualification=accept
        for _ in range(1600):
            e.advance();s.tick();c[0]+=.25
            if s.completed_refresh:break
        self.assertTrue(s.completed_refresh)
        scan=d.state['full_scan'];self.assertEqual(sum(scan['results'].values()),scan['candidates'])
        self.assertEqual(scan['results']['COUNTRY_UNQUALIFIED'],len(d.nodes))
        self.assertFalse(d.state['refresh_session_active'])
    def test_failed_source_has_short_retry_and_no_qualification_renewal(self):
        d,s,c,e=self.setup();d.summary={'datacenter':{'fetch_status':'FAIL','next_retry_at':c[0]}}
        calls=[];d.fetch_source=lambda *a:(calls.append(a[0]) or {'nodes':[],'counts':{},'body':b''})
        d.fetch_source.__name__='fetch_source';old=d.nodes[0]['qualified_at']
        s.tick();self.assertEqual(next(iter(s.pending.values()))[0],'source')
        c[0]+=26;e.advance();s.tick();self.assertEqual(calls,['datacenter'])
        self.assertEqual(d.nodes[0]['qualified_at'],old)
    def test_due_empty_pool_qualification_not_starved_by_full_scan(self):
        d,s,c,e=self.setup(refresh=True,count=10);events=[]
        first=d.nodes[0]
        def qualify(n):
            events.append(n['id']);return {'reason':'UNREACHABLE' if n['id']==first['id'] else 'MATCH'}
        def accept(n,res):
            n.update(qualified_at=0 if res['reason']=='UNREACHABLE' else c[0],qualification_next_at=c[0]+30)
        d.qualify_node=qualify;d.accept_qualification=accept;d.probe_node=lambda n:{'ok':True,'request_ms':100}
        for _ in range(600):e.advance();s.tick();c[0]+=.25
        self.assertGreaterEqual(events.count(first['id']),2);self.assertLessEqual(e.peak,2)
    def test_qualification_streams_to_quality_before_last_member_checked(self):
        d,s,c,e=self.setup(refresh=True,count=5);events=[]
        d.qualify_node=lambda n:(events.append(('qual',n['id'])) or {'reason':'MATCH'})
        d.accept_qualification=lambda n,r:n.update(qualified_at=c[0])
        d.probe_node=lambda n:(events.append(('probe',n['id'])) or {'ok':True,'request_ms':100})
        for _ in range(300):e.advance();s.tick();c[0]+=.25
        first_probe=next(i for i,x in enumerate(events) if x[0]=='probe' and x[1] in s.round_qualified)
        last_qual=max(i for i,x in enumerate(events) if x[0]=='qual')
        self.assertLess(first_probe,last_qual);self.assertLessEqual(e.peak,2)
    def test_completed_pool_not_held_by_other_country(self):
        d,s,c,e=self.setup();jp=d.nodes[0];us=fixtures.node('us',group='dc-us')
        d.nodes=[jp,us];d.state['groups']={'dc-jp':{},'dc-us':{}}
        s.refresh_active=True;s.scan_queue=deque([us['id']]);s.qualify_queue=deque()
        self.assertIn('dc-jp',s._comparison_groups());self.assertNotIn('dc-us',s._comparison_groups())
    def test_old_health_jobs_cannot_jump_a_due_primary(self):
        d,s,c,e=self.setup(count=20);d.nodes[0]['last_checked_at']=c[0]-61
        self.assertEqual(s._probe_due(c[0])[3]['id'],'a')

class BalancedProbeTests(unittest.TestCase):
    def setUp(self):
        mock=patch('app.socket.create_connection');mock.start();self.addCleanup(mock.stop)
    def test_target_specific_failure_can_use_independent_actual_success(self):
        d=Dispatcher.__new__(Dispatcher);n={'proxy':{'name':'fixture'},'probe_port':12345,'last_rtt_checked_at':time.time()}
        with patch('app.request',side_effect=[RequestFailure('TEST_TIMEOUT'),(204,b'')]) as req:
            result=d.probe_node(n)
        self.assertTrue(result['ok']);self.assertTrue(result['primary_target_failed']);self.assertEqual(result['health_target'],'SECONDARY')
        self.assertEqual(req.call_count,2)
    def test_two_failed_targets_not_rescued_by_cached_latency(self):
        d=Dispatcher.__new__(Dispatcher);n={'proxy':{'name':'fixture'},'probe_port':12345,'last_rtt_checked_at':time.time()}
        with patch('app.request',side_effect=[RequestFailure('TEST_TIMEOUT'),RequestFailure('TEST_TIMEOUT')]):
            self.assertFalse(d.probe_node(n)['ok'])
    def test_classification_change_does_not_rewrite_stable_selector_membership(self):
        fixture=fixtures.SchedulerTests();d,s,c,e=fixture.setup(count=0);self.addCleanup(fixture.doCleanups)
        n=d.nodes[0];n.update(country='HK',source='residential',rate=1,group='home1-hk')
        d.binding('home1-hk');d.binding('dc1-hk');before=d.config()
        n['group']='dc1-hk';after=d.config()
        self.assertEqual(before,after)
        members={g['name']:g['proxies'] for g in after['proxy-groups']}
        self.assertIn(n['proxy']['name'],members['home1-hk']);self.assertIn(n['proxy']['name'],members['dc-hk'])
        self.assertEqual(members['dc1-hk'],['dc-hk'])

if __name__=='__main__':unittest.main()
