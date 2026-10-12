import copy,sys,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import test_adaptive as fixtures
from policy import record_observation

class FullPoolTests(unittest.TestCase):
    def setup(self,count=25):
        f=fixtures.SchedulerTests();d,s,clock,e=f.setup(count=count,refresh=True);self.addCleanup(f.doCleanups)
        d.accept_source=lambda *a:None
        d.qualify_node=lambda n:{'reason':'MATCH','country':n['country']}
        d.accept_qualification=lambda n,result:n.update(qualified_at=clock[0])
        calls=[]
        d.probe_node=lambda n:(calls.append(n['id']) or {'ok':True,'delay_ms':100,'request_ms':100})
        return d,s,clock,e,calls
    def run_until_complete(self,s,clock,e,maximum=8000):
        for _ in range(maximum):
            e.advance();s.tick();clock[0]+=.25
            if s.completed_refresh:return
        self.fail('full refresh did not finish')
    def test_entire_pool_after_refresh_no_top_two_or_three_cap(self):
        d,s,c,e,calls=self.setup(count=25);expected={n['id'] for n in d.nodes}
        self.run_until_complete(s,c,e)
        scan=d.state['full_scan'];self.assertEqual(scan['phase'],'COMPLETE')
        self.assertEqual(scan['results']['PASS'],len(expected))
        self.assertTrue(expected <= set(calls));self.assertLessEqual(e.peak,2)
        self.assertEqual(s.d.health['full_scan']['phase'],'COMPLETE')
    def test_removed_and_ineligible_members_accounted_not_silently_ignored(self):
        d,s,c,e,calls=self.setup(count=0)
        a,b=d.nodes;a.update(source='residential',rate=3,group='dc3-jp',network_identity={'kind':'HOSTING','checked_at':c[0]})
        d.state['groups']={};s._begin_scan(c[0]);s.scan_queue.append('removed')
        nxt=s._next_scan(c[0]);self.assertEqual(nxt['id'],b['id'])
        self.assertEqual(s.scan_results['TYPE_OR_TIER_EXCLUDED'],1)
        self.assertIsNone(s._next_scan(c[0]));self.assertEqual(s.scan_results['REMOVED'],1)
    def test_cooldown_deferred_not_revived_and_eventually_tested(self):
        d,s,c,e,calls=self.setup(count=0);n=d.nodes[0]
        n['cooldown_until']=c[0]+300;s._begin_scan(c[0])
        self.assertEqual(s._next_scan(c[0])['id'],d.nodes[1]['id'])
        self.assertIsNone(s._next_scan(c[0]));self.assertIn(n['id'],s.scan_queue)
        c[0]+=301;self.assertEqual(s._next_scan(c[0])['id'],n['id'])
    def test_failing_health_score_does_not_remove_from_scan(self):
        d,s,c,e,calls=self.setup(count=0);n=d.nodes[0]
        n.update(failures=4,recovery_required=True,cooldown_until=c[0]-1)
        s._begin_scan(c[0]);self.assertEqual(s._next_scan(c[0])['id'],n['id'])
    def test_failed_source_not_claimed_fresh_full_test(self):
        d,s,c,e,calls=self.setup(count=0);d.summary['datacenter']={'fetch_status':'FAIL'}
        s._begin_scan(c[0]);self.assertIsNone(s._next_scan(c[0]))
        self.assertEqual(s.scan_results['SOURCE_UNCONFIRMED'],2)
    def test_first_upgrade_runs_fresh_round_without_waiting_90_minutes(self):
        d,s,c,e,calls=self.setup(count=0)
        d.state['last_refresh']=c[0]
        s.tick();self.assertTrue(s.refresh_active)
        self.run_until_complete(s,c,e);self.assertEqual(d.state['full_scan']['results']['PASS'],2)

if __name__=='__main__':unittest.main()
