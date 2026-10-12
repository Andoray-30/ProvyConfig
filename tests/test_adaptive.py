import copy,json,sys,tempfile,time,unittest
from pathlib import Path
from concurrent.futures import Future
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from app import Dispatcher,label
from network_identity import pool_group,pool_eligible
from policy import select,record_observation,metrics,eligible,score
from scheduler import AdaptiveScheduler
from httpio import write_json

def node(ident,ms=100,group='dc-jp',now=10000):
    return {'id':ident,'group':group,'country':group.split('-')[1].upper(),'source':'datacenter',
            'rate':1,'proxy':{'name':'n-'+ident,'type':'vless'},'samples':[ms]*3,
            'legacy_samples':[ms]*3,'qualified_at':now,'failures':0}

def observe(n,now,ms=100):
    record_observation(n,{'ok':ms is not None,'delay_ms':ms,'probe_wall_ms':200,'failure_class':None if ms else 'TEST'},now)

class AdaptivePolicyTests(unittest.TestCase):
    def test_conflict_becomes_machine_same_country_rate_identity(self):
        for rate in (1,3):
            n=node('same');n.update(source='residential',rate=rate,group='home'+str(rate)+'-jp',network_identity={'kind':'CONFLICT','checked_at':10000})
            old=copy.deepcopy(n['proxy']);n['group']=pool_group(n,10001)
            self.assertEqual(n['group'],('dc' if rate==1 else 'dc'+str(rate))+'-jp');self.assertEqual(pool_eligible(n,10001),rate==1);self.assertEqual(n['proxy'],old)
    def test_unknown_never_becomes_verified_house_or_machine(self):
        n=node('a');n.update(source='residential',group='home1-jp',network_identity={'kind':'UNKNOWN','checked_at':10000})
        self.assertEqual(pool_group(n,10001),'home1-jp');self.assertFalse(pool_eligible(n,10001))
    def test_machine_evidence_expiry_withdraws_not_house(self):
        n=node('a');n.update(source='residential',group='dc1-jp',network_identity={'kind':'CONFLICT','checked_at':10000})
        self.assertEqual(pool_group(n,18000),'dc-jp');self.assertFalse(pool_eligible(n,18000))
    def test_failure_bypasses_dwell_only_recent_backup(self):
        a,b=node('a'),node('b',140);g={'selected':'a','selected_at':10000}
        observe(a,10001,100);observe(b,10001,140)
        observe(a,10016,None);self.assertEqual(select(g,[a,b],10016,require_recent=True),'a')
        observe(a,10031,None);self.assertEqual(select(g,[a,b],10031,require_recent=True),'b')
        self.assertTrue(a['recovery_required']);self.assertEqual(a['cooldown_until'],10061)
    def test_stale_backup_is_not_trusted(self):
        a,b=node('a'),node('b');g={'selected':'a'}
        observe(a,10200,None);observe(a,10215,None);observe(b,10001)
        self.assertIsNone(select(g,[a,b],10215,require_recent=True))
    def test_recovery_requires_two_spaced_checks(self):
        n=node('a');observe(n,10001,None);observe(n,10016,None)
        observe(n,10046,100);self.assertFalse(eligible(n,10046))
        observe(n,10046,100);self.assertFalse(eligible(n,10046))
        observe(n,10061,100);self.assertTrue(eligible(n,10061))
    def test_same_evidence_cannot_count_three_confirmations(self):
        a,b=node('a',400),node('b',100);g={'selected':'a','selected_at':9000}
        observe(a,10001,400);observe(b,10001,100)
        for at in (10002,10003,10004):self.assertEqual(select(g,[a,b],at,require_recent=True),'a')
        self.assertEqual(g['confirmations'],1)
        for at in (10061,10121):
            observe(a,at,400);observe(b,at,100);select(g,[a,b],at,require_recent=True)
        self.assertEqual(g['selected'],'b')
    def test_small_crossing_never_switches(self):
        a,b=node('a',130),node('b',120);g={'selected':'a','selected_at':9000}
        for at in range(10000,11200,60):
            observe(a,at,130);observe(b,at,120);self.assertEqual(select(g,[a,b],at,require_recent=True),'a')
    def test_partial_failures_are_not_compressed_away(self):
        n=node('a');observe(n,10001,100);observe(n,10016,None);observe(n,10031,110)
        self.assertAlmostEqual(metrics(n)['success_rate'],2/3);self.assertEqual(metrics(n)['observations'],3)
        self.assertIsNone(metrics(n)['p95_ms'])
    def test_history_bound_and_p95_minimum(self):
        n=node('a')
        for at in range(10000,10100):observe(n,at,100)
        self.assertEqual(len(n['observations']),30);self.assertEqual(metrics(n)['p95_ms'],100)
    def test_mixed_measurement_modes_do_not_drive_switch(self):
        a,b=node('a',400),node('b',100);g={'selected':'a','selected_at':9000};observe(b,10001,100)
        for at in (10001,10061,10121):self.assertEqual(select(g,[a,b],at),'a')

class FakeExecutor:
    def __init__(self,clock):self.clock=clock;self.jobs=[];self.peak=0
    def submit(self,fn,*args):
        f=Future();name=fn.__name__;duration=25 if name=='fetch_source' else 5 if args[0]['id'].startswith('slow') or args[0]['id']=='a' else .1
        self.jobs.append((f,self.clock[0]+duration,fn,args));self.peak=max(self.peak,sum(not x[0].done() for x in self.jobs));return f
    def advance(self):
        for f,at,fn,args in self.jobs:
            if not f.done() and self.clock[0]>=at:
                try:f.set_result(fn(*args))
                except Exception as e:f.set_exception(e)
    def shutdown(self,**kwargs):pass

class SchedulerTests(unittest.TestCase):
    def setup(self,count=100,refresh=False):
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup)
        root=Path(tmp.name);(root/'secrets').mkdir();write_json(root/'secrets/providers.json',{'datacenter':'https://example.test'})
        d=Dispatcher(root);clock=[10000.0]
        a,b=node('a'),node('b',140);a['last_checked_at']=9940;b['last_checked_at']=9999;b['last_success_at']=9999
        d.nodes=[a,b]+[node('slow'+str(i),200) for i in range(count)]
        d.state={'scheduler_schema':2,'last_refresh':0 if refresh else 10000,'groups':{'dc-jp':{'selected':'a','backup':'b','selected_at':10000}}}
        if not refresh:d.state['full_scan']={'phase':'COMPLETE','finished_at':10000}
        d.apply_selections=lambda:None;d.save=lambda:None;d.write_config=lambda:False
        d.probe_node=lambda n:{'ok':n['id']=='b','delay_ms':140 if n['id']=='b' else None,'probe_wall_ms':100}
        d.fetch_source=lambda *a: {'nodes':[],'counts':{},'body':b''}
        d.fetch_source.__name__='fetch_source'
        executor=FakeExecutor(clock);s=AdaptiveScheduler(d,clock=lambda:clock[0],executor=executor)
        return d,s,clock,executor
    def test_busy_pool_failover_under_90_seconds_two_workers(self):
        d,s,clock,e=self.setup();start=clock[0];switched=None
        # Failure starts immediately after a successful check: include the 60s cadence.
        d.nodes[0]['last_checked_at']=start
        for _ in range(400):
            e.advance();s.tick()
            if d.state['groups']['dc-jp']['selected']=='b':switched=clock[0]-start;break
            clock[0]+=.25
        self.assertIsNotNone(switched);self.assertLessEqual(switched,90);self.assertLessEqual(e.peak,2)
        self.assertLessEqual(len(s.pending),2)
    def test_source_stall_does_not_block_primary(self):
        d,s,clock,e=self.setup(count=1,refresh=True)
        # Avoid accepting the dummy fetch before recording failover.
        d.accept_source=lambda *a:None
        for _ in range(120):e.advance();s.tick();clock[0]+=.25
        self.assertEqual(d.state['groups']['dc-jp']['selected'],'b');self.assertLessEqual(e.peak,2)
    def test_removal_discards_inflight_result(self):
        d,s,clock,e=self.setup(count=0);s.tick();d.nodes=[n for n in d.nodes if n['id']!='a']
        clock[0]+=6;e.advance();s.tick();self.assertGreaterEqual(s.discarded_results,1)
    def test_expiry_rejects_without_completed_workers(self):
        d,s,clock,e=self.setup(count=0)
        for n in d.nodes:n['qualified_at']=0
        s.tick();self.assertIsNone(d.state['groups']['dc-jp']['selected'])
    def test_fixed_config_no_reload_on_evidence_renewal_or_selection(self):
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup);root=Path(tmp.name);d=Dispatcher(root)
        a,b=node('a',now=time.time()),node('b',now=time.time());d.nodes=[a,b]
        d.state['groups']={'dc-jp':{'selected':'a'}};first=d.config()
        d.state['groups']['dc-jp']['selected']='b';a['qualified_at']+=10
        self.assertEqual(first,d.config());self.assertEqual(first['rules'],['MATCH,REJECT'])
    def test_old_bindings_ports_and_caddy_are_preserved(self):
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup);d=Dispatcher(Path(tmp.name))
        old=copy.deepcopy(d.binding('home1-jp'));text=d.caddy_fragment()
        self.assertEqual(d.binding('home1-jp'),old);self.assertIn('/dispatch/dc1-jp',text)
        ports=[d.port_for(t+'-'+c.lower()) for c in __import__('nodes').COUNTRIES for t in ('dc','home1','home3','dc1','dc3')]
        self.assertEqual(len(ports),len(set(ports)))

    def test_continuously_due_health_does_not_starve_source(self):
        d,s,clock,e=self.setup(count=0,refresh=True);accepted=[]
        d.nodes=[];d.state['groups']={}
        for i,c in enumerate(list(__import__('nodes').COUNTRIES)[:30]):
            n=node('slow'+str(i),group='dc-'+c.lower());d.nodes.append(n)
            d.state['groups'][n['group']]={'selected':n['id'],'selected_at':10000}
        d.probe_node=lambda n:{'ok':True,'delay_ms':100,'request_ms':100,'probe_wall_ms':100}
        d.accept_source=lambda source,result:accepted.append(source)
        d.qualify_node=lambda n:{'reason':'MATCH','country':n['country'],'evidence':None}
        d.accept_qualification=lambda *a:None
        for _ in range(121):e.advance();s.tick();clock[0]+=.5
        self.assertTrue(accepted);self.assertLessEqual(e.peak,2)

    def test_refresh_keeps_existing_probe_bindings_on_insertion(self):
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup);d=Dispatcher(Path(tmp.name))
        d.nodes=[node('b',now=time.time()),node('c',now=time.time())];d.config()
        ports={n['id']:n['probe_port'] for n in d.nodes}
        d.nodes.append(node('a',now=time.time()));d.config()
        for n in d.nodes:
            if n['id'] in ports:self.assertEqual(n['probe_port'],ports[n['id']])

if __name__=='__main__':unittest.main()
