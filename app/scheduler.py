"""Single routing owner, two fair workers, independent qualification recovery."""
import copy,json,time
from collections import deque,Counter
from concurrent.futures import ThreadPoolExecutor
from httpio import RequestFailure
from policy import (PRIMARY_SECONDS,BACKUP_SECONDS,SAMPLE_SECONDS,RECHECK_SECONDS,
                    RECOVERY_SECONDS,REFRESH_SECONDS,QUALIFICATION_TTL,record_observation)
from network_identity import pool_eligible,NETWORK_TTL

class AdaptiveScheduler:
    def __init__(self,dispatch,clock=time.time,executor=None):
        self.d=dispatch;self.clock=clock
        self.executor=executor or ThreadPoolExecutor(max_workers=2,thread_name_prefix='bounded-io')
        self.pending={};self.source_queue=deque();self.qualify_queue=deque();self.scan_queue=deque()
        self.refresh_active=False;self.completed_refresh=False;self.last_save=0;self.last_apply=0
        self.peak_pending=0;self.total_jobs=0;self.discarded_results=0
        self.scan_started=False;self.scan_results=Counter();self.round_qualified=set()
        self.qualification_started=False;self.background_turn=0
        self.control_failures=0;self.control_retry_at=0
        self.resume_round=((self.d.state.get('full_scan') or {}).get('phase')=='RUNNING' or
                           self.d.state.get('refresh_session_active',False) or
                           self.d.state.get('scheduler_schema')!=2)

    def _busy(self):
        return {job[1] for job in self.pending.values() if job[0]!='source'}

    def _begin_scan(self,now):
        self.scan_queue=deque(n['id'] for n in sorted(self.d.nodes,key=lambda n:n['id']))
        self.scan_started=True;self.scan_results=Counter();self.round_qualified=set()
        self.d.state['full_scan']={'started_at':now,'candidates':len(self.scan_queue),
                                  'phase':'RUNNING','results':{}}

    def _next_scan(self,now):
        busy=self._busy();indexed={n['id']:n for n in self.d.nodes}
        for _ in range(len(self.scan_queue)):
            ident=self.scan_queue.popleft();n=indexed.get(ident)
            if n is None:self.scan_results['REMOVED']+=1;continue
            if self.refresh_active and ident not in self.round_qualified:
                self.scan_queue.append(ident);continue
            if n.get('qualified_at',0)+QUALIFICATION_TTL<=now:
                self.scan_results['COUNTRY_UNQUALIFIED']+=1;continue
            if not pool_eligible(n,now):self.scan_results['TYPE_OR_TIER_EXCLUDED']+=1;continue
            if self.d.summary.get(n.get('source'),{}).get('fetch_status','PASS').startswith('FAIL'):
                self.scan_results['SOURCE_UNCONFIRMED']+=1;continue
            if ident in busy or n.get('cooldown_until',0)>now or n.get('probe_infra_retry_at',0)>now:
                self.scan_queue.append(ident);continue
            return n
        return None

    def _comparison_groups(self):
        if not self.refresh_active:return None
        unresolved=set(self.qualify_queue)|set(self.scan_queue)
        unresolved.update(job[1] for job in self.pending.values() if job[0] in ('qualification','scan'))
        blocked=set()
        for n in self.d.nodes:
            if n['id'] not in unresolved:continue
            country=n['country'].lower()
            if getattr(self.d,'hy2_candidate',lambda n:False)(n):blocked.add('hy-'+country)
            if n['source']=='datacenter':blocked.add('dc-'+country)
            else:
                rate=str(int(n['rate']))
                blocked.update(('home'+rate+'-'+country,('dc' if rate=='1' else 'dc'+rate)+'-'+country))
        return set(self.d.state['groups'])-blocked

    def _reconcile(self,now,compare=True):
        self.d.reconcile(compare=compare,now=now,compare_groups=self._comparison_groups())

    def _submit(self,kind,node=None,source=None,url=None):
        if kind=='source':future=self.executor.submit(self.d.fetch_source,source,url)
        elif kind=='qualification':future=self.executor.submit(self.d.qualify_node,copy.deepcopy(node))
        else:future=self.executor.submit(self.d.probe_node,copy.deepcopy(node))
        self.pending[future]=(kind,node['id'] if node else source,node.get('group') if node else None)
        self.total_jobs+=1;self.peak_pending=max(self.peak_pending,len(self.pending))

    def _complete(self,now):
        changed=False
        for future,job in list(self.pending.items()):
            if not future.done():continue
            del self.pending[future];kind,ident,group=job
            try:result=future.result()
            except Exception as e:
                if kind=='source':
                    summary=self.d.summary.setdefault(ident,{})
                    failures=min(5,summary.get('fetch_failures',0)+1)
                    summary.update(fetch_status='FAIL',failure_type=type(e).__name__,
                                   fetch_failures=failures,next_retry_at=now+min(300,30*2**(failures-1)))
                    changed=True;continue
                result={'reason':'CONTROL_UNAVAILABLE' if isinstance(e,RequestFailure) else 'UNREACHABLE'} if kind=='qualification' else {'ok':False,'failure_class':'REQUEST_FAILED'}
            if kind=='source':
                try:
                    self.d.accept_source(ident,result)
                    self.d.summary.setdefault(ident,{}).update(fetch_failures=0,next_retry_at=0)
                except Exception as e:
                    self.d.summary.setdefault(ident,{}).update(fetch_status='FAIL_CONFIG',next_retry_at=now+30)
                    self.d.health.update(last_refresh_failure=type(e).__name__)
                changed=True;continue
            node=next((n for n in self.d.nodes if n['id']==ident),None)
            if kind=='qualification':self.round_qualified.add(ident)
            if node is None or (kind in ('probe','scan') and node['group']!=group):
                if kind=='scan':self.scan_results['IDENTITY_OR_GROUP_CHANGED']+=1
                self.discarded_results+=1;continue
            if kind=='qualification':
                self.d.accept_qualification(node,result)
                node.setdefault('qualification_attempt_at',now)
                node.setdefault('qualification_next_at',now+(QUALIFICATION_TTL-900 if result['reason']=='MATCH' else 30))
                if result['reason']=='MATCH' and pool_eligible(node,now):node['health_due_at']=now
            else:
                if result.get('infrastructure_error'):
                    node['probe_infra_retry_at']=now+10
                    self.d.health['last_probe_infrastructure_failure']={'at':now,'node_id':ident,'code':result['failure_class']}
                    if kind=='scan':self.scan_queue.append(ident)
                    changed=True;continue
                node.pop('probe_infra_retry_at',None)
                record_observation(node,result,now);node.pop('health_due_at',None)
                if not result['ok'] or result.get('repeat_request_ok') is False:
                    for route,g in self.d.state['groups'].items():
                        if node['id']!=g.get('selected'):continue
                        backup=g.get('backup')
                        alternate=next((n for n in self.d.nodes if n['id']==backup),None)
                        if alternate:alternate['health_due_at']=now
                if kind=='scan':self.scan_results['PASS' if result['ok'] else 'FAIL']+=1
                self.d.state['last_sample']=now
                self._reconcile(now)
            changed=True
        return changed

    def _qualification_due(self,now):
        busy=self._busy();due=[]
        for n in self.d.nodes:
            if n['id'] in busy:continue
            if self.refresh_active and n['id'] not in self.round_qualified:continue
            if self.d.summary.get(n['source'],{}).get('fetch_status','PASS').startswith('FAIL'):continue
            evidence=n.get('network_identity') or {}
            expiry=n.get('qualified_at',0)+QUALIFICATION_TTL
            if n['source']=='residential':expiry=min(expiry,evidence.get('checked_at',0)+NETWORK_TTL)
            at=n.get('qualification_next_at',max(0,expiry-900))
            if at<=now:
                empty=(not self.d.state['groups'].get(n['group'],{}).get('selected') or
                       (getattr(self.d,'hy2',{}).get('enabled') and self.d.hy2_candidate(n) and
                        not self.d.state['groups'].get('hy-'+n['country'].lower(),{}).get('selected')))
                due.append((0 if empty else 1,at,n['id'],n))
        return min(due,key=lambda x:x[:3])[-1] if due else None

    def _probe_due(self,now):
        busy=self._busy();primaries={g.get('selected') for g in self.d.state['groups'].values()}
        backups={g.get('backup') or g.get('backup_candidate') for g in self.d.state['groups'].values()};due=[]
        for n in self.d.nodes:
            if n['id'] in busy or n.get('qualified_at',0)+QUALIFICATION_TTL<=now or not pool_eligible(n,now):continue
            if n.get('probe_infra_retry_at',0)>now:continue
            if n.get('cooldown_until',0)>now:continue
            if n['id'] in primaries:
                rows=n.get('observations',[])
                suspect=n.get('failures',0) or (rows and rows[-1].get('repeat_request_ok') is False)
                priority=0;interval=RECHECK_SECONDS if suspect else PRIMARY_SECONDS
            elif n['id'] in backups:priority=1;interval=PRIMARY_SECONDS
            elif (not self.d.state['groups'].get(n['group'],{}).get('selected') or
                  (getattr(self.d,'hy2',{}).get('enabled') and self.d.hy2_candidate(n) and
                   not self.d.state['groups'].get('hy-'+n['country'].lower(),{}).get('selected'))):
                priority=1;interval=RECOVERY_SECONDS if n.get('recovery_required') else PRIMARY_SECONDS
            elif n.get('recovery_required'):priority=2;interval=RECOVERY_SECONDS
            else:priority=3;interval=SAMPLE_SECONDS/2 if n['group'].startswith('home3-') else SAMPLE_SECONDS
            at=min(n.get('last_checked_at',0)+interval,n.get('health_due_at',float('inf')))
            if at<=now:
                # Aging may promote background health to recovery priority,
                # never ahead of a due active primary.
                effective=0 if priority==0 else (1 if priority==1 else max(2,priority-int((now-at)/60)))
                due.append((effective,at,n['id'],n))
        return min(due,key=lambda x:x[:3]) if due else None

    def _next_qualification(self):
        indexed={n['id']:n for n in self.d.nodes};busy=self._busy()
        for _ in range(len(self.qualify_queue)):
            ident=self.qualify_queue.popleft()
            if ident in busy:self.qualify_queue.append(ident);continue
            if ident in indexed:return indexed[ident]
            self.round_qualified.add(ident)
        return None

    def _background(self,now):
        if self.source_queue:
            source,url=self.source_queue.popleft();self._submit('source',source=source,url=url);return True
        if self.refresh_active and not self.qualification_started:
            selected={g.get('selected') for g in self.d.state['groups'].values()}
            ordered=sorted(self.d.nodes,key=lambda n:(n['id'] not in selected,n.get('rate')!=3,n['id']))
            self.qualify_queue=deque(n['id'] for n in ordered);self.qualification_started=True
            self._begin_scan(now)
        if self.refresh_active and self.scan_started and not self.qualify_queue and not self.scan_queue:
            # Close the finite round before scheduling unrelated retry work.
            # Otherwise continuously due qualification retries can keep a
            # fully assessed round RUNNING forever.
            self.d.state['full_scan'].update(phase='COMPLETE',finished_at=now,
                                           results=dict(self.scan_results),pending=0)
            self.d.state['last_refresh']=now;self.refresh_active=False;self.completed_refresh=True
            self.d.state['refresh_session_active']=False
            self.qualification_started=False;self.scan_started=False
        self.background_turn+=1
        if self.refresh_active:
            if self.background_turn%3==0:
                node=self._qualification_due(now)
                if node:self._submit('qualification',node=node);return True
            if self.background_turn%2==0:
                node=self._next_scan(now)
                if node:self._submit('scan',node=node);return True
            node=self._next_qualification()
            if node:self._submit('qualification',node=node);return True
            node=self._next_scan(now)
            if node:self._submit('scan',node=node);return True
            if not self.qualify_queue and not self.scan_queue:return False
        else:
            for source,summary in self.d.summary.items():
                if summary.get('fetch_status','PASS').startswith('FAIL') and summary.get('next_retry_at',0)<=now:
                    sources=json.loads((self.d.root/'secrets/providers.json').read_text())
                    if source in sources:self._submit('source',source=source,url=sources[source]);return True
        node=self._qualification_due(now)
        if node:self._submit('qualification',node=node);return True
        return False

    def _apply(self,now,changed):
        unsafe=not getattr(self.d,'actual_admission_safe',lambda at:True)(now)
        # Admission revocation is not ordinary retry traffic: neither a
        # controller backoff nor the five-second apply cadence may postpone it.
        if not unsafe and (now<self.control_retry_at or (not changed and now-self.last_apply<5)):return
        try:
            if getattr(self.d,'config_dirty',False):
                self.d.write_config();self.d.config_dirty=False
            self.d.apply_selections();self.last_apply=now
            self.control_failures=0;self.control_retry_at=0
        except RequestFailure as e:
            self.control_failures+=1
            self.control_retry_at=now+min(15,2**min(4,self.control_failures-1))
            code=str(e) if str(e).replace('_','').isalnum() else 'CONTROL_REQUEST_FAILED'
            self.d.health.update(last_control_failure={'at':now,'code':code[:96]},control_failures=self.control_failures)
            if not getattr(self.d,'actual_admission_safe',lambda at:True)(now):
                raise RequestFailure('CONTROL_HARD_REVOCATION_UNCONFIRMED')

    def tick(self):
        now=self.clock();changed=self._complete(now)
        self.d.reconcile(compare=False,now=now)
        if not self.refresh_active and (now-self.d.state.get('last_refresh',0)>=REFRESH_SECONDS
                                       or 'full_scan' not in self.d.state or self.resume_round):
            sources=json.loads((self.d.root/'secrets/providers.json').read_text())
            self.source_queue=deque(sources.items());self.refresh_active=True;self.resume_round=False
            self.d.state.update(scheduler_schema=2,refresh_session_active=True)
        while len(self.pending)<2:
            background_busy=any(job[0] in ('source','qualification','scan') for job in self.pending.values())
            if not background_busy and self._background(now):continue
            due=self._probe_due(now)
            if due:self._submit('probe',node=due[3]);continue
            break
        background_busy=any(job[0] in ('source','qualification','scan') for job in self.pending.values())
        if (self.refresh_active and self.scan_started and not self.source_queue and
                not self.qualify_queue and not self.scan_queue and not background_busy):
            self.d.state['full_scan'].update(phase='COMPLETE',finished_at=now,results=dict(self.scan_results),pending=0)
            self.d.state['last_refresh']=now;self.refresh_active=False;self.completed_refresh=True
            self.d.state['refresh_session_active']=False
            self.qualification_started=False;self.scan_started=False;changed=True
        self._reconcile(now)
        self._apply(now,changed)
        infra_pending=sum(n.get('probe_infra_retry_at',0)>0 for n in self.d.nodes)
        self.d.health.update(phase='DEGRADED' if self.control_failures or infra_pending else 'READY',updated_at=now,
                             probe_infrastructure_pending=infra_pending,
                             refresh_in_progress=self.refresh_active,inflight_jobs=len(self.pending),
                             peak_inflight_jobs=self.peak_pending,completed_jobs=self.total_jobs-len(self.pending),
                             discarded_results=self.discarded_results,pending_qualification=len(self.qualify_queue),
                             pending_sources=len(self.source_queue),control_failures=self.control_failures)
        if self.scan_started:self.d.state['full_scan'].update(results=dict(self.scan_results),pending=len(self.scan_queue))
        self.d.health['full_scan']=self.d.state.get('full_scan')
        if now-self.last_save>=5:self.d.save();self.last_save=now

    def close(self):
        for future in self.pending:future.cancel()
        self.executor.shutdown(wait=True,cancel_futures=True)
