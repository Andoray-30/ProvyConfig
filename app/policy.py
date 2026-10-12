"""One selection owner: confirmed failover, bounded histories and sticky quality."""
import math
import statistics
from network_identity import pool_eligible

DWELL_SECONDS=600
QUALIFICATION_TTL=7200
REFRESH_SECONDS=5400
SAMPLE_SECONDS=600
PRIMARY_SECONDS=60
BACKUP_SECONDS=90
RECHECK_SECONDS=15
COOLDOWN_SECONDS=300
RECOVERY_SECONDS=15
RECOVERY_CONFIRMATIONS=2
RELIABILITY_DWELL_SECONDS=120
RTT_SECONDS=180
QUALITY_WINDOW=10
FLAP_WINDOW_SECONDS=360
FLAP_SAMPLES=6
FLAP_FAILURES=3

def recent_flaps(node,now):
    epoch=node.get('last_recovered_at',0)
    rows=[r for r in node.get('observations',[]) if
          max(epoch,now-FLAP_WINDOW_SECONDS)<r['at']<=now][-FLAP_SAMPLES:]
    return len(rows)>=FLAP_SAMPLES and sum(not r.get('ok') for r in rows)>=FLAP_FAILURES

def record_sample(node, milliseconds):
    history=node.setdefault('samples',[])
    history.append(milliseconds);del history[:-6]
    node['failures']=node.get('failures',0)+1 if milliseconds is None else 0

def record_observation(node, result, now):
    observations=node.setdefault('observations',[])
    row={'at':now,'ok':bool(result['ok']),'delay_ms':result.get('delay_ms'),
         'probe_wall_ms':result.get('probe_wall_ms'),'failure_class':result.get('failure_class'),
         'request_ms':result.get('request_ms'),'http_status':result.get('http_status'),
         'measurement_mode':'UNIFIED_DELAY_AND_ACTUAL_204',
         'health_target':result.get('health_target'),
         'repeat_request_ok':result.get('repeat_request_ok'),
         'connection_ms':result.get('connection_ms'),
         'primary_target_failed':result.get('primary_target_failed',False)}
    observations.append(row);del observations[:-30]
    node['last_checked_at']=now
    if result.get('rtt_checked_at') is not None:
        node['last_rtt_checked_at']=result['rtt_checked_at']
    record_sample(node,(row['delay_ms'] or row['request_ms']) if row['ok'] else None)
    if row['ok']:node['failures']=0
    if row['ok']:
        node['last_success_at']=now
        if node.get('recovery_required'):
            if now<node.get('cooldown_until',0):return
            if now-node.get('last_recovery_success_at',0)>=RECOVERY_SECONDS:
                node['recovery_successes']=node.get('recovery_successes',0)+1
                node['last_recovery_success_at']=now
            if node['recovery_successes']>=node.get('recovery_confirmations_required',RECOVERY_CONFIRMATIONS):
                node['recovery_required']=False
                node['cooldown_until']=0
                node['last_recovered_at']=now
                node['stability_reason']='RECOVERED'
        elif node.get('incident_level',0) and now-node.get('last_incident_at',now)>=600:
            node['incident_level']=0
    else:
        node['recovery_successes']=0
        flap=recent_flaps(node,now)
        if node.get('failures',0)>=2 or flap:
            level=min(5,node.get('incident_level',0)+1)
            node.update(cooldown_until=now+min(COOLDOWN_SECONDS,30*2**(level-1)),
                        recovery_required=True,incident_level=level,last_incident_at=now,
                        last_recovery_success_at=0,
                        recovery_confirmations_required=max(node.get('recovery_confirmations_required',2),3 if flap else 2),
                        stability_reason='INTERMITTENT_FAILURE' if flap else 'CONSECUTIVE_FAILURE')

def metrics(node):
    rows=node.get('observations',[])
    good=[r['delay_ms'] for r in rows if r.get('ok') and isinstance(r.get('delay_ms'),(float,int))]
    legacy=[v for v in node.get('samples',[]) if v is not None]
    delays=good if rows else legacy
    ordered=sorted(good)
    requests=sorted(r['request_ms'] for r in rows if r.get('ok') and r.get('request_ms') is not None)
    return {'observations':len(rows),'success_rate':sum(bool(r.get('ok')) for r in rows)/len(rows) if rows else None,
            'median_ms':statistics.median(delays) if delays else None,
            'tail_ms':ordered[max(0,math.ceil(.9*len(ordered))-1)] if ordered else None,
            'p95_ms':ordered[math.ceil(.95*len(ordered))-1] if len(ordered)>=20 else None,
            'measurement_mode':'UNIFIED_DELAY_AND_ACTUAL_204' if rows else 'LEGACY_HANDSHAKE_INCLUDED',
            'last_checked_at':node.get('last_checked_at'),'rtt_checked_at':node.get('last_rtt_checked_at'),
            'last_probe_wall_ms':rows[-1].get('probe_wall_ms') if rows else None,
            'request_median_ms':statistics.median(requests) if requests else None,
            'request_tail_ms':requests[math.ceil(.9*len(requests))-1] if requests else None,
            'request_p95_ms':requests[math.ceil(.95*len(requests))-1] if len(requests)>=20 else None}

def score(node):
    if node.get('failures',0)>=2 or node.get('recovery_required'):return float('inf')
    rows=node.get('observations',[])
    samples=[(r.get('delay_ms') or r.get('request_ms')) if r.get('ok') else None for r in rows] if rows else node.get('samples',[])
    good=[x for x in samples if x is not None]
    if not good and rows:good=[x for x in node.get('legacy_samples',[]) if x is not None]
    if not good:return float('inf')
    failed=len(samples)-sum(x is not None for x in samples)
    if len(samples)>=4 and samples[-1] is None and failed>=len(samples)/2:return float('inf')
    return statistics.median(good)*(1+failed/max(1,len(samples))*2)

def eligible(node, now):
    return (node.get('qualified_at',0)+QUALIFICATION_TTL>now and pool_eligible(node,now)
            and node.get('cooldown_until',0)<=now and score(node)!=float('inf'))

def quality(node):
    """Recent quality for choosing; full bounded history remains in status."""
    rows=node.get('observations',[])[-QUALITY_WINDOW:]
    successful=[r for r in rows if r.get('ok') and r.get('repeat_request_ok') is not False]
    requests=sorted(r.get('connection_ms') or r['request_ms'] for r in rows if r.get('ok') and
                    isinstance(r.get('connection_ms') or r.get('request_ms'),(int,float)))
    if not requests:
        delays=[r['delay_ms'] for r in successful if isinstance(r.get('delay_ms'),(int,float))]
        requests=sorted(delays or [x for x in node.get('samples',[]) if x is not None])
    rate=len(successful)/len(rows) if rows else sum(x is not None for x in node.get('samples',[]))/max(1,len(node.get('samples',[])))
    median=statistics.median(requests) if requests else None
    tail=requests[max(0,math.ceil(.9*len(requests))-1)] if requests else None
    repeats=[r['repeat_request_ok'] for r in rows if isinstance(r.get('repeat_request_ok'),bool)]
    stable=not rows or (len(rows)>=3 and all(r.get('ok') and r.get('repeat_request_ok') is not False for r in rows[-3:])
                       and (not repeats or repeats[-1]))
    cost=(.75*median+.25*tail)*(1+2*(1-rate)) if requests else float('inf')
    return {'rate':rate,'median_ms':median,'tail_ms':tail,'stable':stable,'cost':cost,'samples':len(rows),
            'transport_rate':sum(bool(r.get('ok')) for r in rows)/len(rows) if rows else rate,
            'repeat_checks':len(repeats),'repeat_failures':sum(not x for x in repeats)}

def rank(node):
    q=quality(node)
    # Avoid choosing a fast but mostly failing route. Within the reliable class,
    # a single old failure cannot outrank every material performance advantage.
    return (q['rate']<.9,q['cost'],score(node),node['id'])

def standby_ready(node,now):
    if node.get('last_success_at',0)+BACKUP_SECONDS<=now:return False
    rows=node.get('observations',[])
    repeats=[r['repeat_request_ok'] for r in rows[-QUALITY_WINDOW:] if isinstance(r.get('repeat_request_ok'),bool)]
    if repeats and not repeats[-1]:return False
    if rows and not (rows[-1].get('ok') and rows[-1].get('repeat_request_ok') is not False):return False
    if len(rows)>=2:return all(r.get('ok') and r.get('repeat_request_ok') is not False for r in rows[-2:])
    # Existing cache may supply history; a newly discovered one-hit node cannot.
    legacy=node.get('legacy_samples') or []
    return len(legacy)>=3 and all(x is not None for x in legacy[-3:])

def choose_backup(group,nodes,now):
    candidates=sorted((n for n in nodes if n['id']!=group.get('selected') and eligible(n,now)),key=rank)
    available=[n for n in candidates if standby_ready(n,now)]
    group['backup']=available[0]['id'] if available else None
    group['backup_candidate']=None if available or not candidates else candidates[0]['id']
    return available[0] if available else None

def select(group,nodes,now, *, require_recent=False, compare=True):
    valid=sorted((n for n in nodes if eligible(n,now)),key=rank)
    current=next((n for n in valid if n['id']==group.get('selected')),None)
    if current is None:
        previous=group.get('selected')
        failover=bool(previous or group.get('failover_pending'))
        best=next((n for n in valid if (not require_recent or n.get('last_success_at',0)+BACKUP_SECONDS>now)
                   and (not failover or not require_recent or standby_ready(n,now))),None)
        group.update(selected=best['id'] if best else None,reason='INITIAL_OR_FAILURE' if best else 'NO_VERIFIED_HEALTHY_NODE',
                     challenger=None,confirmations=0,comparison=None,failover_pending=failover and best is None)
        if best:group['selected_at']=now
        if previous and previous!=group['selected']:group['switch_count']=group.get('switch_count',0)+1
        choose_backup(group,nodes,now)
        return group['selected']
    cq=quality(current)
    # Reliability is a separate decision, not contingent on a latency win.
    reliable=[n for n in valid if n['id']!=current['id'] and
              quality(n)['samples']>=5 and cq['samples']>=5 and quality(n)['stable'] and
              quality(n)['rate']>=.9 and quality(n)['rate']-cq['rate']>=.19 and
              quality(n)['median_ms'] is not None and cq['median_ms'] is not None and
              quality(n)['median_ms']<=cq['median_ms']*2]
    best=min(reliable,key=rank) if reliable else valid[0]
    if compare and best['id']!=current['id']:
        cm,bm=metrics(current),metrics(best)
        cq,bq=quality(current),quality(best)
        rates_ok=bq['rate']>=.8 and bq['rate']+1/QUALITY_WINDOW+1e-9>=cq['rate']
        c,b=cq['median_ms'],bq['median_ms']
        tail_ok=bq['tail_ms'] is not None and cq['tail_ms'] is not None and bq['tail_ms']<=cq['tail_ms']*1.1
        speed=(cm['measurement_mode']==bm['measurement_mode'] and rates_ok and tail_ok and
                     bq['cost']<=cq['cost']*.75 and b is not None and c is not None and b<=c*.75 and c-b>=40)
        reliability=bool(reliable and best in reliable)
        significant=reliability or speed
        fresh=(not require_recent or (best.get('last_success_at',0)+BACKUP_SECONDS>now and current.get('last_success_at',0)+BACKUP_SECONDS>now))
        pair=(current.get('last_checked_at'),best.get('last_checked_at'));old=group.get('comparison')
        if significant and fresh:
            mode='RELIABILITY' if reliability else 'SPEED'
            if group.get('challenger')!=best['id'] or group.get('challenge_mode')!=mode:
                group.update(challenger=best['id'],challenge_mode=mode,confirmations=0,comparison=None);old=None
            if old is None or (pair[0]!=old[0] and pair[1]!=old[1]):
                group['confirmations']=group.get('confirmations',0)+1;group['comparison']=list(pair)
            confirmations=2 if reliability else 3
            dwell=RELIABILITY_DWELL_SECONDS if reliability else DWELL_SECONDS
            if bq['stable'] and group['confirmations']>=confirmations and now-group.get('selected_at',now)>=dwell:
                group.update(selected=best['id'],selected_at=now,
                             reason='SUSTAINED_RELIABILITY_IMPROVEMENT' if reliability else 'SUSTAINED_MATERIAL_IMPROVEMENT',
                             challenger=None,confirmations=0,comparison=None)
                group['switch_count']=group.get('switch_count',0)+1
        else:group.update(challenger=None,confirmations=0,comparison=None,reason='HEALTHY_WINNER_RETAINED')
    choose_backup(group,nodes,now)
    return group['selected']
