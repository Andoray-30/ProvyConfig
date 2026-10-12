import json,sys,time,unittest,tempfile
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from network_identity import from_body,kind,advertised_home,preference,pool_group,pool_eligible
from nodes import classify
from policy import select
from app import label,Dispatcher

class NetworkTests(unittest.TestCase):
    def node(self,ident,org,claimed=True,ms=150):
        country,evidence=from_body(json.dumps({'ip':'192.0.2.10','country':'HK','org':org}).encode(),now=10000)
        return {'id':ident,'group':'home3-hk','country':country,'source':'residential','rate':3,
                'advertised_residential':claimed,'network_identity':evidence,'samples':[ms]*3,'qualified_at':10000}
    def test_known_hosting_never_home(self):
        for asn in (197540,154177,205548,62240,26666,30058):
            n=self.node('a','AS'+str(asn)+' Hosting')
            self.assertEqual(kind(n,11000),'HOSTING');self.assertNotIn('家宽',label('home3-hk',n,11000))
    def test_isp_not_residential_certification(self):
        n=self.node('a','AS4760 HKT Limited');self.assertFalse(n['network_identity']['residential_proven'])
        self.assertEqual(label('home3-hk',n,11000),'香港｜3倍家宽候选')
        n['advertised_residential']=False;self.assertNotIn('家宽',label('home3-hk',n,11000))
    def test_unknown_and_expired_not_positive(self):
        n=self.node('a','AS999999 Unknown');self.assertEqual(kind(n,11000),'UNKNOWN')
        self.assertNotIn('家宽',label('home3-hk',n,11000))
        n=self.node('a','AS4760 HKT');self.assertEqual(kind(n,18000),'UNKNOWN')
        self.assertNotIn('家宽',label('home3-hk',n,18000))
    def test_declared_isp_preferred_over_fast_bgp(self):
        host=self.node('host','AS205548 ZOUTER',False,100);isp=self.node('isp','AS4760 HKT',True,200)
        self.assertEqual(pool_group(host,11000),'dc3-hk');self.assertFalse(pool_eligible(isp,11000))
        host['group']=pool_group(host,11000)
        self.assertIsNone(select({},[host],11000))
    def test_hosting_only_stays_available_honestly(self):
        n=self.node('host','AS205548 ZOUTER',False);g={}
        n['group']=pool_group(n,11000)
        self.assertIsNone(select(g,[n],11000));self.assertIn('机房',label('home3-hk',n,11000))
    def test_dc_unchanged(self):
        a=self.node('a','AS205548 ZOUTER',False,100);b=self.node('b','AS4760 HKT',True,200)
        for n in (a,b):n.update(source='datacenter',group='dc-hk')
        self.assertEqual(select({},[a,b],11000),'a');self.assertEqual(label('dc-hk',a,11000),'香港｜机房节点')
    def test_source_does_not_imply_home(self):
        base={'type':'vless','server':'example.test','port':443,'uuid':'dummy'}
        a,c=classify([dict(base,name='【3x】中转|香港BGP')],'residential')
        self.assertFalse(a[0]['advertised_residential'])
        b,c=classify([dict(base,name='【3x】中转|香港家宽')],'residential')
        self.assertTrue(b[0]['advertised_residential']);self.assertEqual(a[0]['id'],b[0]['id'])
    def test_aliases_and_early_high_rate_exclusion(self):
        base={'type':'vless','server':'example.test','port':443,'uuid':'dummy'}
        ns,c=classify([dict(base,name='【3x】中转|香港BGP'),dict(base,name='【3x】香港家宽')],'residential')
        self.assertEqual(len(ns),1);self.assertTrue(ns[0]['advertised_residential'])
        ns,c=classify([dict(base,name='【6x】香港家宽')],'residential');self.assertFalse(ns)
    def test_no_exit_ip_persisted(self):
        _,e=from_body(b'{"ip":"192.0.2.10","country":"HK","org":"AS4760 HKT"}')
        self.assertNotIn('192.0.2.10',json.dumps(e))
    def test_actual_exit_and_country_one_request(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/'secrets').mkdir();d=Dispatcher(root)
            n=self.node('a','AS205548 ZOUTER',False);n['proxy']={'name':'dummy'};d.nodes=[n]
            d.api=lambda *a,**kw:{};d.write_config=lambda:False
            with patch('app.request',return_value=(200,b'{"ip":"192.0.2.11","country":"HK","org":"AS4760 HKT"}')) as req:d.qualify()
            self.assertEqual(req.call_count,1);self.assertEqual(req.call_args.args[0],'https://my.ippure.com/v1/info')
            self.assertEqual(n['network_identity']['kind'],'ISP_NETWORK');self.assertEqual(n['country_result'],'MATCH')
    def test_failed_type_lookup_never_renews_old_type(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/'secrets').mkdir();d=Dispatcher(root)
            n=self.node('a','AS4760 HKT');n['proxy']={'name':'dummy'};d.nodes=[n]
            d.api=lambda *a,**kw:{};d.write_config=lambda:False
            with patch('app.request',return_value=(200,b'{"country":"HK"}')):d.qualify()
            self.assertNotIn('network_identity',n);self.assertEqual(n['country_result'],'UNREACHABLE')
    def test_public_residential_flag_and_hosting_conflict(self):
        body={'ip':'192.0.2.10','countryCode':'HK','asn':4760,'asOrganization':'HKT','isResidential':True}
        country,e=from_body(json.dumps(body).encode(),now=10000)
        self.assertEqual(country,'HK');self.assertEqual(e['kind'],'RESIDENTIAL_CLASSIFIED');self.assertFalse(e['residential_proven'])
        n={'network_identity':e};self.assertEqual(label('home3-hk',n,11000),'香港｜3倍家宽（IP检测）')
        body['isResidential']=False;e=from_body(json.dumps(body).encode(),now=10000)[1]
        self.assertEqual(e['kind'],'NON_RESIDENTIAL');self.assertNotIn('家宽候选',label('home3-hk',{'network_identity':e},11000))
        body.update(isResidential=True,asn=2514,asOrganization='Server Hosting Service(NTTPC)')
        e=from_body(json.dumps(body).encode(),now=10000)[1];self.assertEqual(e['kind'],'CONFLICT')
        self.assertNotIn('家宽',label('home3-jp',{'network_identity':e},11000))
    def test_omitted_flag_never_positive(self):
        _,e=from_body(b'{"ip":"192.0.2.10","countryCode":"HK","asn":4760,"asOrganization":"HKT"}',now=10000)
        self.assertEqual(e['kind'],'ISP_NETWORK');self.assertIsNone(e['residential_classified'])
    def test_failed_primary_has_bounded_fallback(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/'secrets').mkdir();d=Dispatcher(root)
            n=self.node('a','AS4760 HKT');n['proxy']={'name':'dummy'};d.nodes=[n]
            d.api=lambda *a,**kw:{};d.write_config=lambda:False
            from httpio import RequestFailure
            with patch('app.request',side_effect=[RequestFailure('TEST_TIMEOUT'),(200,b'{"ip":"192.0.2.10","country":"HK","org":"AS4760 HKT"}')]) as req:d.qualify()
            self.assertEqual(req.call_count,2);self.assertEqual(n['country_result'],'MATCH');self.assertIsNone(n['network_identity']['residential_classified'])
    def test_startup_replaces_unhealthy_same_fee_current(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/'secrets').mkdir();d=Dispatcher(root)
            a=self.node('a','AS4760 HKT');b=self.node('b','AS4760 HKT',ms=180)
            now=time.time()
            for n in (a,b):
                n['qualified_at']=now;n['network_identity'].update(checked_at=now,kind='RESIDENTIAL_CLASSIFIED')
            a.update(samples=[None,300,None,250,None],failures=1)
            d.nodes=[a,b];d.state['groups']={'home3-hk':{'selected':'a','selected_at':now}}
            d.load_network_evidence();self.assertEqual(d.state['groups']['home3-hk']['selected'],'b')
    def test_cache_upgrade_keeps_ids_tokens_and_bindings(self):
        from httpio import write_json
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/'secrets').mkdir();(root/'runtime').mkdir()
            proxy={'type':'vless','server':'example.test','port':443,'uuid':'dummy','name':'【3x】香港家宽'}
            ns,_=classify([proxy],'residential');n=ns[0];n.pop('advertised_residential')
            n.update(samples=[150]*3,qualified_at=time.time())
            write_json(root/'runtime/candidates.json',[n]);write_json(root/'runtime/state.json',{'groups':{'home3-hk':{'selected':n['id']}},'last_refresh':123,'last_sample':234})
            (root/'runtime/input-residential.txt').write_text('proxies:\n- '+json.dumps(proxy,ensure_ascii=False))
            access={'subscription':'dummy-token','controller':'dummy-secret','bindings':{'home3-hk':{'uuid':'existing-dummy','port':18452}}}
            write_json(root/'secrets/access.json',access)
            evidence=from_body(b'{"ip":"192.0.2.10","country":"HK","org":"AS4760 HKT"}')[1]
            write_json(root/'runtime/network-evidence.json',{n['id']:evidence})
            d=Dispatcher(root)
            self.assertEqual(d.access,access);self.assertEqual(d.nodes[0]['id'],n['id'])
            self.assertTrue(d.nodes[0]['advertised_residential']);self.assertEqual(d.nodes[0]['network_identity']['kind'],'ISP_NETWORK')
            self.assertEqual(d.state['last_refresh'],123);self.assertEqual(d.state['last_sample'],234)

if __name__=='__main__':unittest.main()
