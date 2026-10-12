import sys,time,json,tempfile,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from app import Dispatcher,country_from_body,label
from httpio import write_json

class AppTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
        (self.root/'secrets').mkdir();(self.root/'runtime').mkdir()
        self.d=Dispatcher(self.root)
        self.node={'id':'a','country':'JP','group':'dc-jp','source':'datacenter','rate':1,'qualified_at':time.time(),
                   'samples':[120,125,130], 'proxy':{'name':'n-a','type':'vless','server':'upstream.test','port':443,'uuid':'upstream-dummy'}}
        self.d.nodes=[self.node];self.d.state['groups']={'dc-jp':{'selected':'a','selected_at':time.time()}}
    def tearDown(self):self.tmp.cleanup()
    def test_direct_listener_mapping(self):
        c=self.d.config();listener=next(x for x in c['listeners'] if x['name']=='in-dc-jp')
        self.assertEqual(listener['proxy'],'dc-jp');self.assertEqual(listener['listen'],'127.0.0.1')
        self.assertEqual(c['rules'],['MATCH,REJECT'])
        self.assertEqual(c['proxy-groups'][1]['proxies'],['REJECT','n-a'])
    def test_profile_hides_upstream_and_no_automatic_cross_country(self):
        body=self.d.client_profile();self.assertNotIn(b'upstream.test',body);self.assertNotIn(b'upstream-dummy',body)
        import yaml
        p=yaml.safe_load(body);self.assertEqual(p['proxy-groups'][0]['type'],'select');self.assertEqual(len(p['proxies']),1)
        self.assertFalse(p['proxies'][0]['skip-cert-verify']);self.assertEqual(p['proxies'][0]['ws-opts']['path'],'/dispatch/dc-jp')
    def test_expired_reject(self):
        self.node['qualified_at']=0;c=self.d.config();self.assertEqual(c['proxy-groups'][1]['proxies'][0],'REJECT')
        with self.assertRaises(Exception):self.d.client_profile()
    def test_country_response(self):
        self.assertEqual(country_from_body(b'US\n'),'US');self.assertEqual(country_from_body(b'{"country":"JP"}'),'JP')
        with self.assertRaises(Exception):country_from_body(b'<html>')
    def test_labels(self):
        self.assertEqual(label('home1-us'),'美国｜普通未核实出口');self.assertEqual(label('home3-us'),'美国｜3倍未核实出口')
    def test_stable_binding_and_caddy_namespace(self):
        fragment=self.d.caddy_fragment();a=self.d.binding('dc-jp');new=Dispatcher(self.root)
        self.assertEqual(new.binding('dc-jp'),a);self.assertIn('/dispatch/home3-sg',fragment)
        self.assertNotIn(self.d.access['subscription'],fragment)
    def test_report_does_not_leak_identity(self):
        s=json.dumps(self.d.status());self.assertNotIn('upstream.test',s);self.assertNotIn('upstream-dummy',s)
        self.assertNotIn(self.d.access['controller'],s)

    def test_three_times_machine_is_withdrawn_but_other_tiers_remain(self):
        import copy,yaml
        now=time.time()
        for group,kind,rate in [('dc1-jp','CONFLICT',1),('dc3-jp','CONFLICT',3),('home3-hk','RESIDENTIAL_CLASSIFIED',3)]:
            n=copy.deepcopy(self.node);n.update(id=group,group=group,country=group.split('-')[1].upper(),source='residential',rate=rate,
                network_identity={'kind':kind,'checked_at':now},last_success_at=now)
            self.d.nodes.append(n);self.d.state['groups'][group]={'selected':n['id'],'selected_at':now}
        self.d.reconcile(now=now)
        self.assertIsNone(self.d.state['groups']['dc3-jp']['selected'])
        self.assertNotIn('dc1-jp',self.d.state['groups'])
        self.assertIsNotNone(self.d.state['groups']['dc-jp']['selected'])
        self.assertIsNotNone(self.d.state['groups']['home3-hk']['selected'])
        profile=yaml.safe_load(self.d.client_profile())
        paths=[p['ws-opts']['path'] for p in profile['proxies']]
        self.assertNotIn('/dispatch/dc3-jp',paths)
        self.assertIn('/dispatch/dc-jp',paths);self.assertNotIn('/dispatch/dc1-jp',paths);self.assertIn('/dispatch/home3-hk',paths)
        with self.assertRaises(Exception):self.d.client_profile('dc3')

if __name__=='__main__':unittest.main()
