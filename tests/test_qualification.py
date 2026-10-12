import sys,time,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from app import Dispatcher

class QualificationTests(unittest.TestCase):
    def run_country(self,body,old=0):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/'secrets').mkdir();(root/'runtime').mkdir()
            d=Dispatcher(root);d.nodes=[{'id':'dummy','group':'dc-jp','country':'JP','source':'datacenter','rate':1,
                                      'proxy':{'name':'dummy'},'qualified_at':old}]
            d.api=lambda *args,**kwargs:{};d.write_config=lambda:False
            with patch('app.request',return_value=(200,body)):d.qualify()
            return d.nodes[0]
    def test_country_match_renews(self):
        n=self.run_country(b'JP');self.assertGreater(n['qualified_at'],time.time()-2);self.assertEqual(n['country_result'],'MATCH')
    def test_country_mismatch_revokes(self):
        n=self.run_country(b'US',time.time());self.assertEqual(n['qualified_at'],0);self.assertEqual(n['country_result'],'MISMATCH')
    def test_failure_cannot_renew(self):
        old=time.time()-3600;n=self.run_country(b'error',old);self.assertEqual(n['qualified_at'],old)
    def test_unconfirmed_source_cannot_renew(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/'secrets').mkdir();(root/'runtime').mkdir()
            d=Dispatcher(root);old=time.time()-3600
            d.nodes=[{'id':'dummy','group':'dc-jp','country':'JP','source':'datacenter','proxy':{'name':'dummy'},'qualified_at':old}]
            d.summary={'datacenter':{'fetch_status':'FAIL'}};d.api=lambda *a,**kw:{};d.write_config=lambda:False
            with patch('app.request') as req:d.qualify()
            req.assert_not_called();self.assertEqual(d.nodes[0]['qualified_at'],old)
    def test_successful_empty_source_removes_nodes(self):
        from httpio import write_json
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/'secrets').mkdir();(root/'runtime').mkdir()
            write_json(root/'secrets/providers.json',{'datacenter':'https://example.test/no-secret'})
            d=Dispatcher(root);d.nodes=[{'id':'dummy','group':'dc-jp','country':'JP','source':'datacenter','proxy':{'name':'dummy'}}]
            d.write_config=lambda:False
            with patch('app.request',return_value=(200,b'proxies: []')):d.fetch()
            self.assertEqual(d.nodes,[])

if __name__=='__main__':unittest.main()
