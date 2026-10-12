import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import unittest
from nodes import name_country,multiplier,classify,parse_subscription
from policy import select,record_sample,score

class NodesTests(unittest.TestCase):
    def test_country(self):
        for name,code in [('🇯🇵 AWS日本01','JP'),('新加坡3','SG'),('美西','US'),('印度尼西亚','ID'),('HK01','HK'),('美国0.1倍率','US')]:
            self.assertEqual(name_country(name),code)
        self.assertIsNone(name_country('流量剩余'))
    def test_rates(self):
        for text,rate in [('美国',1),('US 3*',3),('JP ６＊',6),('10× 美国',10),('日本 [x3]',3),('6倍 香港',6)]:
            self.assertEqual(multiplier(text),rate)
    def test_excluded_before_probe(self):
        p={'name':'美国6*','type':'vless','server':'example.test','port':443,'uuid':'dummy'}
        ns,c=classify([p],'residential'); self.assertEqual(ns,[]);self.assertEqual(c['excluded_high_rate'],1)
    def test_stable_identity(self):
        p={'name':'日本1','type':'trojan','server':'example.test','port':443,'password':'dummy'}
        a,_=classify([p],'datacenter');p['name']='日本2';b,_=classify([p],'datacenter')
        self.assertEqual(a[0]['id'],b[0]['id'])
        p['password']='changed';c,_=classify([p],'datacenter');self.assertNotEqual(a[0]['id'],c[0]['id'])
    def test_yaml_and_uri(self):
        ns,e=parse_subscription(b'proxies:\n- {name: JP, type: vless, server: example.test, port: 443, uuid: dummy}\n')
        self.assertEqual(len(ns),1)
        ns,e=parse_subscription(b'vless://dummy@example.test:443?security=tls&type=ws&path=%2Fa#JP')
        self.assertEqual(ns[0]['ws-opts']['path'],'/a');self.assertFalse(ns[0]['skip-cert-verify'])

class PolicyTests(unittest.TestCase):
    def node(self,ident,ms=100): return {'id':ident,'samples':[ms]*3,'qualified_at':10000,'failures':0}
    def test_no_small_latency_chasing(self):
        g={'selected':'a','selected_at':10000};ns=[self.node('a',130),self.node('b',120)]
        for t in range(10001,15000,600): self.assertEqual(select(g,ns,t),'a')
    def test_material_improvement_needs_dwell_and_confirmation(self):
        g={'selected':'a','selected_at':10000};ns=[self.node('a',200),self.node('b',100)]
        for n in ns:n['last_checked_at']=10600
        self.assertEqual(select(g,ns,10600),'a')
        for n in ns:n['last_checked_at']=11200
        self.assertEqual(select(g,ns,11200),'a')
        for n in ns:n['last_checked_at']=11800
        self.assertEqual(select(g,ns,11800),'b')
    def test_failure_country_isolation(self):
        g={'selected':'a','selected_at':10000};a=self.node('a');b=self.node('b',140)
        record_sample(a,None);self.assertEqual(select(g,[a,b],10100),'a')
        record_sample(a,None);self.assertEqual(select(g,[a,b],10200),'b')
        record_sample(b,None);record_sample(b,None);self.assertIsNone(select(g,[a,b],10300))
    def test_expiry_and_removal(self):
        g={'selected':'a','selected_at':10000};self.assertIsNone(select(g,[self.node('a')],18000))
        g={'selected':'a'};self.assertEqual(select(g,[self.node('b')],11000),'b')
    def test_intermittent_majority_failure_not_sticky(self):
        a=self.node('a');a.update(samples=[None,2308,None,1280,None],failures=1)
        b=self.node('b',1696);g={'selected':'a','selected_at':10000}
        self.assertEqual(score(a),float('inf'));self.assertEqual(select(g,[a,b],11000),'b')
        c=self.node('c');c.update(samples=[100,110,105,None],failures=1)
        self.assertNotEqual(score(c),float('inf'))

if __name__=='__main__': unittest.main()
