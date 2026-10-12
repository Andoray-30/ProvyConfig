import copy,ipaddress,json,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
from httpio import atomic
from rule_update import prefixes,google_services,refresh,SOURCES,BEHAVIORS
from client_routing import settings,rule_body,bundle_revision

class DynamicRulesTests(unittest.TestCase):
    def test_google_subtracts_customer_cloud_not_all_cloud_proxy(self):
        own=[ipaddress.ip_network('8.8.0.0/16'),ipaddress.ip_network('2001:4860::/32')]
        cloud=[ipaddress.ip_network('8.8.0.0/17'),ipaddress.ip_network('2001:4860::/33')]
        result=google_services(own,cloud)
        self.assertEqual(set(map(str,result)),{'8.8.128.0/17','2001:4860:8000::/33'})
        self.assertFalse(any(ipaddress.ip_address('8.8.8.8') in n for n in result if n.version==4))
    def test_invalid_or_empty_google_source_rejected(self):
        for body in (b'{}',b'{"prefixes":[]}',b'{"prefixes":[{"ipv4Prefix":"0.0.0.0/0"}]}'):
            with self.assertRaises((KeyError,ValueError)):prefixes(body)
    def test_versioned_urls_and_dns_google_priority(self):
        cfg=settings('fixture','0123456789abcdef');p=cfg['rule-providers']
        self.assertTrue(all('/rules/0123456789abcdef/' in row['url'] for row in p.values()))
        self.assertTrue(all('/0123456789abcdef/' in row['path'] for row in p.values()))
        self.assertLess(cfg['rules'].index('RULE-SET,google-ip,出口选择,no-resolve'),cfg['rules'].index('RULE-SET,cn-ip,DIRECT'))
        keys=list(cfg['dns']['nameserver-policy'])
        self.assertLess(keys.index('rule-set:google-domain'),keys.index('rule-set:cn-domain'))
        self.assertTrue(cfg['sniffer']['parse-pure-ip']);self.assertFalse(cfg['sniffer']['override-destination'])
        self.assertFalse(any('39.104.106.33' in r for r in cfg['rules']))
    def test_revision_reader_and_path_restrictions(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);rules=root/'rules';rules.mkdir();bundle=rules/'bundles/0123456789abcdef';bundle.mkdir(parents=True)
            atomic(bundle/'cn-ip.mrs',b'fixture');atomic(rules/'current.json',b'{"revision":"0123456789abcdef"}')
            self.assertEqual(bundle_revision(root),'0123456789abcdef');self.assertEqual(rule_body(root,'cn-ip'),b'fixture')
            with self.assertRaises(ValueError):rule_body(root,'cn-ip','../secrets')
            with self.assertRaises(ValueError):settings('fixture','../../')
    def fixtures(self):
        bodies={url:bytes.fromhex('28b52ffd')+name.encode() for name,url in SOURCES.items()}
        bodies[SOURCES['google-owned']]=b'{"prefixes":[{"ipv4Prefix":"8.8.0.0/16"}]}'
        bodies[SOURCES['google-cloud']]=b'{"prefixes":[{"ipv4Prefix":"8.8.0.0/17"}]}'
        return bodies
    def test_atomic_complete_refresh_and_failure_keeps_old(self):
        bodies=self.fixtures()
        def compiler(args,**kwargs):
            atomic(Path(args[-1]),bytes.fromhex('28b52ffd')+b'google fixture')
            class Result:returncode=0
            return Result()
        with tempfile.TemporaryDirectory() as tmp,patch('rule_update.subprocess.run',side_effect=compiler):
            root=Path(tmp);result=refresh(root,fetch=lambda url:bodies[url],validate=lambda p:None)
            self.assertEqual(result['status'],'PASS')
            original=(root/'rules/current.json').read_bytes()
            revision=bundle_revision(root)
            self.assertTrue(all(rule_body(root,name,revision) for name in BEHAVIORS))
            def fail(url):raise ValueError('failed')
            with self.assertRaises(ValueError):refresh(root,fetch=fail,validate=lambda p:None)
            self.assertEqual((root/'rules/current.json').read_bytes(),original)
            with self.assertRaises(ValueError):refresh(root,fetch=lambda u:bodies[u],validate=lambda p:(_ for _ in ()).throw(ValueError('invalid native')))
            self.assertEqual((root/'rules/current.json').read_bytes(),original)

if __name__=='__main__':unittest.main()
