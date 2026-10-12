import sys,tempfile,unittest,threading,time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from client_routing import settings,rule_body,RULE_FILES,MAX_RULE_BYTES,OVERSEAS

class ClientRoutingTests(unittest.TestCase):
    def test_domestic_and_foreign_priority(self):
        c=settings('dummy');rules=c['rules']
        self.assertLess(rules.index('RULE-SET,foreign-domain,出口选择'),rules.index('RULE-SET,cn-ip,DIRECT'))
        self.assertLess(rules.index('DOMAIN-SUFFIX,openai.com,出口选择'),rules.index('RULE-SET,cn-domain,DIRECT'))
        self.assertEqual(rules[-1],'MATCH,出口选择')
        self.assertIn('IP-CIDR,100.64.0.0/10,DIRECT,no-resolve',rules)
        self.assertIn('IP-CIDR6,fc00::/7,DIRECT,no-resolve',rules)
        self.assertFalse(any('39.104.106.33' in r for r in rules))
    def test_no_remote_startup_geodata_or_extra_selection(self):
        c=settings('dummy')
        self.assertNotIn('geodata-mode',c);self.assertNotIn('proxy-groups',c)
        self.assertTrue(all('GEOSITE' not in r and 'GEOIP' not in r for r in c['rules']))
        for p in c['rule-providers'].values():
            self.assertTrue(p['url'].startswith('https://sub.sync-api.xyz/s/dummy/rules/'))
            self.assertEqual(p['proxy'],'DIRECT');self.assertEqual(p['size-limit'],MAX_RULE_BYTES)
    def test_dns_bootstrap_and_no_overseas_direct_dns_fallback(self):
        dns=settings('dummy')['dns']
        self.assertTrue(dns['enable']);self.assertTrue(dns['ipv6'])
        self.assertNotIn('listen',dns);self.assertNotIn('fallback',dns)
        self.assertEqual(dns['enhanced-mode'],'fake-ip');self.assertFalse(dns['prefer-h3'])
        self.assertTrue(all('#DIRECT' in s for s in dns['proxy-server-nameserver']))
        self.assertTrue(all('#出口选择&disable-ipv6=true' in s for s in dns['nameserver']))
        self.assertTrue(dns['direct-nameserver-follow-policy'])
        self.assertEqual(dns['nameserver-policy']['+.lan'],['system'])
        for domain in OVERSEAS:self.assertEqual(dns['nameserver-policy']['+.'+domain],dns['nameserver'])
    def test_fixed_allowlist_and_bounded_rule_reads(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/'rules').mkdir()
            for name in RULE_FILES:
                (root/'rules'/(name+'.mrs')).write_bytes(b'fixture')
                self.assertEqual(rule_body(root,name),b'fixture')
            with self.assertRaises(ValueError):rule_body(root,'../secrets/access')
            (root/'rules/cn-ip.mrs').write_bytes(b'')
            with self.assertRaises(ValueError):rule_body(root,'cn-ip')

    def test_subscription_rule_handler_auth_and_paths(self):
        from app import Dispatcher
        from httpio import request
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/'secrets').mkdir();(root/'rules').mkdir()
            d=Dispatcher(root);d.client_profile=lambda tier=None:b'fixture-subscription'
            for name in RULE_FILES:(root/'rules'/(name+'.mrs')).write_bytes(b'fixture-rules')
            thread=threading.Thread(target=d.serve,args=(('127.0.0.1',0),));thread.start()
            try:
                for _ in range(40):
                    if hasattr(d,'server'):break
                    time.sleep(.025)
                base='http://127.0.0.1:'+str(d.server.server_port)
                prefix='/s/'+d.access['subscription']
                for path,expected in [(prefix,200),(prefix+'/rules/cn-domain.mrs',200),
                    ('/s/wrong/rules/cn-domain.mrs',404),(prefix+'/rules/unknown.mrs',404),
                    (prefix+'/rules/%2e%2e/access.json',404),(prefix+'/other/cn-ip.mrs',404)]:
                    code,body=request(base+path,seconds=2,limit=4096)
                    self.assertEqual(code,expected)
                revision='0123456789abcdef';bundle=root/'rules/bundles'/revision;bundle.mkdir(parents=True)
                (bundle/'google-ip.mrs').write_bytes(b'versioned-google')
                code,body=request(base+prefix+'/rules/'+revision+'/google-ip.mrs',seconds=2,limit=4096)
                self.assertEqual(code,200);self.assertEqual(body,b'versioned-google')
                (root/'rules/cn-domain.mrs').unlink()
                self.assertEqual(request(base+prefix+'/rules/cn-domain.mrs',seconds=2,limit=4096)[0],503)
            finally:d.stop.set();thread.join(timeout=3);self.assertFalse(thread.is_alive())

    def test_identity_matches_script_and_import_without_starting_service(self):
        import ast,hashlib,json
        import app
        source=Path(app.__file__)
        tree=ast.parse(source.read_text());tree.body=tree.body[:-1]
        namespace={'__name__':'__main__','__file__':str(source)}
        exec(compile(tree,str(source),'exec'),namespace)
        self.assertEqual(namespace['loaded_identity'](),app.loaded_identity())
        expected={name:hashlib.sha256((source.parent/name).read_bytes()).hexdigest() for name in app._CODE_FILES}
        expected_hash=hashlib.sha256(json.dumps(expected,sort_keys=True,separators=(',',':')).encode()).hexdigest()
        self.assertEqual(expected_hash,app.loaded_identity())

if __name__=='__main__':unittest.main()
