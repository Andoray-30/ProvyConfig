import sys
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from client_routing import settings, CAMPUS_DOMAINS, OVERSEAS, webrtc_rules

class CampusDNSTests(unittest.TestCase):
    def test_generic_zone_uses_current_network_dns(self):
        policy=settings('fixture')['dns']['nameserver-policy']
        self.assertEqual(CAMPUS_DOMAINS,('edu.cn',))
        self.assertEqual(policy['+.edu.cn'],['system'])
        self.assertNotIn('+.cup.edu.cn',policy)
        self.assertNotIn('login.cup.edu.cn',policy)

    def test_direct_side_resolution_follows_policy(self):
        dns=settings('fixture')['dns']
        self.assertTrue(dns['direct-nameserver-follow-policy'])
        self.assertTrue(all('#DIRECT' in s for s in dns['direct-nameserver']))

    def test_campus_real_addresses_preserved(self):
        dns=settings('fixture')['dns']
        self.assertIn('+.edu.cn',dns['fake-ip-filter'])
        self.assertEqual(dns['enhanced-mode'],'fake-ip')
        self.assertTrue(dns['ipv6'])

    def test_education_direct_after_stun_guards(self):
        rules=settings('fixture')['rules'];campus=rules.index('DOMAIN-SUFFIX,edu.cn,DIRECT')
        self.assertTrue(all(rules.index(r)<campus for r in webrtc_rules()))
        self.assertLess(campus,rules.index('RULE-SET,google-ip,出口选择,no-resolve'))
        self.assertEqual(rules[-1],'MATCH,出口选择')

    def test_foreign_dns_and_private_dns_remain(self):
        dns=settings('fixture')['dns']
        for host in OVERSEAS:
            self.assertEqual(dns['nameserver-policy']['+.'+host],dns['nameserver'])
        self.assertEqual(dns['nameserver-policy']['+.lan'],['system'])
        self.assertTrue(all('#出口选择&disable-ipv6=true' in s for s in dns['nameserver']))
        self.assertNotIn('fallback',dns)

    def test_no_school_ip_or_client_bypass_configuration(self):
        cfg=settings('fixture')
        for addr in ('202.204.193.9','202.204.193.222','2001:da8:258:99::9'):
            self.assertNotIn(addr,str(cfg))
        self.assertNotIn('tun',cfg)
        self.assertNotIn('allow-bypass',cfg)

    def test_only_dns_and_one_routing_rule_change(self):
        cfg=settings('fixture')
        self.assertEqual(cfg['rules'].count('DOMAIN-SUFFIX,edu.cn,DIRECT'),1)
        for matcher in webrtc_rules():self.assertEqual(cfg['rules'].count(matcher),1)
        self.assertEqual(len(cfg['rule-providers']),6)

if __name__=='__main__':unittest.main()
