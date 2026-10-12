import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from client_routing import (settings, webrtc_rules, WEBRTC_DOMAIN_REGEX,
                            WEBRTC_MATCHERS, RULE_FILES)


class WebRTCPrivacyTests(unittest.TestCase):
    def test_detector_and_other_conventional_hosts(self):
        for host in ('stun.chat.bilibili.com', 'stun.hitv.com', 'stun.miwifi.com',
                     'stun.cloudflare.com', 'stun.l.google.com',
                     'stun1.l.google.com', 'global.turn.twilio.com',
                     'turns.example.cn', 'stun-service.example.cn',
                     'STUN2.EXAMPLE.CN'):
            with self.subTest(host=host):
                self.assertIsNotNone(re.search(WEBRTC_DOMAIN_REGEX, host))

    def test_regular_domestic_hosts_are_not_captured(self):
        for host in ('www.baidu.com', 'www.bilibili.com', 'api.hitv.com',
                     'www.miwifi.com', 'turnip.example.cn',
                     'return.example.cn', 'notstun.example.cn'):
            with self.subTest(host=host):
                self.assertIsNone(re.search(WEBRTC_DOMAIN_REGEX, host))

    def test_privacy_precedes_cn_and_preserves_local_routing(self):
        rules = settings('dummy')['rules']
        privacy = webrtc_rules()
        first, last = rules.index(privacy[0]), rules.index(privacy[-1])
        self.assertEqual(rules[first:last+1], privacy)
        self.assertLess(rules.index('IP-CIDR,192.168.0.0/16,DIRECT,no-resolve'), first)
        self.assertLess(rules.index('IP-CIDR6,fe80::/10,DIRECT,no-resolve'), first)
        self.assertLess(last, rules.index('RULE-SET,cn-domain,DIRECT'))
        self.assertLess(last, rules.index('RULE-SET,cn-ip,DIRECT'))

    def test_fail_closed_if_udp_proxy_is_skipped(self):
        rules = webrtc_rules()
        for matcher in WEBRTC_MATCHERS:
            i = rules.index(matcher + ',出口选择')
            self.assertEqual(rules[i+1], matcher + ',REJECT')

    def test_ip_only_stun_and_turn_have_bounded_port_guards(self):
        rules = webrtc_rules()
        self.assertIn('AND,((NETWORK,UDP),(DST-PORT,3478/5349/19302-19309)),出口选择', rules)
        self.assertIn('AND,((NETWORK,TCP),(DST-PORT,3478/5349)),出口选择', rules)
        self.assertFalse(any(r.startswith('NETWORK,') for r in rules))
        self.assertFalse(any('DST-PORT,443' in r or 'DST-PORT,53' in r for r in rules))

    def test_no_dns_geodata_tun_or_provider_scope_expansion(self):
        config = settings('dummy')
        self.assertEqual(set(config['rule-providers']), set(RULE_FILES))
        self.assertNotIn('tun', config)
        self.assertTrue(config['ipv6'])
        self.assertTrue(config['dns']['ipv6'])
        self.assertIn('+.stun.*.*', config['dns']['fake-ip-filter'])
        self.assertEqual(config['rules'][-1], 'MATCH,出口选择')
        for ip in ('219.142.55.192', '202.204.205.110', '39.104.106.33'):
            self.assertFalse(any(ip in r for r in config['rules']))


if __name__ == '__main__':
    unittest.main()
