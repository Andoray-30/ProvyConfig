import copy
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'app'))
import app
import portable
from httpio import atomic, request
from test_hy2_engine import core, stop, port


def deployment(mode='local-test'):
    return {'mode': mode, 'listen': '127.0.0.1', 'https_port': 8443, 'hy2_port': 8443,
            'hy2_enabled': True, 'port_offset': 20000, 'fetch_proxy': '',
            'acme_email': 'owner@fixture.test',
            'domains': {'gateway': 'home-gw.fixture.test', 'subscription': 'home-sub.fixture.test'},
            'providers': {'residential': 'https://provider.fixture.test/private-subscription'},
            'tls': {'mode': 'auto', 'wait_seconds': 0}}


def upstream(name, protocol='hysteria2', source='residential'):
    now = time.time()
    return {'id': name, 'country': 'JP', 'rate': 1, 'source': source, 'group': 'dc-jp',
            'network_identity': {'kind': 'HOSTING', 'checked_at': now},
            'qualified_at': now, 'last_success_at': now, 'last_checked_at': now,
            'samples': [100, 100, 100], 'proxy': {'name': 'n-' + name, 'type': protocol,
            'server': 'upstream.fixture.test', 'port': 443, 'password': 'synthetic-only'},
            'observations': [{'at': now - 20, 'ok': True, 'request_ms': 100, 'repeat_request_ok': True},
                             {'at': now, 'ok': True, 'request_ms': 100, 'repeat_request_ok': True}]}


class PortableTests(unittest.TestCase):
    def root(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        for name in ('secrets', 'runtime', 'handoff'):
            (root / name).mkdir()
        return root

    def test_config_requires_private_permissions(self):
        root = self.root(); path = root / 'config.yaml'
        atomic(path, yaml.safe_dump(deployment()).encode(), mode=0o644)
        with self.assertRaisesRegex(ValueError, '0600'):
            portable.config(path)

    def test_only_known_provider_roles_and_real_urls(self):
        root = self.root(); path = root / 'config.yaml'
        for bad in ({'unknown': 'https://fixture.test'}, {'residential': 'file:///etc/passwd'}, {}):
            c = deployment(); c['providers'] = bad
            atomic(path, yaml.safe_dump(c).encode())
            with self.assertRaises(ValueError): portable.config(path)

    def test_placeholder_domain_and_injection_rejected(self):
        for host in ('home-gw.example.com', 'abc\n{', '127.0.0.1', '*.test', 'bad..test'):
            root = self.root(); path = root / 'config.yaml'; c = deployment('relay')
            c['domains']['gateway'] = host; atomic(path, yaml.safe_dump(c).encode())
            with self.assertRaises(ValueError): portable.config(path)

    def test_nonloopback_fetch_proxy_rejected(self):
        c = deployment(); c['fetch_proxy'] = 'http://remote.fixture.test:7890'
        root = self.root(); path = root / 'config.yaml'; atomic(path, yaml.safe_dump(c).encode())
        with self.assertRaises(ValueError): portable.config(path)

    def test_new_domains_all_client_addresses_and_campus_order(self):
        c = deployment('relay'); cfg = portable.client_settings('fixture-token', '0123456789abcdef', c)
        encoded = yaml.safe_dump(cfg, sort_keys=False)
        self.assertNotIn('sync-api.xyz', encoded)
        self.assertIn('https://home-sub.fixture.test:8443/s/fixture-token/rules/', encoded)
        keys = list(cfg['dns']['nameserver-policy'])
        self.assertEqual(cfg['dns']['nameserver-policy']['+.edu.cn'], ['system'])
        for key in keys:
            if key.startswith('rule-set:'): self.assertLess(keys.index('+.edu.cn'), keys.index(key))
        self.assertTrue(cfg['dns']['direct-nameserver-follow-policy'])
        self.assertEqual(cfg['rules'][-1], 'MATCH,出口选择')
        self.assertIn('DOMAIN,home-gw.fixture.test,DIRECT', cfg['rules'])

    def test_caddy_no_http3_or_old_domains_or_tokens(self):
        text = portable.caddy_config(deployment('relay'))
        self.assertIn('protocols h1 h2', text); self.assertNotIn('h3', text)
        self.assertIn('storage file_system', text); self.assertIn('root /data', text)
        self.assertNotIn('sync-api.xyz', text); self.assertNotIn('/s/', text)
        self.assertIn('127.0.0.1:38192', text)
        self.assertIn('handle /dispatch/home3-jp', text)

    def test_local_only_hy_owner_and_same_source_contract(self):
        c = deployment(); root = self.root(); d = portable.PortableDispatcher(c, root)
        d.nodes = [upstream('home'), upstream('machine', source='datacenter'), upstream('vless', protocol='vless')]
        d.reconcile(initial=True); cfg = d.config()
        self.assertFalse(any(l['type'] == 'hysteria2' for l in cfg['listeners']))
        self.assertTrue(all(l['listen'] == '127.0.0.1' for l in cfg['listeners']))
        self.assertEqual(next(g for g in cfg['proxy-groups'] if g['name'] == 'hy-jp')['proxies'], ['REJECT', 'n-home'])
        self.assertEqual(d.state['groups']['hy-jp']['selected'], 'home')
        self.assertFalse((root / 'handoff/subscription-url.txt').exists())
        with self.assertRaisesRegex(Exception, 'NO_PUBLIC_SUBSCRIPTION'): d.client_profile()

    def test_health_names_and_ports_stable_across_reorder(self):
        d = portable.PortableDispatcher(deployment(), self.root())
        d.nodes = [upstream('bbb'), upstream('ddd')]; first = d.config()
        before = {n['id']: n['probe_port'] for n in d.nodes}
        d.nodes = [upstream('aaa')] + list(reversed(d.nodes)); second = d.config()
        for n in d.nodes:
            if n['id'] in before: self.assertEqual(n['probe_port'], before[n['id']])
        for cfg in (first, second):
            for listener in cfg['listeners']:
                if listener['type'] == 'http' and listener['name'] != 'probe':
                    self.assertEqual(listener['name'], 'health-port-' + str(listener['port']))
                    self.assertTrue(41000 <= listener['port'] < 42000)

    def test_independent_credentials_no_imported_qualification(self):
        a = portable.PortableDispatcher(deployment(), self.root())
        b = portable.PortableDispatcher(deployment(), self.root())
        self.assertNotEqual(a.access['subscription'], b.access['subscription'])
        self.assertNotEqual(a.access['controller'], b.access['controller'])
        self.assertEqual(a.nodes, []); self.assertEqual(b.nodes, [])

    def test_source_fetch_does_not_inherit_host_proxy(self):
        d = portable.PortableDispatcher(deployment(), self.root())
        body = yaml.safe_dump({'proxies': [{'name': '日本hy2', 'type': 'hysteria2',
                            'server': 'synthetic.fixture.test', 'port': 443, 'password': 'fixture'}]}).encode()
        with patch('portable.request', return_value=(200, body)) as req:
            result = d.fetch_source('residential', 'https://provider.fixture.test')
        self.assertEqual(req.call_args.kwargs['proxy'], None)
        self.assertEqual(len(result['nodes']), 1)

    def test_port_offset_cannot_change_existing_layout(self):
        root = self.root(); c = deployment()
        with patch('portable.seed_rules'), patch('portable.refresh_rules', return_value={'status': 'PASS'}):
            portable.prepare(c, root)
            c['port_offset'] += 1000
            with self.assertRaisesRegex(ValueError, 'LAYOUT_CHANGED'): portable.prepare(c, root)

    def test_seed_is_full_hash_validated_and_not_overwritten(self):
        import hashlib
        root = self.root()
        with self.assertRaisesRegex(ValueError, 'INITIAL_RULE_DOWNLOAD_REQUIRED'): portable.seed_rules(root)
        files = {name: hashlib.sha256(b'fixture-body').hexdigest() for name in portable.RULE_FILES}
        pointer = {'revision': '0123456789abcdef', 'files': files}
        folder = root / 'rules/bundles/0123456789abcdef'; folder.mkdir(parents=True)
        for name in files: atomic(folder / (name + '.mrs'), b'fixture-body')
        atomic(root / 'rules/current.json', json.dumps(pointer).encode())
        before = (root / 'rules/current.json').read_bytes(); portable.seed_rules(root)
        self.assertEqual(before, (root / 'rules/current.json').read_bytes())
        atomic(folder / 'cn-ip.mrs', b'changed')
        with self.assertRaisesRegex(ValueError, 'HASH_MISMATCH'): portable.seed_rules(root)


class NativePortableTests(unittest.TestCase):
    def test_real_hy2_adapter_strict_tls_raw_probe_and_new_profile(self):
        old = app.MIHOMO, app.CONTROLLER, app.PROBE_PROXY, app.RELEASE_ID, app.loaded_identity
        self.addCleanup(lambda: [setattr(app, name, value) for name, value in zip(
            ('MIHOMO', 'CONTROLLER', 'PROBE_PROXY', 'RELEASE_ID', 'loaded_identity'), old)])
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); cert = root / 'test.crt'; key = root / 'test.key'
            subprocess.run(['openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256',
                            '-nodes', '-keyout', str(key), '-out', str(cert), '-days', '1',
                            '-subj', '/CN=home-gw.fixture.test', '-addext',
                            'subjectAltName=DNS:home-gw.fixture.test,DNS:home-sub.fixture.test',
                            '-addext', 'basicConstraints=critical,CA:TRUE'],
                           check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
            key.chmod(0o600)
            env = {k: v for k, v in os.environ.items() if 'proxy' not in k.lower()}
            env.update(SAFE_PATHS=str(root), SSL_CERT_FILE=str(cert))
            class Handler(BaseHTTPRequestHandler):
                def log_message(self, *args): pass
                def do_GET(self): self.send_response(204); self.end_headers()
            server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
            thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
            self.addCleanup(server.server_close); self.addCleanup(server.shutdown)
            upstream_port, upstream_api = port(), port()
            upstream_cfg = {'external-controller': '127.0.0.1:' + str(upstream_api), 'log-level': 'silent',
                            'listeners': [{'name': 'upstream', 'type': 'hysteria2', 'listen': '127.0.0.1',
                            'port': upstream_port, 'users': {'fixture-user': 'fixture-password'},
                            'certificate': str(cert), 'private-key': str(key), 'alpn': ['h3']}],
                            'rules': ['MATCH,DIRECT']}
            child, _, _ = core(root / 'upstream', upstream_cfg, env)
            self.addCleanup(stop, child)
            c = deployment('relay'); c['hy2_port'] = port()
            c['tls'] = {'mode': 'manual', 'certificate': str(cert), 'private_key': str(key), 'wait_seconds': 0}
            portable.configure_engine(c)
            data = root / 'data'; data.mkdir();
            for name in ('secrets', 'runtime', 'handoff'): (data / name).mkdir()
            d = portable.PortableDispatcher(c, data)
            node = upstream('native')
            node['proxy'].update(server='127.0.0.1', port=upstream_port,
                                 password='fixture-password',
                                 sni=c['domains']['gateway'], **{'skip-cert-verify': False, 'alpn': ['h3']})
            d.nodes = [node]; d.reconcile(initial=True)
            with patch.dict(os.environ, env, clear=True): d.start_gateway()
            self.addCleanup(stop, d.proc)
            self.assertTrue(d.listeners_ready())
            profile = yaml.safe_load(d.client_profile())
            self.assertNotIn('sync-api.xyz', yaml.safe_dump(profile))
            self.assertTrue(all(p['server'] == c['domains']['gateway'] and not p['skip-cert-verify'] for p in profile['proxies']))
            public = copy.deepcopy(next(p for p in profile['proxies'] if p['type'] == 'hysteria2'))
            public['server'] = '127.0.0.1'
            client_port, client_api = port(), port()
            cfg = {'external-controller': '127.0.0.1:' + str(client_api), 'log-level': 'silent',
                   'proxies': [public], 'listeners': [{'name': 'test', 'type': 'http', 'listen': '127.0.0.1',
                   'port': client_port, 'proxy': public['name']}], 'rules': ['MATCH,REJECT']}
            client, _, _ = core(root / 'client', cfg, env); self.addCleanup(stop, client)
            target = 'http://127.0.0.1:' + str(server.server_port)
            self.assertEqual(request(target, proxy='http://127.0.0.1:' + str(client_port), seconds=5)[0], 204)
            self.assertEqual(request(target, proxy='http://127.0.0.1:' + str(node['probe_port']), seconds=5)[0], 204)
            self.assertEqual(d.api('/proxies/hy-jp')['now'], node['proxy']['name'])
            old_port = node['probe_port']; extra = upstream('extra', source='datacenter')
            extra['proxy'] = copy.deepcopy(node['proxy']); extra['proxy']['name'] = 'n-extra'
            d.nodes = [extra, node]; d.reconcile(initial=True); d.write_config()
            self.assertEqual(node['probe_port'], old_port); self.assertTrue(d.listeners_ready())
            self.assertEqual(d.api('/proxies/hy-jp')['all'], ['REJECT', 'n-native'])


if __name__ == '__main__': unittest.main()
