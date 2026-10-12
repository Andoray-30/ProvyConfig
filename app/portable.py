"""Deployment adapter. Original selection, evidence and client policies stay unchanged."""
import argparse
import copy
import fcntl
import hashlib
import ipaddress
import json
import os
import re
import signal
import socket
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from urllib.parse import quote, urlsplit

import yaml
import app as core
import rule_update
from client_routing import settings, subscription_layout, bundle_revision, RULE_FILES
from httpio import atomic, write_json, request, RequestFailure
from nodes import COUNTRIES, classify, parse_subscription

PACKAGE = Path(__file__).resolve().parents[1]


def hostname(value):
    if not isinstance(value, str) or len(value) > 253 or not re.fullmatch(
            r'[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?', value):
        raise ValueError('INVALID_DOMAIN')
    labels = value.split('.')
    if len(labels) < 2 or any(not p or len(p) > 63 or p.startswith('-') or p.endswith('-') for p in labels):
        raise ValueError('INVALID_DOMAIN')
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return value
    raise ValueError('DOMAIN_NOT_IP')


def config(path, require_providers=True):
    path = Path(path)
    if path.stat().st_mode & 0o077:
        raise ValueError('CONFIG_REQUIRES_0600')
    c = yaml.safe_load(path.read_text())
    if not isinstance(c, dict):
        raise ValueError('INVALID_CONFIG')
    defaults = {'mode': 'relay', 'listen': '0.0.0.0', 'https_port': 443,
                'hy2_port': 443, 'hy2_enabled': True, 'port_offset': 10000,
                'fetch_proxy': '', 'acme_email': ''}
    for key, value in defaults.items():
        c.setdefault(key, value)
    if c['mode'] not in ('relay', 'local-test'):
        raise ValueError('INVALID_MODE')
    if type(c['hy2_enabled']) is not bool:
        raise ValueError('INVALID_HY2_FLAG')
    for key in ('https_port', 'hy2_port'):
        if type(c[key]) is not int or not 1024 <= c[key] <= 65535 and c[key] != 443:
            raise ValueError('INVALID_PUBLIC_PORT')
    if type(c['port_offset']) is not int or not 0 <= c['port_offset'] <= 30000:
        raise ValueError('INVALID_PORT_OFFSET')
    address = ipaddress.ip_address(c['listen'])
    if address.version != 4:
        raise ValueError('IPV4_LISTEN_REQUIRED')
    providers = c.get('providers', {})
    if not isinstance(providers, dict) or set(providers) - {'residential', 'datacenter'}:
        raise ValueError('INVALID_PROVIDER_ROLES')
    providers = {k: v for k, v in providers.items() if v}
    for url in providers.values():
        u = urlsplit(url)
        if u.scheme not in ('http', 'https') or not u.hostname or u.fragment or '\n' in url:
            raise ValueError('INVALID_PROVIDER_URL')
    if require_providers and not providers.get('residential'):
        raise ValueError('RESIDENTIAL_SUBSCRIPTION_REQUIRED')
    c['providers'] = providers
    proxy = c['fetch_proxy']
    if proxy:
        u = urlsplit(proxy)
        if u.scheme not in ('http', 'socks5h') or u.hostname not in ('127.0.0.1', 'localhost') or not u.port:
            raise ValueError('FETCH_PROXY_MUST_BE_LOOPBACK')
    c.setdefault('tls', {})
    c['tls'].setdefault('mode', 'auto')
    c['tls'].setdefault('wait_seconds', 300)
    if c['tls']['mode'] not in ('auto', 'manual'):
        raise ValueError('INVALID_TLS_MODE')
    if type(c['tls']['wait_seconds']) is not int or not 0 <= c['tls']['wait_seconds'] <= 600:
        raise ValueError('INVALID_CERT_WAIT')
    if c['mode'] == 'relay':
        domains = c.get('domains', {})
        c['domains'] = {k: hostname(domains.get(k)) for k in ('gateway', 'subscription')}
        if len(set(c['domains'].values())) != 2 or any(d.endswith('.example.com') for d in c['domains'].values()):
            raise ValueError('SET_TWO_REAL_DOMAINS')
        if c['tls']['mode'] == 'auto':
            if not re.fullmatch(r'[A-Za-z0-9_.+%-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}', c['acme_email']) or c['acme_email'].endswith('@example.com'):
                raise ValueError('SET_ACME_EMAIL')
        else:
            for key in ('certificate', 'private_key'):
                if not Path(c['tls'].get(key, '')).is_absolute():
                    raise ValueError('ABSOLUTE_CERT_PATH_REQUIRED')
    return c


def configure_engine(c, binary=None):
    binary = str(binary or os.environ.get('MIHOMO_BINARY', '/usr/local/bin/mihomo'))
    if not Path(binary).is_file() or not os.access(binary, os.X_OK):
        raise ValueError('MIHOMO_NOT_EXECUTABLE')
    manifest = PACKAGE / 'PACKAGE-MANIFEST.json'
    if not manifest.exists():
        manifest = PACKAGE / 'ENGINE.json'
    if manifest.exists() and hashlib.sha256(Path(binary).read_bytes()).hexdigest() != json.loads(manifest.read_text())['mihomo_sha256']:
        raise ValueError('MIHOMO_BINARY_HASH_MISMATCH')
    core.MIHOMO = binary
    core.CONTROLLER = 'http://127.0.0.1:' + str(19190 + c['port_offset'])
    core.PROBE_PROXY = 'http://127.0.0.1:' + str(18190 + c['port_offset'])
    # Include the adapter in the actual loaded fingerprint, without editing core.
    files = sorted((PACKAGE / 'app').glob('*.py'))
    hashes = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in files}
    digest = hashlib.sha256(json.dumps(hashes, sort_keys=True).encode()).hexdigest()
    core.loaded_identity = lambda: digest
    core.RELEASE_ID = 'PORTABLE-20261012-v1'


def certificate_paths(c, root):
    if c['tls']['mode'] == 'manual':
        return Path(c['tls']['certificate']), Path(c['tls']['private_key'])
    domain = c['domains']['gateway']
    directory = Path(root) / 'caddy/certificates/acme-v02.api.letsencrypt.org-directory' / domain
    return directory / (domain + '.crt'), directory / (domain + '.key')


def validate_certificate(c, root):
    cert, key = certificate_paths(c, root)
    if not cert.is_file() or not key.is_file():
        raise ValueError('CERTIFICATE_NOT_READY')
    checks = ['x509', '-in', str(cert), '-noout', '-checkend', '0', '-checkhost', c['domains']['gateway']]
    result = subprocess.run(['openssl'] + checks, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
    if result.returncode:
        raise ValueError('CERTIFICATE_EXPIRED_OR_WRONG_HOST')
    public_cert = subprocess.check_output(['openssl', 'x509', '-in', str(cert), '-pubkey', '-noout'], stderr=subprocess.DEVNULL, timeout=5)
    public_key = subprocess.check_output(['openssl', 'pkey', '-in', str(key), '-pubout'], stderr=subprocess.DEVNULL, timeout=5)
    if public_cert != public_key:
        raise ValueError('CERT_KEY_MISMATCH')
    if c['tls']['mode'] == 'manual':
        result = subprocess.run(['openssl', 'x509', '-in', str(cert), '-noout', '-checkhost', c['domains']['subscription']],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
        if result.returncode:
            raise ValueError('MANUAL_CERT_MUST_COVER_BOTH_DOMAINS')
    return cert, key


def caddy_config(c):
    if c['mode'] != 'relay':
        return '# local-test: no public TLS listeners\n'
    offset = c['port_offset']
    # Disable HTTP/3: UDP HTTPS port belongs to the authenticated HY2 listener.
    lines = ['{', '  admin off', '  servers {', '    protocols h1 h2', '  }']
    if c['tls']['mode'] == 'auto':
        lines += ['  email ' + c['acme_email'], '  acme_ca https://acme-v02.api.letsencrypt.org/directory']
        # Explicit storage removes image XDG directory nesting ambiguity.
        lines += ['  storage file_system {', '    root /data', '  }']
    lines += ['}', 'https://' + c['domains']['gateway'] + ':' + str(c['https_port']) + ' {', '  bind ' + c['listen']]
    if c['tls']['mode'] == 'manual':
        lines += ['  tls ' + json.dumps(c['tls']['certificate']) + ' ' + json.dumps(c['tls']['private_key'])]
    for group in sorted(tier + '-' + country.lower() for country in COUNTRIES for tier in ('dc', 'home1', 'home3', 'dc1', 'dc3')):
        port = core.Dispatcher.port_for(group) + offset
        lines += ['  handle /dispatch/' + group + ' {', '    reverse_proxy 127.0.0.1:' + str(port), '  }']
    lines += ['  respond 404', '}', 'https://' + c['domains']['subscription'] + ':' + str(c['https_port']) + ' {',
              '  bind ' + c['listen']]
    if c['tls']['mode'] == 'manual':
        lines += ['  tls ' + json.dumps(c['tls']['certificate']) + ' ' + json.dumps(c['tls']['private_key'])]
    lines += ['  reverse_proxy 127.0.0.1:' + str(18192 + offset), '}']
    return '\n'.join(lines) + '\n'


def client_settings(token, revision, c):
    result = settings(token, revision)
    # Rebuild ordered DNS keys in-place; campus exception remains first.
    replacements = {'gw.sync-api.xyz': c['domains']['gateway'], 'sub.sync-api.xyz': c['domains']['subscription']}
    policy = result['dns']['nameserver-policy']
    result['dns']['nameserver-policy'] = {
        next(('+.' + new for old, new in replacements.items() if k == '+.' + old), k): v
        for k, v in policy.items()}
    result['rules'] = [next(('DOMAIN,' + new + ',DIRECT' for old, new in replacements.items()
                            if rule == 'DOMAIN,' + old + ',DIRECT'), rule) for rule in result['rules']]
    base = 'https://' + c['domains']['subscription'] + (':' + str(c['https_port']) if c['https_port'] != 443 else '')
    for provider in result['rule-providers'].values():
        provider['url'] = base + urlsplit(provider['url']).path
    return result


def seed_rules(root):
    rules = Path(root) / 'rules'
    if (rules / 'current.json').exists():
        # Never replace a newer independently updated bundle with the packaged seed.
        rev = bundle_revision(root)
        manifest = json.loads((rules / 'current.json').read_text())
        if set(manifest['files']) != set(RULE_FILES):
            raise ValueError('INCOMPLETE_RULE_BUNDLE')
        for name, digest in manifest['files'].items():
            body = (rules / 'bundles' / rev / (name + '.mrs')).read_bytes()
            if hashlib.sha256(body).hexdigest() != digest:
                raise ValueError('EXISTING_RULE_HASH_MISMATCH')
        return
    raise ValueError('INITIAL_RULE_DOWNLOAD_REQUIRED')


def prepare(c, root):
    root = Path(root)
    if str(root.resolve()) in ('/', '/etc', '/usr', '/var', '/root', '/home', '/server-work',
                               '/root/codex-work', '/etc/mihomo', '/server-work/andoray-node-dispatch'):
        raise ValueError('REFUSE_SYSTEM_OR_PRODUCTION_DATA_ROOT')
    if root.is_symlink() or (root / 'app.py').exists():
        raise ValueError('DATA_ROOT_IS_NOT_AN_INDEPENDENT_DIRECTORY')
    if root.exists() and not (root / 'layout.json').exists():
        known = {'runtime', 'secrets', 'rules', 'caddy', 'caddy-config', 'caddy-settings', 'handoff'}
        if any(p.name not in known or p.is_symlink() or not p.is_dir() or any(p.iterdir()) for p in root.iterdir()):
            raise ValueError('REFUSE_UNRECOGNIZED_EXISTING_DATA')
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    root.chmod(0o700)
    for name in ('runtime', 'secrets', 'rules', 'caddy', 'caddy-config', 'caddy-settings', 'handoff'):
        (root / name).mkdir(mode=0o700, exist_ok=True)
        (root / name).chmod(0o700)
    layout = {'port_offset': c['port_offset']}
    layout_file = root / 'layout.json'
    if layout_file.exists() and json.loads(layout_file.read_text()) != layout:
        raise ValueError('PORT_LAYOUT_CHANGED_USE_NEW_DATA_DIRECTORY')
    write_json(layout_file, layout)
    write_json(root / 'secrets/providers.json', c['providers'])
    # Core deployment-specific legacy validation is never used by the adapter.
    if (root / 'secrets/hy2.json').exists():
        raise ValueError('DO_NOT_CREATE_INTERNAL_HY2_JSON')
    atomic(root / 'caddy-config/Caddyfile', caddy_config(c).encode())
    if (root / 'rules/current.json').exists():
        seed_rules(root)
    else:
        result = refresh_rules(c, root)
        if result.get('status') != 'PASS':
            raise ValueError('INITIAL_RULE_DOWNLOAD_FAILED')
        seed_rules(root)


def occupied_ports(c):
    offset = c['port_offset']
    ports = [18190 + offset, 18192 + offset, 19190 + offset]
    ports += [core.Dispatcher.port_for(tier + '-' + country.lower()) + offset
              for country in COUNTRIES for tier in ('dc', 'home1', 'home3', 'dc1', 'dc3')]
    ports += list(range(21000 + offset, 22000 + offset))
    occupied = []
    for port in ports:
        with socket.socket() as sock:
            try:
                sock.bind(('127.0.0.1', port))
            except OSError:
                occupied.append(port)
    if c['mode'] == 'relay' and c['hy2_enabled']:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            try:
                sock.bind((c['listen'], c['hy2_port']))
            except OSError:
                occupied.append(c['hy2_port'])
    return sorted(set(occupied))


class PortableDispatcher(core.Dispatcher):
    def __init__(self, c, root):
        self.deploy = c
        super().__init__(root)
        self.nodes = [n for n in self.nodes if n['source'] in c['providers']]
        self.hy2 = {'enabled': c['hy2_enabled']}
        if c['mode'] == 'relay' and c['hy2_enabled']:
            cert, key = validate_certificate(c, root)
            self.hy2.update(listen=c['listen'], port=c['hy2_port'],
                            certificate=str(cert), **{'private-key': str(key)})
        self.reconcile(initial=True)
        if c['mode'] == 'relay':
            base = 'https://' + c['domains']['subscription'] + (':' + str(c['https_port']) if c['https_port'] != 443 else '')
            atomic(Path(root) / 'handoff/subscription-url.txt', (base + '/s/' + self.access['subscription'] + '\n').encode())

    def port_for(self, group):
        return core.Dispatcher.port_for(group) + self.deploy['port_offset']

    def config(self):
        offset = self.deploy['port_offset']
        # Core owns allocation/reuse in its original namespace. Translate only
        # at the adapter boundary; persistent health names follow actual sockets.
        for n in self.nodes:
            if 21000 + offset <= n.get('probe_port', 0) < 22000 + offset:
                n['probe_port'] -= offset
        enabled = self.hy2.get('enabled')
        if self.deploy['mode'] == 'local-test':
            self.hy2['enabled'] = False
        try:
            cfg = super().config()
        finally:
            self.hy2['enabled'] = enabled
            for n in self.nodes:
                if 21000 <= n.get('probe_port', 0) < 22000:
                    n['probe_port'] += offset
        for listener in cfg['listeners']:
            if listener['type'] == 'http':
                listener['port'] += offset
                if listener['name'] != 'probe':
                    listener['name'] = 'health-port-' + str(listener['port'])
        cfg['external-controller'] = '127.0.0.1:' + str(19190 + offset)
        if self.deploy['mode'] == 'local-test' and enabled:
            for country in sorted(COUNTRIES):
                group = 'hy-' + country.lower()
                cfg['proxy-groups'].append({'name': group, 'type': 'select', 'proxies': ['REJECT'] +
                    [n['proxy']['name'] for n in sorted(self.route_members(group), key=lambda n: n['id'])]})
        return cfg

    def listeners_ready(self):
        enabled = self.hy2.get('enabled')
        if self.deploy['mode'] == 'local-test':
            self.hy2['enabled'] = False
        try:
            return super().listeners_ready()
        finally:
            self.hy2['enabled'] = enabled

    def gateway_environment(self):
        env = {k: v for k, v in os.environ.items() if 'proxy' not in k.lower()}
        if self.deploy['mode'] == 'relay' and self.hy2.get('enabled'):
            env['SAFE_PATHS'] = str(Path(self.hy2['certificate']).parent)
        return env

    def serve(self, address=None):
        return super().serve(address or ('127.0.0.1', 18192 + self.deploy['port_offset']))

    def fetch_source(self, source, url):
        routes = [None] + ([self.deploy['fetch_proxy']] if self.deploy['fetch_proxy'] else [])
        last = None
        for route in routes:
            try:
                status, body = request(url, seconds=25, limit=8*1024*1024, proxy=route)
                if status != 200:
                    raise RequestFailure('SOURCE_STATUS')
                parsed, errors = parse_subscription(body)
                nodes, counts = classify(parsed, source)
                counts.update(parse_errors=errors, fetch_at=time.time(), fetch_status='PASS')
                return {'nodes': nodes, 'counts': counts, 'body': body}
            except Exception as exc:
                last = exc
        raise last

    def client_profile(self, tier=None):
        if self.deploy['mode'] == 'local-test':
            # Do not pretend a direct upstream profile measures the home relay.
            raise RequestFailure('LOCAL_TEST_HAS_NO_PUBLIC_SUBSCRIPTION')
        profile = yaml.safe_load(super().client_profile(tier))
        for proxy in profile['proxies']:
            proxy['server'] = self.deploy['domains']['gateway']
            if proxy['type'] == 'vless':
                proxy['port'] = self.deploy['https_port']
                proxy['servername'] = proxy['server']
                proxy['ws-opts']['headers']['Host'] = proxy['server']
            else:
                proxy['port'] = self.deploy['hy2_port']
                proxy['sni'] = proxy['server']
        profile.update(client_settings(self.access['subscription'], bundle_revision(self.root), self.deploy))
        return yaml.safe_dump(profile, allow_unicode=True, sort_keys=False).encode()


def refresh_rules(c, root):
    def fetch(url):
        for proxy in [None] + ([c['fetch_proxy']] if c['fetch_proxy'] else []):
            try:
                code, body = request(url, proxy=proxy, seconds=12, limit=rule_update.LIMIT)
                if code == 200 and body:
                    return body
            except RequestFailure:
                pass
        raise ValueError('RULE_SOURCE_UNAVAILABLE')
    try:
        return rule_update.refresh(root, fetch=fetch)
    except Exception as exc:
        result = {'status': 'FAILED_KEEP_LAST_GOOD', 'checked_at': time.time(), 'failure_class': type(exc).__name__}
        write_json(Path(root) / 'rules/refresh-status.json', result)
        return result


def run(c, root):
    with (Path(root) / '.run.lock').open('a') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ValueError('ANOTHER_DISPATCHER_IS_RUNNING')
        busy = occupied_ports(c)
        if busy:
            print(json.dumps({'error': 'PORTS_IN_USE', 'ports': busy}), flush=True)
            raise ValueError('PORTS_IN_USE')
        if c['mode'] == 'relay':
            deadline = time.monotonic() + c['tls']['wait_seconds']
            while True:
                try:
                    validate_certificate(c, root)
                    break
                except (ValueError, subprocess.SubprocessError):
                    if time.monotonic() >= deadline:
                        raise ValueError('CERT_WAIT_EXPIRED_CHECK_DNS_AND_PORTS')
                    time.sleep(2)
        d = PortableDispatcher(c, root)
        signal.signal(signal.SIGTERM, lambda *_: d.stop.set())
        signal.signal(signal.SIGINT, lambda *_: d.stop.set())
        rule_stop = threading.Event()
        def updater():
            # Persisted freshness survives restarts; failures keep the seed and
            # retry in 15 minutes rather than postponing another entire day.
            while not rule_stop.is_set():
                manifest = json.loads((Path(root) / 'rules/current.json').read_text())
                remaining = max(0, manifest.get('validated_at', 0) + 86400 - time.time())
                if remaining and rule_stop.wait(remaining):
                    return
                result = refresh_rules(c, root)
                if result['status'] == 'FAILED_KEEP_LAST_GOOD' and rule_stop.wait(900):
                    return
        worker = threading.Thread(target=updater, daemon=True)
        worker.start()
        try:
            d.run()
        finally:
            rule_stop.set()
            worker.join(timeout=1)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('command', choices=['prepare', 'check', 'run', 'status', 'refresh-rules', 'benchmark'])
    parser.add_argument('--config', default=os.environ.get('DEPLOY_CONFIG', str(PACKAGE / 'config.yaml')))
    parser.add_argument('--data', default=os.environ.get('DATA_ROOT', str(PACKAGE / 'data')))
    parser.add_argument('--country', default='JP')
    parser.add_argument('--repeats', type=int, default=3)
    args = parser.parse_args()
    os.umask(0o077)
    c = config(args.config)
    configure_engine(c)
    root = Path(args.data).resolve()
    if args.command == 'check':
        print(json.dumps({'status': 'CONFIG_VALID', 'mode': c['mode'], 'occupied_ports': occupied_ports(c)}))
    elif args.command == 'status':
        print((root / 'runtime/status.json').read_text())
    elif args.command == 'benchmark':
        from benchmark import benchmark
        print(json.dumps(benchmark(root, args.country, args.repeats), ensure_ascii=False))
    elif args.command == 'prepare':
        prepare(c, root)
        print('Prepared private state and Caddyfile; no listeners or services started.')
    elif args.command == 'refresh-rules':
        result = refresh_rules(c, root)
        print(json.dumps(result))
        if result['status'] == 'FAILED_KEEP_LAST_GOOD':
            raise SystemExit(1)
    else:
        prepare(c, root)
        run(c, root)


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        safe = str(exc) if isinstance(exc, (ValueError, RequestFailure)) and re.fullmatch('[A-Z0-9_]+', str(exc)) else 'INTERNAL_FAILURE'
        print(json.dumps({'status': 'FAILED', 'code': safe}), flush=True)
        raise SystemExit(1)
