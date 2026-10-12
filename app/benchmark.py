"""Bounded per-node requests: no selector writes, no health-history overrides."""
import json
import statistics
import time
from pathlib import Path
from httpio import request, RequestFailure


def benchmark(root, country='JP', repeats=3):
    if country not in ('JP', 'HK', 'TW', 'SG', 'US', 'CA', 'DE') or not 1 <= repeats <= 10:
        raise ValueError('INVALID_BENCHMARK_SCOPE')
    nodes = json.loads((Path(root) / 'runtime/candidates.json').read_text())
    nodes = [n for n in nodes if n['country'] == country and n['source'] == 'residential'
             and n['rate'] == 1 and n['proxy'].get('type') == 'hysteria2']
    results = []
    for n in nodes:
        attempts = []
        for _ in range(repeats):
            for target in ('https://www.gstatic.com/generate_204', 'https://cp.cloudflare.com/generate_204'):
                start = time.monotonic()
                row = {'target': target.split('/')[2]}
                try:
                    status, _ = request(target, seconds=5, limit=2048,
                                        proxy='http://127.0.0.1:' + str(n['probe_port']))
                    row.update(ok=status == 204, status=status)
                except RequestFailure as exc:
                    row.update(ok=False, error=str(exc))
                row['request_ms'] = round(1000 * (time.monotonic() - start))
                attempts.append(row)
        good = [r['request_ms'] for r in attempts if r['ok']]
        results.append({'country': country, 'node_id': n['id'], 'protocol': 'hysteria2',
                        'success_rate': len(good) / len(attempts),
                        'median_request_ms': statistics.median(good) if good else None,
                        'max_success_request_ms': max(good) if good else None, 'attempts': attempts})
    return {'tested_at': time.time(), 'measurement': 'ACTUAL_HTTP_204_NOT_PING',
            'path': 'THIS_SERVER_DIRECT_TO_RAW_UPSTREAM', 'health_history_modified': False,
            'results': results}
