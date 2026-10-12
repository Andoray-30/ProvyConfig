"""All HTTP via curl with total wall deadlines and capped in-memory output."""
import json
import os
import selectors
import subprocess
import time

class RequestFailure(Exception):
    pass

def request(url, *, seconds=10, limit=1024*1024, proxy=None, method='GET', data=None, headers=None):
    cfg = ['url = ' + json.dumps(url), 'silent', 'show-error', 'noproxy = "*"' if not proxy else 'noproxy = ""',
           'connect-timeout = ' + str(min(5,seconds)), 'max-time = ' + str(seconds), 'user-agent = "clash-meta/1.19.30"',
           'write-out = "\\n%{http_code}"']
    if proxy: cfg += ['proxy = ' + json.dumps(proxy)]
    if method != 'GET': cfg += ['request = ' + json.dumps(method)]
    if data is not None: cfg += ['data = ' + json.dumps(json.dumps(data,separators=(',',':')))]
    for key, value in (headers or {}).items(): cfg += ['header = ' + json.dumps(key + ': ' + value)]
    proc = subprocess.Popen(['curl','--config','-'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env={k:v for k,v in os.environ.items() if 'proxy' not in k.lower()})
    try:
        proc.stdin.write(('\n'.join(cfg)+'\n').encode()); proc.stdin.close()
        out = bytearray(); deadline = time.monotonic() + seconds + 0.5
        sel = selectors.DefaultSelector(); sel.register(proc.stdout, selectors.EVENT_READ)
        try:
            while True:
                remaining = deadline-time.monotonic()
                if remaining <= 0: raise RequestFailure('TOTAL_TIMEOUT')
                events = sel.select(min(remaining,0.5))
                if not events: continue
                chunk = os.read(proc.stdout.fileno(),65536)
                if not chunk: break
                out.extend(chunk)
                if len(out) > limit+4: raise RequestFailure('BODY_TOO_LARGE')
        finally: sel.close()
        code = proc.wait(timeout=max(0.1,deadline-time.monotonic()))
        if code: raise RequestFailure('TRANSPORT_FAILURE_' + str(code))
        body, status = bytes(out).rsplit(b'\n',1)
        return int(status), body
    finally:
        if proc.poll() is None: proc.kill()
        proc.wait(); proc.stdout.close()

def atomic(path, body, mode=0o600):
    import tempfile
    from pathlib import Path
    path = Path(path); path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    fd, tmp = tempfile.mkstemp(prefix='.' + path.name + '-',dir=path.parent)
    try:
        os.fchmod(fd,mode)
        with os.fdopen(fd,'wb') as f: f.write(body); f.flush(); os.fsync(f.fileno())
        os.replace(tmp,path)
        dfd = os.open(path.parent,os.O_DIRECTORY)
        try: os.fsync(dfd)
        finally: os.close(dfd)
    finally:
        if os.path.exists(tmp): os.unlink(tmp)

def write_json(path, obj): atomic(path, json.dumps(obj,ensure_ascii=False,indent=2).encode())
