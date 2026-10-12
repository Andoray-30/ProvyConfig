"""Daily bounded rule refresh. Publish a complete validated bundle or keep last good."""
import argparse,fcntl,hashlib,ipaddress,json,os,re,shutil,subprocess,tempfile,time
from pathlib import Path
import yaml
from httpio import request,atomic,write_json

META='https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/'
SOURCES={'cn-domain':META+'geosite/cn.mrs','foreign-domain':META+'geosite/geolocation-!cn.mrs',
         'cn-ip':META+'geoip/cn.mrs','google-domain':META+'geosite/google.mrs',
         'gemini-domain':META+'geosite/google-gemini.mrs',
         'google-owned':'https://www.gstatic.com/ipranges/goog.json',
         'google-cloud':'https://www.gstatic.com/ipranges/cloud.json'}
BEHAVIORS={'cn-domain':'domain','foreign-domain':'domain','cn-ip':'ipcidr',
           'google-domain':'domain','gemini-domain':'domain','google-ip':'ipcidr'}
LIMIT=2*1024*1024

def prefixes(body):
    data=json.loads(body);rows=data['prefixes']
    if not isinstance(rows,list) or not 1<=len(rows)<=10000:raise ValueError('INVALID_GOOGLE_LIST')
    result=[]
    for row in rows:
        value=row.get('ipv4Prefix') or row.get('ipv6Prefix')
        net=ipaddress.ip_network(value)
        if not net.is_global or net.prefixlen==0:raise ValueError('NON_PUBLIC_GOOGLE_PREFIX')
        result.append(net)
    return result

def google_services(owned,cloud):
    result=[]
    for version in (4,6):
        remaining=list(ipaddress.collapse_addresses(n for n in owned if n.version==version))
        for excluded in ipaddress.collapse_addresses(n for n in cloud if n.version==version):
            updated=[]
            for net in remaining:
                if not net.overlaps(excluded):updated.append(net)
                elif net.subnet_of(excluded):continue
                else:updated.extend(net.address_exclude(excluded))
            remaining=updated
        result.extend(ipaddress.collapse_addresses(remaining))
    if not result:raise ValueError('EMPTY_GOOGLE_SERVICES')
    return result

def download(url):
    routes=('http://127.0.0.1:7890',None) if 'githubusercontent.com' in url else (None,'http://127.0.0.1:7890')
    for proxy in routes:
        try:
            code,body=request(url,proxy=proxy,seconds=12,limit=LIMIT)
            if code==200 and body:return body
        except Exception:pass
    raise ValueError('SOURCE_UNAVAILABLE')

def native_validate(directory):
    providers={n:{'type':'file','behavior':b,'format':'mrs','path':str(directory/(n+'.mrs'))} for n,b in BEHAVIORS.items()}
    cfg={'mode':'rule','log-level':'silent','rule-providers':providers,
         'rules':['RULE-SET,'+n+',REJECT' for n in providers]+['MATCH,REJECT']}
    atomic(directory/'validate.yaml',yaml.safe_dump(cfg).encode())
    p=subprocess.run(['/usr/local/bin/mihomo','-t','-d',str(directory),'-f',str(directory/'validate.yaml')],
        stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=15)
    if p.returncode:raise ValueError('NATIVE_RULE_VALIDATION_FAILED')
    (directory/'validate.yaml').unlink()

def refresh(root,fetch=download,validate=native_validate):
    root=Path(root);rules=root/'rules';rules.mkdir(mode=0o700,parents=True,exist_ok=True)
    with (rules/'.refresh.lock').open('a') as lock:
        try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:return {'status':'ALREADY_RUNNING'}
        bodies={name:fetch(url) for name,url in SOURCES.items()}
        if any(not 0<len(b)<=LIMIT for b in bodies.values()):raise ValueError('SOURCE_SIZE')
        own=prefixes(bodies['google-owned']);cloud=prefixes(bodies['google-cloud'])
        nets=google_services(own,cloud)
        with tempfile.TemporaryDirectory(prefix='.candidate-',dir=rules) as tmp:
            candidate=Path(tmp)
            for name in BEHAVIORS:
                if name=='google-ip':continue
                b=bodies[name]
                if b[:4]!=bytes.fromhex('28b52ffd'):raise ValueError('INVALID_MRS')
                atomic(candidate/(name+'.mrs'),b)
            atomic(candidate/'google-ip.txt',('\n'.join(map(str,nets))+'\n').encode())
            p=subprocess.run(['/usr/local/bin/mihomo','convert-ruleset','ipcidr','text',str(candidate/'google-ip.txt'),str(candidate/'google-ip.mrs')],
                stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=10)
            if p.returncode:raise ValueError('GOOGLE_COMPILE_FAILED')
            (candidate/'google-ip.txt').unlink();validate(candidate)
            files={name:hashlib.sha256((candidate/(name+'.mrs')).read_bytes()).hexdigest() for name in BEHAVIORS}
            revision=hashlib.sha256(json.dumps(files,sort_keys=True).encode()).hexdigest()[:16]
            manifest={'revision':revision,'validated_at':time.time(),'files':files,'sources':SOURCES,
                      'google_prefix_count':len(nets),'google_derivation':'goog.json minus cloud.json'}
            write_json(candidate/'manifest.json',manifest)
            bundles=rules/'bundles';bundles.mkdir(mode=0o700,exist_ok=True)
            final=bundles/revision
            if not final.exists():os.rename(candidate,final)
            else:
                if any(hashlib.sha256((final/(n+'.mrs')).read_bytes()).hexdigest()!=h for n,h in files.items()):
                    raise ValueError('EXISTING_BUNDLE_CHANGED')
            # The only activation write. Readers never see a half-updated bundle.
            write_json(rules/'current.json',manifest)
            old=sorted((p for p in bundles.iterdir() if p.is_dir() and re.fullmatch('[a-f0-9]{16}',p.name)),key=lambda p:p.stat().st_mtime,reverse=True)
            for directory in old[14:]:
                if directory!=final:
                    # Exact known bundle names and files; never recurse into arbitrary paths.
                    if set(p.name for p in directory.iterdir()) <= {n+'.mrs' for n in BEHAVIORS}|{'manifest.json'}:
                        for p in directory.iterdir():p.unlink()
                        directory.rmdir()
        result={'status':'PASS','revision':revision,'checked_at':time.time(),'google_prefix_count':len(nets)}
        write_json(rules/'refresh-status.json',result)
        return result

def main():
    p=argparse.ArgumentParser();p.add_argument('--root',default=str(Path(__file__).resolve().parent));args=p.parse_args()
    try:result=refresh(args.root)
    except Exception as e:
        result={'status':'FAILED_KEEP_LAST_GOOD','checked_at':time.time(),'failure_class':type(e).__name__}
        write_json(Path(args.root)/'rules/refresh-status.json',result)
        print(json.dumps(result),flush=True);raise SystemExit(1)
    print(json.dumps(result),flush=True)
if __name__=='__main__':main()
