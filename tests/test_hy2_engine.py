"""Finite native fixtures: listener-reload ownership, QUIC TLS/auth and UDP."""
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import yaml

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from httpio import atomic, request, RequestFailure


def port():
    with socket.socket() as s:
        s.bind(('127.0.0.1',0));return s.getsockname()[1]


def listening(p):
    try:
        with socket.create_connection(('127.0.0.1',p),timeout=.2):return True
    except OSError:return False


def core(directory,config,env=None):
    directory.mkdir(mode=0o700)
    file=directory/'config.yaml';atomic(file,yaml.safe_dump(config,sort_keys=False).encode())
    child=subprocess.Popen(['/usr/local/bin/mihomo','-d',str(directory),'-f',str(file)],
        env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    api='http://'+config['external-controller']
    for _ in range(100):
        if child.poll() is not None:raise RuntimeError('FIXTURE_CORE_EXITED')
        try:
            headers={'Authorization':'Bearer '+config['secret']} if config.get('secret') else None
            if request(api+'/version',seconds=.5,headers=headers)[0]==200:return child,file,api
        except RequestFailure:pass
        time.sleep(.05)
    child.terminate();child.wait(timeout=5);raise RuntimeError('FIXTURE_CORE_NOT_READY')


def stop(child):
    child.terminate()
    try:child.wait(timeout=5)
    except subprocess.TimeoutExpired:child.kill();child.wait()


class NativeHY2Tests(unittest.TestCase):
    def test_index_names_reproduce_lost_ports_port_names_survive_reload(self):
        with tempfile.TemporaryDirectory() as tmp:
            for stable in (False,True):
                p1,p2,apiport=port(),port(),port()
                def cfg(swapped):
                    ports=[p2,p1] if swapped else [p1,p2]
                    return {'external-controller':'127.0.0.1:'+str(apiport),'log-level':'silent',
                        'listeners':[{'name':'health-port-'+str(p) if stable else 'health-'+str(i),
                            'type':'http','listen':'127.0.0.1','port':p,'proxy':'DIRECT'}
                            for i,p in enumerate(ports)],'rules':['MATCH,REJECT']}
                child,file,api=core(Path(tmp)/str(stable),cfg(False))
                try:
                    deadline=time.monotonic()+4
                    while not (listening(p1) and listening(p2)) and time.monotonic()<deadline:time.sleep(.025)
                    self.assertTrue(listening(p1));self.assertTrue(listening(p2))
                    atomic(file,yaml.safe_dump(cfg(True),sort_keys=False).encode())
                    self.assertEqual(request(api+'/configs?force=true',method='PUT',
                        data={'path':str(file)},seconds=3)[0],204)
                    results=[listening(p1),listening(p2)]
                    self.assertEqual(all(results),stable)
                finally:stop(child)

    def test_hy2_strict_tls_authentication_group_isolation_and_udp(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);cert=root/'fixture.crt';key=root/'fixture.key'
            subprocess.run(['openssl','req','-x509','-newkey','ec','-pkeyopt','ec_paramgen_curve:P-256',
                '-nodes','-keyout',str(key),'-out',str(cert),'-days','1','-subj','/CN=hy2.fixture.test',
                '-addext','subjectAltName=DNS:hy2.fixture.test','-addext','basicConstraints=critical,CA:TRUE'],
                stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=True,timeout=10)
            key.chmod(0o600)
            environment={k:v for k,v in os.environ.items() if 'proxy' not in k.lower()}
            environment['SAFE_PATHS']=str(root);environment['SSL_CERT_FILE']=str(cert)
            udp=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);udp.bind(('127.0.0.1',0));udp.settimeout(.1)
            done=threading.Event()
            def echo():
                while not done.is_set():
                    try:data,peer=udp.recvfrom(4096);udp.sendto(data,peer)
                    except socket.timeout:pass
            echo_thread=threading.Thread(target=echo,daemon=True);echo_thread.start()
            class Handler(BaseHTTPRequestHandler):
                def log_message(self,*a):pass
                def do_GET(self):self.send_response(204);self.end_headers()
            http=ThreadingHTTPServer(('127.0.0.1',0),Handler)
            http_thread=threading.Thread(target=http.serve_forever,daemon=True);http_thread.start()
            server_port,server_api,client_port,client_api=port(),port(),port(),port()
            # JP is deliberately rejected; US is reachable. A wrong-user route
            # must never borrow US or the server's default DIRECT.
            server={'mode':'rule','log-level':'silent','external-controller':'127.0.0.1:'+str(server_api),
                'listeners':[{'name':'hy2-gateway','type':'hysteria2','listen':'127.0.0.1','port':server_port,
                    'users':{'hy2-dc-jp':'jp-fixture','hy2-dc-us':'us-fixture','unmapped':'unmapped-fixture'},
                    'certificate':str(cert),'private-key':str(key),'ignore-client-bandwidth':True}],
                'proxy-groups':[{'name':'dc-jp','type':'select','proxies':['REJECT']},
                    {'name':'dc-us','type':'select','proxies':['DIRECT']}],
                'rules':['AND,((IN-NAME,hy2-gateway),(IN-USER,hy2-dc-jp)),dc-jp',
                    'AND,((IN-NAME,hy2-gateway),(IN-USER,hy2-dc-us)),dc-us','MATCH,REJECT']}
            def node(name,password,sni='hy2.fixture.test'):
                return {'name':name,'type':'hysteria2','server':'127.0.0.1','port':server_port,
                    'password':password,'sni':sni,'skip-cert-verify':False,'udp':True}
            client={'mixed-port':client_port,'allow-lan':False,'bind-address':'127.0.0.1','log-level':'silent',
                'external-controller':'127.0.0.1:'+str(client_api),
                'proxies':[node('us','us-fixture'),node('jp','jp-fixture'),node('bad-auth','bad-fixture'),
                    node('bad-sni','us-fixture','wrong.fixture.test'),node('unmapped','unmapped-fixture')],
                'rules':['MATCH,us']}
            server_child=client_child=None
            try:
                server_child,_,_=core(root/'server',server,environment)
                client_child,_,api=core(root/'client',client,environment)
                target='http://127.0.0.1:'+str(http.server_port)+'/'
                from urllib.parse import quote
                for name in ('us','jp','bad-auth','bad-sni','unmapped'):
                    code,body=request(api+'/proxies/'+name+'/delay?timeout=1500&url='+quote(target,safe=''),
                        seconds=2.5,limit=1024)
                    self.assertEqual(code==200,name=='us',(name,code))
                self.assertEqual(request(target,proxy='http://127.0.0.1:'+str(client_port),seconds=3)[0],204)
                with socket.create_connection(('127.0.0.1',client_port),timeout=3) as control:
                    control.sendall(b'\x05\x01\x00');self.assertEqual(control.recv(2),b'\x05\x00')
                    control.sendall(b'\x05\x03\x00\x01'+b'\0'*6)
                    data=control.recv(32);self.assertEqual(data[:3],b'\x05\x00\x00')
                    if data[3]==1:relay=(socket.inet_ntoa(data[4:8]),struct.unpack('!H',data[8:10])[0])
                    elif data[3]==4:relay=('127.0.0.1',struct.unpack('!H',data[20:22])[0])
                    else:self.fail('UNEXPECTED_SOCKS_UDP_ADDRESS')
                    if relay[0]=='0.0.0.0':relay=('127.0.0.1',relay[1])
                    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as datagram:
                        datagram.settimeout(3)
                        payload=b'HY2_UDP_FIXTURE'
                        packet=b'\x00\x00\x00\x01'+socket.inet_aton('127.0.0.1')+struct.pack('!H',udp.getsockname()[1])+payload
                        datagram.sendto(packet,relay);reply,_=datagram.recvfrom(4096)
                        self.assertTrue(reply.endswith(payload))
            finally:
                if client_child:stop(client_child)
                if server_child:stop(server_child)
                done.set();echo_thread.join(1);udp.close()
                http.shutdown();http.server_close();http_thread.join(2)


if __name__=='__main__':unittest.main()
