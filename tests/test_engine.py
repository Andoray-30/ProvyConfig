"""Installed engine, isolated local fixture: expected=204 and cleanup."""
import json,subprocess,tempfile,threading,time,unittest,sys
from pathlib import Path
from http.server import BaseHTTPRequestHandler,HTTPServer
from urllib.parse import quote
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from httpio import atomic,request
from app import Dispatcher
from unittest.mock import patch

class EngineTests(unittest.TestCase):
    def test_current_engine_expected_status_and_unified_delay(self):
        class Handler(BaseHTTPRequestHandler):
            def log_message(self,*a):pass
            def do_GET(self):
                self.send_response(204 if self.path=='/ok' else 200);self.end_headers()
        server=HTTPServer(('127.0.0.1',0),Handler)
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'fixture.yaml'
            atomic(path,b'mode: rule\nlog-level: silent\nunified-delay: true\nexternal-controller: 127.0.0.1:19394\nproxies:\n- {name: fixture-direct, type: direct}\nlisteners:\n- {name: health, type: http, listen: 127.0.0.1, port: 19395, proxy: fixture-direct}\nrules:\n- MATCH,REJECT\n')
            child=subprocess.Popen(['/usr/local/bin/mihomo','-d',tmp,'-f',str(path)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            try:
                deadline=time.monotonic()+5
                while time.monotonic()<deadline:
                    try:
                        code,body=request('http://127.0.0.1:19394/proxies',seconds=.3,limit=8192)
                        if code==200 and 'fixture-direct' in json.loads(body).get('proxies',{}):break
                    except Exception:time.sleep(.05)
                self.assertIsNone(child.poll())
                base='http://127.0.0.1:'+str(server.server_port)
                endpoint='http://127.0.0.1:19394/proxies/fixture-direct/delay?timeout=1000&expected=204&url='
                code,body=request(endpoint+quote(base+'/ok',safe=''),seconds=2,limit=2048)
                self.assertEqual(code,200);self.assertIn('delay',json.loads(body))
                root=Path(tmp)/'dispatcher';(root/'secrets').mkdir(parents=True)
                d=Dispatcher(root)
                d.api=lambda url,**kw:json.loads(request('http://127.0.0.1:19394'+url,seconds=2,limit=2048)[1])
                n={'proxy':{'name':'fixture-direct'},'probe_port':19395}
                with patch('app.HEALTH_URL',base+'/ok'):
                    result=d.probe_node(n);self.assertTrue(result['ok']);self.assertEqual(result['http_status'],204)
                with patch('app.HEALTH_URL',base+'/wrong'), patch('app.SECONDARY_HEALTH_URL',base+'/wrong'):
                    result=d.probe_node(n);self.assertFalse(result['ok']);self.assertEqual(result['http_status'],200)
            finally:
                child.terminate();child.wait(timeout=5)
                server.shutdown();server.server_close();thread.join(timeout=2)
                self.assertFalse(thread.is_alive());self.assertIsNotNone(child.poll())

if __name__=='__main__':unittest.main()
