import sys,time,threading,unittest
from pathlib import Path
from http.server import BaseHTTPRequestHandler,HTTPServer
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from httpio import request,RequestFailure

class Handler(BaseHTTPRequestHandler):
    def log_message(self,*args):pass
    def do_GET(self):
        self.send_response(200);self.end_headers()
        try:
            if self.path=='/stall':time.sleep(2)
            elif self.path=='/drip':
                for _ in range(100):self.wfile.write(b'x');self.wfile.flush();time.sleep(.05)
            elif self.path=='/large':self.wfile.write(b'x'*20000)
            else:self.wfile.write(b'JP')
        except (BrokenPipeError,ConnectionResetError):pass

class HttpTests(unittest.TestCase):
    def run_case(self,path,seconds=0.4,limit=1000):
        server=HTTPServer(('127.0.0.1',0),Handler);thread=threading.Thread(target=server.handle_request,daemon=True);thread.start()
        before=time.monotonic()
        try:return request('http://127.0.0.1:'+str(server.server_port)+path,seconds=seconds,limit=limit)
        finally:
            self.assertLess(time.monotonic()-before,1.5);server.server_close()
    def test_normal(self):self.assertEqual(self.run_case('/ok'),(200,b'JP'))
    def test_stall(self):
        with self.assertRaises(RequestFailure):self.run_case('/stall')
    def test_slow_drip_total_bound(self):
        with self.assertRaises(RequestFailure):self.run_case('/drip')
    def test_oversized(self):
        with self.assertRaises(RequestFailure):self.run_case('/large')

if __name__=='__main__':unittest.main()
