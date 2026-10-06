import json
import ssl
import threading
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from urllib.parse import urlsplit,parse_qs

class Lab(BaseHTTPRequestHandler):
    server_version='Aurora-Lab/1.0'
    def log_message(self,*args):
        pass
    def do_GET(self):
        u=urlsplit(self.path)
        q=parse_qs(u.query)
        host=self.headers.get('Host','')
        data={'ok':True}
        mime='application/json'
        status=200
        if host.startswith('crt.sh'):
            data=[{'name_value':'api.aurora.test\nstaging.aurora.test','common_name':'api.aurora.test','id':1}]
        elif host.startswith('api.certspotter.com'):
            data=[{'id':'1','dns_names':['api.aurora.test','staging.aurora.test']}]
        elif host.startswith('web.archive.org'):
            data=[['original','timestamp','statuscode','mimetype'],['https://aurora.test:8443/api/valid','20260101000000','200','application/json']]
        elif host.startswith('internetdb.shodan.io'):
            data={'ip':'203.0.113.10','ports':[80,443],'hostnames':['api.aurora.test'],'cpes':[],'tags':[],'vulns':[]}
        elif u.path=='/':
            mime='text/html'
            data='<html><title>Aurora Lab</title><a href="/admin">Admin</a></html>'
        elif u.path=='/reflect':
            mime='text/html'
            data='<html><input name="q" value="'+q.get('q',[''])[0]+'"></html>'
        elif u.path=='/parameters':
            data={'ok':True,'selected':q.get('debug',[''])[0]} if 'debug' in q else {'ok':True}
        elif u.path not in ['/admin','/api/valid']:
            status=404
            data={'error':'not found'}
        wire=(data if isinstance(data,str) else json.dumps(data)).encode()
        self.send_response(status)
        self.send_header('Content-Type',mime)
        self.send_header('Content-Length',str(len(wire)))
        self.send_header('Cache-Control','no-store')
        self.end_headers()
        try:
            self.wfile.write(wire)
        except (BrokenPipeError,ConnectionResetError):
            pass
    def do_POST(self):
        self.send_response(405)
        self.end_headers()

http=ThreadingHTTPServer(('0.0.0.0',8080),Lab)
https=ThreadingHTTPServer(('0.0.0.0',8443),Lab)
tls=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
tls.load_cert_chain('/lab/cert.pem','/lab/key.pem')
https.socket=tls.wrap_socket(https.socket,server_side=True)
threading.Thread(target=https.serve_forever,daemon=True).start()
http.serve_forever()
