import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ssl
import threading
import time

class Lab(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass
    def do_HEAD(self):
        self.do_GET()
    def do_GET(self):
        path = self.path.split("?")[0]
        status = 200
        content_type = "application/json"
        headers = {"Cache-Control": "no-store"}
        data = {"ok": True}
        if path == "/":
            content_type = "text/html"
            data = '<html><title>Aurora API Lab</title><a href="/api/valid">API</a><script src="/app.js"></script><form action="/api/search" method="get"><input name="q"></form><a href="http://outside.invalid/">Blocked</a></html>'
        elif path == "/app.js":
            content_type = "application/javascript"
            data = 'const profile="/api/profile";fetch("/api/valid");fetch("/api/undocumented");'
        elif path == "/api/valid":
            data = {"id": 1, "name": "Aurora fictitious"}
        elif path == "/api/broken":
            data = {"id": "incorrect-type"}
        elif path == "/api/crash":
            status = 500
            data = {"error": "fixture"}
        elif path == "/api/auth":
            if self.headers.get("Authorization") != "Bearer fictional-lab-token":
                status = 401
                data = {"error": "unauthorized"}
        elif path == "/api/timeout":
            time.sleep(12)
        elif path == "/redirect":
            status = 302
            headers["Location"] = "http://outside.invalid/"
        if not isinstance(data, str):
            data = json.dumps(data)
        body = data.encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for name, value in headers.items():
            self.send_header(name, value)
        self.end_headers()
        if self.command != "HEAD":
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass
    def do_POST(self):
        self.send_response(405)
        self.end_headers()

http = ThreadingHTTPServer(("0.0.0.0", 8080), Lab)
https = ThreadingHTTPServer(("0.0.0.0", 8443), Lab)
tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
tls.load_cert_chain("/lab/cert.pem", "/lab/key.pem")
https.socket = tls.wrap_socket(https.socket, server_side=True)
threading.Thread(target=https.serve_forever, daemon=True).start()
http.serve_forever()
