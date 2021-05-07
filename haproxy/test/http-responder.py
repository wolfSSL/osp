#!/usr/bin/python3

from http.server import HTTPServer, BaseHTTPRequestHandler
from sys import argv

class EmptyResponseHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()

def run(server_class=HTTPServer, handler_class=EmptyResponseHandler, port=10082):
    server_address = ('', port)
    httpd = server_class(server_address, handler_class)
    httpd.serve_forever()

if __name__ == '__main__':
    if len(argv) == 2:
        run(port=int(argv[1]))
    else:
        run()
