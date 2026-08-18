#!/usr/bin/env python3
"""cli-spy-receive: catch sealed findings, decrypt, print json.
usage: cli-spy-receive.py <cli-spy.sk> <port>

incredibly basic listener with blob decryption for demo/lab purposes
"""
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from nacl.public import PrivateKey, PublicKey, Box

SK = PrivateKey(bytes.fromhex(open(sys.argv[1]).read().strip()))


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        blob = self.rfile.read(n) if n else b""
        try:
            epk, nonce, ct = blob[:32], blob[32:56], blob[56:]
            print(Box(SK, PublicKey(epk)).decrypt(ct, nonce).decode(),
                  end="", flush=True)
        except Exception as e:
            print(f"[!] dropped bad blob ({len(blob)}B): {e}",
                  file=sys.stderr)
        self.send_response(200)
        self.end_headers()

    def log_message(self, *args):
        pass


HTTPServer(("0.0.0.0", int(sys.argv[2])), Handler).serve_forever()
