"""Cover web server: an allowlisted site / CDN stand-in. HTTPS (TLS 1.3) on 443 and HTTP on 80.
/small = 2 KB (feed JSON/thumbnail), /media = 2 MB (a reel), / = 200."""

from __future__ import annotations

import ssl
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SMALL = b"s" * 2048
MEDIA = b"m" * (2 * 1024 * 1024)


class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a: object) -> None:
        return

    def do_GET(self) -> None:
        body = {"/small": SMALL, "/media": MEDIA}.get(self.path.split("?")[0], b"ok\n")
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)


class TLSServer(ThreadingHTTPServer):
    ctx: ssl.SSLContext

    def get_request(self):  # type: ignore[no-untyped-def]
        # handshake lazily in the handler thread, so one slow client cannot block accept()
        sock, addr = self.socket.accept()
        return self.ctx.wrap_socket(sock, server_side=True, do_handshake_on_connect=False), addr


def main() -> int:
    cert, key = sys.argv[1], sys.argv[2]
    plain = ThreadingHTTPServer(("0.0.0.0", 80), H)
    tls = TLSServer(("0.0.0.0", 443), H)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.set_alpn_protocols(["http/1.1"])
    ctx.load_cert_chain(cert, key)
    tls.ctx = ctx
    threading.Thread(target=plain.serve_forever, daemon=True).start()
    tls.serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
