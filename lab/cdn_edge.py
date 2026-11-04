"""Lab CDN edge (stdlib): terminates TLS for cdn.lab on :443 and forwards the plain bytes to
the origin's cdn-xhttp listener, like a CDN in "full" mode without caching or rewriting.

Usage: cdn_edge.py CERT KEY ORIGIN_HOST ORIGIN_PORT
"""

from __future__ import annotations

import socket
import ssl
import sys
import threading
from contextlib import suppress


def pipe(src: socket.socket, dst: socket.socket) -> None:
    try:
        while data := src.recv(65536):
            dst.sendall(data)
    except OSError:
        pass
    finally:
        for s in (src, dst):
            with suppress(OSError):
                s.shutdown(socket.SHUT_RDWR)


def serve(conn: socket.socket, ctx: ssl.SSLContext, origin: tuple[str, int]) -> None:
    try:
        tls = ctx.wrap_socket(conn, server_side=True)
        up = socket.create_connection(origin, timeout=10)
        up.settimeout(None)
    except OSError:
        conn.close()
        return
    threading.Thread(target=pipe, args=(up, tls), daemon=True).start()
    pipe(tls, up)


def main() -> int:
    cert, key, host, port = sys.argv[1:5]
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    ctx.set_alpn_protocols(["http/1.1"])
    srv = socket.create_server(("0.0.0.0", 443), backlog=256)
    print("cdn edge on :443 ->", host, port, flush=True)
    while True:
        conn, _ = srv.accept()
        threading.Thread(target=serve, args=(conn, ctx, (host, int(port))), daemon=True).start()


if __name__ == "__main__":
    sys.exit(main())
