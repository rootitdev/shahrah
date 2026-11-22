"""Tiny TCP forwarder that stands in for a CDN edge in lab tests.

Production edges (Cloudflare, …) terminate TLS and forward HTTP to the origin. For
Shahrah's ``cdn-xhttp`` profile the origin speaks plain XHTTP; this helper only proves the
*indirection* — clients hit ``edge_host:edge_port``, never the origin IP directly.
"""

from __future__ import annotations

import socket
import threading
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from dataclasses import dataclass

from .models import ConfigError


@dataclass
class EdgeProxy:
    listen_port: int
    upstream_host: str
    upstream_port: int
    _stop: threading.Event
    _thread: threading.Thread | None = None
    accepted: int = 0


def _pipe(src: socket.socket, dst: socket.socket) -> None:
    try:
        while True:
            data = src.recv(65536)
            if not data:
                break
            dst.sendall(data)
    except OSError:
        pass
    finally:
        for sock in (src, dst):
            with suppress(OSError):
                sock.shutdown(socket.SHUT_RDWR)
            sock.close()


@contextmanager
def tcp_edge(
    upstream_host: str,
    upstream_port: int,
    *,
    listen_host: str = "127.0.0.1",
) -> Iterator[EdgeProxy]:
    """Bind an ephemeral port and forward every accepted TCP stream upstream."""
    if not upstream_host or upstream_port <= 0:
        raise ConfigError("edge proxy needs a valid upstream")
    listen = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listen.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listen.bind((listen_host, 0))
    listen.listen(128)
    listen.settimeout(0.5)
    port = listen.getsockname()[1]
    stop = threading.Event()
    state = EdgeProxy(port, upstream_host, upstream_port, stop)

    def serve() -> None:
        while not stop.is_set():
            try:
                client, _ = listen.accept()
            except TimeoutError:
                continue
            except OSError:
                break
            state.accepted += 1
            try:
                upstream = socket.create_connection((upstream_host, upstream_port), timeout=5)
            except OSError:
                client.close()
                continue
            threading.Thread(target=_pipe, args=(client, upstream), daemon=True).start()
            threading.Thread(target=_pipe, args=(upstream, client), daemon=True).start()

    thread = threading.Thread(target=serve, daemon=True)
    state._thread = thread
    thread.start()
    try:
        yield state
    finally:
        stop.set()
        listen.close()
        thread.join(timeout=3)
