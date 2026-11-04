from __future__ import annotations

import socket
import threading

from shahrah.edge_proxy import tcp_edge


def test_tcp_edge_forwards_bytes() -> None:
    upstream = socket.socket()
    upstream.bind(("127.0.0.1", 0))
    upstream.listen(1)
    up_port = upstream.getsockname()[1]
    got: list[bytes] = []

    def accept() -> None:
        conn, _ = upstream.accept()
        with conn:
            got.append(conn.recv(64))
            conn.sendall(b"pong")

    threading.Thread(target=accept, daemon=True).start()
    with tcp_edge("127.0.0.1", up_port) as edge:
        client = socket.create_connection(("127.0.0.1", edge.listen_port), timeout=3)
        with client:
            client.sendall(b"ping")
            assert client.recv(64) == b"pong"
        assert edge.accepted == 1
    upstream.close()
    assert got == [b"ping"]
