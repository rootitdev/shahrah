"""Two named peers render distinct configs (unit).

WW multi-instance binary e2e: optional via SHAHRAH_WW_BIN in test_waterwall_e2e.
"""

from __future__ import annotations

from shahrah.relay_peers import RelayPeer, render_peer_configs


def test_two_peers_distinct_ports_and_configs() -> None:
    iran = "198.51.100.2"
    de = RelayPeer("de", "203.0.113.1", user_port=443, tunnel_port=8443, iran_ip=iran)
    tr = RelayPeer("tr", "203.0.113.2", user_port=4430, tunnel_port=9453, iran_ip=iran)
    c1, _ = render_peer_configs(de, "passwordone1234567", iran)
    c2, _ = render_peer_configs(tr, "passwordtwo1234567", iran)
    assert c1 != c2
