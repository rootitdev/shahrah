# SNI scout and candidate bank

`shahrah sni-bank` keeps a scored, self-expiring list of cover SNIs (REALITY
`serverNames`, TLS front names) for two regions: `foreign` (dest sites a
REALITY server borrows) and `ir` (domestic names that survive the national
allowlist). It stores hostnames and scores only, never keys or links.
The bank file defaults to `sni-bank.json` next to the state file (`--bank` overrides it).

## Score (0-100)

| factor | weight | source |
|---|---|---|
| TLS validity | gate | handshake OK and the chain verifies; otherwise the score is 0 |
| REALITY suitability | 15 | TLS 1.3 + X25519 + h2 ALPN, no redirect to another host |
| latency | 15 | handshake RTT from the server (lower is better) |
| DNS/IP plausibility | 35 | `sni_dns` verdict: the name must resolve to the server's own or a plausible network, because a mismatched SNI/IP pair is what a mismatch DPI (and the lab's `sni-dpi`) catches |
| certificate age/expiry | 10 | `notAfter` from the scout; near-expiry certs lose points |
| vantage | 25 | recent pass/fail reports from probes inside Iranian ASNs |

Any `blocked` sighting from a vantage newer than 6 h caps the score at 10.

## Expiry and rotation

- Each candidate expires 12 h after its last verification (`DEFAULT_TTL_S`). An expired candidate scores 0 until `refresh` runs again.
- `rotate` proposes the best candidate with a score of at least 50. It moves away from the active name only when the new one is 15 points better, so the choice does not flap. `rotate --apply` records the switch.

## Multi-vantage

A probe inside an ASN runs `sni-bank report --vantage ir-mci --asn 197207`, which
writes a JSON report. The operator then folds reports from several ASNs in with
`sni-bank merge FILE...`. `tactics.with_bank_snis()` gives each ASN profile the names that
pass on that ASN, and drops pinned names that are blocked there.
`ready-check --sni-bank PATH` flags link SNIs that are unknown to the bank, expired or blocked.
`tests/test_sni_bank.py` simulates two ASNs with different verdicts.

## CLI

    shahrah sni-bank seed | add HOST... --region ir | refresh [--all] [--node-ip IP]
    shahrah sni-bank list [--region R] [--strict-dns] [--json] | rotate --region R [--apply]
    shahrah sni-bank report --vantage NAME --asn N [--out F] | merge REPORT...

## Deferred: IP spoofing

Source-IP spoofing (for example, sending from an allowlisted domestic address) is
not implemented. It needs a provider capability check first: bare metal or own
BGP announcements with no BCP38 source filtering. Commodity VPS providers
filter spoofed sources. Spoofing also only helps on one-way paths.
