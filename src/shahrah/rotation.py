"""Standby rotation: replace burned or dead endpoints with pre-provisioned spares.

Shahrah ships no cloud-provider code, so "a new IP/domain" is provisioned ahead of time by the
operator (a spare server or a spare domain, already present in the panel as a host). Spares are
*standby* endpoints: probed like any other, but kept out of what clients see until needed.

A standby is promoted when

* an endpoint was declared burned (blocked in the field, fine from control), one spare per
  burned endpoint; or
* no non-standby endpoint is healthy at all (plain failover).

When the burn is forgiven (the endpoint is reachable again for long enough) the spare is
demoted again. Pure function, no I/O.
"""

from __future__ import annotations

from collections.abc import Collection, Sequence


def serving_ranking(
    ranking: Sequence[str],
    standby: Sequence[str],
    burned: Collection[str],
) -> tuple[str, ...]:
    """Return the healthy endpoints clients should currently be offered, best first.

    ``ranking`` is the Oracle's healthy list; ``standby`` the spares in promotion order.
    """
    spare = set(standby)
    healthy_active = [name for name in ranking if name not in spare]
    needed = len(burned)
    if not healthy_active:
        needed = max(needed, 1)
    healthy_spares = [name for name in standby if name in set(ranking)]
    promoted = set(healthy_spares[:needed])
    return tuple(name for name in ranking if name not in spare or name in promoted)
