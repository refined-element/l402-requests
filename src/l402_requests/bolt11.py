"""Pure Python BOLT11 invoice amount extraction.

Parses the human-readable part of a BOLT11 invoice to extract the amount
in satoshis. No external Lightning libraries required.

BOLT11 format: ln{bc|tb|...}{amount}{multiplier}1{data}
Multipliers: m (milli = 0.001), u (micro = 0.000001),
             n (nano = 0.000000001), p (pico = 0.000000000001)
"""

from __future__ import annotations

import re
from decimal import Decimal

# Match: ln + network + optional(amount + optional multiplier) + "1" separator
_BOLT11_RE = re.compile(
    r'^ln(?P<network>[a-z]+?)'
    r'(?P<amount>\d+)?'
    r'(?P<multiplier>[munp])?'
    r'1',
    re.IGNORECASE,
)

_MULTIPLIERS: dict[str, Decimal] = {
    "m": Decimal("0.001"),
    "u": Decimal("0.000001"),
    "n": Decimal("0.000000001"),
    "p": Decimal("0.000000000001"),
}

_SATS_PER_BTC = Decimal("100000000")


def extract_amount_sats(bolt11: str) -> int | None:
    """Extract the amount in satoshis from a BOLT11 invoice string.

    Args:
        bolt11: A BOLT11-encoded Lightning invoice (e.g., "lnbc10u1p...").

    Returns:
        Amount in satoshis as an integer, or None if no amount is encoded
        (zero-amount / "any amount" invoices).
    """
    if not bolt11:
        return None

    invoice = bolt11.strip().lower()
    match = _BOLT11_RE.match(invoice)
    if not match:
        return None

    amount_str = match.group("amount")
    if amount_str is None:
        # No amount specified — this is a "any amount" invoice
        return None

    amount = Decimal(amount_str)
    multiplier = match.group("multiplier")

    if multiplier:
        btc_amount = amount * _MULTIPLIERS[multiplier.lower()]
    else:
        # No multiplier means the amount is in BTC
        btc_amount = amount

    sats = btc_amount * _SATS_PER_BTC
    return int(sats)
