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


#: Why :func:`extract_amount_sats` could not determine an amount.
#:
#: - ``"no-amount-encoded"`` — the invoice parsed fine but carries no amount
#:   (a zero-amount / "any amount" invoice, where the payer picks the value).
#: - ``"unparseable"`` — the string could not be read as a BOLT11 invoice.
#:
#: Both mean the amount is unknown and so cannot be authorised, but they point
#: at different causes: a server that sent an amountless invoice, versus one
#: that sent something malformed or unsupported.
NO_AMOUNT_ENCODED = "no-amount-encoded"
UNPARSEABLE = "unparseable"


def classify_missing_amount(bolt11: str) -> str:
    """Explain why :func:`extract_amount_sats` returned None for an invoice.

    Only meaningful when ``extract_amount_sats(bolt11)`` returned None; it
    re-reads the invoice to separate the two causes. Deliberately off the happy
    path — callers use it to build an error message, not to decide pay vs.
    refuse.

    Args:
        bolt11: The invoice ``extract_amount_sats`` could not price.

    Returns:
        Either ``NO_AMOUNT_ENCODED`` or ``UNPARSEABLE``.
    """
    if not bolt11:
        return UNPARSEABLE

    if not _BOLT11_RE.match(bolt11.strip().lower()):
        return UNPARSEABLE

    # The prefix read cleanly, so a missing amount group is the only way
    # extract_amount_sats could have returned None for this invoice.
    return NO_AMOUNT_ENCODED


def extract_amount_sats(bolt11: str) -> int | None:
    """Extract the amount in satoshis from a BOLT11 invoice string.

    Args:
        bolt11: A BOLT11-encoded Lightning invoice (e.g., "lnbc10u1p...").

    Returns:
        Amount in satoshis as an integer, or None if the amount cannot be
        determined — either none is encoded (zero-amount / "any amount"
        invoices) or the invoice cannot be parsed. Use
        :func:`classify_missing_amount` to tell those apart.

        Callers must NOT read None as "no limit applies": an amount that cannot
        be determined cannot be checked against a budget, so it must be refused
        rather than paid.
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
