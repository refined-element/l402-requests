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

# Match the WHOLE human-readable part: ln + network + optional(amount +
# multiplier). Terminated with "$" (not a trailing "1") so it only ever matches
# a complete HRP, never a prefix that stops at an earlier "1". The HRP is
# isolated first (see _human_readable_part); anchoring here as well means a
# digit sitting in the bech32 data part can never be lifted out as the amount.
_BOLT11_HRP_RE = re.compile(
    r'^ln(?P<network>[a-z]+?)'
    r'(?P<amount>\d+)?'
    r'(?P<multiplier>[munp])?'
    r'$',
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


def _human_readable_part(bolt11: str) -> str | None:
    """Return the BOLT11 human-readable part, or None if there is no separator.

    Per BIP-173 the bech32 separator is the LAST ``"1"`` in the string: the data
    charset excludes ``"1"``, so every earlier ``"1"`` belongs to the HRP (only
    ever inside the amount). Everything before that final ``"1"`` is the HRP; the
    amount must be read from there and nowhere else.

    Isolating the HRP with ``rfind("1")`` — rather than letting a regex stop at
    the FIRST ``"1"`` — is what prevents a digit in the DATA part, or a crafted
    stray ``"1"``, from being matched as a bogus amount (ledger #74). Mirrors the
    hardened decoder in le-agent-sdk-python's ``_decode_invoice_amount_sats``.
    """
    invoice = bolt11.strip().lower()
    separator = invoice.rfind("1")
    if separator < 0:
        return None
    return invoice[:separator]


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

    hrp = _human_readable_part(bolt11)
    if hrp is None or not _BOLT11_HRP_RE.match(hrp):
        return UNPARSEABLE

    # The HRP read cleanly, so a missing amount group is the only way
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

    hrp = _human_readable_part(bolt11)
    if hrp is None:
        return None

    match = _BOLT11_HRP_RE.match(hrp)
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
