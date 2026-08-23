"""Parse the draft-00 ``Payment-Receipt`` response header.

Per draft-ryan-httpauth-payment-00, a server that accepted a Payment
credential may return a receipt on the successful response:

    Payment-Receipt: <base64url(JSON)>

decoding to ``{"challengeId", "method", "reference", "status", "timestamp"}``
where ``reference`` is the payment hash. The receipt contains no preimage, so
it is safe to store.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from l402_requests.challenge import _b64url_decode


@dataclass(frozen=True)
class PaymentReceipt:
    """A parsed draft-00 ``Payment-Receipt`` header.

    Any field the server omitted (or sent as a non-string) is None —
    receipts are informational and parsed tolerantly. ``raw`` keeps the
    encoded header value exactly as received, for durable logging.
    """

    challenge_id: str | None
    method: str | None
    reference: str | None
    status: str | None
    timestamp: str | None
    raw: str


def _string_or_none(value: object) -> str | None:
    return value if isinstance(value, str) else None


def parse_payment_receipt(value: str | None) -> PaymentReceipt | None:
    """Parse a ``Payment-Receipt`` header value, tolerantly.

    A missing or malformed receipt returns None rather than raising: older
    servers don't send the header at all, and a bad receipt must never fail
    an already-successful payment.

    Args:
        value: The raw header value, or None when the header was absent.

    Returns:
        The parsed receipt, or None when there is nothing usable to parse.
    """
    if not value or not value.strip():
        return None

    try:
        data = json.loads(_b64url_decode(value.strip()))
    except ValueError:
        # binascii.Error, JSONDecodeError and UnicodeDecodeError are all
        # ValueError subclasses — any of them means "not a usable receipt".
        return None
    if not isinstance(data, dict):
        return None

    return PaymentReceipt(
        challenge_id=_string_or_none(data.get("challengeId")),
        method=_string_or_none(data.get("method")),
        reference=_string_or_none(data.get("reference")),
        status=_string_or_none(data.get("status")),
        timestamp=_string_or_none(data.get("timestamp")),
        raw=value,
    )
