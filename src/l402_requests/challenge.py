"""Parse L402 and MPP challenges from HTTP 402 responses."""

from __future__ import annotations

import re
from dataclasses import dataclass

from l402_requests.exceptions import ChallengeParseError


@dataclass(frozen=True)
class L402Challenge:
    """Parsed L402 challenge from a WWW-Authenticate header."""

    macaroon: str
    invoice: str

    @property
    def token_type(self) -> str:
        return "L402"


@dataclass(frozen=True)
class MppChallenge:
    """Parsed MPP challenge from a Payment WWW-Authenticate header.

    Per IETF draft-ryan-httpauth-payment (Machine Payments Protocol).
    """

    invoice: str
    amount: str | None = None
    realm: str | None = None

    @property
    def token_type(self) -> str:
        return "Payment"


# Matches: L402 macaroon="...", invoice="..."
# Also handles LSAT for backwards compatibility
_CHALLENGE_RE = re.compile(
    r'(?:L402|LSAT)\s+'
    r'macaroon="(?P<macaroon>[^"]+)"\s*,\s*'
    r'invoice="(?P<invoice>[^"]+)"',
    re.IGNORECASE,
)

# Some servers use space-separated key=value without quotes
_CHALLENGE_NOQUOTE_RE = re.compile(
    r'(?:L402|LSAT)\s+'
    r'macaroon=(?P<macaroon>[^\s,]+)\s*,?\s*'
    r'invoice=(?P<invoice>[^\s,]+)',
    re.IGNORECASE,
)

# MPP: Payment method="lightning", invoice="..."
_MPP_CHALLENGE_RE = re.compile(
    r'Payment\s+.*?method="lightning".*?invoice="(?P<invoice>[^"]+)"',
    re.IGNORECASE,
)

_MPP_AMOUNT_RE = re.compile(r'amount="(?P<amount>[^"]+)"', re.IGNORECASE)
_MPP_REALM_RE = re.compile(r'realm="(?P<realm>[^"]+)"', re.IGNORECASE)


def parse_challenge(header: str) -> L402Challenge:
    """Parse a WWW-Authenticate header containing an L402 challenge.

    Supports formats:
        L402 macaroon="<mac>", invoice="<bolt11>"
        L402 macaroon=<mac>, invoice=<bolt11>
        LSAT macaroon="<mac>", invoice="<bolt11>"  (legacy)

    Args:
        header: The WWW-Authenticate header value.

    Returns:
        Parsed L402Challenge with macaroon and invoice.

    Raises:
        ChallengeParseError: If the header cannot be parsed.
    """
    if not header:
        raise ChallengeParseError(header, "empty header")

    match = _CHALLENGE_RE.search(header) or _CHALLENGE_NOQUOTE_RE.search(header)
    if not match:
        raise ChallengeParseError(header, "no L402/LSAT challenge found")

    macaroon = match.group("macaroon").strip()
    invoice = match.group("invoice").strip()

    if not macaroon:
        raise ChallengeParseError(header, "empty macaroon")
    if not invoice:
        raise ChallengeParseError(header, "empty invoice")

    return L402Challenge(macaroon=macaroon, invoice=invoice)


def parse_mpp_challenge(header: str) -> MppChallenge:
    """Parse a Payment (MPP) challenge from WWW-Authenticate header.

    Supports format:
        Payment realm="...", method="lightning", invoice="...", amount="...", currency="sat"

    Args:
        header: The WWW-Authenticate header value.

    Returns:
        Parsed MppChallenge with invoice and optional amount/realm.

    Raises:
        ChallengeParseError: If the header cannot be parsed.
    """
    if not header or not header.strip():
        raise ChallengeParseError(header or "", "empty header")

    match = _MPP_CHALLENGE_RE.search(header)
    if not match:
        raise ChallengeParseError(header, 'no Payment method="lightning" challenge found')

    invoice = match.group("invoice")
    if not invoice:
        raise ChallengeParseError(header, "empty invoice")

    amount_match = _MPP_AMOUNT_RE.search(header)
    realm_match = _MPP_REALM_RE.search(header)

    return MppChallenge(
        invoice=invoice,
        amount=amount_match.group("amount") if amount_match else None,
        realm=realm_match.group("realm") if realm_match else None,
    )


def find_payment_challenge(
    headers: dict[str, str],
) -> L402Challenge | MppChallenge | None:
    """Search response headers for an L402 or MPP challenge.

    Prefers L402 when both are present. Falls back to MPP.

    Returns:
        Parsed L402Challenge or MppChallenge, or None if no valid challenge found.
    """
    raw = None
    if hasattr(headers, "get"):
        # Case-insensitive header lookup
        for key in headers:
            if key.lower() == "www-authenticate":
                raw = headers[key]
                break

    if raw is None:
        return None

    # Try L402 first (preferred)
    try:
        return parse_challenge(raw)
    except ChallengeParseError:
        pass

    # Try MPP fallback
    try:
        return parse_mpp_challenge(raw)
    except ChallengeParseError:
        pass

    return None


# Backward-compatible alias
find_l402_challenge = find_payment_challenge
