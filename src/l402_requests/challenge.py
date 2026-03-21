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
    currency: str | None = None
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
# First isolate the Payment challenge segment (per RFC 7235), then parse
# auth-params only from that segment to avoid crossing into other schemes.
_MPP_SEGMENT_RE = re.compile(
    r'Payment\s+(?P<params>[^\0]*)',
    re.IGNORECASE,
)

# A new auth scheme in a combined header looks like: ", SchemeToken "
# (unquoted alpha token followed by a space, NOT followed by '=').
_SCHEME_BOUNDARY_RE = re.compile(
    r',\s*[A-Za-z][A-Za-z0-9!#$&\-^_`|~]*\s+(?![=])',
)

# Auth-param extractors (applied only to the isolated Payment segment).
_PARAM_RE = re.compile(r'(\w+)="([^"]*)"', re.IGNORECASE)


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


def _extract_payment_segment(header: str) -> str | None:
    """Extract the auth-params belonging to the Payment scheme only.

    Per RFC 7235, a WWW-Authenticate header may contain multiple challenges
    separated by commas.  We locate the ``Payment`` scheme token and then
    collect everything until the start of the next scheme or end-of-string.
    """
    seg_match = _MPP_SEGMENT_RE.search(header)
    if seg_match is None:
        return None
    params_raw = seg_match.group("params")
    # Truncate at the boundary of the next auth scheme (if any).
    boundary = _SCHEME_BOUNDARY_RE.search(params_raw)
    if boundary:
        params_raw = params_raw[: boundary.start()]
    return params_raw


def parse_mpp_challenge(header: str | None) -> MppChallenge:
    """Parse a Payment (MPP) challenge from WWW-Authenticate header.

    Supports format:
        Payment realm="...", method="lightning", invoice="...", amount="...", currency="sat"

    Auth-params may appear in any order.  When multiple challenges coexist
    in a single header value, only the ``Payment`` segment is considered.

    Args:
        header: The WWW-Authenticate header value, or None.

    Returns:
        Parsed MppChallenge with invoice and optional amount/realm.

    Raises:
        ChallengeParseError: If the header cannot be parsed.
    """
    if not header or not header.strip():
        raise ChallengeParseError(header or "", "empty header")

    segment = _extract_payment_segment(header)
    if segment is None:
        raise ChallengeParseError(header, 'no Payment challenge found')

    # Parse all key="value" pairs from the isolated segment.
    params: dict[str, str] = {}
    for m in _PARAM_RE.finditer(segment):
        params[m.group(1).lower()] = m.group(2)

    if params.get("method", "").lower() != "lightning":
        raise ChallengeParseError(header, 'no Payment method="lightning" challenge found')

    invoice = params.get("invoice", "")
    if not invoice:
        raise ChallengeParseError(header, "empty invoice")

    return MppChallenge(
        invoice=invoice,
        amount=params.get("amount"),
        currency=params.get("currency"),
        realm=params.get("realm"),
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


def find_l402_challenge(headers: dict[str, str]) -> L402Challenge | None:
    """Search response headers for an L402 challenge only.

    This preserves the historical behavior of returning only an L402Challenge
    (or None) and will never return an MppChallenge.
    """
    raw = None
    if hasattr(headers, "get"):
        for key in headers:
            if key.lower() == "www-authenticate":
                raw = headers[key]
                break

    if raw is None:
        return None

    try:
        return parse_challenge(raw)
    except ChallengeParseError:
        return None
