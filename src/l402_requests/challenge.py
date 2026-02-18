"""Parse L402 challenges from HTTP 402 responses."""

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


def find_l402_challenge(headers: dict[str, str]) -> L402Challenge | None:
    """Search response headers for an L402 challenge.

    Checks WWW-Authenticate (standard) and common variations.

    Returns:
        Parsed challenge, or None if no L402 challenge found.
    """
    # Normalize header names to lowercase for case-insensitive lookup
    lower_headers = {k.lower(): v for k, v in headers.items()}

    www_auth = lower_headers.get("www-authenticate", "")
    if not www_auth:
        return None

    try:
        return parse_challenge(www_auth)
    except ChallengeParseError:
        return None
