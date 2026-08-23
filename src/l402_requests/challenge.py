"""Parse L402 and MPP challenges from HTTP 402 responses.

MPP ``Payment`` challenges come in two profiles, both handled here:

- **Legacy**: ``Payment method="lightning", invoice="lnbc..."`` with optional
  ``amount``/``currency``/``realm`` params.
- **Modern draft-00** (draft-ryan-httpauth-payment-00 +
  draft-lightning-charge-00): ``Payment id="...", realm="...",
  method="lightning", intent="charge", request="<b64url(JSON)>",
  expires="..."`` where the decoded ``request`` carries the invoice. Modern is
  preferred whenever a non-empty ``request`` param is present.
"""

from __future__ import annotations

import base64
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone

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


def _parse_rfc3339(value: str) -> datetime | None:
    """Parse an RFC 3339 timestamp, or None if it can't be read."""
    text = value.strip()
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


@dataclass(frozen=True)
class MppDraft00Challenge(MppChallenge):
    """Parsed modern (draft-00) Payment challenge.

    Per draft-ryan-httpauth-payment-00 with the draft-lightning-charge-00
    method profile. ``request`` holds the ENCODED base64url string exactly as
    received — the credential must echo it byte-exact, so it is never decoded
    and re-encoded. ``invoice``/``amount``/``currency`` (inherited) are filled
    from the DECODED request, not from legacy header params.

    Credentials answering a modern challenge are single-use server-side:
    never cache or replay one.
    """

    id: str | None = None
    method: str = "lightning"
    intent: str = "charge"
    request: str = ""
    expires: str | None = None
    digest: str | None = None
    description: str | None = None
    opaque: str | None = None
    payment_hash: str | None = None
    network: str | None = None

    def is_expired(self) -> bool:
        """Whether the challenge's ``expires`` timestamp is already past.

        Absent or unparseable ``expires`` reads as not expired (tolerant) —
        a genuinely stale invoice still fails at the wallet, without access
        having been granted.
        """
        if not self.expires:
            return False
        expires_at = _parse_rfc3339(self.expires)
        if expires_at is None:
            return False
        return datetime.now(timezone.utc) >= expires_at


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

# A Payment scheme token at the start of the header or of a new challenge
# (after a comma). Used to find EVERY Payment challenge in a combined header,
# so a modern draft-00 challenge is seen even when a legacy one comes first.
_MPP_SCHEME_TOKEN_RE = re.compile(r'(?:^|,)\s*Payment\s+', re.IGNORECASE)


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


def _extract_payment_segments(header: str) -> list[str]:
    """All ``Payment``-scheme param segments in the header, in order.

    Unlike :func:`_extract_payment_segment`, this finds EVERY Payment
    challenge in a combined header value, so a modern draft-00 challenge can
    be preferred even when a legacy Payment challenge precedes it.  Falls back
    to the historical single-segment extractor for anything it can't anchor.
    """
    segments: list[str] = []
    for match in _MPP_SCHEME_TOKEN_RE.finditer(header):
        params_raw = header[match.end():]
        boundary = _SCHEME_BOUNDARY_RE.search(params_raw)
        if boundary:
            params_raw = params_raw[: boundary.start()]
        segments.append(params_raw)
    if not segments:
        legacy = _extract_payment_segment(header)
        if legacy is not None:
            segments.append(legacy)
    return segments


class _MalformedModernRequestError(Exception):
    """Internal: the modern ``request`` param is malformed — bad base64url,
    bad JSON, or missing invoice.  This is the ONE class of failure the
    legacy-superset fallback applies to; semantic refusals (wrong method,
    intent, or currency) raise :class:`ChallengeParseError` directly and are
    never retried as legacy."""


def _b64url_decode(value: str) -> bytes:
    """Decode base64url, accepting input with or without padding."""
    text = value.strip()
    padded = text + "=" * (-len(text) % 4)
    return base64.b64decode(padded, altchars=b"-_", validate=True)


def _decode_modern_request(encoded: str) -> tuple[dict, dict]:
    """Decode a modern ``request`` param into (request JSON, methodDetails).

    Raises:
        _MalformedModernRequestError: On bad base64url, bad JSON, or a
            missing/empty ``methodDetails.invoice``.
    """
    try:
        raw = _b64url_decode(encoded)
    except ValueError as e:  # binascii.Error is a ValueError subclass
        raise _MalformedModernRequestError(
            "Payment request param is not valid base64url"
        ) from e
    try:
        data = json.loads(raw)
    except ValueError as e:  # JSONDecodeError / UnicodeDecodeError
        raise _MalformedModernRequestError(
            "Payment request param is not valid JSON"
        ) from e
    if not isinstance(data, dict):
        raise _MalformedModernRequestError(
            "Payment request param is not a JSON object"
        )
    details = data.get("methodDetails")
    if not isinstance(details, dict):
        raise _MalformedModernRequestError(
            "Payment request param has no methodDetails.invoice"
        )
    invoice = details.get("invoice")
    if not isinstance(invoice, str) or not invoice.strip():
        raise _MalformedModernRequestError(
            "Payment request param has no methodDetails.invoice"
        )
    return data, details


def _parse_modern_params(header: str, params: dict[str, str]) -> MppDraft00Challenge:
    """Parse a modern draft-00 challenge from its extracted auth-params.

    Sanity checks (spec rule: verify before paying): the method must be
    ``lightning``, the intent ``charge``, and the currency ``sat`` when
    present.  Those failures are semantic refusals raising
    :class:`ChallengeParseError` — the legacy-superset fallback does NOT
    apply to them, only to a malformed ``request`` encoding.
    """
    if params.get("method", "").lower() != "lightning":
        raise ChallengeParseError(
            header, 'no Payment method="lightning" challenge found'
        )
    if params.get("intent", "").lower() != "charge":
        raise ChallengeParseError(
            header, 'unsupported Payment intent (only "charge" is supported)'
        )

    encoded = params["request"]
    data, details = _decode_modern_request(encoded)

    currency = data.get("currency")
    if currency is not None:
        currency = str(currency)
        if currency.lower() != "sat":
            raise ChallengeParseError(
                header, 'unsupported Payment currency (only "sat" is supported)'
            )

    amount = data.get("amount")
    if amount is not None and not isinstance(amount, str):
        amount = str(amount)

    payment_hash = details.get("paymentHash")
    network = details.get("network")

    return MppDraft00Challenge(
        invoice=details["invoice"],
        amount=amount,
        currency=currency,
        realm=params.get("realm"),
        id=params.get("id"),
        method=params.get("method", ""),
        intent=params.get("intent", ""),
        request=encoded,  # the received encoded string, byte-exact
        expires=params.get("expires"),
        digest=params.get("digest"),
        description=params.get("description"),
        opaque=params.get("opaque"),
        payment_hash=payment_hash if isinstance(payment_hash, str) else None,
        network=network if isinstance(network, str) else None,
    )


def _parse_legacy_params(header: str, params: dict[str, str]) -> MppChallenge:
    """Parse a legacy Payment challenge from its extracted auth-params."""
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


def parse_mpp_challenge(header: str | None) -> MppChallenge:
    """Parse a Payment (MPP) challenge from a WWW-Authenticate header.

    Supports both profiles:

        Payment realm="...", method="lightning", invoice="...", amount="...", currency="sat"
        Payment id="...", realm="...", method="lightning", intent="charge", request="<b64url>", expires="..."

    Auth-params may appear in any order, and unknown params are ignored per
    RFC 9110.  A challenge with a non-empty ``request`` param is modern
    draft-00; modern is preferred over legacy when both are present — whether
    as one superset challenge or as separate challenges in the header.  A
    malformed modern challenge is NOT silently retried as legacy unless the
    same challenge also carries legacy ``invoice=`` params (the superset
    case, where the legacy params are an intentional fallback).

    Args:
        header: The WWW-Authenticate header value, or None.

    Returns:
        Parsed MppDraft00Challenge (modern) or MppChallenge (legacy).

    Raises:
        ChallengeParseError: If the header cannot be parsed.
    """
    if not header or not header.strip():
        raise ChallengeParseError(header or "", "empty header")

    segments = _extract_payment_segments(header)
    if not segments:
        raise ChallengeParseError(header, 'no Payment challenge found')

    modern_error: ChallengeParseError | None = None
    legacy_param_sets: list[dict[str, str]] = []

    for segment in segments:
        # Parse all key="value" pairs from the isolated segment.
        params: dict[str, str] = {}
        for m in _PARAM_RE.finditer(segment):
            params[m.group(1).lower()] = m.group(2)

        if params.get("request"):
            try:
                return _parse_modern_params(header, params)
            except _MalformedModernRequestError as e:
                if params.get("invoice"):
                    # Superset challenge: the legacy params are an intentional
                    # fallback the server offered alongside the modern ones.
                    legacy_param_sets.append(params)
                elif modern_error is None:
                    modern_error = ChallengeParseError(header, str(e))
            # A semantic ChallengeParseError (method/intent/currency)
            # propagates — never silently downgraded to legacy.
        else:
            legacy_param_sets.append(params)

    legacy_error: ChallengeParseError | None = None
    for params in legacy_param_sets:
        try:
            return _parse_legacy_params(header, params)
        except ChallengeParseError as e:
            if legacy_error is None:
                legacy_error = e

    raise modern_error or legacy_error or ChallengeParseError(
        header, 'no Payment challenge found'
    )


# Spec-defined challenge params, echoed byte-exact into the credential when
# present.  Legacy superset extras (invoice/amount/currency) are unknown
# params to draft-00 and are deliberately NOT in this list.
_CREDENTIAL_ECHO_PARAMS = (
    "id",
    "realm",
    "method",
    "intent",
    "request",
    "expires",
    "digest",
    "description",
    "opaque",
)


def build_payment_credential(challenge: MppDraft00Challenge, preimage: str) -> str:
    """Build the retry ``Authorization`` value for a modern Payment challenge.

    Echoes every spec-defined challenge param that was received, byte-exact —
    in particular ``request`` is the received ENCODED string, never decoded
    and re-encoded.  The preimage is lowercased before insertion (wallets
    sometimes return uppercase hex).  The credential envelope is compact JSON
    encoded as base64url without padding.

    Modern credentials are SINGLE-USE server-side: never cache or replay one.

    Args:
        challenge: The parsed modern challenge being answered.
        preimage: The Lightning payment preimage (hex) proving settlement.

    Returns:
        The full header value: ``Payment <base64url(JSON, no padding)>``.
    """
    echoed = {
        name: getattr(challenge, name)
        for name in _CREDENTIAL_ECHO_PARAMS
        if getattr(challenge, name) is not None
    }
    body = {"challenge": echoed, "payload": {"preimage": preimage.strip().lower()}}
    token = (
        base64.urlsafe_b64encode(
            json.dumps(body, separators=(",", ":")).encode("utf-8")
        )
        .decode("ascii")
        .rstrip("=")
    )
    return f"Payment {token}"


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
