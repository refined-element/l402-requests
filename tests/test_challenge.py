"""Tests for L402 and MPP challenge parsing."""

import base64
import json
from dataclasses import FrozenInstanceError

import pytest

from l402_requests.challenge import (
    L402Challenge,
    MppChallenge,
    MppDraft00Challenge,
    build_payment_credential,
    find_l402_challenge,
    find_payment_challenge,
    parse_challenge,
    parse_mpp_challenge,
)
from l402_requests.exceptions import ChallengeParseError


# ── draft-00 fixture helpers ─────────────────────────────────────────────

FIXTURE_PAYMENT_HASH = "ab" * 32


def _b64url(data: bytes, padded: bool = False) -> str:
    if padded:
        # Force real '=' padding: JSON tolerates trailing whitespace, and a
        # length not divisible by 3 guarantees the encoding is padded.
        while len(data) % 3 == 0:
            data += b" "
    encoded = base64.urlsafe_b64encode(data).decode("ascii")
    return encoded if padded else encoded.rstrip("=")


def _make_request_param(
    amount: object = "1000",
    currency: object = "sat",
    invoice: object = "lnbc10u1ptest",
    payment_hash: str | None = None,
    network: str | None = None,
    padded: bool = False,
) -> str:
    """Build an encoded draft-00 ``request`` param (base64url JSON)."""
    details: dict = {}
    if invoice is not None:
        details["invoice"] = invoice
    if payment_hash is not None:
        details["paymentHash"] = payment_hash
    if network is not None:
        details["network"] = network
    body: dict = {"methodDetails": details}
    if amount is not None:
        body["amount"] = amount
    if currency is not None:
        body["currency"] = currency
    return _b64url(json.dumps(body).encode(), padded=padded)


def _make_modern_header(
    request_param: str | None = None,
    challenge_id: str | None = "fixture-challenge-id",
    realm: str | None = "api.example.com",
    method: str | None = "lightning",
    intent: str | None = "charge",
    expires: str | None = "2099-01-01T00:00:00Z",
    digest: str | None = None,
    description: str | None = None,
    opaque: str | None = None,
    extra: str = "",
) -> str:
    """Build a modern draft-00 Payment WWW-Authenticate header value."""
    if request_param is None:
        request_param = _make_request_param()
    params = []
    if challenge_id is not None:
        params.append(f'id="{challenge_id}"')
    if realm is not None:
        params.append(f'realm="{realm}"')
    if method is not None:
        params.append(f'method="{method}"')
    if intent is not None:
        params.append(f'intent="{intent}"')
    params.append(f'request="{request_param}"')
    if expires is not None:
        params.append(f'expires="{expires}"')
    if digest is not None:
        params.append(f'digest="{digest}"')
    if description is not None:
        params.append(f'description="{description}"')
    if opaque is not None:
        params.append(f'opaque="{opaque}"')
    header = "Payment " + ", ".join(params)
    if extra:
        header += ", " + extra
    return header


class TestParseChallenge:
    def test_standard_l402_quoted(self):
        header = 'L402 macaroon="abc123mac", invoice="lnbc10u1ptest"'
        result = parse_challenge(header)
        assert result.macaroon == "abc123mac"
        assert result.invoice == "lnbc10u1ptest"
        assert result.token_type == "L402"

    def test_standard_l402_unquoted(self):
        header = "L402 macaroon=abc123mac, invoice=lnbc10u1ptest"
        result = parse_challenge(header)
        assert result.macaroon == "abc123mac"
        assert result.invoice == "lnbc10u1ptest"

    def test_lsat_backwards_compat(self):
        header = 'LSAT macaroon="abc123mac", invoice="lnbc10u1ptest"'
        result = parse_challenge(header)
        assert result.macaroon == "abc123mac"
        assert result.invoice == "lnbc10u1ptest"

    def test_case_insensitive(self):
        header = 'l402 macaroon="abc123mac", invoice="lnbc10u1ptest"'
        result = parse_challenge(header)
        assert result.macaroon == "abc123mac"

    def test_empty_header_raises(self):
        with pytest.raises(ChallengeParseError, match="empty header"):
            parse_challenge("")

    def test_no_l402_challenge_raises(self):
        with pytest.raises(ChallengeParseError, match="no L402/LSAT challenge found"):
            parse_challenge("Basic realm=test")

    def test_complex_macaroon_value(self):
        mac = "AgEEbHNhdAJCAABhIGludm9pY2VfaWQ9dGVzdF8xMjM0NTY3ODkwAAAGIA"
        header = f'L402 macaroon="{mac}", invoice="lnbc500n1p0test"'
        result = parse_challenge(header)
        assert result.macaroon == mac

    def test_frozen_dataclass(self):
        challenge = L402Challenge(macaroon="mac", invoice="inv")
        with pytest.raises(AttributeError):
            challenge.macaroon = "new"  # type: ignore


class TestParseMppChallenge:
    def test_valid_mpp_header(self):
        header = 'Payment realm="api.example.com", method="lightning", invoice="lnbc100n1pjtest", amount="100", currency="sat"'
        result = parse_mpp_challenge(header)
        assert isinstance(result, MppChallenge)
        assert result.invoice == "lnbc100n1pjtest"
        assert result.amount == "100"
        assert result.currency == "sat"
        assert result.realm == "api.example.com"
        assert result.token_type == "Payment"

    def test_non_lightning_method(self):
        header = 'Payment method="stripe", invoice="lnbc100n1pjtest"'
        with pytest.raises(ChallengeParseError):
            parse_mpp_challenge(header)

    def test_missing_invoice(self):
        header = 'Payment method="lightning", amount="100"'
        with pytest.raises(ChallengeParseError):
            parse_mpp_challenge(header)

    def test_empty_header(self):
        with pytest.raises(ChallengeParseError):
            parse_mpp_challenge("")

    def test_none_header(self):
        with pytest.raises(ChallengeParseError):
            parse_mpp_challenge(None)

    def test_whitespace_only_header(self):
        with pytest.raises(ChallengeParseError):
            parse_mpp_challenge("   ")

    def test_minimal_header(self):
        result = parse_mpp_challenge('Payment method="lightning", invoice="lnbc100n1pjtest"')
        assert result.invoice == "lnbc100n1pjtest"
        assert result.amount is None
        assert result.currency is None
        assert result.realm is None

    def test_frozen(self):
        result = parse_mpp_challenge('Payment method="lightning", invoice="lnbc100n1pjtest"')
        with pytest.raises(FrozenInstanceError):
            result.invoice = "changed"  # type: ignore

    def test_case_insensitive_method(self):
        header = 'Payment method="Lightning", invoice="lnbc100n1pjtest"'
        result = parse_mpp_challenge(header)
        assert result.invoice == "lnbc100n1pjtest"

    def test_invoice_before_method(self):
        """Parameters can appear in any order per RFC 7235."""
        header = 'Payment invoice="lnbc100n1pjtest", method="lightning", amount="100"'
        result = parse_mpp_challenge(header)
        assert result.invoice == "lnbc100n1pjtest"
        assert result.amount == "100"

    def test_currency_parsed(self):
        header = 'Payment method="lightning", invoice="lnbc100n1pjtest", amount="500", currency="usd"'
        result = parse_mpp_challenge(header)
        assert result.currency == "usd"
        assert result.amount == "500"

    def test_currency_absent_is_none(self):
        header = 'Payment method="lightning", invoice="lnbc100n1pjtest", amount="500"'
        result = parse_mpp_challenge(header)
        assert result.currency is None

    def test_multiple_challenges_in_one_header(self):
        """Ensure Payment parsing does not cross into a different auth scheme."""
        # Payment has method="lightning" and invoice; Bearer follows with its
        # own realm.  The parser must not pick up Bearer's realm.
        header = (
            'Payment method="lightning", invoice="lnbc100n1pjtest", amount="100", currency="sat", '
            'Bearer realm="other-api"'
        )
        result = parse_mpp_challenge(header)
        assert result.invoice == "lnbc100n1pjtest"
        assert result.amount == "100"
        assert result.currency == "sat"
        # realm should be None — it belongs to the Bearer challenge, not Payment
        assert result.realm is None

    def test_multiple_challenges_method_in_wrong_scheme(self):
        """Payment without method="lightning" should fail even if another scheme has it."""
        # method="lightning" only appears in the Bearer segment, not in Payment.
        header = (
            'Payment invoice="lnbc100n1pjtest", amount="100", '
            'Bearer realm="api", method="lightning"'
        )
        with pytest.raises(ChallengeParseError):
            parse_mpp_challenge(header)


class TestFindL402Challenge:
    def test_finds_in_www_authenticate(self):
        headers = {
            "WWW-Authenticate": 'L402 macaroon="mac123", invoice="lnbc10u1p"',
            "Content-Type": "application/json",
        }
        result = find_l402_challenge(headers)
        assert result is not None
        assert isinstance(result, L402Challenge)
        assert result.macaroon == "mac123"

    def test_case_insensitive_header_name(self):
        headers = {
            "www-authenticate": 'L402 macaroon="mac123", invoice="lnbc10u1p"',
        }
        result = find_l402_challenge(headers)
        assert result is not None

    def test_returns_none_no_www_authenticate(self):
        headers = {"Content-Type": "application/json"}
        result = find_l402_challenge(headers)
        assert result is None

    def test_returns_none_on_unparseable(self):
        headers = {"WWW-Authenticate": "Bearer realm=test"}
        result = find_l402_challenge(headers)
        assert result is None


class TestFindPaymentChallenge:
    def test_l402_preferred_over_mpp(self):
        # When header contains L402 pattern, it should be returned
        headers = {"www-authenticate": 'L402 macaroon="abc", invoice="lnbc100n1pjtest"'}
        result = find_payment_challenge(headers)
        assert isinstance(result, L402Challenge)
        assert result.macaroon == "abc"

    def test_mpp_fallback(self):
        headers = {"www-authenticate": 'Payment method="lightning", invoice="lnbc100n1pjtest"'}
        result = find_payment_challenge(headers)
        assert isinstance(result, MppChallenge)
        assert result.invoice == "lnbc100n1pjtest"

    def test_mpp_with_full_params(self):
        headers = {
            "www-authenticate": 'Payment realm="api.example.com", method="lightning", invoice="lnbc100n1pjtest", amount="100", currency="sat"'
        }
        result = find_payment_challenge(headers)
        assert isinstance(result, MppChallenge)
        assert result.amount == "100"
        assert result.currency == "sat"
        assert result.realm == "api.example.com"

    def test_no_valid_header(self):
        headers = {"www-authenticate": "Bearer token123"}
        result = find_payment_challenge(headers)
        assert result is None

    def test_no_www_authenticate_header(self):
        headers = {"Content-Type": "application/json"}
        result = find_payment_challenge(headers)
        assert result is None

    def test_empty_headers(self):
        result = find_payment_challenge({})
        assert result is None

    def test_find_l402_challenge_returns_l402_only(self):
        # find_l402_challenge returns L402Challenge for L402 headers
        from l402_requests.challenge import find_l402_challenge

        headers = {"www-authenticate": 'L402 macaroon="abc", invoice="lnbc100n1pjtest"'}
        result = find_l402_challenge(headers)
        assert isinstance(result, L402Challenge)
        assert result.macaroon == "abc"

    def test_find_l402_challenge_ignores_mpp(self):
        # find_l402_challenge should NOT return MPP challenges (backward compat)
        from l402_requests.challenge import find_l402_challenge as alias

        headers = {"www-authenticate": 'Payment method="lightning", invoice="lnbc100n1pjtest"'}
        result = alias(headers)
        assert result is None


# ── draft-00 (modern Payment) challenge parsing ──────────────────────────


class TestParseMppDraft00Challenge:
    def test_happy_path_full_params(self):
        request_param = _make_request_param(
            payment_hash=FIXTURE_PAYMENT_HASH, network="mainnet"
        )
        header = _make_modern_header(request_param=request_param)

        result = parse_mpp_challenge(header)

        assert isinstance(result, MppDraft00Challenge)
        assert result.id == "fixture-challenge-id"
        assert result.realm == "api.example.com"
        assert result.method == "lightning"
        assert result.intent == "charge"
        assert result.request == request_param  # byte-exact encoded string
        assert result.expires == "2099-01-01T00:00:00Z"
        assert result.invoice == "lnbc10u1ptest"
        assert result.amount == "1000"
        assert result.currency == "sat"
        assert result.payment_hash == FIXTURE_PAYMENT_HASH
        assert result.network == "mainnet"
        assert result.token_type == "Payment"

    def test_is_mpp_challenge_subtype(self):
        result = parse_mpp_challenge(_make_modern_header())
        assert isinstance(result, MppChallenge)

    def test_frozen(self):
        result = parse_mpp_challenge(_make_modern_header())
        with pytest.raises(FrozenInstanceError):
            result.request = "changed"  # type: ignore

    def test_optional_params_parsed(self):
        header = _make_modern_header(
            digest="fixture-digest",
            description="Fixture resource",
            opaque="fixture-opaque",
        )
        result = parse_mpp_challenge(header)
        assert result.digest == "fixture-digest"
        assert result.description == "Fixture resource"
        assert result.opaque == "fixture-opaque"

    def test_optional_params_absent_are_none(self):
        result = parse_mpp_challenge(_make_modern_header())
        assert result.digest is None
        assert result.description is None
        assert result.opaque is None

    def test_optional_request_fields_absent_are_none(self):
        request_param = _make_request_param(amount=None, currency=None)
        result = parse_mpp_challenge(_make_modern_header(request_param=request_param))
        assert result.amount is None
        assert result.currency is None
        assert result.payment_hash is None
        assert result.network is None

    def test_request_with_padding_accepted_and_kept_byte_exact(self):
        request_param = _make_request_param(padded=True)
        assert request_param.endswith("=")  # fixture must actually be padded
        result = parse_mpp_challenge(_make_modern_header(request_param=request_param))
        assert result.invoice == "lnbc10u1ptest"
        # The received encoded string is stored untouched, padding included.
        assert result.request == request_param

    def test_expires_absent_ok(self):
        result = parse_mpp_challenge(_make_modern_header(expires=None))
        assert result.expires is None
        assert result.is_expired() is False

    def test_superset_header_prefers_modern(self):
        """A server may send one Payment header carrying BOTH modern and
        legacy params. Modern wins; the invoice comes from the decoded
        request, not the legacy invoice= param."""
        header = _make_modern_header(
            extra='invoice="lnbc20u1plegacy", amount="2000", currency="sat"'
        )
        result = parse_mpp_challenge(header)
        assert isinstance(result, MppDraft00Challenge)
        assert result.invoice == "lnbc10u1ptest"
        assert result.amount == "1000"

    def test_two_payment_challenges_prefers_modern(self):
        """Legacy Payment challenge first, modern second, one header value:
        the modern challenge must be selected."""
        legacy = 'Payment method="lightning", invoice="lnbc20u1plegacy", amount="2000", currency="sat"'
        header = legacy + ", " + _make_modern_header()
        result = parse_mpp_challenge(header)
        assert isinstance(result, MppDraft00Challenge)
        assert result.invoice == "lnbc10u1ptest"

    def test_modern_with_trailing_bearer_challenge(self):
        """Params from a following Bearer challenge must not bleed in."""
        header = _make_modern_header(realm=None, extra='Bearer realm="other-api"')
        result = parse_mpp_challenge(header)
        assert isinstance(result, MppDraft00Challenge)
        assert result.realm is None
        assert result.invoice == "lnbc10u1ptest"

    def test_malformed_request_bad_base64_raises(self):
        header = _make_modern_header(request_param="!!!not-base64url!!!")
        with pytest.raises(ChallengeParseError):
            parse_mpp_challenge(header)

    def test_malformed_request_bad_json_raises(self):
        header = _make_modern_header(request_param=_b64url(b"not json at all"))
        with pytest.raises(ChallengeParseError):
            parse_mpp_challenge(header)

    def test_malformed_request_non_object_json_raises(self):
        header = _make_modern_header(request_param=_b64url(b'["not", "an", "object"]'))
        with pytest.raises(ChallengeParseError):
            parse_mpp_challenge(header)

    def test_missing_invoice_raises(self):
        header = _make_modern_header(request_param=_make_request_param(invoice=None))
        with pytest.raises(ChallengeParseError):
            parse_mpp_challenge(header)

    def test_malformed_modern_not_silently_legacy(self):
        """A malformed modern challenge with NO legacy invoice= param must
        raise — never be quietly retried as legacy."""
        header = _make_modern_header(request_param=_b64url(b"not json at all"))
        with pytest.raises(ChallengeParseError):
            parse_mpp_challenge(header)

    def test_malformed_modern_with_superset_falls_back_to_legacy(self):
        """The superset case is the ONE sanctioned fallback: the same header
        carries legacy invoice= params as an intentional alternative."""
        header = _make_modern_header(
            request_param=_b64url(b"not json at all"),
            extra='invoice="lnbc20u1plegacy", amount="2000", currency="sat"',
        )
        result = parse_mpp_challenge(header)
        assert isinstance(result, MppChallenge)
        assert not isinstance(result, MppDraft00Challenge)
        assert result.invoice == "lnbc20u1plegacy"
        assert result.amount == "2000"

    def test_wrong_intent_raises(self):
        header = _make_modern_header(intent="hold")
        with pytest.raises(ChallengeParseError):
            parse_mpp_challenge(header)

    def test_wrong_intent_raises_even_with_superset_invoice(self):
        """An unsupported intent is a semantic refusal, not a malformed
        encoding — the legacy fallback does not apply."""
        header = _make_modern_header(
            intent="hold",
            extra='invoice="lnbc20u1plegacy", amount="2000", currency="sat"',
        )
        with pytest.raises(ChallengeParseError):
            parse_mpp_challenge(header)

    def test_missing_intent_raises(self):
        header = _make_modern_header(intent=None)
        with pytest.raises(ChallengeParseError):
            parse_mpp_challenge(header)

    def test_non_lightning_method_raises(self):
        header = _make_modern_header(method="card")
        with pytest.raises(ChallengeParseError):
            parse_mpp_challenge(header)

    def test_non_sat_currency_raises(self):
        header = _make_modern_header(
            request_param=_make_request_param(currency="usd")
        )
        with pytest.raises(ChallengeParseError):
            parse_mpp_challenge(header)

    def test_empty_request_param_is_legacy(self):
        """Detection rule: only a NON-EMPTY request param marks a modern
        challenge. An empty one plus legacy params parses as legacy."""
        header = (
            'Payment method="lightning", request="", '
            'invoice="lnbc20u1plegacy", amount="2000", currency="sat"'
        )
        result = parse_mpp_challenge(header)
        assert isinstance(result, MppChallenge)
        assert not isinstance(result, MppDraft00Challenge)
        assert result.invoice == "lnbc20u1plegacy"


class TestMppDraft00Expiry:
    def test_past_expires_is_expired(self):
        result = parse_mpp_challenge(
            _make_modern_header(expires="2001-01-01T00:00:00Z")
        )
        assert result.is_expired() is True

    def test_future_expires_not_expired(self):
        result = parse_mpp_challenge(
            _make_modern_header(expires="2099-01-01T00:00:00Z")
        )
        assert result.is_expired() is False

    def test_numeric_offset_form_accepted(self):
        result = parse_mpp_challenge(
            _make_modern_header(expires="2001-01-01T00:00:00+00:00")
        )
        assert result.is_expired() is True

    def test_absent_expires_never_expired(self):
        result = parse_mpp_challenge(_make_modern_header(expires=None))
        assert result.is_expired() is False

    def test_unparseable_expires_tolerated(self):
        result = parse_mpp_challenge(
            _make_modern_header(expires="not-a-timestamp")
        )
        assert result.is_expired() is False


class TestFindPaymentChallengeDraft00:
    def test_finds_modern_challenge(self):
        headers = {"www-authenticate": _make_modern_header()}
        result = find_payment_challenge(headers)
        assert isinstance(result, MppDraft00Challenge)
        assert result.invoice == "lnbc10u1ptest"

    def test_l402_still_preferred_over_modern_same_header(self):
        header = (
            'L402 macaroon="abc", invoice="lnbc10u1ptest", ' + _make_modern_header()
        )
        result = find_payment_challenge({"www-authenticate": header})
        assert isinstance(result, L402Challenge)
        assert result.macaroon == "abc"

    def test_find_l402_challenge_ignores_modern(self):
        headers = {"www-authenticate": _make_modern_header()}
        assert find_l402_challenge(headers) is None


# ── draft-00 credential builder ──────────────────────────────────────────


def _decode_credential(header_value: str) -> dict:
    """Decode an ``Authorization: Payment <token>`` value back to JSON."""
    assert header_value.startswith("Payment ")
    token = header_value[len("Payment "):]
    padded = token + "=" * (-len(token) % 4)
    return json.loads(base64.urlsafe_b64decode(padded))


class TestBuildPaymentCredential:
    PREIMAGE = "deadbeef" * 8

    def test_header_shape(self):
        challenge = parse_mpp_challenge(_make_modern_header())
        header_value = build_payment_credential(challenge, self.PREIMAGE)
        assert header_value.startswith("Payment ")
        token = header_value[len("Payment "):]
        # base64url without padding
        assert "=" not in token
        assert "+" not in token
        assert "/" not in token

    def test_challenge_echoed_byte_exact(self):
        request_param = _make_request_param(padded=True)
        header = _make_modern_header(request_param=request_param)
        challenge = parse_mpp_challenge(header)

        decoded = _decode_credential(build_payment_credential(challenge, self.PREIMAGE))

        echoed = decoded["challenge"]
        assert echoed["id"] == "fixture-challenge-id"
        assert echoed["realm"] == "api.example.com"
        assert echoed["method"] == "lightning"
        assert echoed["intent"] == "charge"
        # The encoded request string is echoed exactly as received — padding
        # and all — never decoded and re-encoded.
        assert echoed["request"] == request_param
        assert echoed["expires"] == "2099-01-01T00:00:00Z"

    def test_payload_preimage(self):
        challenge = parse_mpp_challenge(_make_modern_header())
        decoded = _decode_credential(build_payment_credential(challenge, self.PREIMAGE))
        assert decoded["payload"] == {"preimage": self.PREIMAGE}

    def test_uppercase_preimage_lowercased(self):
        challenge = parse_mpp_challenge(_make_modern_header())
        decoded = _decode_credential(
            build_payment_credential(challenge, self.PREIMAGE.upper())
        )
        assert decoded["payload"]["preimage"] == self.PREIMAGE

    def test_optional_params_echoed_when_present(self):
        header = _make_modern_header(
            digest="fixture-digest",
            description="Fixture resource",
            opaque="fixture-opaque",
        )
        challenge = parse_mpp_challenge(header)
        echoed = _decode_credential(
            build_payment_credential(challenge, self.PREIMAGE)
        )["challenge"]
        assert echoed["digest"] == "fixture-digest"
        assert echoed["description"] == "Fixture resource"
        assert echoed["opaque"] == "fixture-opaque"

    def test_absent_params_omitted(self):
        challenge = parse_mpp_challenge(_make_modern_header(expires=None))
        echoed = _decode_credential(
            build_payment_credential(challenge, self.PREIMAGE)
        )["challenge"]
        for absent in ("expires", "digest", "description", "opaque"):
            assert absent not in echoed

    def test_legacy_superset_extras_not_echoed(self):
        """invoice/amount/currency are unknown params to draft-00 — a superset
        challenge must not leak them into the credential echo."""
        header = _make_modern_header(
            extra='invoice="lnbc20u1plegacy", amount="2000", currency="sat"'
        )
        challenge = parse_mpp_challenge(header)
        echoed = _decode_credential(
            build_payment_credential(challenge, self.PREIMAGE)
        )["challenge"]
        for unknown in ("invoice", "amount", "currency"):
            assert unknown not in echoed

    def test_no_source_field(self):
        challenge = parse_mpp_challenge(_make_modern_header())
        decoded = _decode_credential(build_payment_credential(challenge, self.PREIMAGE))
        assert "source" not in decoded
        assert set(decoded.keys()) == {"challenge", "payload"}
