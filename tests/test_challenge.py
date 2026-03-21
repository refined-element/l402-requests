"""Tests for L402 and MPP challenge parsing."""

from dataclasses import FrozenInstanceError

import pytest

from l402_requests.challenge import (
    L402Challenge,
    MppChallenge,
    find_l402_challenge,
    find_payment_challenge,
    parse_challenge,
    parse_mpp_challenge,
)
from l402_requests.exceptions import ChallengeParseError


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
