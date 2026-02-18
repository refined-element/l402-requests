"""Tests for L402 challenge parsing."""

import pytest

from l402_requests.challenge import L402Challenge, find_l402_challenge, parse_challenge
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


class TestFindL402Challenge:
    def test_finds_in_www_authenticate(self):
        headers = {
            "WWW-Authenticate": 'L402 macaroon="mac123", invoice="lnbc10u1p"',
            "Content-Type": "application/json",
        }
        result = find_l402_challenge(headers)
        assert result is not None
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
