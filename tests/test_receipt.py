"""Tests for Payment-Receipt (draft-00) parsing."""

import base64
import json
from dataclasses import FrozenInstanceError

import pytest

from l402_requests.receipt import PaymentReceipt, parse_payment_receipt

FIXTURE_PAYMENT_HASH = "ab" * 32


def _b64url(data: bytes, padded: bool = False) -> str:
    if padded:
        # Force real '=' padding: JSON tolerates trailing whitespace, and a
        # length not divisible by 3 guarantees the encoding is padded.
        while len(data) % 3 == 0:
            data += b" "
    encoded = base64.urlsafe_b64encode(data).decode("ascii")
    return encoded if padded else encoded.rstrip("=")


def _make_receipt_value(padded: bool = False, **overrides) -> str:
    body = {
        "challengeId": "fixture-challenge-id",
        "method": "lightning",
        "reference": FIXTURE_PAYMENT_HASH,
        "status": "settled",
        "timestamp": "2026-08-23T00:00:00Z",
    }
    body.update(overrides)
    return _b64url(json.dumps(body).encode(), padded=padded)


class TestParsePaymentReceipt:
    def test_valid_receipt(self):
        value = _make_receipt_value()
        receipt = parse_payment_receipt(value)
        assert isinstance(receipt, PaymentReceipt)
        assert receipt.challenge_id == "fixture-challenge-id"
        assert receipt.method == "lightning"
        assert receipt.reference == FIXTURE_PAYMENT_HASH
        assert receipt.status == "settled"
        assert receipt.timestamp == "2026-08-23T00:00:00Z"

    def test_raw_preserved(self):
        value = _make_receipt_value()
        receipt = parse_payment_receipt(value)
        assert receipt.raw == value

    def test_padded_input_accepted(self):
        value = _make_receipt_value(padded=True)
        assert value.endswith("=")  # fixture must actually be padded
        receipt = parse_payment_receipt(value)
        assert receipt is not None
        assert receipt.reference == FIXTURE_PAYMENT_HASH

    def test_none_returns_none(self):
        assert parse_payment_receipt(None) is None

    def test_empty_returns_none(self):
        assert parse_payment_receipt("") is None

    def test_whitespace_returns_none(self):
        assert parse_payment_receipt("   ") is None

    def test_bad_base64_returns_none(self):
        assert parse_payment_receipt("!!!not-base64url!!!") is None

    def test_bad_json_returns_none(self):
        assert parse_payment_receipt(_b64url(b"not json at all")) is None

    def test_non_object_json_returns_none(self):
        assert parse_payment_receipt(_b64url(b'["not", "an", "object"]')) is None

    def test_missing_fields_tolerated(self):
        value = _b64url(json.dumps({"status": "settled"}).encode())
        receipt = parse_payment_receipt(value)
        assert receipt is not None
        assert receipt.status == "settled"
        assert receipt.challenge_id is None
        assert receipt.method is None
        assert receipt.reference is None
        assert receipt.timestamp is None

    def test_non_string_fields_tolerated(self):
        value = _make_receipt_value(status=42)
        receipt = parse_payment_receipt(value)
        assert receipt is not None
        assert receipt.status is None
        assert receipt.reference == FIXTURE_PAYMENT_HASH

    def test_frozen(self):
        receipt = parse_payment_receipt(_make_receipt_value())
        with pytest.raises(FrozenInstanceError):
            receipt.status = "changed"  # type: ignore
