"""Tests for BOLT11 invoice amount extraction."""

import pytest

from l402_requests.bolt11 import (
    NO_AMOUNT_ENCODED,
    UNPARSEABLE,
    classify_missing_amount,
    extract_amount_sats,
)


class TestExtractAmountSats:
    def test_micro_btc(self):
        # lnbc10u = 10 micro BTC = 10 * 0.000001 BTC = 0.00001 BTC = 1000 sats
        assert extract_amount_sats("lnbc10u1ptest") == 1000

    def test_milli_btc(self):
        # lnbc1m = 1 milli BTC = 0.001 BTC = 100,000 sats
        assert extract_amount_sats("lnbc1m1ptest") == 100_000

    def test_nano_btc(self):
        # lnbc1000n = 1000 nano BTC = 0.000001 BTC = 100 sats
        assert extract_amount_sats("lnbc1000n1ptest") == 100

    def test_pico_btc(self):
        # lnbc1000000p = 1,000,000 pico BTC = 0.000000001 BTC * 1,000,000
        # = 0.000001 BTC = 100 sats (but pico can represent sub-sat amounts)
        # Actually: 1000000 * 0.000000000001 BTC = 0.000001 BTC = 100 sats
        assert extract_amount_sats("lnbc1000000p1ptest") == 100

    def test_500_sats(self):
        # lnbc5u = 5 micro BTC = 500 sats
        assert extract_amount_sats("lnbc5u1ptest") == 500

    def test_1_sat(self):
        # lnbc10n = 10 nano BTC = 10 * 0.000000001 * 100000000 = 1 sat
        assert extract_amount_sats("lnbc10n1ptest") == 1

    def test_no_amount_returns_none(self):
        # Any-amount invoice
        assert extract_amount_sats("lnbc1ptest") is None

    def test_empty_string_returns_none(self):
        assert extract_amount_sats("") is None

    def test_invalid_format_returns_none(self):
        assert extract_amount_sats("not-a-bolt11") is None

    def test_testnet_invoice(self):
        # lntb = testnet
        assert extract_amount_sats("lntb10u1ptest") == 1000

    def test_case_insensitive(self):
        assert extract_amount_sats("LNBC10U1PTEST") == 1000

    def test_whole_btc(self):
        # lnbc2 = 2 BTC = 200,000,000 sats (no multiplier = BTC)
        assert extract_amount_sats("lnbc21ptest") == 200_000_000

    def test_real_world_invoice_prefix(self):
        # Typical 100 sat invoice: lnbc1u (1 micro BTC = 100 sats)
        assert extract_amount_sats("lnbc1u1pjk2q3xyz") == 100


class TestHrpAnchoring:
    """Ledger #74: the amount must be read ONLY from the human-readable part —
    everything before the LAST '1' separator. The bech32 data charset excludes
    '1', so the final '1' is always the true separator. A decoder that stops at
    an EARLIER '1' (or scans the whole string) can lift a small bogus amount out
    of the data part / a crafted stray segment, report a positive number the
    invoice does not actually encode, and sail through a budget check.
    """

    def test_amount_not_matched_before_a_later_separator(self):
        # First '1' sits right after "9u", so an un-anchored decoder reports
        # 9u = 900 sats. The real separator is the LAST '1', making the true HRP
        # "lnbc9u1qpzq" — not a valid amount HRP — so the amount is unknown.
        crafted = "lnbc9u1qpzq1qpzry9x8gf2tvdw0s3jn54khce6mua7l"
        assert extract_amount_sats(crafted) is None

    def test_amount_not_matched_from_data_part(self):
        # Reference examples from le-agent-sdk-python's hardened decoder: digits
        # and a multiplier sitting inside the data part must not be read as the
        # amount.
        assert extract_amount_sats("lnbc1pabc9u1def") is None
        assert extract_amount_sats("lnbc1pvjl5p1uez") is None

    def test_crafted_invoice_classified_unparseable_not_priced(self):
        crafted = "lnbc9u1qpzq1qpzry9x8gf2tvdw0s3jn54khce6mua7l"
        assert extract_amount_sats(crafted) is None
        assert classify_missing_amount(crafted) == UNPARSEABLE

    def test_legitimate_invoices_still_decode(self):
        # HRP anchoring must not over-reject: normal single-separator invoices,
        # including amounts whose own digits contain '1', still price correctly.
        assert extract_amount_sats("lnbc10u1pdata") == 1000
        assert extract_amount_sats("lnbc1500n1pdata") == 150
        assert extract_amount_sats("lnbc1m1pdata") == 100_000
        assert classify_missing_amount("lnbc1pdata") == NO_AMOUNT_ENCODED
