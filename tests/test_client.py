"""End-to-end tests for L402Client with mock server responses."""

from __future__ import annotations

import asyncio
import concurrent.futures
import threading
import time

import pytest
import httpx

from l402_requests.budget import BudgetController
from l402_requests.client import AsyncL402Client, L402Client
from l402_requests.exceptions import (
    BudgetExceededError,
    InvoiceAmountUnknownError,
    PaymentFailedError,
    UnsupportedWalletError,
)
from l402_requests.wallets import WalletBase


# ── Mock wallet ──────────────────────────────────────────────────────────

class MockWallet(WalletBase):
    """Wallet that returns a fixed preimage."""

    def __init__(self, preimage: str = "deadbeef" * 8):
        self.preimage = preimage
        self.paid_invoices: list[str] = []

    async def pay_invoice(self, bolt11: str) -> str:
        self.paid_invoices.append(bolt11)
        return self.preimage

    def pay_invoice_sync(self, bolt11: str) -> str:
        self.paid_invoices.append(bolt11)
        return self.preimage


class FailingWallet(WalletBase):
    async def pay_invoice(self, bolt11: str) -> str:
        raise PaymentFailedError("mock failure", bolt11)

    def pay_invoice_sync(self, bolt11: str) -> str:
        raise PaymentFailedError("mock failure", bolt11)


class NoPreimageWallet(WalletBase):
    """OpenNode-like adapter: settles the payment but can't surface a preimage."""

    supports_preimage = False

    def __init__(self):
        self.paid_invoices: list[str] = []

    async def pay_invoice(self, bolt11: str) -> str:
        self.paid_invoices.append(bolt11)
        raise PaymentFailedError("no preimage returned", bolt11)

    def pay_invoice_sync(self, bolt11: str) -> str:
        self.paid_invoices.append(bolt11)
        raise PaymentFailedError("no preimage returned", bolt11)


class LegacyDuckTypedWallet:
    """A wallet from before ``supports_preimage`` existed — no such attribute.

    Not a WalletBase subclass, so it can't inherit the default. The client must
    still use it: only an EXPLICIT False means "can't do L402".
    """

    def __init__(self, preimage: str = "deadbeef" * 8):
        self.preimage = preimage
        self.paid_invoices: list[str] = []

    async def pay_invoice(self, bolt11: str) -> str:
        self.paid_invoices.append(bolt11)
        return self.preimage

    def pay_invoice_sync(self, bolt11: str) -> str:
        self.paid_invoices.append(bolt11)
        return self.preimage


# ── Mock httpx transport ─────────────────────────────────────────────────

class MockL402Transport(httpx.BaseTransport):
    """Simulates an L402 server: returns 402 on first request, 200 after payment."""

    def __init__(self):
        self.request_count = 0

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        self.request_count += 1
        auth = request.headers.get("authorization", "")

        if auth.startswith("L402 "):
            # Client has valid L402 credential
            return httpx.Response(200, json={"data": "paid content"})

        # No credential — return 402 with L402 challenge
        # lnbc10u = 1000 sats
        return httpx.Response(
            402,
            headers={
                "WWW-Authenticate": 'L402 macaroon="testmacaroon123", invoice="lnbc10u1ptest"',
            },
            json={"error": "Payment Required"},
        )


class MockNon402Transport(httpx.BaseTransport):
    """Returns 200 directly — no payment needed."""

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"data": "free content"})


class MockMppTransport(httpx.BaseTransport):
    """Simulates an MPP server: returns 402 with Payment challenge, 200 after payment."""

    def __init__(self):
        self.request_count = 0

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        self.request_count += 1
        auth = request.headers.get("authorization", "")

        if auth.startswith("Payment ") and "preimage=" in auth:
            return httpx.Response(200, json={"data": "mpp paid content"})

        # lnbc10u = 1000 sats
        return httpx.Response(
            402,
            headers={
                "WWW-Authenticate": 'Payment realm="api.example.com", method="lightning", invoice="lnbc10u1ptest", amount="1000", currency="sat"',
            },
            json={"error": "Payment Required"},
        )


class MockAsyncMppTransport(httpx.AsyncBaseTransport):
    """Async version of MockMppTransport."""

    def __init__(self):
        self.request_count = 0

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.request_count += 1
        auth = request.headers.get("authorization", "")

        if auth.startswith("Payment ") and "preimage=" in auth:
            return httpx.Response(200, json={"data": "mpp paid content"})

        return httpx.Response(
            402,
            headers={
                "WWW-Authenticate": 'Payment realm="api.example.com", method="lightning", invoice="lnbc10u1ptest", amount="1000", currency="sat"',
            },
            json={"error": "Payment Required"},
        )


class MockMultiHeaderTransport(httpx.BaseTransport):
    """Returns 402 with separate WWW-Authenticate headers for Bearer and L402.

    Tests that the client iterates all header values instead of losing one
    when converting to dict.
    """

    def __init__(self):
        self.request_count = 0

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        self.request_count += 1
        auth = request.headers.get("authorization", "")

        if auth.startswith("L402 "):
            return httpx.Response(200, json={"data": "paid content"})

        # httpx.Response accepts a list of (name, value) tuples for headers
        # so we can emit two WWW-Authenticate headers.
        return httpx.Response(
            402,
            headers=[
                ("WWW-Authenticate", "Bearer realm=test"),
                ("WWW-Authenticate", 'L402 macaroon="testmacaroon123", invoice="lnbc10u1ptest"'),
            ],
            json={"error": "Payment Required"},
        )


class Mock402NoChallenge(httpx.BaseTransport):
    """Returns 402 but without L402 challenge (e.g., Stripe paywall)."""

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        return httpx.Response(402, json={"error": "Payment Required"})


class MockChallengeTransport(httpx.BaseTransport):
    """Returns 402 with a caller-supplied WWW-Authenticate value.

    Lets a test hand the client a challenge carrying an amountless, malformed,
    or hostile invoice. Always answers 402 — the client under test is expected
    to refuse before any retry.
    """

    def __init__(self, www_authenticate: str):
        self.www_authenticate = www_authenticate
        self.request_count = 0

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        self.request_count += 1
        return httpx.Response(
            402,
            headers={"WWW-Authenticate": self.www_authenticate},
            json={"error": "Payment Required"},
        )


class MockAsyncChallengeTransport(httpx.AsyncBaseTransport):
    """Async version of MockChallengeTransport."""

    def __init__(self, www_authenticate: str):
        self.www_authenticate = www_authenticate
        self.request_count = 0

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.request_count += 1
        return httpx.Response(
            402,
            headers={"WWW-Authenticate": self.www_authenticate},
            json={"error": "Payment Required"},
        )


# Challenges whose invoice amount cannot be determined.
NO_AMOUNT_L402 = 'L402 macaroon="testmacaroon123", invoice="lnbc1ptest"'
UNPARSEABLE_L402 = 'L402 macaroon="testmacaroon123", invoice="not-a-bolt11"'
# Zero-amount invoice plus a server-supplied negative MPP amount.
NEGATIVE_MPP = (
    'Payment realm="api.example.com", method="lightning", '
    'invoice="lnbc1ptest", amount="-100000", currency="sat"'
)
# Zero-amount invoice plus a server-supplied MPP amount of 0 — a blank cheque
# (ledger #42): with no positive bound, the wallet would pick the spend.
ZERO_MPP = (
    'Payment realm="api.example.com", method="lightning", '
    'invoice="lnbc1ptest", amount="0", currency="sat"'
)
# Literal-zero BOLT11 invoices ("lnbc0p1...", "lnbc01...") — the amount field is
# PRESENT and parses, it is just zero, so the decoder returns 0 rather than None.
# A bare None-check lets that 0 through, budget.check(0) passes, and the wallet —
# not the server — then picks the spend: the same blank-cheque class as ZERO_MPP
# above, but reached on the BOLT11 branch instead of the MPP fallback.
ZERO_AMOUNT_L402 = 'L402 macaroon="testmacaroon123", invoice="lnbc0p1ptest"'
ZERO_AMOUNT_NO_MULTIPLIER_L402 = 'L402 macaroon="testmacaroon123", invoice="lnbc01ptest"'


# ── Tests ────────────────────────────────────────────────────────────────

class TestL402Client:
    def test_auto_pays_402_and_retries(self):
        wallet = MockWallet()
        transport = MockL402Transport()
        client = L402Client(
            wallet=wallet,
            budget=BudgetController(max_sats_per_request=2000),
            transport=transport,
        )

        response = client.get("https://api.example.com/data")

        assert response.status_code == 200
        assert response.json() == {"data": "paid content"}
        assert len(wallet.paid_invoices) == 1
        assert wallet.paid_invoices[0] == "lnbc10u1ptest"
        assert transport.request_count == 2  # First 402, then retry

    def test_free_endpoint_no_payment(self):
        wallet = MockWallet()
        client = L402Client(
            wallet=wallet,
            transport=MockNon402Transport(),
        )

        response = client.get("https://api.example.com/free")

        assert response.status_code == 200
        assert len(wallet.paid_invoices) == 0

    def test_402_without_l402_challenge_passed_through(self):
        wallet = MockWallet()
        client = L402Client(
            wallet=wallet,
            transport=Mock402NoChallenge(),
        )

        response = client.get("https://api.example.com/stripe-paywall")

        assert response.status_code == 402
        assert len(wallet.paid_invoices) == 0

    def test_budget_prevents_payment(self):
        wallet = MockWallet()
        transport = MockL402Transport()
        client = L402Client(
            wallet=wallet,
            budget=BudgetController(max_sats_per_request=500),  # Invoice is 1000 sats
            transport=transport,
        )

        with pytest.raises(BudgetExceededError):
            client.get("https://api.example.com/data")

        assert len(wallet.paid_invoices) == 0

    def test_payment_failure_raises(self):
        wallet = FailingWallet()
        transport = MockL402Transport()
        client = L402Client(
            wallet=wallet,
            budget=BudgetController(max_sats_per_request=2000),
            transport=transport,
        )

        with pytest.raises(PaymentFailedError, match="mock failure"):
            client.get("https://api.example.com/data")

    def test_spending_log_records_payment(self):
        wallet = MockWallet()
        transport = MockL402Transport()
        client = L402Client(
            wallet=wallet,
            budget=BudgetController(max_sats_per_request=2000),
            transport=transport,
        )

        client.get("https://api.example.com/data")

        assert client.spending_log.total_spent() == 1000
        assert len(client.spending_log.records) == 1
        record = client.spending_log.records[0]
        assert record.domain == "api.example.com"
        assert record.amount_sats == 1000
        assert record.success is True
        assert record.macaroon == "testmacaroon123"
        assert record.preimage == wallet.preimage

    def test_cached_credential_reused(self):
        wallet = MockWallet()
        transport = MockL402Transport()
        client = L402Client(
            wallet=wallet,
            budget=BudgetController(max_sats_per_request=2000),
            transport=transport,
        )

        # First request: pays
        client.get("https://api.example.com/data")
        assert len(wallet.paid_invoices) == 1

        # Second request: should use cached credential
        client.get("https://api.example.com/data")
        assert len(wallet.paid_invoices) == 1  # No new payment

    def test_no_budget_allows_any_amount(self):
        wallet = MockWallet()
        transport = MockL402Transport()
        client = L402Client(
            wallet=wallet,
            budget=None,  # Explicitly disable budget
            transport=transport,
        )

        response = client.get("https://api.example.com/data")
        assert response.status_code == 200

    def test_spending_log_records_failure(self):
        wallet = FailingWallet()
        transport = MockL402Transport()
        client = L402Client(
            wallet=wallet,
            budget=BudgetController(max_sats_per_request=2000),
            transport=transport,
        )

        with pytest.raises(PaymentFailedError):
            client.get("https://api.example.com/data")

        assert len(client.spending_log.records) == 1
        assert client.spending_log.records[0].success is False
        # Macaroon from the parsed challenge is still recorded on failure
        assert client.spending_log.records[0].macaroon == "testmacaroon123"

    def test_post_method(self):
        wallet = MockWallet()
        transport = MockL402Transport()
        client = L402Client(
            wallet=wallet,
            budget=BudgetController(max_sats_per_request=2000),
            transport=transport,
        )

        response = client.post("https://api.example.com/data", json={"key": "value"})
        assert response.status_code == 200

    def test_multiple_www_authenticate_headers(self):
        """When server sends separate Bearer and L402 WWW-Authenticate headers,
        the client should find and use the L402 challenge."""
        wallet = MockWallet()
        transport = MockMultiHeaderTransport()
        client = L402Client(
            wallet=wallet,
            budget=BudgetController(max_sats_per_request=2000),
            transport=transport,
        )

        response = client.get("https://api.example.com/data")

        assert response.status_code == 200
        assert response.json() == {"data": "paid content"}
        assert len(wallet.paid_invoices) == 1
        assert wallet.paid_invoices[0] == "lnbc10u1ptest"
        assert transport.request_count == 2


# ── Async tests ──────────────────────────────────────────────────────────

class MockAsyncL402Transport(httpx.AsyncBaseTransport):
    def __init__(self):
        self.request_count = 0

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.request_count += 1
        auth = request.headers.get("authorization", "")

        if auth.startswith("L402 "):
            return httpx.Response(200, json={"data": "paid content"})

        return httpx.Response(
            402,
            headers={
                "WWW-Authenticate": 'L402 macaroon="testmacaroon123", invoice="lnbc10u1ptest"',
            },
            json={"error": "Payment Required"},
        )


class TestAsyncL402Client:
    @pytest.mark.asyncio
    async def test_auto_pays_402_and_retries(self):
        wallet = MockWallet()
        transport = MockAsyncL402Transport()

        async with AsyncL402Client(
            wallet=wallet,
            budget=BudgetController(max_sats_per_request=2000),
            transport=transport,
        ) as client:
            response = await client.get("https://api.example.com/data")

        assert response.status_code == 200
        assert response.json() == {"data": "paid content"}
        assert len(wallet.paid_invoices) == 1

    @pytest.mark.asyncio
    async def test_spending_log_tracks_async(self):
        wallet = MockWallet()
        transport = MockAsyncL402Transport()

        async with AsyncL402Client(
            wallet=wallet,
            budget=BudgetController(max_sats_per_request=2000),
            transport=transport,
        ) as client:
            await client.get("https://api.example.com/data")

        assert client.spending_log.total_spent() == 1000
        assert client.spending_log.records[0].macaroon == "testmacaroon123"


# ── MPP (Machine Payments Protocol) tests ─────────────────────────────

class TestMppClient:
    def test_auto_pays_mpp_402_and_retries(self):
        """MPP 402 challenge triggers payment and retry with Payment auth header."""
        wallet = MockWallet()
        transport = MockMppTransport()
        client = L402Client(
            wallet=wallet,
            budget=BudgetController(max_sats_per_request=2000),
            transport=transport,
        )

        response = client.get("https://api.example.com/data")

        assert response.status_code == 200
        assert response.json() == {"data": "mpp paid content"}
        assert len(wallet.paid_invoices) == 1
        assert wallet.paid_invoices[0] == "lnbc10u1ptest"
        assert transport.request_count == 2  # First 402, then retry

    def test_mpp_cached_credential_reused(self):
        """Second MPP request reuses cached credential without re-paying."""
        wallet = MockWallet()
        transport = MockMppTransport()
        client = L402Client(
            wallet=wallet,
            budget=BudgetController(max_sats_per_request=2000),
            transport=transport,
        )

        # First request: pays
        client.get("https://api.example.com/data")
        assert len(wallet.paid_invoices) == 1

        # Second request: should use cached credential
        client.get("https://api.example.com/data")
        assert len(wallet.paid_invoices) == 1  # No new payment

    def test_mpp_spending_log_records_payment(self):
        wallet = MockWallet()
        transport = MockMppTransport()
        client = L402Client(
            wallet=wallet,
            budget=BudgetController(max_sats_per_request=2000),
            transport=transport,
        )

        client.get("https://api.example.com/data")

        assert client.spending_log.total_spent() == 1000
        assert len(client.spending_log.records) == 1
        record = client.spending_log.records[0]
        assert record.domain == "api.example.com"
        assert record.amount_sats == 1000
        assert record.success is True
        # MPP challenges carry no macaroon
        assert record.macaroon == ""

    def test_mpp_payment_failure_raises(self):
        wallet = FailingWallet()
        transport = MockMppTransport()
        client = L402Client(
            wallet=wallet,
            budget=BudgetController(max_sats_per_request=2000),
            transport=transport,
        )

        with pytest.raises(PaymentFailedError, match="mock failure"):
            client.get("https://api.example.com/data")


class MockMppNonSatTransport(httpx.BaseTransport):
    """MPP server with non-sat currency — amount should NOT be used for budget."""

    def __init__(self):
        self.request_count = 0

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        self.request_count += 1
        auth = request.headers.get("authorization", "")

        if auth.startswith("Payment ") and "preimage=" in auth:
            return httpx.Response(200, json={"data": "mpp paid content"})

        # lnbc10u = 1000 sats in the invoice, but amount/currency say USD
        return httpx.Response(
            402,
            headers={
                "WWW-Authenticate": 'Payment realm="api.example.com", method="lightning", invoice="lnbc10u1ptest", amount="500", currency="usd"',
            },
            json={"error": "Payment Required"},
        )


class MockMppZeroAmountTransport(httpx.BaseTransport):
    """MPP server returning amount=0 (pay-what-you-want resource)."""

    def __init__(self):
        self.request_count = 0

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        self.request_count += 1
        auth = request.headers.get("authorization", "")

        if auth.startswith("Payment ") and "preimage=" in auth:
            return httpx.Response(200, json={"data": "mpp paid content"})

        # Zero-amount invoice with explicit amount="0" in MPP header
        return httpx.Response(
            402,
            headers={
                "WWW-Authenticate": 'Payment realm="api.example.com", method="lightning", invoice="lnbc1ptest", amount="0", currency="sat"',
            },
            json={"error": "Payment Required"},
        )


class TestMppCurrencyHandling:
    def test_non_sat_currency_ignores_mpp_amount(self):
        """When MPP currency is not 'sat', the amount should not be used for budget/logging."""
        wallet = MockWallet()
        transport = MockMppNonSatTransport()
        client = L402Client(
            wallet=wallet,
            budget=BudgetController(max_sats_per_request=2000),
            transport=transport,
        )

        response = client.get("https://api.example.com/data")

        assert response.status_code == 200
        assert len(wallet.paid_invoices) == 1
        # The invoice amount (1000 sats from lnbc10u) should be used,
        # not the MPP amount (500 "usd")
        assert client.spending_log.total_spent() == 1000
        record = client.spending_log.records[0]
        assert record.amount_sats == 1000

    def test_refuses_zero_amount_mpp(self):
        """Ledger #42: an MPP amount<=0 resolving onto an amountless invoice is
        a blank cheque — the wallet, not the server, would pick the spend — so
        it can't be positively bounded and must be refused.

        This test was FLIPPED from test_zero_amount_still_recorded, which pinned
        the unsafe behaviour (it asserted the 0-sat payment succeeded and got
        recorded). It now asserts fail-closed refusal with no payment.
        """
        wallet = MockWallet()
        transport = MockMppZeroAmountTransport()
        client = L402Client(
            wallet=wallet,
            budget=None,  # Refusal is on the amount's own merits, budget or not
            transport=transport,
        )

        with pytest.raises(InvoiceAmountUnknownError) as exc_info:
            client.get("https://api.example.com/data")

        assert exc_info.value.reason == "no-amount-encoded"
        # Refused BEFORE spending, and nothing recorded as spent.
        assert wallet.paid_invoices == []
        assert client.spending_log.records == []

    def test_positive_mpp_amount_on_amountless_invoice_is_paid(self):
        """The #42 refusal is scoped to amount<=0. A strictly POSITIVE MPP
        amount on an amountless invoice still resolves and pays — this guards
        against the fail-closed fix over-rejecting legitimate MPP prices."""
        wallet = MockWallet()
        transport = MockChallengeTransport(
            'Payment realm="api.example.com", method="lightning", '
            'invoice="lnbc1ptest", amount="500", currency="sat"'
        )
        client = L402Client(wallet=wallet, budget=None, transport=transport)

        client.get("https://api.example.com/data")

        assert wallet.paid_invoices == ["lnbc1ptest"]
        assert client.spending_log.total_spent() == 500


class TestAsyncMppClient:
    @pytest.mark.asyncio
    async def test_auto_pays_mpp_402_and_retries(self):
        """Async MPP 402 challenge triggers payment and retry."""
        wallet = MockWallet()
        transport = MockAsyncMppTransport()

        async with AsyncL402Client(
            wallet=wallet,
            budget=BudgetController(max_sats_per_request=2000),
            transport=transport,
        ) as client:
            response = await client.get("https://api.example.com/data")

        assert response.status_code == 200
        assert response.json() == {"data": "mpp paid content"}
        assert len(wallet.paid_invoices) == 1

    @pytest.mark.asyncio
    async def test_mpp_spending_log_tracks_async(self):
        wallet = MockWallet()
        transport = MockAsyncMppTransport()

        async with AsyncL402Client(
            wallet=wallet,
            budget=BudgetController(max_sats_per_request=2000),
            transport=transport,
        ) as client:
            await client.get("https://api.example.com/data")

        assert client.spending_log.total_spent() == 1000


class TestUnknownAmountRefusal:
    """An amount we can't determine is an amount we can't authorise.

    ``extract_amount_sats`` returns None both for invoices that encode no
    amount and for invoices it can't parse at all. Reading that None as "no
    limit applies" let a server skip ``budget.check`` entirely — which is not
    just the sats limits but the domain allowlist too — and the spend never
    reached the log either, hiding it from every later budget check as well.
    """

    def test_refuses_invoice_with_no_amount(self):
        wallet = MockWallet()
        client = L402Client(
            wallet=wallet,
            budget=BudgetController(max_sats_per_request=2000),
            transport=MockChallengeTransport(NO_AMOUNT_L402),
        )

        with pytest.raises(InvoiceAmountUnknownError) as exc_info:
            client.get("https://api.example.com/data")

        assert exc_info.value.reason == "no-amount-encoded"
        # Refused BEFORE spending, and nothing recorded as spent.
        assert wallet.paid_invoices == []
        assert client.spending_log.records == []

    def test_refuses_unparseable_invoice(self):
        wallet = MockWallet()
        client = L402Client(
            wallet=wallet,
            budget=BudgetController(max_sats_per_request=2000),
            transport=MockChallengeTransport(UNPARSEABLE_L402),
        )

        with pytest.raises(InvoiceAmountUnknownError) as exc_info:
            client.get("https://api.example.com/data")

        assert exc_info.value.reason == "unparseable"
        assert wallet.paid_invoices == []

    def test_refuses_amountless_invoice_outside_allowlist(self):
        """The allowlist lives inside budget.check(), so skipping the check for
        a None amount disabled the allowlist too — an amountless invoice from
        ANY domain got paid."""
        wallet = MockWallet()
        client = L402Client(
            wallet=wallet,
            budget=BudgetController(allowed_domains={"trusted.example.com"}),
            transport=MockChallengeTransport(NO_AMOUNT_L402),
        )

        with pytest.raises(InvoiceAmountUnknownError):
            client.get("https://evil.example.com/data")

        assert wallet.paid_invoices == []

    def test_refuses_amountless_invoice_with_budget_disabled(self):
        """An unknown amount is refused on its own merits: even with budgets
        off, the client still can't tell the caller what it is about to spend."""
        wallet = MockWallet()
        client = L402Client(
            wallet=wallet,
            budget=None,
            transport=MockChallengeTransport(NO_AMOUNT_L402),
        )

        with pytest.raises(InvoiceAmountUnknownError):
            client.get("https://api.example.com/data")

        assert wallet.paid_invoices == []

    def test_refuses_negative_mpp_amount(self):
        """A negative MPP amount is worse than useless: budget.check() waves it
        through, then record_payment() SUBTRACTS it from the running total,
        handing back headroom for later real payments. Don't trust it."""
        wallet = MockWallet()
        budget = BudgetController(max_sats_per_hour=10_000)
        client = L402Client(
            wallet=wallet,
            budget=budget,
            transport=MockChallengeTransport(NEGATIVE_MPP),
        )

        with pytest.raises(InvoiceAmountUnknownError):
            client.get("https://api.example.com/data")

        assert wallet.paid_invoices == []
        # The budget must not have gained headroom from a bogus negative spend.
        assert budget.spent_last_hour() == 0

    @pytest.mark.asyncio
    async def test_refuses_invoice_with_no_amount_async(self):
        wallet = MockWallet()
        async with AsyncL402Client(
            wallet=wallet,
            budget=BudgetController(max_sats_per_request=2000),
            transport=MockAsyncChallengeTransport(NO_AMOUNT_L402),
        ) as client:
            with pytest.raises(InvoiceAmountUnknownError) as exc_info:
                await client.get("https://api.example.com/data")

        assert exc_info.value.reason == "no-amount-encoded"
        assert wallet.paid_invoices == []
        assert client.spending_log.records == []

    @pytest.mark.asyncio
    async def test_refuses_unparseable_invoice_async(self):
        wallet = MockWallet()
        async with AsyncL402Client(
            wallet=wallet,
            budget=BudgetController(max_sats_per_request=2000),
            transport=MockAsyncChallengeTransport(UNPARSEABLE_L402),
        ) as client:
            with pytest.raises(InvoiceAmountUnknownError) as exc_info:
                await client.get("https://api.example.com/data")

        assert exc_info.value.reason == "unparseable"
        assert wallet.paid_invoices == []

    # The async mirrors below. AsyncL402Client.request() was copy-pasted from
    # the sync one and only the sync copy was tested, so these refusals were
    # load-bearing but unverified. The negative-MPP guard in particular could
    # be deleted outright with all 248 tests still passing.

    @pytest.mark.asyncio
    async def test_refuses_amountless_invoice_outside_allowlist_async(self):
        wallet = MockWallet()
        async with AsyncL402Client(
            wallet=wallet,
            budget=BudgetController(allowed_domains={"trusted.example.com"}),
            transport=MockAsyncChallengeTransport(NO_AMOUNT_L402),
        ) as client:
            with pytest.raises(InvoiceAmountUnknownError):
                await client.get("https://evil.example.com/data")

        assert wallet.paid_invoices == []

    @pytest.mark.asyncio
    async def test_refuses_amountless_invoice_with_budget_disabled_async(self):
        wallet = MockWallet()
        async with AsyncL402Client(
            wallet=wallet,
            budget=None,
            transport=MockAsyncChallengeTransport(NO_AMOUNT_L402),
        ) as client:
            with pytest.raises(InvoiceAmountUnknownError):
                await client.get("https://api.example.com/data")

        assert wallet.paid_invoices == []

    @pytest.mark.asyncio
    async def test_refuses_zero_mpp_amount_async(self):
        """Ledger #42, async mirror of test_refuses_zero_amount_mpp. Both
        clients price through the shared _resolve_amount_sats, so this pins the
        async path onto the same non-positive-amount guard."""
        wallet = MockWallet()
        async with AsyncL402Client(
            wallet=wallet,
            budget=None,
            transport=MockAsyncChallengeTransport(ZERO_MPP),
        ) as client:
            with pytest.raises(InvoiceAmountUnknownError):
                await client.get("https://api.example.com/data")

        assert wallet.paid_invoices == []
        assert client.spending_log.records == []

    @pytest.mark.asyncio
    async def test_refuses_negative_mpp_amount_async(self):
        """Mirror of test_refuses_negative_mpp_amount. Both clients now price
        challenges through _resolve_amount_sats, so this pins the async path
        onto that shared guard rather than a private copy of it."""
        wallet = MockWallet()
        budget = BudgetController(max_sats_per_hour=10_000)
        async with AsyncL402Client(
            wallet=wallet,
            budget=budget,
            transport=MockAsyncChallengeTransport(NEGATIVE_MPP),
        ) as client:
            with pytest.raises(InvoiceAmountUnknownError):
                await client.get("https://api.example.com/data")

        assert wallet.paid_invoices == []
        # The budget must not have gained headroom from a bogus negative spend.
        assert budget.spent_last_hour() == 0


class TestLiteralZeroBolt11Refusal:
    """Ledger #42, BOLT11 branch: a literal-zero invoice ("lnbc0p1...") decodes
    to 0, not None. The #42 fix guarded only the MPP fallback; the BOLT11 branch
    returned its decoded value directly, so a 0 slipped past the None-check,
    passed budget.check(0), and handed the wallet an effectively-amountless
    (blank-cheque) invoice. The resolved amount must be strictly positive from
    the BOLT11 source too — a non-positive decode is refused.
    """

    def test_refuses_literal_zero_amount_invoice(self):
        wallet = MockWallet()
        client = L402Client(
            wallet=wallet,
            budget=None,  # refusal is on the amount's own merits, budget or not
            transport=MockChallengeTransport(ZERO_AMOUNT_L402),
        )

        with pytest.raises(InvoiceAmountUnknownError):
            client.get("https://api.example.com/data")

        assert wallet.paid_invoices == []
        assert client.spending_log.records == []

    def test_refuses_literal_zero_amount_no_multiplier(self):
        wallet = MockWallet()
        client = L402Client(
            wallet=wallet,
            budget=None,
            transport=MockChallengeTransport(ZERO_AMOUNT_NO_MULTIPLIER_L402),
        )

        with pytest.raises(InvoiceAmountUnknownError):
            client.get("https://api.example.com/data")

        assert wallet.paid_invoices == []

    def test_positive_amount_invoice_still_pays(self):
        """Guard against over-rejection: a strictly positive BOLT11 amount
        (lnbc10u = 1000 sats) is unaffected by the zero-amount refusal."""
        wallet = MockWallet()
        client = L402Client(
            wallet=wallet,
            budget=BudgetController(max_sats_per_request=2000),
            transport=MockL402Transport(),  # serves lnbc10u1ptest = 1000 sats
        )

        response = client.get("https://api.example.com/data")

        assert response.status_code == 200
        assert wallet.paid_invoices == ["lnbc10u1ptest"]

    @pytest.mark.asyncio
    async def test_refuses_literal_zero_amount_invoice_async(self):
        wallet = MockWallet()
        async with AsyncL402Client(
            wallet=wallet,
            budget=None,
            transport=MockAsyncChallengeTransport(ZERO_AMOUNT_L402),
        ) as client:
            with pytest.raises(InvoiceAmountUnknownError):
                await client.get("https://api.example.com/data")

        assert wallet.paid_invoices == []
        assert client.spending_log.records == []


class GatedSyncWallet(WalletBase):
    """Wallet that blocks inside the payment until the test opens the gate.

    Lets the test hold one or more payments 'in flight' simultaneously so the
    check-then-pay-then-record race can be provoked deterministically: with the
    old code both concurrent requests pass ``check()`` and both settle; with the
    reserve/commit fix the second request is refused at ``reserve()`` and never
    reaches the wallet.
    """

    def __init__(self, preimage: str = "ab" * 32):
        self.preimage = preimage
        self.pay_calls = 0
        self._lock = threading.Lock()
        self.entered = threading.Event()  # set once a payment is in-flight
        self.gate = threading.Event()  # test opens this to let payments finish

    def pay_invoice_sync(self, bolt11: str) -> str:
        with self._lock:
            self.pay_calls += 1
        self.entered.set()
        # Block so concurrent payments overlap; bounded so a bug can't hang CI.
        self.gate.wait(timeout=5)
        return self.preimage

    async def pay_invoice(self, bolt11: str) -> str:  # pragma: no cover - unused
        return self.pay_invoice_sync(bolt11)


class GatedAsyncWallet(WalletBase):
    """Async analogue of GatedSyncWallet using asyncio primitives."""

    def __init__(self, preimage: str = "ab" * 32):
        self.preimage = preimage
        self.pay_calls = 0
        self.entered = asyncio.Event()
        self.gate = asyncio.Event()

    async def pay_invoice(self, bolt11: str) -> str:
        self.pay_calls += 1
        self.entered.set()
        await self.gate.wait()
        return self.preimage

    def pay_invoice_sync(self, bolt11: str) -> str:  # pragma: no cover - unused
        raise NotImplementedError


class TestConcurrentPaymentBudget:
    """Two concurrent payments whose sum exceeds the cap: exactly one must win
    and the window total must never exceed the cap. This is the funds-safety
    TOCTOU: ``check()`` and ``record_payment()`` are separate, so a second
    request slips through against the still-unrecorded total.
    """

    def test_sync_concurrent_payments_never_exceed_cap(self):
        # Each invoice is 1000 sats (lnbc10u); cap is 1500 => only one fits.
        budget = BudgetController(
            max_sats_per_request=1000,
            max_sats_per_hour=1500,
            max_sats_per_day=1500,
        )
        wallet = GatedSyncWallet()
        transport = MockL402Transport()
        client = L402Client(wallet=wallet, budget=budget, transport=transport)
        url = "https://api.example.com/data"

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as ex:
            futures = [ex.submit(client.get, url) for _ in range(2)]

            # Wait for one payment to be in-flight, then let the other resolve
            # (enter the wallet under the buggy code, or be refused under the
            # fix) before opening the gate.
            assert wallet.entered.wait(timeout=5)
            deadline = time.time() + 5
            while time.time() < deadline:
                done = sum(1 for f in futures if f.done())
                if wallet.pay_calls >= 2 or done >= 1:
                    break
                time.sleep(0.01)
            wallet.gate.set()

            results = []
            for f in futures:
                try:
                    results.append(("ok", f.result(timeout=5)))
                except Exception as e:  # noqa: BLE001
                    results.append(("err", e))

        successes = [r for _, r in results if _ == "ok"]
        errors = [e for tag, e in results if tag == "err"]

        assert len(successes) == 1, f"expected exactly one success, got {results}"
        assert len(errors) == 1
        assert isinstance(errors[0], BudgetExceededError)
        # Only one payment actually settled.
        assert wallet.pay_calls == 1
        # The window total never exceeded the cap.
        assert budget.spent_last_hour() == 1000
        assert budget.spent_last_hour() <= 1500

    @pytest.mark.asyncio
    async def test_async_concurrent_payments_never_exceed_cap(self):
        budget = BudgetController(
            max_sats_per_request=1000,
            max_sats_per_hour=1500,
            max_sats_per_day=1500,
        )
        wallet = GatedAsyncWallet()
        transport = MockAsyncL402Transport()
        url = "https://api.example.com/data"

        async with AsyncL402Client(
            wallet=wallet, budget=budget, transport=transport
        ) as client:

            async def one():
                try:
                    return ("ok", await client.get(url))
                except Exception as e:  # noqa: BLE001
                    return ("err", e)

            task_a = asyncio.create_task(one())
            task_b = asyncio.create_task(one())

            # One payment reaches the wallet; let the other resolve, then open.
            await asyncio.wait_for(wallet.entered.wait(), timeout=5)
            for _ in range(1000):
                if wallet.pay_calls >= 2 or task_a.done() or task_b.done():
                    break
                await asyncio.sleep(0)
            wallet.gate.set()

            results = await asyncio.gather(task_a, task_b)

        successes = [r for tag, r in results if tag == "ok"]
        errors = [r for tag, r in results if tag == "err"]

        assert len(successes) == 1, f"expected exactly one success, got {results}"
        assert len(errors) == 1
        assert isinstance(errors[0], BudgetExceededError)
        assert wallet.pay_calls == 1
        assert budget.spent_last_hour() == 1000
        assert budget.spent_last_hour() <= 1500


class TestWalletPreimageSupport:
    """L402 can't complete without a preimage, so a wallet that can't produce
    one must be rejected BEFORE paying — otherwise the invoice is settled and
    the retry still has no Authorization header to send. Funds gone, no access.
    """

    def test_refuses_wallet_that_cannot_produce_preimage(self):
        wallet = NoPreimageWallet()
        client = L402Client(
            wallet=wallet,
            budget=BudgetController(max_sats_per_request=2000),
            transport=MockL402Transport(),
        )

        with pytest.raises(UnsupportedWalletError):
            client.get("https://api.example.com/data")

        # The whole point of failing fast: no payment was attempted.
        assert wallet.paid_invoices == []

    def test_uses_wallet_without_supports_preimage_attribute(self):
        """Back-compat: a duck-typed wallet predating the attribute keeps
        working. Only an explicit False blocks."""
        wallet = LegacyDuckTypedWallet()
        client = L402Client(
            wallet=wallet,
            budget=BudgetController(max_sats_per_request=2000),
            transport=MockL402Transport(),
        )

        response = client.get("https://api.example.com/data")

        assert response.status_code == 200
        assert wallet.paid_invoices == ["lnbc10u1ptest"]

    @pytest.mark.asyncio
    async def test_refuses_wallet_that_cannot_produce_preimage_async(self):
        wallet = NoPreimageWallet()
        async with AsyncL402Client(
            wallet=wallet,
            budget=BudgetController(max_sats_per_request=2000),
            transport=MockAsyncL402Transport(),
        ) as client:
            with pytest.raises(UnsupportedWalletError):
                await client.get("https://api.example.com/data")

        assert wallet.paid_invoices == []
