"""End-to-end tests for L402Client with mock server responses."""

from __future__ import annotations

import pytest
import httpx

from l402_requests.budget import BudgetController
from l402_requests.client import AsyncL402Client, L402Client
from l402_requests.exceptions import BudgetExceededError, PaymentFailedError
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


class Mock402NoChallenge(httpx.BaseTransport):
    """Returns 402 but without L402 challenge (e.g., Stripe paywall)."""

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        return httpx.Response(402, json={"error": "Payment Required"})


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
