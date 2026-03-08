"""Shared fixtures for integration tests."""

from __future__ import annotations

import httpx
import pytest

from l402_requests.budget import BudgetController
from l402_requests.client import L402Client
from l402_requests.exceptions import PaymentFailedError
from l402_requests.wallets import WalletBase


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


class MockL402Transport(httpx.BaseTransport):
    """Simulates an L402 server: returns 402 on first request, 200 after payment."""

    def __init__(self):
        self.request_count = 0

    def handle_request(self, request: httpx.Request) -> httpx.Response:
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


class MockFreeTransport(httpx.BaseTransport):
    """Returns 200 directly — no payment needed."""

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"data": "free content"})


class MockPostTransport(httpx.BaseTransport):
    """Echoes back the POST body after L402 payment."""

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        auth = request.headers.get("authorization", "")

        if auth.startswith("L402 "):
            return httpx.Response(200, json={"received": True, "data": "post result"})

        return httpx.Response(
            402,
            headers={
                "WWW-Authenticate": 'L402 macaroon="testmacaroon123", invoice="lnbc10u1ptest"',
            },
            json={"error": "Payment Required"},
        )


class MockTextTransport(httpx.BaseTransport):
    """Returns plain text (non-JSON) after L402 payment."""

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        auth = request.headers.get("authorization", "")

        if auth.startswith("L402 "):
            return httpx.Response(200, text="Hello plain text")

        return httpx.Response(
            402,
            headers={
                "WWW-Authenticate": 'L402 macaroon="testmacaroon123", invoice="lnbc10u1ptest"',
            },
            json={"error": "Payment Required"},
        )


@pytest.fixture
def mock_wallet():
    return MockWallet()


@pytest.fixture
def failing_wallet():
    return FailingWallet()


@pytest.fixture
def l402_client(mock_wallet):
    """L402Client with mock wallet and L402 transport."""
    return L402Client(
        wallet=mock_wallet,
        budget=BudgetController(max_sats_per_request=2000),
        transport=MockL402Transport(),
    )


@pytest.fixture
def free_client(mock_wallet):
    """L402Client with mock wallet and free (non-402) transport."""
    return L402Client(
        wallet=mock_wallet,
        budget=BudgetController(max_sats_per_request=2000),
        transport=MockFreeTransport(),
    )


@pytest.fixture
def post_client(mock_wallet):
    """L402Client with mock wallet and POST echo transport."""
    return L402Client(
        wallet=mock_wallet,
        budget=BudgetController(max_sats_per_request=2000),
        transport=MockPostTransport(),
    )


@pytest.fixture
def text_client(mock_wallet):
    """L402Client with mock wallet and plain text transport."""
    return L402Client(
        wallet=mock_wallet,
        budget=BudgetController(max_sats_per_request=2000),
        transport=MockTextTransport(),
    )


@pytest.fixture
def budget_exceeded_client(mock_wallet):
    """L402Client with a budget too low for the 1000-sat invoice."""
    return L402Client(
        wallet=mock_wallet,
        budget=BudgetController(max_sats_per_request=500),
        transport=MockL402Transport(),
    )


@pytest.fixture
def failing_client(failing_wallet):
    """L402Client with a wallet that always fails."""
    return L402Client(
        wallet=failing_wallet,
        budget=BudgetController(max_sats_per_request=2000),
        transport=MockL402Transport(),
    )
