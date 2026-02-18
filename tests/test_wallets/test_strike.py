"""Tests for Strike wallet adapter."""

from __future__ import annotations

import json

import httpx
import pytest

from l402_requests.exceptions import PaymentFailedError
from l402_requests.wallets.strike import StrikeWallet


class MockStrikeTransport(httpx.AsyncBaseTransport):
    """Mocks Strike API responses."""

    def __init__(self, preimage: str = "abc123preimage"):
        self.preimage = preimage
        self.requests: list[httpx.Request] = []

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        url = str(request.url)

        if "/v1/payment-quotes/lightning" in url and request.method == "POST":
            return httpx.Response(
                200,
                json={"paymentQuoteId": "quote-123"},
            )

        if "/v1/payment-quotes/quote-123/execute" in url and request.method == "PATCH":
            return httpx.Response(
                200,
                json={
                    "paymentId": "pay-456",
                    "lightning": {"preImage": self.preimage},
                },
            )

        return httpx.Response(404)


class MockStrikeNoPreimageTransport(httpx.AsyncBaseTransport):
    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        url = str(request.url)

        if "/v1/payment-quotes/lightning" in url:
            return httpx.Response(200, json={"paymentQuoteId": "quote-123"})

        if "/v1/payment-quotes/quote-123/execute" in url:
            return httpx.Response(200, json={"paymentId": "pay-456"})

        if "/v1/payments/pay-456" in url:
            return httpx.Response(200, json={})

        return httpx.Response(404)


class MockStrikeErrorTransport(httpx.AsyncBaseTransport):
    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, text="Unauthorized")


class TestStrikeWallet:
    @pytest.mark.asyncio
    async def test_successful_payment(self):
        transport = MockStrikeTransport(preimage="deadbeef1234")
        wallet = StrikeWallet.__new__(StrikeWallet)
        wallet._api_key = "test-key"
        wallet._base_url = "https://api.strike.me"

        # Patch _build_client to use mock transport
        original_build = wallet._build_client

        def mock_build():
            return httpx.AsyncClient(
                base_url=wallet._base_url,
                headers={
                    "Authorization": f"Bearer {wallet._api_key}",
                    "Content-Type": "application/json",
                },
                transport=transport,
                timeout=60.0,
            )

        wallet._build_client = mock_build

        preimage = await wallet.pay_invoice("lnbc10u1ptest")
        assert preimage == "deadbeef1234"
        assert len(transport.requests) == 2  # quote + execute

    @pytest.mark.asyncio
    async def test_payment_no_preimage_raises(self):
        transport = MockStrikeNoPreimageTransport()
        wallet = StrikeWallet.__new__(StrikeWallet)
        wallet._api_key = "test-key"
        wallet._base_url = "https://api.strike.me"

        def mock_build():
            return httpx.AsyncClient(
                base_url=wallet._base_url,
                headers={
                    "Authorization": f"Bearer {wallet._api_key}",
                    "Content-Type": "application/json",
                },
                transport=transport,
                timeout=60.0,
            )

        wallet._build_client = mock_build

        with pytest.raises(PaymentFailedError, match="no preimage"):
            await wallet.pay_invoice("lnbc10u1ptest")

    @pytest.mark.asyncio
    async def test_auth_error_raises(self):
        transport = MockStrikeErrorTransport()
        wallet = StrikeWallet.__new__(StrikeWallet)
        wallet._api_key = "bad-key"
        wallet._base_url = "https://api.strike.me"

        def mock_build():
            return httpx.AsyncClient(
                base_url=wallet._base_url,
                headers={
                    "Authorization": f"Bearer {wallet._api_key}",
                    "Content-Type": "application/json",
                },
                transport=transport,
                timeout=60.0,
            )

        wallet._build_client = mock_build

        with pytest.raises(PaymentFailedError, match="Strike quote failed"):
            await wallet.pay_invoice("lnbc10u1ptest")

    def test_constructor(self):
        wallet = StrikeWallet(api_key="my-key")
        assert wallet._api_key == "my-key"
        assert wallet._base_url == "https://api.strike.me"

    def test_custom_base_url(self):
        wallet = StrikeWallet(api_key="my-key", base_url="https://custom.strike.me/")
        assert wallet._base_url == "https://custom.strike.me"
