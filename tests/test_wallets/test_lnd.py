"""Tests for LND wallet adapter."""

from __future__ import annotations

import base64
import json

import httpx
import pytest

from l402_requests.exceptions import PaymentFailedError
from l402_requests.wallets.lnd import LndWallet


class MockLndTransport(httpx.AsyncBaseTransport):
    """Mocks LND REST API responses."""

    def __init__(self, preimage_hex: str = "deadbeef" * 8):
        # LND returns base64-encoded preimage
        preimage_bytes = bytes.fromhex(preimage_hex)
        self.preimage_b64 = base64.b64encode(preimage_bytes).decode()
        self.preimage_hex = preimage_hex

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        url = str(request.url)

        if "/v2/router/send" in url:
            # Streaming response — final update with SUCCEEDED
            body = json.dumps({
                "result": {
                    "status": "SUCCEEDED",
                    "payment_preimage": self.preimage_b64,
                }
            })
            return httpx.Response(200, text=body)

        return httpx.Response(404)


class MockLndFailTransport(httpx.AsyncBaseTransport):
    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        body = json.dumps({
            "result": {
                "status": "FAILED",
                "failure_reason": "FAILURE_REASON_NO_ROUTE",
            }
        })
        return httpx.Response(200, text=body)


class TestLndWallet:
    @pytest.mark.asyncio
    async def test_successful_payment(self):
        transport = MockLndTransport(preimage_hex="abcd1234" * 8)
        wallet = LndWallet.__new__(LndWallet)
        wallet._host = "https://localhost:8080"
        wallet._macaroon_hex = "testmacaroon"
        wallet._tls_cert_path = None

        def mock_build():
            return httpx.AsyncClient(
                base_url=wallet._host,
                headers={"Grpc-Metadata-macaroon": wallet._macaroon_hex},
                transport=transport,
                timeout=60.0,
            )

        wallet._build_client = mock_build

        preimage = await wallet.pay_invoice("lnbc10u1ptest")
        assert preimage == "abcd1234" * 8

    @pytest.mark.asyncio
    async def test_payment_failure(self):
        transport = MockLndFailTransport()
        wallet = LndWallet.__new__(LndWallet)
        wallet._host = "https://localhost:8080"
        wallet._macaroon_hex = "testmacaroon"
        wallet._tls_cert_path = None

        def mock_build():
            return httpx.AsyncClient(
                base_url=wallet._host,
                headers={"Grpc-Metadata-macaroon": wallet._macaroon_hex},
                transport=transport,
                timeout=60.0,
            )

        wallet._build_client = mock_build

        with pytest.raises(PaymentFailedError, match="NO_ROUTE"):
            await wallet.pay_invoice("lnbc10u1ptest")

    def test_constructor(self):
        wallet = LndWallet(
            host="https://mynode:8080",
            macaroon_hex="aabbcc",
        )
        assert wallet._host == "https://mynode:8080"
        assert wallet._macaroon_hex == "aabbcc"
        assert wallet._tls_cert_path is None
