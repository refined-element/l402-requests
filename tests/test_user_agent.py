"""Every request the library issues carries ``User-Agent: l402-requests/<version>``.

Servers (Lightning Enable's analytics among them) classify paid L402 traffic by
this product token, so it must be present on the initial request that receives
the 402, on the paid retry, and on the wallet calls that pay the invoice. A
caller-supplied ``User-Agent`` always wins.
"""

from __future__ import annotations

import importlib.metadata
import re

import httpx
import pytest

import l402_requests
from l402_requests.budget import BudgetController
from l402_requests.client import AsyncL402Client, L402Client
from l402_requests.wallets import WalletBase
from l402_requests.wallets.lnd import LndWallet
from l402_requests.wallets.opennode import OpenNodeWallet
from l402_requests.wallets.strike import StrikeWallet

CHALLENGE = 'L402 macaroon="fixture-macaroon", invoice="lnbc10u1ptest"'
CALLER_UA = "fixture-agent/9.9"


def _expected_version() -> str:
    try:
        return importlib.metadata.version("l402-requests")
    except importlib.metadata.PackageNotFoundError:  # pragma: no cover
        return l402_requests.__version__


def _user_agent() -> str:
    from l402_requests._version import USER_AGENT

    return USER_AGENT


class _Wallet(WalletBase):
    async def pay_invoice(self, bolt11: str) -> str:
        return "deadbeef" * 8

    def pay_invoice_sync(self, bolt11: str) -> str:
        return "deadbeef" * 8


def _respond(request: httpx.Request) -> httpx.Response:
    if request.headers.get("authorization", "").startswith("L402 "):
        return httpx.Response(200, json={"data": "paid content"})
    return httpx.Response(402, headers={"WWW-Authenticate": CHALLENGE})


class _RecordingTransport(httpx.BaseTransport):
    def __init__(self, status: int | None = None) -> None:
        self.requests: list[httpx.Request] = []
        self._status = status

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if self._status is not None:
            return httpx.Response(self._status)
        return _respond(request)


class _AsyncRecordingTransport(httpx.AsyncBaseTransport):
    def __init__(self) -> None:
        self.requests: list[httpx.Request] = []

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return _respond(request)


def _ua_values(request: httpx.Request) -> list[str]:
    return request.headers.get_list("user-agent")


class TestUserAgentConstant:
    def test_format_is_product_slash_semver(self):
        assert re.fullmatch(r"l402-requests/\d+\.\d+\.\d+", _user_agent())

    def test_matches_package_version(self):
        assert _user_agent() == f"l402-requests/{_expected_version()}"
        assert l402_requests.__version__ == _expected_version()


class TestSyncClientUserAgent:
    def test_402_request_and_paid_retry_carry_user_agent(self):
        transport = _RecordingTransport()
        client = L402Client(
            wallet=_Wallet(),
            budget=BudgetController(max_sats_per_request=2000),
            transport=transport,
        )

        response = client.get("https://api.example.com/data")

        assert response.status_code == 200
        assert len(transport.requests) == 2
        initial, retry = transport.requests
        assert "authorization" not in initial.headers
        assert retry.headers["authorization"].startswith("L402 ")
        assert _ua_values(initial) == [_user_agent()]
        assert _ua_values(retry) == [_user_agent()]

    def test_non_402_request_carries_user_agent(self):
        transport = _RecordingTransport(status=200)
        L402Client(wallet=_Wallet(), transport=transport).get(
            "https://api.example.com/free"
        )

        assert len(transport.requests) == 1
        assert _ua_values(transport.requests[0]) == [_user_agent()]

    def test_per_request_user_agent_wins_on_both_requests(self):
        transport = _RecordingTransport()
        client = L402Client(
            wallet=_Wallet(),
            budget=BudgetController(max_sats_per_request=2000),
            transport=transport,
        )

        client.get("https://api.example.com/data", headers={"user-agent": CALLER_UA})

        assert len(transport.requests) == 2
        for request in transport.requests:
            assert _ua_values(request) == [CALLER_UA]

    def test_client_level_user_agent_wins_on_both_requests(self):
        transport = _RecordingTransport()
        client = L402Client(
            wallet=_Wallet(),
            budget=BudgetController(max_sats_per_request=2000),
            transport=transport,
            headers={"User-Agent": CALLER_UA, "X-Fixture": "kept"},
        )

        client.get("https://api.example.com/data")

        assert len(transport.requests) == 2
        for request in transport.requests:
            assert _ua_values(request) == [CALLER_UA]
            assert request.headers["x-fixture"] == "kept"


class TestAsyncClientUserAgent:
    @pytest.mark.asyncio
    async def test_402_request_and_paid_retry_carry_user_agent(self):
        transport = _AsyncRecordingTransport()
        async with AsyncL402Client(
            wallet=_Wallet(),
            budget=BudgetController(max_sats_per_request=2000),
            transport=transport,
        ) as client:
            response = await client.get("https://api.example.com/data")

        assert response.status_code == 200
        assert len(transport.requests) == 2
        initial, retry = transport.requests
        assert retry.headers["authorization"].startswith("L402 ")
        assert _ua_values(initial) == [_user_agent()]
        assert _ua_values(retry) == [_user_agent()]

    @pytest.mark.asyncio
    async def test_per_request_user_agent_wins_on_both_requests(self):
        transport = _AsyncRecordingTransport()
        async with AsyncL402Client(
            wallet=_Wallet(),
            budget=BudgetController(max_sats_per_request=2000),
            transport=transport,
        ) as client:
            await client.get(
                "https://api.example.com/data", headers={"User-Agent": CALLER_UA}
            )

        assert len(transport.requests) == 2
        for request in transport.requests:
            assert _ua_values(request) == [CALLER_UA]

    @pytest.mark.asyncio
    async def test_client_level_user_agent_wins_without_context_manager(self):
        transport = _AsyncRecordingTransport()
        client = AsyncL402Client(
            wallet=_Wallet(),
            budget=BudgetController(max_sats_per_request=2000),
            transport=transport,
            headers={"user-agent": CALLER_UA},
        )
        try:
            await client.get("https://api.example.com/data")
        finally:
            await client._ensure_client().aclose()

        assert len(transport.requests) == 2
        for request in transport.requests:
            assert _ua_values(request) == [CALLER_UA]


class TestWalletUserAgent:
    @pytest.mark.parametrize(
        "wallet",
        [
            StrikeWallet(api_key="fixture-string-strike"),
            OpenNodeWallet(api_key="fixture-string-opennode"),
            LndWallet(host="https://localhost:8080", macaroon_hex="00" * 8),
        ],
        ids=["strike", "opennode", "lnd"],
    )
    @pytest.mark.asyncio
    async def test_wallet_http_client_sends_user_agent(self, wallet):
        client = wallet._build_client()
        try:
            assert client.headers.get_list("user-agent") == [_user_agent()]
        finally:
            await client.aclose()
