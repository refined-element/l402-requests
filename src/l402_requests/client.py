"""L402 HTTP client — auto-pays Lightning invoices on 402 responses.

Drop-in replacement for httpx. Any API behind an L402 paywall just works.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

import httpx

from l402_requests.bolt11 import extract_amount_sats
from l402_requests.budget import BudgetController
from l402_requests.challenge import find_l402_challenge
from l402_requests.credential_cache import CredentialCache
from l402_requests.exceptions import (
    L402Error,
    NoWalletError,
    PaymentFailedError,
)
from l402_requests.spending_log import SpendingLog
from l402_requests.wallets import WalletBase, auto_detect_wallet


class L402Client:
    """Synchronous HTTP client with automatic L402 payment handling.

    Usage:
        client = L402Client()
        response = client.get("https://api.example.com/paid-resource")
        # If 402 is returned, the client pays the invoice and retries automatically.
    """

    def __init__(
        self,
        wallet: WalletBase | None = None,
        budget: BudgetController | None = ...,  # type: ignore[assignment]
        credential_cache: CredentialCache | None = None,
        **httpx_kwargs: Any,
    ):
        """
        Args:
            wallet: Wallet adapter for paying invoices. If None, auto-detects.
            budget: Budget controller. Pass None to disable budget limits.
                    Defaults to BudgetController() with sensible limits.
            credential_cache: Cache for L402 tokens. Defaults to a new CredentialCache.
            **httpx_kwargs: Additional kwargs passed to httpx.Client.
        """
        self._wallet = wallet
        self._budget = BudgetController() if budget is ... else budget
        self._cache = credential_cache or CredentialCache()
        self._httpx_kwargs = httpx_kwargs
        self.spending_log = SpendingLog()

    def _get_wallet(self) -> WalletBase:
        if self._wallet is None:
            self._wallet = auto_detect_wallet()
        return self._wallet

    def _apply_cached_credential(
        self, url: str, headers: dict[str, str]
    ) -> dict[str, str]:
        """If we have a cached L402 token for this URL, add it to headers."""
        parsed = urlparse(url)
        cred = self._cache.get(parsed.hostname or "", parsed.path)
        if cred:
            headers = dict(headers)
            headers["Authorization"] = cred.authorization_header
        return headers

    def request(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        """Make an HTTP request, auto-paying L402 challenges."""
        headers = dict(kwargs.pop("headers", {}) or {})

        # Try cached credential first
        headers = self._apply_cached_credential(url, headers)

        with httpx.Client(**self._httpx_kwargs) as client:
            response = client.request(method, url, headers=headers, **kwargs)

            if response.status_code != 402:
                return response

            # Parse L402 challenge
            challenge = find_l402_challenge(dict(response.headers))
            if challenge is None:
                return response  # 402 but not L402 — return as-is

            # Extract amount and check budget
            amount_sats = extract_amount_sats(challenge.invoice)
            parsed_url = urlparse(url)
            domain = parsed_url.hostname or ""

            if self._budget and amount_sats is not None:
                self._budget.check(amount_sats, domain)

            # Pay the invoice
            wallet = self._get_wallet()
            try:
                preimage = wallet.pay_invoice_sync(challenge.invoice)
            except Exception as e:
                if amount_sats:
                    self.spending_log.record(
                        domain=domain,
                        path=parsed_url.path,
                        amount_sats=amount_sats,
                        preimage="",
                        success=False,
                    )
                if isinstance(e, L402Error):
                    raise
                raise PaymentFailedError(str(e), challenge.invoice) from e

            # Record successful payment
            if amount_sats:
                if self._budget:
                    self._budget.record_payment(amount_sats)
                self.spending_log.record(
                    domain=domain,
                    path=parsed_url.path,
                    amount_sats=amount_sats,
                    preimage=preimage,
                    success=True,
                )

            # Cache the credential
            self._cache.put(
                domain=domain,
                path=parsed_url.path,
                macaroon=challenge.macaroon,
                preimage=preimage,
            )

            # Retry with L402 authorization
            auth_header = f"L402 {challenge.macaroon}:{preimage}"
            headers["Authorization"] = auth_header
            retry_response = client.request(method, url, headers=headers, **kwargs)
            return retry_response

    def get(self, url: str, **kwargs: Any) -> httpx.Response:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs: Any) -> httpx.Response:
        return self.request("POST", url, **kwargs)

    def put(self, url: str, **kwargs: Any) -> httpx.Response:
        return self.request("PUT", url, **kwargs)

    def delete(self, url: str, **kwargs: Any) -> httpx.Response:
        return self.request("DELETE", url, **kwargs)

    def patch(self, url: str, **kwargs: Any) -> httpx.Response:
        return self.request("PATCH", url, **kwargs)

    def head(self, url: str, **kwargs: Any) -> httpx.Response:
        return self.request("HEAD", url, **kwargs)

    def options(self, url: str, **kwargs: Any) -> httpx.Response:
        return self.request("OPTIONS", url, **kwargs)


class AsyncL402Client:
    """Async HTTP client with automatic L402 payment handling.

    Usage:
        async with AsyncL402Client() as client:
            response = await client.get("https://api.example.com/paid-resource")
    """

    def __init__(
        self,
        wallet: WalletBase | None = None,
        budget: BudgetController | None = ...,  # type: ignore[assignment]
        credential_cache: CredentialCache | None = None,
        **httpx_kwargs: Any,
    ):
        self._wallet = wallet
        self._budget = BudgetController() if budget is ... else budget
        self._cache = credential_cache or CredentialCache()
        self._httpx_kwargs = httpx_kwargs
        self._client: httpx.AsyncClient | None = None
        self.spending_log = SpendingLog()

    def _get_wallet(self) -> WalletBase:
        if self._wallet is None:
            self._wallet = auto_detect_wallet()
        return self._wallet

    def _apply_cached_credential(
        self, url: str, headers: dict[str, str]
    ) -> dict[str, str]:
        parsed = urlparse(url)
        cred = self._cache.get(parsed.hostname or "", parsed.path)
        if cred:
            headers = dict(headers)
            headers["Authorization"] = cred.authorization_header
        return headers

    async def __aenter__(self) -> AsyncL402Client:
        self._client = httpx.AsyncClient(**self._httpx_kwargs)
        return self

    async def __aexit__(self, *args: Any) -> None:
        if self._client:
            await self._client.aclose()
            self._client = None

    def _ensure_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(**self._httpx_kwargs)
        return self._client

    async def request(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        """Make an async HTTP request, auto-paying L402 challenges."""
        headers = dict(kwargs.pop("headers", {}) or {})
        headers = self._apply_cached_credential(url, headers)
        client = self._ensure_client()

        response = await client.request(method, url, headers=headers, **kwargs)

        if response.status_code != 402:
            return response

        challenge = find_l402_challenge(dict(response.headers))
        if challenge is None:
            return response

        amount_sats = extract_amount_sats(challenge.invoice)
        parsed_url = urlparse(url)
        domain = parsed_url.hostname or ""

        if self._budget and amount_sats is not None:
            self._budget.check(amount_sats, domain)

        wallet = self._get_wallet()
        try:
            preimage = await wallet.pay_invoice(challenge.invoice)
        except Exception as e:
            if amount_sats:
                self.spending_log.record(
                    domain=domain,
                    path=parsed_url.path,
                    amount_sats=amount_sats,
                    preimage="",
                    success=False,
                )
            if isinstance(e, L402Error):
                raise
            raise PaymentFailedError(str(e), challenge.invoice) from e

        if amount_sats:
            if self._budget:
                self._budget.record_payment(amount_sats)
            self.spending_log.record(
                domain=domain,
                path=parsed_url.path,
                amount_sats=amount_sats,
                preimage=preimage,
                success=True,
            )

        self._cache.put(
            domain=domain,
            path=parsed_url.path,
            macaroon=challenge.macaroon,
            preimage=preimage,
        )

        auth_header = f"L402 {challenge.macaroon}:{preimage}"
        headers["Authorization"] = auth_header
        retry_response = await client.request(method, url, headers=headers, **kwargs)
        return retry_response

    async def get(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self.request("POST", url, **kwargs)

    async def put(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self.request("PUT", url, **kwargs)

    async def delete(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self.request("DELETE", url, **kwargs)

    async def patch(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self.request("PATCH", url, **kwargs)

    async def head(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self.request("HEAD", url, **kwargs)

    async def options(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self.request("OPTIONS", url, **kwargs)

    async def aclose(self) -> None:
        if self._client:
            await self._client.aclose()
            self._client = None
