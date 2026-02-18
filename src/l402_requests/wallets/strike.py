"""Strike REST API wallet adapter."""

from __future__ import annotations

import httpx

from l402_requests.exceptions import PaymentFailedError
from l402_requests.wallets import WalletBase


class StrikeWallet(WalletBase):
    """Pay invoices via Strike REST API.

    Requires: STRIKE_API_KEY environment variable.

    Strike provides preimage support and charges no additional fees,
    making it an excellent choice for L402 payments.
    """

    BASE_URL = "https://api.strike.me"

    def __init__(self, api_key: str, base_url: str | None = None):
        self._api_key = api_key
        self._base_url = (base_url or self.BASE_URL).rstrip("/")

    def _build_client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            base_url=self._base_url,
            headers={
                "Authorization": f"Bearer {self._api_key}",
                "Content-Type": "application/json",
            },
            timeout=60.0,
        )

    async def pay_invoice(self, bolt11: str) -> str:
        """Pay via Strike's quote + execute flow.

        1. POST /v1/payment-quotes/lightning — create quote from bolt11
        2. PATCH /v1/payment-quotes/{id}/execute — execute the payment
        3. Extract preimage from completed payment
        """
        async with self._build_client() as client:
            # Step 1: Create payment quote
            try:
                quote_resp = await client.post(
                    "/v1/payment-quotes/lightning",
                    json={
                        "lnInvoice": bolt11,
                        "sourceCurrency": "BTC",
                    },
                )
            except httpx.HTTPError as e:
                raise PaymentFailedError(f"Strike connection error: {e}", bolt11)

            if quote_resp.status_code != 200 and quote_resp.status_code != 201:
                raise PaymentFailedError(
                    f"Strike quote failed ({quote_resp.status_code}): {quote_resp.text}",
                    bolt11,
                )

            quote = quote_resp.json()
            quote_id = quote.get("paymentQuoteId")
            if not quote_id:
                raise PaymentFailedError("Strike quote missing paymentQuoteId", bolt11)

            # Step 2: Execute payment
            try:
                exec_resp = await client.patch(
                    f"/v1/payment-quotes/{quote_id}/execute",
                )
            except httpx.HTTPError as e:
                raise PaymentFailedError(f"Strike execution error: {e}", bolt11)

            if exec_resp.status_code not in (200, 201):
                raise PaymentFailedError(
                    f"Strike execution failed ({exec_resp.status_code}): {exec_resp.text}",
                    bolt11,
                )

            payment = exec_resp.json()

            # Extract preimage from Lightning payment details
            preimage = (
                payment.get("lightning", {}).get("preImage")
                or payment.get("lightning", {}).get("preimage")
                or payment.get("preimage")
            )

            if not preimage:
                # Payment may have succeeded but preimage not immediately available
                # Try fetching payment details
                payment_id = payment.get("paymentId") or payment.get("paymentQuoteId")
                if payment_id:
                    preimage = await self._fetch_preimage(client, payment_id)

            if not preimage:
                raise PaymentFailedError(
                    "Strike payment succeeded but no preimage returned. "
                    "This may happen with older Strike API versions.",
                    bolt11,
                )

            return preimage

    async def _fetch_preimage(self, client: httpx.AsyncClient, payment_id: str) -> str | None:
        """Attempt to fetch preimage from payment details."""
        try:
            resp = await client.get(f"/v1/payments/{payment_id}")
            if resp.status_code == 200:
                data = resp.json()
                return (
                    data.get("lightning", {}).get("preImage")
                    or data.get("lightning", {}).get("preimage")
                )
        except httpx.HTTPError:
            pass
        return None
