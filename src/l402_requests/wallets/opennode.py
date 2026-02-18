"""OpenNode REST API wallet adapter."""

from __future__ import annotations

import httpx

from l402_requests.exceptions import PaymentFailedError
from l402_requests.wallets import WalletBase


class OpenNodeWallet(WalletBase):
    """Pay invoices via OpenNode REST API.

    Requires: OPENNODE_API_KEY environment variable.

    Note: OpenNode does not return preimages in withdrawal responses,
    which limits L402 functionality. For full L402 support, prefer
    Strike, LND, or compatible NWC wallets.
    """

    BASE_URL = "https://api.opennode.com"

    def __init__(self, api_key: str, base_url: str | None = None):
        self._api_key = api_key
        self._base_url = (base_url or self.BASE_URL).rstrip("/")

    def _build_client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            base_url=self._base_url,
            headers={
                "Authorization": self._api_key,
                "Content-Type": "application/json",
            },
            timeout=60.0,
        )

    async def pay_invoice(self, bolt11: str) -> str:
        """Pay via OpenNode's withdrawal endpoint.

        POST /v2/withdrawals — pays an invoice from OpenNode balance.

        Warning: OpenNode typically does not return the preimage, which
        means L402 token construction will fail. This adapter is provided
        for completeness but is NOT recommended for L402 use cases.
        """
        async with self._build_client() as client:
            try:
                resp = await client.post(
                    "/v2/withdrawals",
                    json={
                        "type": "ln",
                        "address": bolt11,
                    },
                )
            except httpx.HTTPError as e:
                raise PaymentFailedError(f"OpenNode connection error: {e}", bolt11)

            if resp.status_code not in (200, 201):
                raise PaymentFailedError(
                    f"OpenNode withdrawal failed ({resp.status_code}): {resp.text}",
                    bolt11,
                )

            data = resp.json().get("data", resp.json())

            # OpenNode may not return a preimage — check response
            preimage = data.get("preimage") or data.get("payment_preimage")

            if not preimage:
                raise PaymentFailedError(
                    "OpenNode payment succeeded but no preimage returned. "
                    "OpenNode does not support preimage extraction. "
                    "For L402, use Strike, LND, or a compatible NWC wallet.",
                    bolt11,
                )

            return preimage
