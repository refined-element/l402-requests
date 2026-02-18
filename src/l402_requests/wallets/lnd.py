"""LND REST wallet adapter."""

from __future__ import annotations

import base64
import ssl

import httpx

from l402_requests.exceptions import PaymentFailedError
from l402_requests.wallets import WalletBase


class LndWallet(WalletBase):
    """Pay invoices via LND REST API.

    Requires:
        - LND_REST_HOST: e.g., "https://localhost:8080"
        - LND_MACAROON_HEX: admin macaroon in hex format
        - LND_TLS_CERT_PATH (optional): path to tls.cert
    """

    def __init__(
        self,
        host: str,
        macaroon_hex: str,
        tls_cert_path: str | None = None,
    ):
        self._host = host.rstrip("/")
        self._macaroon_hex = macaroon_hex
        self._tls_cert_path = tls_cert_path

    def _build_client(self) -> httpx.AsyncClient:
        verify: bool | ssl.SSLContext = True
        if self._tls_cert_path:
            ctx = ssl.create_default_context()
            ctx.load_verify_locations(self._tls_cert_path)
            verify = ctx

        return httpx.AsyncClient(
            base_url=self._host,
            headers={"Grpc-Metadata-macaroon": self._macaroon_hex},
            verify=verify,
            timeout=60.0,
        )

    async def pay_invoice(self, bolt11: str) -> str:
        """Pay via LND's v2/router/send (sync streaming route).

        Uses the Router RPC SendPaymentV2 REST endpoint which returns
        the payment result including the preimage.
        """
        async with self._build_client() as client:
            # Use v2/router/send for synchronous payment with streaming response
            payment_request_b64 = base64.b64encode(bolt11.encode()).decode()
            payload = {
                "payment_request": bolt11,
                "timeout_seconds": 60,
                "fee_limit_sat": 100,
            }

            try:
                response = await client.post("/v2/router/send", json=payload, timeout=60.0)
            except httpx.HTTPError as e:
                raise PaymentFailedError(f"LND connection error: {e}", bolt11)

            if response.status_code != 200:
                raise PaymentFailedError(
                    f"LND returned {response.status_code}: {response.text}", bolt11
                )

            # v2/router/send returns newline-delimited JSON stream
            # Parse the last complete JSON object for the final payment state
            last_update = None
            for line in response.text.strip().split("\n"):
                line = line.strip()
                if line:
                    import json

                    try:
                        last_update = json.loads(line)
                    except json.JSONDecodeError:
                        continue

            if not last_update:
                raise PaymentFailedError("No response from LND router", bolt11)

            result = last_update.get("result", last_update)
            status = result.get("status", "")

            if status == "SUCCEEDED":
                preimage = result.get("payment_preimage", "")
                if not preimage:
                    raise PaymentFailedError("LND payment succeeded but no preimage returned", bolt11)
                # LND returns base64-encoded preimage, convert to hex
                try:
                    preimage_bytes = base64.b64decode(preimage)
                    return preimage_bytes.hex()
                except Exception:
                    # Already hex
                    return preimage
            elif status == "FAILED":
                failure_reason = result.get("failure_reason", "unknown")
                raise PaymentFailedError(f"LND payment failed: {failure_reason}", bolt11)
            else:
                raise PaymentFailedError(f"LND unexpected status: {status}", bolt11)
