"""l402-requests — Auto-paying L402 HTTP client for Python.

APIs behind Lightning paywalls just work. Drop-in replacement for httpx
that automatically handles HTTP 402 responses by paying Lightning invoices
and retrying with L402 credentials.

Usage:
    import l402_requests

    # Module-level convenience (auto-detects wallet from env vars)
    response = l402_requests.get("https://api.example.com/paid-resource")

    # Or use the client directly for more control
    from l402_requests import L402Client, BudgetController

    client = L402Client(
        budget=BudgetController(max_sats_per_request=500),
    )
    response = client.get("https://api.example.com/paid-resource")
"""

from l402_requests.budget import BudgetController
from l402_requests.client import AsyncL402Client, L402Client
from l402_requests.credential_cache import CredentialCache, L402Credential
from l402_requests.exceptions import (
    BudgetExceededError,
    ChallengeParseError,
    DomainNotAllowedError,
    InvoiceExpiredError,
    L402Error,
    NoWalletError,
    PaymentFailedError,
)
from l402_requests.spending_log import SpendingLog
from l402_requests.wallets import (
    LndWallet,
    NwcWallet,
    OpenNodeWallet,
    StrikeWallet,
    WalletBase,
    auto_detect_wallet,
)

__version__ = "0.1.0"

__all__ = [
    # Clients
    "L402Client",
    "AsyncL402Client",
    # Budget
    "BudgetController",
    # Wallets
    "WalletBase",
    "StrikeWallet",
    "LndWallet",
    "NwcWallet",
    "OpenNodeWallet",
    "auto_detect_wallet",
    # Caching
    "CredentialCache",
    "L402Credential",
    # Spending
    "SpendingLog",
    # Exceptions
    "L402Error",
    "BudgetExceededError",
    "PaymentFailedError",
    "InvoiceExpiredError",
    "ChallengeParseError",
    "NoWalletError",
    "DomainNotAllowedError",
]

# Module-level convenience functions using a default client
_default_client: L402Client | None = None


def _get_default_client() -> L402Client:
    global _default_client
    if _default_client is None:
        _default_client = L402Client()
    return _default_client


def get(url: str, **kwargs) -> "httpx.Response":  # noqa: F821
    """Convenience: GET with automatic L402 payment."""
    return _get_default_client().get(url, **kwargs)


def post(url: str, **kwargs) -> "httpx.Response":  # noqa: F821
    """Convenience: POST with automatic L402 payment."""
    return _get_default_client().post(url, **kwargs)


def put(url: str, **kwargs) -> "httpx.Response":  # noqa: F821
    """Convenience: PUT with automatic L402 payment."""
    return _get_default_client().put(url, **kwargs)


def delete(url: str, **kwargs) -> "httpx.Response":  # noqa: F821
    """Convenience: DELETE with automatic L402 payment."""
    return _get_default_client().delete(url, **kwargs)


def patch(url: str, **kwargs) -> "httpx.Response":  # noqa: F821
    """Convenience: PATCH with automatic L402 payment."""
    return _get_default_client().patch(url, **kwargs)
