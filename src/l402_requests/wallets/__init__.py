"""Wallet adapters for paying Lightning invoices.

Auto-detection priority: LND > NWC > Strike > OpenNode.
Each adapter implements WalletBase with a single pay_invoice() method.

Credentials are resolved from environment variables first, then from
~/.lightning-enable/config.json (matching the MCP server's behavior).
"""

from __future__ import annotations

import json
import os
from abc import ABC, abstractmethod
from pathlib import Path

from l402_requests.exceptions import NoWalletError

_CONFIG_PATH = Path.home() / ".lightning-enable" / "config.json"


class WalletBase(ABC):
    """Abstract base for Lightning wallet adapters."""

    @abstractmethod
    async def pay_invoice(self, bolt11: str) -> str:
        """Pay a BOLT11 invoice and return the preimage (hex).

        Args:
            bolt11: BOLT11-encoded Lightning invoice string.

        Returns:
            Payment preimage as a hex string.

        Raises:
            PaymentFailedError: If the payment fails.
        """

    def pay_invoice_sync(self, bolt11: str) -> str:
        """Synchronous wrapper for pay_invoice.

        Subclasses may override with a native sync implementation.
        """
        import asyncio

        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None

        if loop and loop.is_running():
            # We're inside an async context — run in a new thread
            import concurrent.futures

            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(asyncio.run, self.pay_invoice(bolt11))
                return future.result(timeout=60)
        else:
            return asyncio.run(self.pay_invoice(bolt11))


def _is_real_value(val: str | None) -> bool:
    """Check if an env var value is a real credential (not a placeholder)."""
    if not val:
        return False
    return not val.startswith("${")


def _load_config() -> dict:
    """Load ~/.lightning-enable/config.json if it exists."""
    try:
        if _CONFIG_PATH.exists():
            return json.loads(_CONFIG_PATH.read_text())
    except (json.JSONDecodeError, OSError):
        pass
    return {}


def _resolve_credential(env_var: str, config_key: str, wallets_config: dict) -> str:
    """Resolve a credential: env var first (skip placeholders), then config file."""
    val = os.environ.get(env_var, "")
    if _is_real_value(val):
        return val
    return wallets_config.get(config_key, "")


def _try_build_wallet(
    name: str, wallets_config: dict
) -> WalletBase | None:
    """Try to build a specific wallet by name. Returns None if not configured."""
    if name == "lnd":
        lnd_host = os.environ.get("LND_REST_HOST", "")
        lnd_mac = os.environ.get("LND_MACAROON_HEX", "")
        if _is_real_value(lnd_host) and _is_real_value(lnd_mac):
            from l402_requests.wallets.lnd import LndWallet

            return LndWallet(
                host=lnd_host,
                macaroon_hex=lnd_mac,
                tls_cert_path=os.environ.get("LND_TLS_CERT_PATH"),
            )

    elif name == "nwc":
        nwc_conn = _resolve_credential(
            "NWC_CONNECTION_STRING", "nwcConnectionString", wallets_config
        )
        if nwc_conn:
            from l402_requests.wallets.nwc import NwcWallet

            return NwcWallet(connection_string=nwc_conn)

    elif name == "strike":
        strike_key = _resolve_credential(
            "STRIKE_API_KEY", "strikeApiKey", wallets_config
        )
        if strike_key:
            from l402_requests.wallets.strike import StrikeWallet

            return StrikeWallet(api_key=strike_key)

    elif name == "opennode":
        opennode_key = _resolve_credential(
            "OPENNODE_API_KEY", "openNodeApiKey", wallets_config
        )
        if opennode_key:
            from l402_requests.wallets.opennode import OpenNodeWallet

            return OpenNodeWallet(api_key=opennode_key)

    return None


# Default priority when no config priority is set
_DEFAULT_PRIORITY = ["lnd", "nwc", "strike", "opennode"]

# Map config priority values to wallet names
_PRIORITY_ALIASES = {
    "strike": "strike",
    "opennode": "opennode",
    "nwc": "nwc",
    "lnd": "lnd",
    "nostr": "nwc",
}


def auto_detect_wallet() -> WalletBase:
    """Auto-detect a wallet from environment variables or config file.

    Resolution order for each wallet: env var → ~/.lightning-enable/config.json.
    Env vars that are placeholders (e.g., "${STRIKE_API_KEY}") are skipped.

    If the config file has a "wallets.priority" field (e.g., "strike"), that
    wallet is tried first. Otherwise, default order: LND > NWC > Strike > OpenNode.

    Returns:
        A configured wallet adapter.

    Raises:
        NoWalletError: If no wallet credentials are found.
    """
    config = _load_config()
    wallets_config = config.get("wallets", {})

    # Build priority order: preferred wallet first, then defaults
    priority = list(_DEFAULT_PRIORITY)
    preferred = wallets_config.get("priority", "")
    if preferred:
        preferred_name = _PRIORITY_ALIASES.get(preferred.lower(), "")
        if preferred_name and preferred_name in priority:
            priority.remove(preferred_name)
            priority.insert(0, preferred_name)

    for name in priority:
        wallet = _try_build_wallet(name, wallets_config)
        if wallet is not None:
            return wallet

    raise NoWalletError()


# Re-export wallet classes for convenience
from l402_requests.wallets.lnd import LndWallet as LndWallet
from l402_requests.wallets.nwc import NwcWallet as NwcWallet
from l402_requests.wallets.opennode import OpenNodeWallet as OpenNodeWallet
from l402_requests.wallets.strike import StrikeWallet as StrikeWallet

__all__ = [
    "WalletBase",
    "auto_detect_wallet",
    "LndWallet",
    "NwcWallet",
    "StrikeWallet",
    "OpenNodeWallet",
]
