"""Tests for the ``WalletBase.supports_preimage`` parity attribute.

L402 cannot complete without a preimage, so callers should be able to
check ``wallet.supports_preimage`` up front instead of attempting a payment
and catching the resulting :class:`PaymentFailedError`. This file is a
focused contract test for that attribute across every shipped adapter.
"""

from __future__ import annotations

from l402_requests.wallets import WalletBase
from l402_requests.wallets.lnd import LndWallet
from l402_requests.wallets.opennode import OpenNodeWallet
from l402_requests.wallets.strike import StrikeWallet


def test_walletbase_default_is_true():
    """Default class attribute is True — most backends return preimage."""
    assert WalletBase.supports_preimage is True


def test_strike_supports_preimage():
    wallet = StrikeWallet(api_key="test")
    assert wallet.supports_preimage is True


def test_lnd_supports_preimage():
    wallet = LndWallet(host="https://localhost:8080", macaroon_hex="aabb")
    assert wallet.supports_preimage is True


def test_opennode_does_not_support_preimage():
    wallet = OpenNodeWallet(api_key="test")
    assert wallet.supports_preimage is False


def test_attribute_accessible_via_class_not_only_instance():
    """Lets callers branch on capability without constructing the wallet."""
    assert StrikeWallet.supports_preimage is True
    assert LndWallet.supports_preimage is True
    assert OpenNodeWallet.supports_preimage is False
