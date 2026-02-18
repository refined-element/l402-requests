"""Tests for NWC wallet adapter."""

import pytest

from l402_requests.wallets.nwc import NwcWallet


class TestNwcWallet:
    def test_parses_connection_string(self):
        conn = "nostr+walletconnect://abc123pubkey?relay=wss://relay.example.com&secret=deadbeef1234"
        wallet = NwcWallet(connection_string=conn)
        assert wallet._wallet_pubkey == "abc123pubkey"
        assert wallet._relay == "wss://relay.example.com"
        assert wallet._secret == "deadbeef1234"

    def test_missing_relay_raises(self):
        conn = "nostr+walletconnect://abc123pubkey?secret=deadbeef1234"
        with pytest.raises(ValueError, match="missing relay"):
            NwcWallet(connection_string=conn)

    def test_missing_secret_raises(self):
        conn = "nostr+walletconnect://abc123pubkey?relay=wss://relay.example.com"
        with pytest.raises(ValueError, match="missing secret"):
            NwcWallet(connection_string=conn)

    def test_missing_pubkey_raises(self):
        conn = "nostr+walletconnect://?relay=wss://relay.example.com&secret=deadbeef1234"
        with pytest.raises(ValueError, match="missing wallet pubkey"):
            NwcWallet(connection_string=conn)

    def test_custom_timeout(self):
        conn = "nostr+walletconnect://abc123pubkey?relay=wss://relay.example.com&secret=deadbeef1234"
        wallet = NwcWallet(connection_string=conn, timeout=60.0)
        assert wallet._timeout == 60.0
