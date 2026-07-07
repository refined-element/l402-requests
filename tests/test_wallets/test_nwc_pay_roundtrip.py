"""End-to-end NWC pay_invoice round-trips against an in-memory fake relay.

These are the direct regression proof for the reported bug: a wallet that only
speaks NIP-44 v2 (e.g. Alby Hub) used to time out silently because the client
was NIP-04-only. With NIP-44 support + outbound auto-detect, the client now
pays such a wallet. The fake relay plays the wallet: it signs kind-23195
responses with the wallet key and encrypts them with ECDH(wallet, client), so
the full sign/verify + ECDH + symmetric-cipher path is exercised for real (only
the WebSocket transport is faked).
"""

import json
import time

import pytest

from l402_requests.exceptions import PaymentFailedError
from l402_requests.wallets.nwc import (
    NwcWallet,
    _compute_nostr_event_id,
    _derive_xonly_pubkey,
    _nip04_encrypt,
    _nip44_encrypt,
)

# Deterministic, valid secp256k1 scalars (NOT real wallet creds).
_CLIENT_SECRET = bytes.fromhex("11" * 32)
_WALLET_SECRET = bytes.fromhex("22" * 32)
_ATTACKER_SECRET = bytes.fromhex("33" * 32)
_PREIMAGE = "ab" * 32  # 64-hex — a valid-looking preimage

_WALLET_PUBKEY = _derive_xonly_pubkey(_WALLET_SECRET)
_ATTACKER_PUBKEY = _derive_xonly_pubkey(_ATTACKER_SECRET)


def _conn(relay: str = "ws://fake-relay") -> str:
    return (
        f"nostr+walletconnect://{_WALLET_PUBKEY}"
        f"?relay={relay}&secret={_CLIENT_SECRET.hex()}"
    )


def _build_info_event(signer_secret: bytes, pubkey: str, enc_tag: str) -> dict:
    ev = {
        "kind": 13194,
        "pubkey": pubkey,
        "created_at": int(time.time()),
        "tags": [["encryption", enc_tag]],
        "content": "pay_invoice get_balance",
    }
    ev["id"] = _compute_nostr_event_id(ev)
    ev["sig"] = NwcWallet._sign_event(signer_secret, ev["id"])
    return ev


class _WalletServer:
    """Scriptable NWC wallet backing the fake relay."""

    def __init__(
        self,
        *,
        response_scheme: str = "nip04",
        respond_to_pay: bool = True,
        info_event: dict | None = None,
        serve_info: bool = False,
    ):
        self.response_scheme = response_scheme
        self.respond_to_pay = respond_to_pay
        self.info_event = info_event
        self.serve_info = serve_info
        self._pay_sub: str | None = None

    def on_send(self, msg: list) -> list[str]:
        out: list[str] = []
        if not isinstance(msg, list) or not msg:
            return out
        if msg[0] == "REQ":
            sub_id = msg[1]
            filt = msg[2] if len(msg) > 2 else {}
            kinds = filt.get("kinds", [])
            if 13194 in kinds:
                if self.serve_info and self.info_event is not None:
                    out.append(json.dumps(["EVENT", sub_id, self.info_event]))
                out.append(json.dumps(["EOSE", sub_id]))
            elif 23195 in kinds:
                self._pay_sub = sub_id
            return out
        if msg[0] == "EVENT":
            req = msg[1]
            if self.respond_to_pay and self._pay_sub is not None:
                out.append(
                    json.dumps(["EVENT", self._pay_sub, self._build_pay_response(req)])
                )
            return out
        return out

    def _build_pay_response(self, req: dict) -> dict:
        client_pubkey = req["pubkey"]
        result = {"result_type": "pay_invoice", "result": {"preimage": _PREIMAGE}}
        content = json.dumps(result)
        if self.response_scheme == "nip44_v2":
            enc = _nip44_encrypt(_WALLET_SECRET, client_pubkey, content)
        else:
            enc = _nip04_encrypt(_WALLET_SECRET, client_pubkey, content)
        resp = {
            "kind": 23195,
            "created_at": int(time.time()),
            "tags": [["p", client_pubkey], ["e", req["id"]]],
            "content": enc,
            "pubkey": _WALLET_PUBKEY,
        }
        resp["id"] = _compute_nostr_event_id(resp)
        resp["sig"] = NwcWallet._sign_event(_WALLET_SECRET, resp["id"])
        return resp


class _FakeWS:
    def __init__(self, server: _WalletServer):
        import asyncio

        self._server = server
        self._inbox: "asyncio.Queue[str]" = asyncio.Queue()
        self.closed = False

    async def send(self, raw: str) -> None:
        for resp in self._server.on_send(json.loads(raw)):
            await self._inbox.put(resp)

    async def recv(self) -> str:
        return await self._inbox.get()

    async def close(self) -> None:
        self.closed = True


class _FakeConnect:
    """Supports both ``await connect(url)`` and ``async with connect(url)``."""

    def __init__(self, server: _WalletServer):
        self._server = server

    def __await__(self):
        async def _ret():
            return _FakeWS(self._server)

        return _ret().__await__()

    async def __aenter__(self):
        self._ws = _FakeWS(self._server)
        return self._ws

    async def __aexit__(self, *_a):
        await self._ws.close()


def _install_fake_relay(monkeypatch, server: _WalletServer) -> None:
    import websockets

    def _fake_connect(url, *args, **kwargs):
        return _FakeConnect(server)

    monkeypatch.setattr(websockets, "connect", _fake_connect)


class TestPayRoundTrip:
    async def test_pay_over_nip04_forced(self, monkeypatch):
        monkeypatch.setenv("NWC_ENCRYPTION", "nip04")
        server = _WalletServer(response_scheme="nip04")
        _install_fake_relay(monkeypatch, server)

        wallet = NwcWallet(_conn())
        preimage = await wallet.pay_invoice("lnbc10u1ptestinvoice")
        assert preimage == _PREIMAGE

    async def test_pay_over_nip44_forced(self, monkeypatch):
        # THE BUG FIX: a NIP-44-only wallet (Alby Hub) is now payable.
        monkeypatch.setenv("NWC_ENCRYPTION", "nip44_v2")
        server = _WalletServer(response_scheme="nip44_v2")
        _install_fake_relay(monkeypatch, server)

        wallet = NwcWallet(_conn())
        preimage = await wallet.pay_invoice("lnbc10u1ptestinvoice")
        assert preimage == _PREIMAGE

    async def test_pay_auto_resolves_nip44_from_info_event(self, monkeypatch):
        # AUTO mode: INFO event advertises nip44_v2 → outbound picks nip44_v2 →
        # wallet responds in nip44_v2 → client decrypts (inbound auto-detect).
        monkeypatch.delenv("NWC_ENCRYPTION", raising=False)
        info = _build_info_event(_WALLET_SECRET, _WALLET_PUBKEY, "nip04 nip44_v2")
        server = _WalletServer(
            response_scheme="nip44_v2", info_event=info, serve_info=True
        )
        _install_fake_relay(monkeypatch, server)

        wallet = NwcWallet(_conn())
        preimage = await wallet.pay_invoice("lnbc10u1ptestinvoice")
        assert preimage == _PREIMAGE
        assert wallet._resolved_auto_encryption == "nip44_v2"

    async def test_pay_auto_falls_back_to_nip04_when_no_info(self, monkeypatch):
        # AUTO mode, wallet publishes no INFO event → fall back to nip04 and pay.
        monkeypatch.delenv("NWC_ENCRYPTION", raising=False)
        server = _WalletServer(response_scheme="nip04", serve_info=False)
        _install_fake_relay(monkeypatch, server)

        wallet = NwcWallet(_conn())
        preimage = await wallet.pay_invoice("lnbc10u1ptestinvoice")
        assert preimage == _PREIMAGE
        assert wallet._resolved_auto_encryption == "nip04"

    async def test_pay_inbound_scheme_independent_of_outbound(self, monkeypatch):
        # Outbound nip04, but wallet answers in nip44_v2 — inbound auto-detect
        # must still decrypt it.
        monkeypatch.setenv("NWC_ENCRYPTION", "nip04")
        server = _WalletServer(response_scheme="nip44_v2")
        _install_fake_relay(monkeypatch, server)

        wallet = NwcWallet(_conn())
        preimage = await wallet.pay_invoice("lnbc10u1ptestinvoice")
        assert preimage == _PREIMAGE

    async def test_timeout_error_names_encryption_mismatch(self, monkeypatch):
        # Wallet never responds → the timeout error must name the used scheme
        # and suggest the alternative (the mismatch hint).
        monkeypatch.setenv("NWC_ENCRYPTION", "nip44_v2")
        server = _WalletServer(respond_to_pay=False)
        _install_fake_relay(monkeypatch, server)

        wallet = NwcWallet(_conn(), timeout=0.5)
        with pytest.raises(PaymentFailedError) as excinfo:
            await wallet.pay_invoice("lnbc10u1ptestinvoice")
        msg = str(excinfo.value)
        assert "nip44_v2" in msg
        assert "NWC_ENCRYPTION=nip04" in msg


class TestFetchEncryptionFromInfoEvent:
    async def test_valid_info_event_advertising_nip44(self, monkeypatch):
        monkeypatch.delenv("NWC_ENCRYPTION", raising=False)
        info = _build_info_event(_WALLET_SECRET, _WALLET_PUBKEY, "nip04 nip44_v2")
        server = _WalletServer(info_event=info, serve_info=True)
        _install_fake_relay(monkeypatch, server)

        wallet = NwcWallet(_conn())
        assert await wallet._fetch_encryption_from_info_event() == "nip44_v2"

    async def test_forged_info_event_wrong_pubkey_falls_back_to_nip04(self, monkeypatch):
        # A relay-injected INFO event signed by an attacker key (pubkey != wallet)
        # must be rejected by the F-11 sig/pubkey check → fall back to nip04,
        # never trusting the forged encryption tag.
        monkeypatch.delenv("NWC_ENCRYPTION", raising=False)
        forged = _build_info_event(
            _ATTACKER_SECRET, _ATTACKER_PUBKEY, "nip44_v2"
        )
        server = _WalletServer(info_event=forged, serve_info=True)
        _install_fake_relay(monkeypatch, server)

        wallet = NwcWallet(_conn())
        assert await wallet._fetch_encryption_from_info_event() == "nip04"
