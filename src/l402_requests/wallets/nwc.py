"""NWC (Nostr Wallet Connect) wallet adapter.

Uses ``coincurve`` for BIP340 Schnorr sign/verify, secp256k1 pubkey
derivation, and NIP-04 ECDH. ``coincurve`` ships prebuilt wheels for Linux,
macOS, AND Windows, so this module installs cleanly on every platform with
no compiler toolchain. The old ``[nwc]`` optional extra (which pulled in
the ``secp256k1`` C-extension that has no Windows wheel) is preserved as
an empty no-op for back-compat — see ``pyproject.toml``.

Also requires the ``websockets`` package for the NWC relay transport.
"""

from __future__ import annotations

import hashlib
import json
import secrets
import time
from urllib.parse import parse_qs, urlparse

from l402_requests.exceptions import PaymentFailedError
from l402_requests.wallets import WalletBase


def _compute_nostr_event_id(event: dict) -> str:
    """Compute the NIP-01 event id (single canonical implementation).

    SHA256 of the canonical serialization ``[0, pubkey, created_at, kind, tags,
    content]`` (compact JSON, no spaces, unicode preserved).

    This is the ONE event-id implementation used by both the signing path
    (``NwcWallet._compute_event_id`` delegates here) and the verification path
    (``verify_nostr_event_signature``), so the two can never diverge.
    """
    serialized = json.dumps(
        [
            0,
            event["pubkey"],
            event["created_at"],
            event["kind"],
            event["tags"],
            event["content"],
        ],
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return hashlib.sha256(serialized.encode()).hexdigest()


def _normalize_xonly_pubkey(pubkey_hex: str) -> str:
    """Normalize a secp256k1 pubkey to its lowercase 64-hex x-only form.

    A caller may hand us the wallet pubkey in *compressed* form (66 hex chars
    with an ``02``/``03`` parity-byte prefix — the same form this module already
    accepts in its NIP-04 encrypt/decrypt paths). Nostr events (NIP-01) always
    carry the 32-byte **x-only** pubkey (64 hex). To compare the two correctly we
    drop the parity prefix from a 66-hex compressed key. Anything else is
    returned lowercased and unchanged so the caller's own length/equality checks
    can reject malformed input.
    """
    normalized = (pubkey_hex or "").lower()
    if len(normalized) == 66 and normalized[:2] in ("02", "03"):
        return normalized[2:]
    return normalized


def _derive_xonly_pubkey(secret_key: bytes) -> str:
    """Derive the BIP340 x-only public key (32-byte hex) from a 32-byte secret.

    Wraps ``coincurve.PrivateKey`` so callers don't have to know which library
    is doing the curve math. The compressed-pubkey prefix byte is dropped to
    leave only the 32-byte X coordinate that NIP-01 events carry.
    """
    from coincurve import PrivateKey

    privkey = PrivateKey(secret_key)
    return privkey.public_key.format(compressed=True)[1:33].hex()


def _compute_shared_x(secret_key: bytes, pubkey_hex: str) -> bytes:
    """Compute the raw 32-byte ECDH shared x-coordinate for NIP-04.

    NIP-04 derives the AES-256-CBC key from the raw shared X (NOT
    ``sha256(shared_x)``). This matches the wire format used by ``l402-ts``,
    the .NET port, and the MCP server's NWC client — all empirically
    verified against CoinOS in production. Don't switch to sha256 without
    re-verifying against the wallets we care about.
    """
    from coincurve import PublicKey

    pubkey_bytes = bytes.fromhex(pubkey_hex)
    if len(pubkey_bytes) == 32:
        # 32-byte x-only → prepend an (arbitrary) parity byte for the
        # compressed-form constructor; the resulting curve point's X is the
        # same either way.
        pubkey_bytes = b"\x02" + pubkey_bytes
    pubkey = PublicKey(pubkey_bytes)
    shared_point = pubkey.multiply(secret_key)
    # Uncompressed point is 0x04 || X || Y — take raw X (bytes 1..33).
    return shared_point.format(compressed=False)[1:33]


def verify_nostr_event_signature(event: dict, expected_wallet_pubkey: str) -> bool:
    """Verify a Nostr event came from the expected wallet and is untampered.

    Returns ``True`` only when ALL of the following hold:

    1. ``event["pubkey"]`` equals ``expected_wallet_pubkey`` (case-insensitive).
    2. The recomputed NIP-01 event id matches ``event["id"]`` — so no field
       (content, tags, created_at, ...) was altered after signing.
    3. ``event["sig"]`` is a valid BIP340 Schnorr signature of that id under the
       claimed x-only ``pubkey``.

    Any malformed input (missing fields, wrong lengths, parse/crypto errors)
    returns ``False`` defensively. This is the F-11 guard: without it a malicious
    or compromised relay could forge a ``pay_invoice``/``get_balance`` response
    that the client would otherwise decrypt and trust. Mirrors the MCP server's
    ``_verify_nostr_event_signature`` (security audit F-11, MCP v1.12.8).
    """
    try:
        id_hex = event.get("id")
        pubkey_hex = event.get("pubkey")
        sig_hex = event.get("sig")

        if (
            not id_hex
            or not pubkey_hex
            or not sig_hex
            or len(id_hex) != 64
            or len(pubkey_hex) != 64
            or len(sig_hex) != 128
        ):
            return False

        # Pubkey must be the wallet we're talking to — reject relay-injected
        # events attributed to some other key before doing any signature math.
        # Normalize the expected key first: a caller may pass it in compressed
        # (66-hex, 02/03-prefixed) form, while the event carries the 64-hex
        # x-only pubkey. Without normalizing, a legitimate wallet response would
        # be wrongly rejected and pay_invoice would time out.
        if not expected_wallet_pubkey:
            return False
        if pubkey_hex.lower() != _normalize_xonly_pubkey(expected_wallet_pubkey):
            return False

        # Recompute the id from the canonical serialization. Tampering with any
        # field (including the encrypted content) produces a different id.
        recomputed_id = _compute_nostr_event_id(event)
        if recomputed_id.lower() != id_hex.lower():
            return False

        from coincurve import PublicKeyXOnly

        # BIP340 verification takes the 32-byte x-only pubkey directly. The
        # 32-byte event id is passed in unhashed — coincurve does not hash
        # the message a second time, matching the NIP-01 wire format.
        pubkey = PublicKeyXOnly(bytes.fromhex(pubkey_hex))
        return bool(pubkey.verify(bytes.fromhex(sig_hex), bytes.fromhex(id_hex)))
    except Exception:
        # Defensive: any parsing/crypto exception → treat as unverified.
        return False


class NwcWallet(WalletBase):
    """Pay invoices via Nostr Wallet Connect (NIP-47).

    Connection string format: nostr+walletconnect://<pubkey>?relay=<relay>&secret=<secret>

    Compatible with: CoinOS, CLINK, Alby, and other NWC wallets.
    """

    def __init__(self, connection_string: str, timeout: float = 30.0):
        parsed = urlparse(connection_string)
        raw_pubkey = parsed.hostname or parsed.netloc
        params = parse_qs(parsed.query)
        self._relay = params.get("relay", [None])[0]
        self._secret = params.get("secret", [None])[0]
        self._timeout = timeout

        if not raw_pubkey:
            raise ValueError("NWC connection string missing wallet pubkey")
        if not self._relay:
            raise ValueError("NWC connection string missing relay URL")
        if not self._secret:
            raise ValueError("NWC connection string missing secret")

        # Some NWC URIs ship the wallet pubkey in 66-hex COMPRESSED form
        # (02/03 parity-byte prefix); NIP-01 events carry the 64-hex x-only
        # form. Normalize once at construction time so every downstream use
        # (NIP-04 ECDH key, "p" tag on the kind-23194 request, wallet→client
        # response verification) sees the same canonical x-only key. The
        # verifier already tolerates compressed input on the EXPECTED-pubkey
        # side via _normalize_xonly_pubkey, but the send path used the raw
        # value and would embed the compressed key into the wire event — some
        # relays/wallets reject that, and the shared-X math would silently
        # use a different key from what the wallet uses.
        self._wallet_pubkey = _normalize_xonly_pubkey(raw_pubkey)

    async def pay_invoice(self, bolt11: str) -> str:
        """Pay via NWC protocol (NIP-47 pay_invoice)."""
        try:
            import websockets  # noqa: F401  (required dep — fail loudly if missing)
        except ImportError:
            raise ImportError(
                "NWC wallet requires the 'websockets' package. "
                "Install with: pip install websockets"
            )

        # Derive keypair from secret. coincurve.PrivateKey carries the raw
        # 32-byte secret_bytes through to sign/ECDH; we keep the bytes form so
        # the helpers below stay library-agnostic.
        secret_bytes = bytes.fromhex(self._secret)
        pubkey_hex = _derive_xonly_pubkey(secret_bytes)

        # Build NIP-47 pay_invoice request
        content = json.dumps({
            "method": "pay_invoice",
            "params": {"invoice": bolt11},
        })

        # Encrypt content (NIP-04)
        encrypted_content = self._nip04_encrypt(secret_bytes, self._wallet_pubkey, content)

        # Build unsigned event (kind 23194 = NWC request)
        event = {
            "kind": 23194,
            "created_at": int(time.time()),
            "tags": [["p", self._wallet_pubkey]],
            "content": encrypted_content,
            "pubkey": pubkey_hex,
        }

        # Compute event ID and sign
        event["id"] = self._compute_event_id(event)
        event["sig"] = self._sign_event(secret_bytes, event["id"])

        # Connect to relay and send
        async with websockets.connect(self._relay) as ws:
            # Subscribe for response (kind 23195 = NWC response)
            sub_id = secrets.token_hex(8)
            sub_filter = {
                "kinds": [23195],
                "#p": [event["pubkey"]],
                "since": event["created_at"] - 1,
            }
            await ws.send(json.dumps(["REQ", sub_id, sub_filter]))

            # Publish pay request
            await ws.send(json.dumps(["EVENT", event]))

            # Wait for response
            deadline = time.time() + self._timeout
            while time.time() < deadline:
                try:
                    import asyncio

                    raw = await asyncio.wait_for(
                        ws.recv(), timeout=min(5, deadline - time.time())
                    )
                    msg = json.loads(raw)
                except (TimeoutError, json.JSONDecodeError):
                    continue

                if not isinstance(msg, list) or len(msg) < 3:
                    continue
                if msg[0] != "EVENT" or msg[1] != sub_id:
                    continue

                response_event = msg[2]

                # F-11: verify the response is genuinely from the wallet pubkey
                # and untampered BEFORE decrypting/trusting its content. A
                # malicious relay can match the subscription filter and inject a
                # forged kind-23195 event; the BIP340 signature + pubkey check
                # rejects it. Drop and keep waiting for a valid response.
                if not verify_nostr_event_signature(
                    response_event, self._wallet_pubkey
                ):
                    continue

                decrypted = self._nip04_decrypt(
                    secret_bytes, self._wallet_pubkey, response_event["content"]
                )
                result = json.loads(decrypted)

                if result.get("error"):
                    code = result["error"].get("code", "unknown")
                    message = result["error"].get("message", "unknown error")
                    raise PaymentFailedError(f"NWC error {code}: {message}", bolt11)

                preimage = result.get("result", {}).get("preimage", "")
                if not preimage:
                    raise PaymentFailedError(
                        "NWC payment succeeded but no preimage returned", bolt11
                    )
                return preimage

            raise PaymentFailedError("NWC payment timed out", bolt11)

    @staticmethod
    def _nip04_encrypt(secret_key: bytes, recipient_pubkey_hex: str, plaintext: str) -> str:
        """NIP-04 encryption: AES-256-CBC with raw ECDH shared-X as key."""
        import base64
        import os

        from cryptography.hazmat.primitives import padding
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

        # AES key is the raw 32-byte shared X — matches l402-ts + CoinOS wire
        # format (see _compute_shared_x doctring on why we don't sha256 it).
        shared_x = _compute_shared_x(secret_key, recipient_pubkey_hex)

        iv = os.urandom(16)

        padder = padding.PKCS7(128).padder()
        padded = padder.update(plaintext.encode()) + padder.finalize()
        cipher = Cipher(algorithms.AES(shared_x), modes.CBC(iv))
        encryptor = cipher.encryptor()
        ct = encryptor.update(padded) + encryptor.finalize()

        ct_b64 = base64.b64encode(ct).decode()
        iv_b64 = base64.b64encode(iv).decode()
        return f"{ct_b64}?iv={iv_b64}"

    @staticmethod
    def _nip04_decrypt(secret_key: bytes, sender_pubkey_hex: str, ciphertext: str) -> str:
        """NIP-04 decryption: AES-256-CBC with raw ECDH shared-X as key."""
        import base64

        from cryptography.hazmat.primitives import padding
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

        shared_x = _compute_shared_x(secret_key, sender_pubkey_hex)

        parts = ciphertext.split("?iv=")
        ct = base64.b64decode(parts[0])
        iv = base64.b64decode(parts[1])

        cipher = Cipher(algorithms.AES(shared_x), modes.CBC(iv))
        decryptor = cipher.decryptor()
        padded = decryptor.update(ct) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded) + unpadder.finalize()
        return plaintext.decode()

    @staticmethod
    def _compute_event_id(event: dict) -> str:
        """Compute NIP-01 event ID.

        Delegates to the module-level :func:`_compute_nostr_event_id` so the
        signing path and the verification path share ONE canonical
        serialization and can never diverge.
        """
        return _compute_nostr_event_id(event)

    @staticmethod
    def _sign_event(secret_key: bytes, event_id_hex: str) -> str:
        """Sign event ID with Schnorr (BIP340) — NIP-01 sig field."""
        from coincurve import PrivateKey

        privkey = PrivateKey(secret_key)
        # BIP340 Schnorr over the raw 32-byte event id (coincurve does not
        # re-hash it — the id IS the message).
        sig = privkey.sign_schnorr(bytes.fromhex(event_id_hex))
        return sig.hex()
