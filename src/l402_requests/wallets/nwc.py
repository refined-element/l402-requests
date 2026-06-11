"""NWC (Nostr Wallet Connect) wallet adapter.

Requires optional dependency: pip install l402-requests[nwc]
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
    """Compute the NIP-01 event id.

    SHA256 of the canonical serialization ``[0, pubkey, created_at, kind, tags,
    content]`` (compact JSON, no spaces, unicode preserved).
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
        if not expected_wallet_pubkey or pubkey_hex.lower() != expected_wallet_pubkey.lower():
            return False

        # Recompute the id from the canonical serialization. Tampering with any
        # field (including the encrypted content) produces a different id.
        recomputed_id = _compute_nostr_event_id(event)
        if recomputed_id.lower() != id_hex.lower():
            return False

        import secp256k1

        # BIP340 x-only pubkey: prefix the 32-byte x with an (arbitrary) parity
        # byte to form a 33-byte compressed key; verification drops the parity.
        pubkey = secp256k1.PublicKey(b"\x02" + bytes.fromhex(pubkey_hex), raw=True)
        # raw=True → the 32-byte id is used directly as the message (already a
        # hash; must NOT be re-hashed). bip340tag is ignored when raw=True.
        return bool(
            pubkey.schnorr_verify(
                bytes.fromhex(id_hex), bytes.fromhex(sig_hex), None, raw=True
            )
        )
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
        self._wallet_pubkey = parsed.hostname or parsed.netloc
        params = parse_qs(parsed.query)
        self._relay = params.get("relay", [None])[0]
        self._secret = params.get("secret", [None])[0]
        self._timeout = timeout

        if not self._wallet_pubkey:
            raise ValueError("NWC connection string missing wallet pubkey")
        if not self._relay:
            raise ValueError("NWC connection string missing relay URL")
        if not self._secret:
            raise ValueError("NWC connection string missing secret")

    async def pay_invoice(self, bolt11: str) -> str:
        """Pay via NWC protocol (NIP-47 pay_invoice)."""
        try:
            import secp256k1
            import websockets
        except ImportError:
            raise ImportError(
                "NWC wallet requires extra dependencies. "
                "Install with: pip install l402-requests[nwc]"
            )

        # Derive keypair from secret
        secret_bytes = bytes.fromhex(self._secret)
        privkey = secp256k1.PrivateKey(secret_bytes)
        pubkey_hex = privkey.pubkey.serialize(compressed=True).hex()

        # Build NIP-47 pay_invoice request
        content = json.dumps({
            "method": "pay_invoice",
            "params": {"invoice": bolt11},
        })

        # Encrypt content (NIP-04)
        encrypted_content = self._nip04_encrypt(privkey, self._wallet_pubkey, content)

        # Build unsigned event (kind 23194 = NWC request)
        event = {
            "kind": 23194,
            "created_at": int(time.time()),
            "tags": [["p", self._wallet_pubkey]],
            "content": encrypted_content,
            "pubkey": pubkey_hex[2:] if len(pubkey_hex) == 66 else pubkey_hex,
        }

        # Compute event ID and sign
        event["id"] = self._compute_event_id(event)
        event["sig"] = self._sign_event(privkey, event["id"])

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
                    privkey, self._wallet_pubkey, response_event["content"]
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
    def _nip04_encrypt(privkey, recipient_pubkey_hex: str, plaintext: str) -> str:
        """NIP-04 encryption (simplified — uses shared secret + AES-256-CBC)."""
        import os
        import secp256k1

        # Compute shared secret
        recipient_bytes = bytes.fromhex(
            ("02" + recipient_pubkey_hex) if len(recipient_pubkey_hex) == 64 else recipient_pubkey_hex
        )
        recipient_key = secp256k1.PublicKey(recipient_bytes, raw=True)
        shared = recipient_key.ecdh(privkey.private_key)
        shared_x = shared[:32]

        # AES-256-CBC encrypt
        from hashlib import sha256

        iv = os.urandom(16)

        # Use a simple XOR-based approach or import cryptography if available
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            from cryptography.hazmat.primitives import padding

            padder = padding.PKCS7(128).padder()
            padded = padder.update(plaintext.encode()) + padder.finalize()
            cipher = Cipher(algorithms.AES(shared_x), modes.CBC(iv))
            encryptor = cipher.encryptor()
            ct = encryptor.update(padded) + encryptor.finalize()
        except ImportError:
            raise ImportError(
                "NWC encryption requires 'cryptography' package. "
                "Install with: pip install cryptography"
            )

        import base64

        ct_b64 = base64.b64encode(ct).decode()
        iv_b64 = base64.b64encode(iv).decode()
        return f"{ct_b64}?iv={iv_b64}"

    @staticmethod
    def _nip04_decrypt(privkey, sender_pubkey_hex: str, ciphertext: str) -> str:
        """NIP-04 decryption."""
        import base64
        import secp256k1

        sender_bytes = bytes.fromhex(
            ("02" + sender_pubkey_hex) if len(sender_pubkey_hex) == 64 else sender_pubkey_hex
        )
        sender_key = secp256k1.PublicKey(sender_bytes, raw=True)
        shared = sender_key.ecdh(privkey.private_key)
        shared_x = shared[:32]

        parts = ciphertext.split("?iv=")
        ct = base64.b64decode(parts[0])
        iv = base64.b64decode(parts[1])

        try:
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            from cryptography.hazmat.primitives import padding

            cipher = Cipher(algorithms.AES(shared_x), modes.CBC(iv))
            decryptor = cipher.decryptor()
            padded = decryptor.update(ct) + decryptor.finalize()
            unpadder = padding.PKCS7(128).unpadder()
            plaintext = unpadder.update(padded) + unpadder.finalize()
            return plaintext.decode()
        except ImportError:
            raise ImportError(
                "NWC decryption requires 'cryptography' package. "
                "Install with: pip install cryptography"
            )

    @staticmethod
    def _compute_event_id(event: dict) -> str:
        """Compute NIP-01 event ID."""
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

    @staticmethod
    def _sign_event(privkey, event_id_hex: str) -> str:
        """Sign event ID with Schnorr (NIP-01)."""
        import secp256k1

        msg = bytes.fromhex(event_id_hex)
        sig = privkey.schnorr_sign(msg)
        return sig.hex()
