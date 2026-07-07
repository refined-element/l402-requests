"""NWC (Nostr Wallet Connect) wallet adapter.

Uses ``coincurve`` for BIP340 Schnorr sign/verify, secp256k1 pubkey
derivation, and NIP-04/NIP-44 ECDH. ``coincurve`` ships prebuilt wheels for
Linux, macOS, AND Windows, so this module installs cleanly on every platform
with no compiler toolchain. The old ``[nwc]`` optional extra (which pulled in
the ``secp256k1`` C-extension that has no Windows wheel) is preserved as
an empty no-op for back-compat — see ``pyproject.toml``.

Also requires the ``websockets`` package for the NWC relay transport, and
``cryptography`` for the AES-256-CBC (NIP-04) and ChaCha20 (NIP-44 v2)
symmetric ciphers.

Encryption schemes
------------------
NIP-47 originally mandated NIP-04 (AES-256-CBC). Newer wallets (e.g. Alby Hub)
require NIP-44 v2 (ChaCha20 + HKDF-SHA256) and silently drop NIP-04 requests,
which surfaces as a 30–60s "no response" timeout. This adapter therefore:

* Supports BOTH NIP-04 and NIP-44 v2 for encrypt AND decrypt.
* Auto-detects the OUTBOUND scheme on the first request by fetching the
  wallet's NIP-47 INFO event (kind 13194) and reading its ``encryption`` tag.
  The choice is cached on the wallet instance. Falls back to NIP-04 on any
  timeout/failure (NIP-04 is the original NIP-47 default).
* Auto-detects the INBOUND scheme per response (``?iv=`` present ⇒ NIP-04,
  otherwise NIP-44 v2).

The outbound scheme can be pinned via the ``NWC_ENCRYPTION`` env var:
``auto`` (default) | ``nip04`` | ``nip44_v2``.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import secrets
import time
from urllib.parse import parse_qs, urlparse

from l402_requests.exceptions import PaymentFailedError
from l402_requests.wallets import WalletBase

logger = logging.getLogger("l402_requests.nwc")


# --------------------------------------------------------------------------
# Outbound encryption scheme selection
# --------------------------------------------------------------------------
# Default is ``auto`` — the wallet's NIP-47 INFO event (kind 13194) is fetched
# on the first request and the strongest advertised scheme is picked; the choice
# is cached for the wallet instance's lifetime. Falls back to NIP-04 when no INFO
# event is available, since NIP-04 is the original NIP-47 default and what every
# spec-pre-13194 wallet expects. Operators can pin a scheme via ``NWC_ENCRYPTION``.
NWC_ENCRYPTION_NIP04 = "nip04"
NWC_ENCRYPTION_NIP44_V2 = "nip44_v2"
NWC_ENCRYPTION_AUTO = "auto"
NWC_ENCRYPTION_DEFAULT = NWC_ENCRYPTION_AUTO
_VALID_NWC_ENCRYPTIONS = {
    NWC_ENCRYPTION_NIP04,
    NWC_ENCRYPTION_NIP44_V2,
    NWC_ENCRYPTION_AUTO,
}

# How long to wait for the NIP-47 INFO event before falling back to NIP-04.
# Kept short so a missing or stale relay never delays a real request by more
# than a few seconds. Module-level so tests can monkeypatch it.
NWC_AUTO_RESOLVE_TIMEOUT_SECONDS = 3.0


def _pick_encryption_from_info_tag(encryption_tag_value: str | None) -> str:
    """Pick the strongest scheme from a NIP-47 INFO event's ``encryption`` tag.

    The spec defines the tag value as a space-separated list of supported
    schemes (e.g. ``"nip04 nip44_v2"``). Prefers ``nip44_v2`` when listed
    (more secure); otherwise picks ``nip04``; falls back to ``nip04`` when the
    tag is empty/missing/unknown so spec-pre-13194 wallets still work.

    Pulled out as a module-level function so it can be unit-tested without
    spinning up a relay. Mirrors the MCP server's picker so both ports agree
    on the contract.
    """
    if not encryption_tag_value:
        return NWC_ENCRYPTION_NIP04

    schemes = {
        s.strip().lower()
        for s in encryption_tag_value.replace(",", " ").replace("\t", " ").split(" ")
        if s.strip()
    }

    if NWC_ENCRYPTION_NIP44_V2 in schemes:
        return NWC_ENCRYPTION_NIP44_V2
    return NWC_ENCRYPTION_NIP04


def _resolve_encryption_config() -> str:
    """Resolve the configured outbound-encryption mode from ``NWC_ENCRYPTION``.

    Returns one of the ``NWC_ENCRYPTION_*`` constants. An unset var ⇒ the
    documented default (``auto``). An invalid value ⇒ the default with a
    warning, so a typo doesn't silently disable a previously-working wallet.
    """
    override = os.environ.get("NWC_ENCRYPTION")
    if not override:
        return NWC_ENCRYPTION_DEFAULT

    normalized = override.strip().lower()
    if normalized in _VALID_NWC_ENCRYPTIONS:
        return normalized

    allowed_csv = ", ".join(sorted(_VALID_NWC_ENCRYPTIONS))
    logger.warning(
        "Ignoring invalid NWC_ENCRYPTION=%r (allowed: %s). Falling back to default %r.",
        override,
        allowed_csv,
        NWC_ENCRYPTION_DEFAULT,
    )
    return NWC_ENCRYPTION_DEFAULT


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
    """Compute the raw 32-byte ECDH shared x-coordinate.

    Both NIP-04 and NIP-44 v2 derive their symmetric key material from the raw
    shared X (NOT ``sha256(shared_x)``). For NIP-04 this matches the wire format
    used by ``l402-ts``, the .NET port, and the MCP server's NWC client — all
    empirically verified against CoinOS in production. Don't switch to sha256
    without re-verifying against the wallets we care about.
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
    (or a kind-13194 INFO event that downgrades encryption) that the client would
    otherwise decrypt and trust. Mirrors the MCP server's
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


# --------------------------------------------------------------------------
# NIP-04 (AES-256-CBC) — module-level single source of truth
# --------------------------------------------------------------------------

def _nip04_encrypt(secret_key: bytes, recipient_pubkey_hex: str, plaintext: str) -> str:
    """NIP-04 encryption: AES-256-CBC with raw ECDH shared-X as key."""
    import base64
    import os as _os

    from cryptography.hazmat.primitives import padding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    # AES key is the raw 32-byte shared X — matches l402-ts + CoinOS wire
    # format (see _compute_shared_x docstring on why we don't sha256 it).
    shared_x = _compute_shared_x(secret_key, recipient_pubkey_hex)

    iv = _os.urandom(16)

    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext.encode()) + padder.finalize()
    cipher = Cipher(algorithms.AES(shared_x), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ct = encryptor.update(padded) + encryptor.finalize()

    ct_b64 = base64.b64encode(ct).decode()
    iv_b64 = base64.b64encode(iv).decode()
    return f"{ct_b64}?iv={iv_b64}"


def _nip04_decrypt(secret_key: bytes, sender_pubkey_hex: str, ciphertext: str) -> str:
    """NIP-04 decryption: AES-256-CBC with raw ECDH shared-X as key.

    Raises :class:`ValueError` if ``ciphertext`` is not in the canonical
    NIP-04 format (``base64(ct)?iv=base64(iv)``). Without this guard a
    malformed wallet response would crash ``pay_invoice`` with an
    opaque ``IndexError`` on the split, which is harder to triage.
    """
    import base64
    import binascii

    from cryptography.hazmat.primitives import padding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    parts = ciphertext.split("?iv=")
    if len(parts) != 2 or not parts[0] or not parts[1]:
        raise ValueError(
            "NIP-04 ciphertext is not in the expected "
            "'base64(ct)?iv=base64(iv)' format"
        )

    # Normalize base64 errors into the same ValueError contract — without
    # this, a malformed ct or iv segment would surface as a binascii.Error
    # bubbling out of pay_invoice, which is harder to triage.
    try:
        ct = base64.b64decode(parts[0], validate=True)
        iv = base64.b64decode(parts[1], validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError(
            "NIP-04 ciphertext contains invalid base64 (in the "
            "ciphertext or IV segment)"
        ) from exc
    # AES-CBC requires a 16-byte IV; catch length issues before the
    # crypto layer raises its own (less specific) error.
    if len(iv) != 16:
        raise ValueError(
            f"NIP-04 IV must decode to 16 bytes; got {len(iv)} bytes"
        )

    shared_x = _compute_shared_x(secret_key, sender_pubkey_hex)

    cipher = Cipher(algorithms.AES(shared_x), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded = decryptor.update(ct) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded) + unpadder.finalize()
    return plaintext.decode()


# --------------------------------------------------------------------------
# NIP-44 v2 (ChaCha20 + HKDF-SHA256) — module-level single source of truth
# --------------------------------------------------------------------------

def _calc_padded_len(unpadded_len: int) -> int:
    """Calculate the NIP-44 padded length for a plaintext of ``unpadded_len``."""
    if unpadded_len <= 0:
        raise ValueError("Plaintext length must be > 0")
    if unpadded_len <= 32:
        return 32
    next_power = 1 << (unpadded_len - 1).bit_length()
    chunk = max(32, next_power >> 3)
    return chunk * ((unpadded_len + chunk - 1) // chunk)


def _hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    """HKDF-Expand (RFC 5869) with SHA-256."""
    import hmac as hmac_module
    import math

    hash_len = 32  # SHA-256 output length
    n = math.ceil(length / hash_len)
    okm = b""
    t = b""

    for i in range(1, n + 1):
        t = hmac_module.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t

    return okm[:length]


def _nip44_encrypt(secret_key: bytes, recipient_pubkey_hex: str, plaintext: str) -> str:
    """NIP-44 v2 encryption: ChaCha20 with HKDF-derived keys.

    Returns a base64-encoded payload: ``version(0x02) || nonce(32) ||
    ciphertext || mac(32)``.
    """
    import base64
    import hmac as hmac_module
    import os as _os
    import struct

    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms

    plaintext_bytes = plaintext.encode("utf-8")
    if len(plaintext_bytes) < 1 or len(plaintext_bytes) > 65535:
        raise ValueError(
            f"Plaintext length {len(plaintext_bytes)} out of range (1-65535)"
        )

    # Raw shared x-coordinate (NOT hashed — same derivation as NIP-04 here).
    shared_x = _compute_shared_x(secret_key, recipient_pubkey_hex)

    # conversation_key = HKDF-extract(salt="nip44-v2", ikm=shared_x)
    conversation_key = hmac_module.new(b"nip44-v2", shared_x, hashlib.sha256).digest()

    # Random 32-byte nonce
    nonce = _os.urandom(32)

    # Derive message keys via HKDF-expand
    message_keys = _hkdf_expand(conversation_key, nonce, 76)
    chacha_key = message_keys[0:32]
    chacha_nonce = message_keys[32:44]
    hmac_key = message_keys[44:76]

    # Pad plaintext: 2-byte big-endian length + plaintext + zero padding
    padded_len = _calc_padded_len(len(plaintext_bytes))
    padded = (
        struct.pack(">H", len(plaintext_bytes))
        + plaintext_bytes
        + b"\x00" * (padded_len - len(plaintext_bytes))
    )

    # Encrypt with ChaCha20 (raw stream cipher — 16-byte nonce = 4 counter + 12).
    chacha20_nonce = b"\x00\x00\x00\x00" + chacha_nonce
    cipher = Cipher(
        algorithms.ChaCha20(chacha_key, chacha20_nonce),
        mode=None,
        backend=default_backend(),
    )
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()

    # HMAC over nonce + ciphertext
    mac = hmac_module.new(hmac_key, nonce + ciphertext, hashlib.sha256).digest()

    payload = bytes([0x02]) + nonce + ciphertext + mac
    return base64.b64encode(payload).decode()


def _nip44_decrypt(secret_key: bytes, sender_pubkey_hex: str, ciphertext: str) -> str:
    """NIP-44 v2 decryption: ChaCha20 with HKDF-derived keys.

    Raises :class:`ValueError` if the version byte is not 0x02 or HMAC
    verification fails.
    """
    import base64
    import hmac
    import struct

    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms

    payload = base64.b64decode(ciphertext)

    version = payload[0]
    if version != 0x02:
        raise ValueError(
            f"Unsupported NIP-44 version: {version:#04x}, expected 0x02"
        )

    nonce = payload[1:33]  # 32 bytes
    ct = payload[33:-32]  # variable length
    mac = payload[-32:]  # 32 bytes

    shared_x = _compute_shared_x(secret_key, sender_pubkey_hex)

    # conversation_key = HKDF-extract(salt="nip44-v2", ikm=shared_x)
    conversation_key = hmac.new(b"nip44-v2", shared_x, hashlib.sha256).digest()

    # message_keys = HKDF-expand(prk=conversation_key, info=nonce, length=76)
    message_keys = _hkdf_expand(conversation_key, nonce, 76)
    chacha_key = message_keys[0:32]
    chacha_nonce = message_keys[32:44]  # 12 bytes
    hmac_key = message_keys[44:76]

    # Verify HMAC: HMAC-SHA256(key=hmac_key, msg=nonce + ciphertext)
    expected_mac = hmac.new(hmac_key, nonce + ct, hashlib.sha256).digest()
    if not hmac.compare_digest(mac, expected_mac):
        raise ValueError("NIP-44 HMAC verification failed")

    chacha20_nonce = b"\x00\x00\x00\x00" + chacha_nonce
    cipher = Cipher(
        algorithms.ChaCha20(chacha_key, chacha20_nonce),
        mode=None,
        backend=default_backend(),
    )
    decryptor = cipher.decryptor()
    decrypted = decryptor.update(ct) + decryptor.finalize()

    # First 2 bytes are the big-endian plaintext length.
    plaintext_len = struct.unpack(">H", decrypted[0:2])[0]
    plaintext = decrypted[2 : 2 + plaintext_len]
    return plaintext.decode("utf-8")


def _decrypt_auto(secret_key: bytes, sender_pubkey_hex: str, ciphertext: str) -> str:
    """Decrypt an NWC response, auto-detecting NIP-04 vs NIP-44 v2.

    NIP-04 payloads carry the ``?iv=`` separator; NIP-44 v2 payloads are a
    single base64 blob (no ``?iv=``). This lets the client accept a response in
    whichever scheme the wallet chose, independent of the outbound scheme.
    """
    if "?iv=" in ciphertext:
        return _nip04_decrypt(secret_key, sender_pubkey_hex, ciphertext)
    return _nip44_decrypt(secret_key, sender_pubkey_hex, ciphertext)


class NwcWallet(WalletBase):
    """Pay invoices via Nostr Wallet Connect (NIP-47).

    Connection string format: nostr+walletconnect://<pubkey>?relay=<relay>&secret=<secret>

    Compatible with: CoinOS, CLINK, Alby Hub, and other NWC wallets. The
    outbound encryption scheme (NIP-04 vs NIP-44 v2) is auto-detected from the
    wallet's NIP-47 INFO event on the first request, or pinned via the
    ``NWC_ENCRYPTION`` env var (``auto`` | ``nip04`` | ``nip44_v2``).
    """

    def __init__(self, connection_string: str, timeout: float = 60.0):
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

        # Validate the secret up front. ``bytes.fromhex`` raises a raw, opaque
        # ``ValueError`` from deep inside the pay_invoice path if the secret is
        # malformed — fail with a clearer error here instead, mentioning the
        # canonical NWC URI format. Length check catches "secret hex looks right
        # but it's not 32 bytes", which would otherwise silently produce a wrong
        # keypair downstream.
        try:
            secret_bytes = bytes.fromhex(self._secret)
        except ValueError as exc:
            raise ValueError(
                "NWC connection string 'secret' is not valid hex; expected "
                "64 hex characters (32 bytes; case-insensitive)"
            ) from exc
        if len(secret_bytes) != 32:
            raise ValueError(
                "NWC connection string 'secret' must decode to exactly 32 "
                f"bytes; got {len(secret_bytes)} bytes"
            )

        # Some NWC URIs ship the wallet pubkey in 66-hex COMPRESSED form
        # (02/03 parity-byte prefix); NIP-01 events carry the 64-hex x-only
        # form. Normalize once at construction time so every downstream use
        # (NIP-04/44 ECDH key, "p" tag on the kind-23194 request, wallet→client
        # response verification) sees the same canonical x-only key.
        self._wallet_pubkey = _normalize_xonly_pubkey(raw_pubkey)

        # Outbound encryption mode. Default ``auto`` — resolved lazily on the
        # first pay by fetching the wallet's NIP-47 INFO event. ``NWC_ENCRYPTION``
        # can pin a literal scheme (``nip04``/``nip44_v2``) which skips the fetch.
        self._encryption = _resolve_encryption_config()
        if self._encryption != NWC_ENCRYPTION_DEFAULT:
            logger.info("NWC outbound encryption set to: %s", self._encryption)

        # Auto-detect cache + lock. Populated on the first pay when ``_encryption``
        # is "auto". The lock serialises concurrent first-request fetches so we
        # don't open N relay connections at once. (``asyncio.Lock`` binds to the
        # running loop lazily on first use — safe to construct here on 3.10+.)
        import asyncio

        self._resolved_auto_encryption: str | None = None
        self._auto_resolve_lock = asyncio.Lock()

    async def pay_invoice(self, bolt11: str) -> str:
        """Pay via NWC protocol (NIP-47 pay_invoice)."""
        try:
            import websockets  # noqa: F401  (required dep — fail loudly if missing)
        except ImportError as exc:
            # ``websockets`` is a BASE dependency of l402-requests (see
            # pyproject.toml). If we land here it indicates a broken
            # install (partial pip operation, stale virtualenv, etc.) — not
            # a missing optional extra. Point users at reinstalling the
            # package rather than installing a sub-package the resolver
            # should have already pulled in.
            raise ImportError(
                "NWC wallet requires the 'websockets' package, which is a "
                "base dependency of l402-requests but is missing from your "
                "environment. Reinstall the package: pip install --upgrade "
                "--force-reinstall l402-requests"
            ) from exc

        import asyncio

        # Derive keypair from secret. coincurve.PrivateKey carries the raw
        # 32-byte secret_bytes through to sign/ECDH; we keep the bytes form so
        # the helpers below stay library-agnostic.
        secret_bytes = bytes.fromhex(self._secret)
        pubkey_hex = _derive_xonly_pubkey(secret_bytes)

        # Resolve outbound encryption. "auto" fetches the wallet's NIP-47 INFO
        # event once (cached); explicit "nip04"/"nip44_v2" skip the fetch.
        if self._encryption == NWC_ENCRYPTION_AUTO:
            effective_encryption = await self._resolve_auto_encryption()
        else:
            effective_encryption = self._encryption

        # Build NIP-47 pay_invoice request
        content = json.dumps({
            "method": "pay_invoice",
            "params": {"invoice": bolt11},
        })

        # Encrypt content with the resolved scheme.
        if effective_encryption == NWC_ENCRYPTION_NIP44_V2:
            encrypted_content = _nip44_encrypt(
                secret_bytes, self._wallet_pubkey, content
            )
            # Signal NIP-44 v2 to the wallet via the encryption tag.
            tags = [["p", self._wallet_pubkey], ["encryption", "nip44_v2"]]
        else:
            encrypted_content = _nip04_encrypt(
                secret_bytes, self._wallet_pubkey, content
            )
            # No "encryption" tag for NIP-04 — that's the original NIP-47 default.
            tags = [["p", self._wallet_pubkey]]

        # Build unsigned event (kind 23194 = NWC request)
        event = {
            "kind": 23194,
            "created_at": int(time.time()),
            "tags": tags,
            "content": encrypted_content,
            "pubkey": pubkey_hex,
        }

        # Compute event ID and sign
        event["id"] = self._compute_event_id(event)
        event["sig"] = self._sign_event(secret_bytes, event["id"])

        # Connect to relay and send
        async with websockets.connect(self._relay) as ws:
            # Subscribe for response (kind 23195 = NWC response). The ``#e``
            # filter pins the response to THIS request's event id so we don't
            # pick up a stale/parallel response; ``#p`` scopes it to us.
            sub_id = secrets.token_hex(8)
            sub_filter = {
                "kinds": [23195],
                "#e": [event["id"]],
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
                    raw = await asyncio.wait_for(
                        ws.recv(), timeout=min(5, deadline - time.time())
                    )
                    msg = json.loads(raw)
                except (TimeoutError, asyncio.TimeoutError, json.JSONDecodeError):
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

                # Inbound scheme is auto-detected per response (``?iv=`` ⇒ NIP-04,
                # else NIP-44 v2), independent of the outbound scheme.
                decrypted = _decrypt_auto(
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

            # Timed out with no valid response. The most common cause is an
            # outbound-encryption mismatch (Alby Hub silently drops nip04;
            # Primal/CoinOS silently drop nip44_v2) — name the scheme we used
            # and the alternative so the caller can pin the other one.
            alt_scheme = (
                NWC_ENCRYPTION_NIP04
                if effective_encryption == NWC_ENCRYPTION_NIP44_V2
                else NWC_ENCRYPTION_NIP44_V2
            )
            raise PaymentFailedError(
                f"NWC payment timed out after {self._timeout:.0f}s using "
                f"{effective_encryption} encryption. Most common cause: "
                f"encryption mismatch — the wallet may require the other scheme. "
                f"Try setting NWC_ENCRYPTION={alt_scheme} (e.g. Alby Hub requires "
                f"nip44_v2; Primal/CoinOS require nip04).",
                bolt11,
            )

    async def _resolve_auto_encryption(self) -> str:
        """Resolve outbound encryption when configured as "auto".

        Fetches the wallet's NIP-47 INFO event (kind 13194) once on the first
        request, picks the strongest advertised scheme, and caches the result on
        this wallet instance for the rest of its lifetime. On any failure (relay
        unreachable, timeout, malformed event) falls back to NIP-04.

        Concurrent first calls are serialised by ``_auto_resolve_lock`` so we
        don't open N relay connections for N parallel first-requests.
        """
        # Fast-path cache check
        if self._resolved_auto_encryption is not None:
            return self._resolved_auto_encryption

        async with self._auto_resolve_lock:
            # Double-check after acquiring the lock
            if self._resolved_auto_encryption is not None:
                return self._resolved_auto_encryption

            resolved = await self._fetch_encryption_from_info_event()
            self._resolved_auto_encryption = resolved
            logger.info("NWC auto-detect resolved outbound encryption: %s", resolved)
            return resolved

    async def _fetch_encryption_from_info_event(self) -> str:
        """One-shot WebSocket REQ for the wallet's kind 13194 (NIP-47 INFO) event.

        Always returns a value — exceptions and timeouts translate to the NIP-04
        fallback so a flaky relay or older wallet doesn't make every future
        request fail. Verifies the INFO event's pubkey + BIP340 signature before
        trusting its ``encryption`` tag (a malicious relay could otherwise forge
        an INFO event and force an encryption downgrade/DoS).
        """
        import asyncio

        import websockets

        # Wall-clock deadline for the whole fetch, tracked via monotonic time so
        # the cap is faithfully enforced regardless of message rate or load.
        deadline = time.monotonic() + NWC_AUTO_RESOLVE_TIMEOUT_SECONDS
        ws = None
        try:
            connect_remaining = max(0.0, deadline - time.monotonic())
            ws = await asyncio.wait_for(
                websockets.connect(self._relay),
                timeout=connect_remaining,
            )

            sub_id = secrets.token_hex(8)
            req = json.dumps(
                [
                    "REQ",
                    sub_id,
                    {
                        "kinds": [13194],
                        "authors": [self._wallet_pubkey],
                        "limit": 1,
                    },
                ]
            )
            await ws.send(req)

            # Drain messages until the deadline. The wallet publishes 13194 to
            # the relay; relays usually have it stored, so we get EVENT then EOSE
            # quickly. Older wallets that never published one trigger EOSE
            # without an EVENT and we fall back.
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    logger.info(
                        "NWC INFO-event fetch timed out after %ss; falling back to NIP-04",
                        NWC_AUTO_RESOLVE_TIMEOUT_SECONDS,
                    )
                    return NWC_ENCRYPTION_NIP04
                msg_raw = await asyncio.wait_for(ws.recv(), timeout=remaining)
                try:
                    data = json.loads(msg_raw)
                except json.JSONDecodeError:
                    continue
                if not isinstance(data, list) or len(data) < 2:
                    continue
                msg_type = data[0]
                if msg_type == "EVENT" and len(data) >= 3:
                    # Validate subscription id matches the one we just generated.
                    # A relay (or hostile peer) could otherwise inject an
                    # unsolicited EVENT we'd treat as the wallet's INFO event
                    # and silently downgrade/upgrade encryption for real calls.
                    rcv_sub_id = data[1] if len(data) > 1 else None
                    if rcv_sub_id != sub_id:
                        continue

                    event = data[2]
                    if not isinstance(event, dict) or event.get("kind") != 13194:
                        continue

                    # Cryptographic verification: pubkey must match the wallet AND
                    # the BIP340 signature must be valid over the recomputed id.
                    # Any tampered tag (including the encryption tag we're about
                    # to read) breaks verification. This is the F-11 guard applied
                    # to the INFO-event auto-detect path.
                    if not verify_nostr_event_signature(event, self._wallet_pubkey):
                        logger.info(
                            "NWC INFO event signature verification failed; ignoring"
                        )
                        continue

                    enc_tag_value: str | None = None
                    for tag in event.get("tags", []):
                        if (
                            isinstance(tag, list)
                            and len(tag) >= 2
                            and tag[0] == "encryption"
                        ):
                            enc_tag_value = tag[1]
                            break
                    return _pick_encryption_from_info_tag(enc_tag_value)
                elif msg_type == "EOSE":
                    rcv_sub_id = data[1] if len(data) > 1 else None
                    if rcv_sub_id != sub_id:
                        # EOSE for a different subscription — ignore.
                        continue
                    logger.info(
                        "NWC INFO event not in relay history; falling back to NIP-04"
                    )
                    return NWC_ENCRYPTION_NIP04
        except asyncio.CancelledError:
            # Caller cancellation must propagate — don't translate to a fallback.
            raise
        except (asyncio.TimeoutError, TimeoutError):
            logger.info(
                "NWC INFO-event fetch timed out after %ss; falling back to NIP-04",
                NWC_AUTO_RESOLVE_TIMEOUT_SECONDS,
            )
            return NWC_ENCRYPTION_NIP04
        except Exception as e:
            logger.info(
                "NWC INFO-event fetch failed (%s); falling back to NIP-04",
                e,
            )
            return NWC_ENCRYPTION_NIP04
        finally:
            if ws is not None:
                try:
                    await ws.close()
                except Exception:
                    pass

    # ── Static crypto delegators (stable public-ish test API) ────────────
    # These preserve the historical ``NwcWallet._nip04_encrypt`` / ``_nip04_decrypt``
    # call sites (and add NIP-44 siblings). They delegate to the module-level
    # functions so the crypto has a single source of truth.

    @staticmethod
    def _nip04_encrypt(secret_key: bytes, recipient_pubkey_hex: str, plaintext: str) -> str:
        """NIP-04 encryption: AES-256-CBC with raw ECDH shared-X as key."""
        return _nip04_encrypt(secret_key, recipient_pubkey_hex, plaintext)

    @staticmethod
    def _nip04_decrypt(secret_key: bytes, sender_pubkey_hex: str, ciphertext: str) -> str:
        """NIP-04 decryption: AES-256-CBC with raw ECDH shared-X as key."""
        return _nip04_decrypt(secret_key, sender_pubkey_hex, ciphertext)

    @staticmethod
    def _nip44_encrypt(secret_key: bytes, recipient_pubkey_hex: str, plaintext: str) -> str:
        """NIP-44 v2 encryption: ChaCha20 + HKDF-SHA256."""
        return _nip44_encrypt(secret_key, recipient_pubkey_hex, plaintext)

    @staticmethod
    def _nip44_decrypt(secret_key: bytes, sender_pubkey_hex: str, ciphertext: str) -> str:
        """NIP-44 v2 decryption: ChaCha20 + HKDF-SHA256."""
        return _nip44_decrypt(secret_key, sender_pubkey_hex, ciphertext)

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
