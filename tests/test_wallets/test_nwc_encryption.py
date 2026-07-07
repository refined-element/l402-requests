"""NIP-44 v2 crypto + outbound encryption auto-detect tests.

Ported/adapted from ``lightning-enable-mcp/tests/test_nwc_wallet.py`` to
l402-requests' module API. Covers:

  * NIP-04 decrypt (raw-shared-X CoinOS wire format).
  * NIP-44 v2 encrypt/decrypt, version-byte + HMAC tamper rejection.
  * Inbound auto-detect (``?iv=`` ⇒ NIP-04, else NIP-44 v2).
  * The ``encryption`` INFO-tag picker + ``NWC_ENCRYPTION`` env override.
  * ``_resolve_auto_encryption`` fallback-to-NIP-04 + caching.
  * ``_hkdf_expand`` / ``_calc_padded_len`` primitives.
"""

import base64
import hashlib
import hmac
import os
import struct
from unittest.mock import patch

import pytest

from l402_requests.wallets.nwc import (
    NWC_ENCRYPTION_DEFAULT,
    NwcWallet,
    _calc_padded_len,
    _decrypt_auto,
    _hkdf_expand,
    _nip04_decrypt,
    _nip44_decrypt,
    _nip44_encrypt,
    _pick_encryption_from_info_tag,
)

# ---------- Deterministic test keys (no elliptic-curve lib needed) ----------
# Fixed 32-byte "shared_x" — used directly as the AES-256 / ChaCha20 key by
# patching ``_compute_shared_x``. Must be exactly 32 bytes (64 hex chars).
_FIXED_SHARED_X = bytes.fromhex(
    "4b6a0c7e8f9d2e1a3c5b7d9f0e2a4c6b8d0f1e3a5c7b9d1f0e2a4c6b8d0f1e3a"
)
assert len(_FIXED_SHARED_X) == 32, "Fixed shared_x must be exactly 32 bytes"
_DUMMY_SECRET_KEY = b"\x01" * 32
_DUMMY_PUBKEY_HEX = "02" + "ab" * 32  # Won't be used for actual ECDH

_PATCH_SHARED_X = "l402_requests.wallets.nwc._compute_shared_x"


def _nip04_encrypt_with_shared_x(plaintext: str, shared_x: bytes) -> str:
    """NIP-04 encrypt with a pre-computed shared_x (bypasses ECDH).

    Independent of the production ``_nip04_encrypt`` so the decrypt tests don't
    depend on the production encrypt being correct. Uses raw shared_x as the
    AES key — the l402-ts/CoinOS wire format.
    """
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    iv = os.urandom(16)
    plaintext_bytes = plaintext.encode("utf-8")
    padding_len = 16 - (len(plaintext_bytes) % 16)
    padded = plaintext_bytes + bytes([padding_len] * padding_len)

    cipher = Cipher(algorithms.AES(shared_x), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    return f"{base64.b64encode(ciphertext).decode()}?iv={base64.b64encode(iv).decode()}"


def _nip44_encrypt_with_shared_x(plaintext: str, shared_x: bytes) -> str:
    """NIP-44 v2 encrypt with a pre-computed shared_x (bypasses ECDH)."""
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms

    conversation_key = hmac.new(b"nip44-v2", shared_x, hashlib.sha256).digest()
    nonce = os.urandom(32)
    message_keys = _hkdf_expand(conversation_key, nonce, 76)

    chacha_key = message_keys[0:32]
    chacha_nonce = message_keys[32:44]
    hmac_key = message_keys[44:76]

    # Pad exactly like the NIP-44 spec (2-byte length prefix + plaintext +
    # zero padding to _calc_padded_len). The previous version omitted the zero
    # padding, so TestNIP44Decryption never exercised the real padded region.
    # Guard the empty-string case (_calc_padded_len rejects 0) so the
    # empty-plaintext decrypt-tolerance test still works.
    plaintext_bytes = plaintext.encode("utf-8")
    if len(plaintext_bytes) > 0:
        padded_len = _calc_padded_len(len(plaintext_bytes))
        pad = b"\x00" * (padded_len - len(plaintext_bytes))
    else:
        pad = b""
    padded_plaintext = struct.pack(">H", len(plaintext_bytes)) + plaintext_bytes + pad

    chacha20_nonce = b"\x00\x00\x00\x00" + chacha_nonce
    cipher = Cipher(
        algorithms.ChaCha20(chacha_key, chacha20_nonce),
        mode=None,
        backend=default_backend(),
    )
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

    mac = hmac.new(hmac_key, nonce + ciphertext, hashlib.sha256).digest()
    payload = bytes([0x02]) + nonce + ciphertext + mac
    return base64.b64encode(payload).decode()


class TestNIP04Decryption:
    """NIP-04 decryption (legacy format), raw-shared-X CoinOS wire format."""

    @patch(_PATCH_SHARED_X, return_value=_FIXED_SHARED_X)
    def test_roundtrip_encrypt_decrypt(self, _mock):
        plaintext = '{"method":"pay_invoice","params":{"invoice":"lnbc1..."}}'
        encrypted = _nip04_encrypt_with_shared_x(plaintext, _FIXED_SHARED_X)
        assert "?iv=" in encrypted
        decrypted = _nip04_decrypt(_DUMMY_SECRET_KEY, _DUMMY_PUBKEY_HEX, encrypted)
        assert decrypted == plaintext

    @patch(_PATCH_SHARED_X, return_value=_FIXED_SHARED_X)
    def test_nip04_unicode(self, _mock):
        plaintext = '{"result":{"balance":100000},"emoji":"\\u26a1"}'
        encrypted = _nip04_encrypt_with_shared_x(plaintext, _FIXED_SHARED_X)
        decrypted = _nip04_decrypt(_DUMMY_SECRET_KEY, _DUMMY_PUBKEY_HEX, encrypted)
        assert decrypted == plaintext

    @patch(_PATCH_SHARED_X, return_value=_FIXED_SHARED_X)
    def test_nip04_decrypts_raw_sharedx_for_coinos_compat(self, _mock):
        """Pin the NIP-04 wire format: AES key is raw shared_x (NOT sha256).

        An earlier MCP version keyed with sha256(shared_x) and silently broke
        CoinOS NIP-04 (30s no-response). Anyone flipping back must delete this.
        """
        from cryptography.exceptions import InvalidTag
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

        plaintext = '{"result_type":"pay_invoice","result":{"preimage":"deadbeef"}}'
        encrypted = _nip04_encrypt_with_shared_x(plaintext, _FIXED_SHARED_X)
        decrypted = _nip04_decrypt(_DUMMY_SECRET_KEY, _DUMMY_PUBKEY_HEX, encrypted)
        assert decrypted == plaintext

        # Negative: sha256(shared_x)-keyed ciphertext must NOT round-trip.
        wrong_key = hashlib.sha256(_FIXED_SHARED_X).digest()
        wrong_iv = os.urandom(16)
        plaintext_bytes = plaintext.encode("utf-8")
        padding_len = 16 - (len(plaintext_bytes) % 16)
        padded = plaintext_bytes + bytes([padding_len] * padding_len)
        wrong_cipher = Cipher(
            algorithms.AES(wrong_key), modes.CBC(wrong_iv), backend=default_backend()
        )
        encryptor = wrong_cipher.encryptor()
        wrong_ct = encryptor.update(padded) + encryptor.finalize()
        sha256_keyed = (
            f"{base64.b64encode(wrong_ct).decode()}?iv={base64.b64encode(wrong_iv).decode()}"
        )
        try:
            wrong_decrypted = _nip04_decrypt(
                _DUMMY_SECRET_KEY, _DUMMY_PUBKEY_HEX, sha256_keyed
            )
        except (ValueError, InvalidTag):
            return
        assert wrong_decrypted != plaintext

    def test_nip04_invalid_format_raises(self):
        with pytest.raises(ValueError, match="NIP-04 ciphertext"):
            _nip04_decrypt(_DUMMY_SECRET_KEY, _DUMMY_PUBKEY_HEX, "justbase64withnoiv")


class TestNIP44Decryption:
    """NIP-44 v2 decryption (Alby Hub format)."""

    @patch(_PATCH_SHARED_X, return_value=_FIXED_SHARED_X)
    def test_roundtrip_encrypt_decrypt(self, _mock):
        plaintext = '{"result_type":"pay_invoice","result":{"preimage":"abc123"}}'
        encrypted = _nip44_encrypt_with_shared_x(plaintext, _FIXED_SHARED_X)
        assert "?iv=" not in encrypted
        decrypted = _nip44_decrypt(_DUMMY_SECRET_KEY, _DUMMY_PUBKEY_HEX, encrypted)
        assert decrypted == plaintext

    @patch(_PATCH_SHARED_X, return_value=_FIXED_SHARED_X)
    def test_nip44_unicode(self, _mock):
        plaintext = '{"description":"Pay for API access \\u26a1","amount":1000}'
        encrypted = _nip44_encrypt_with_shared_x(plaintext, _FIXED_SHARED_X)
        decrypted = _nip44_decrypt(_DUMMY_SECRET_KEY, _DUMMY_PUBKEY_HEX, encrypted)
        assert decrypted == plaintext

    @patch(_PATCH_SHARED_X, return_value=_FIXED_SHARED_X)
    def test_nip44_invalid_version_byte_raises(self, _mock):
        encrypted = _nip44_encrypt_with_shared_x("test", _FIXED_SHARED_X)
        payload = bytearray(base64.b64decode(encrypted))
        payload[0] = 0x01
        corrupted = base64.b64encode(bytes(payload)).decode()
        with pytest.raises(ValueError, match="Unsupported NIP-44 version"):
            _nip44_decrypt(_DUMMY_SECRET_KEY, _DUMMY_PUBKEY_HEX, corrupted)

    @patch(_PATCH_SHARED_X, return_value=_FIXED_SHARED_X)
    def test_nip44_invalid_version_byte_v3(self, _mock):
        encrypted = _nip44_encrypt_with_shared_x("test", _FIXED_SHARED_X)
        payload = bytearray(base64.b64decode(encrypted))
        payload[0] = 0x03
        corrupted = base64.b64encode(bytes(payload)).decode()
        with pytest.raises(ValueError, match="Unsupported NIP-44 version.*0x03"):
            _nip44_decrypt(_DUMMY_SECRET_KEY, _DUMMY_PUBKEY_HEX, corrupted)

    @patch(_PATCH_SHARED_X, return_value=_FIXED_SHARED_X)
    def test_nip44_tampered_ciphertext_fails_hmac(self, _mock):
        encrypted = _nip44_encrypt_with_shared_x("secret data", _FIXED_SHARED_X)
        payload = bytearray(base64.b64decode(encrypted))
        if len(payload) > 40:
            payload[35] ^= 0xFF
        corrupted = base64.b64encode(bytes(payload)).decode()
        with pytest.raises(ValueError, match="HMAC verification failed"):
            _nip44_decrypt(_DUMMY_SECRET_KEY, _DUMMY_PUBKEY_HEX, corrupted)

    @patch(_PATCH_SHARED_X, return_value=_FIXED_SHARED_X)
    def test_nip44_tampered_mac_fails_hmac(self, _mock):
        encrypted = _nip44_encrypt_with_shared_x("secret data", _FIXED_SHARED_X)
        payload = bytearray(base64.b64decode(encrypted))
        payload[-1] ^= 0xFF
        corrupted = base64.b64encode(bytes(payload)).decode()
        with pytest.raises(ValueError, match="HMAC verification failed"):
            _nip44_decrypt(_DUMMY_SECRET_KEY, _DUMMY_PUBKEY_HEX, corrupted)

    @patch(_PATCH_SHARED_X, return_value=_FIXED_SHARED_X)
    def test_nip44_long_plaintext(self, _mock):
        plaintext = "A" * 500
        encrypted = _nip44_encrypt_with_shared_x(plaintext, _FIXED_SHARED_X)
        decrypted = _nip44_decrypt(_DUMMY_SECRET_KEY, _DUMMY_PUBKEY_HEX, encrypted)
        assert decrypted == plaintext

    @patch(_PATCH_SHARED_X, return_value=_FIXED_SHARED_X)
    def test_nip44_empty_plaintext(self, _mock):
        plaintext = ""
        encrypted = _nip44_encrypt_with_shared_x(plaintext, _FIXED_SHARED_X)
        decrypted = _nip44_decrypt(_DUMMY_SECRET_KEY, _DUMMY_PUBKEY_HEX, encrypted)
        assert decrypted == plaintext


class TestNIP44Encryption:
    """Production NIP-44 v2 encryption (outgoing NWC requests)."""

    @patch(_PATCH_SHARED_X, return_value=_FIXED_SHARED_X)
    def test_encrypt_decrypt_roundtrip(self, _mock):
        plaintext = '{"method":"pay_invoice","params":{"invoice":"lnbc1..."}}'
        encrypted = _nip44_encrypt(_DUMMY_SECRET_KEY, _DUMMY_PUBKEY_HEX, plaintext)
        assert "?iv=" not in encrypted
        decrypted = _nip44_decrypt(_DUMMY_SECRET_KEY, _DUMMY_PUBKEY_HEX, encrypted)
        assert decrypted == plaintext

    @patch(_PATCH_SHARED_X, return_value=_FIXED_SHARED_X)
    def test_encrypt_produces_version_02(self, _mock):
        encrypted = _nip44_encrypt(_DUMMY_SECRET_KEY, _DUMMY_PUBKEY_HEX, "test")
        payload = base64.b64decode(encrypted)
        assert payload[0] == 0x02

    @patch(_PATCH_SHARED_X, return_value=_FIXED_SHARED_X)
    def test_encrypt_different_nonce_each_time(self, _mock):
        enc1 = _nip44_encrypt(_DUMMY_SECRET_KEY, _DUMMY_PUBKEY_HEX, "same message")
        enc2 = _nip44_encrypt(_DUMMY_SECRET_KEY, _DUMMY_PUBKEY_HEX, "same message")
        assert enc1 != enc2

    @patch(_PATCH_SHARED_X, return_value=_FIXED_SHARED_X)
    def test_encrypt_large_payload(self, _mock):
        plaintext = "A" * 5000
        encrypted = _nip44_encrypt(_DUMMY_SECRET_KEY, _DUMMY_PUBKEY_HEX, plaintext)
        decrypted = _nip44_decrypt(_DUMMY_SECRET_KEY, _DUMMY_PUBKEY_HEX, encrypted)
        assert decrypted == plaintext

    @patch(_PATCH_SHARED_X, return_value=_FIXED_SHARED_X)
    def test_encrypt_unicode(self, _mock):
        plaintext = '{"description":"Pay for API access ⚡","amount":1000}'
        encrypted = _nip44_encrypt(_DUMMY_SECRET_KEY, _DUMMY_PUBKEY_HEX, plaintext)
        decrypted = _nip44_decrypt(_DUMMY_SECRET_KEY, _DUMMY_PUBKEY_HEX, encrypted)
        assert decrypted == plaintext

    def test_encrypt_empty_plaintext_raises(self):
        # Production encrypt guards the NIP-44 1..65535 length range.
        with pytest.raises(ValueError, match="out of range"):
            _nip44_encrypt(_DUMMY_SECRET_KEY, _DUMMY_PUBKEY_HEX, "")


class TestDecryptAutoDetection:
    """Inbound auto-detect: ``?iv=`` ⇒ NIP-04, else NIP-44 v2."""

    @patch(_PATCH_SHARED_X, return_value=_FIXED_SHARED_X)
    def test_nip04_detected_by_iv_marker(self, _mock):
        plaintext = "nip04 test"
        encrypted = _nip04_encrypt_with_shared_x(plaintext, _FIXED_SHARED_X)
        assert "?iv=" in encrypted
        assert _decrypt_auto(_DUMMY_SECRET_KEY, _DUMMY_PUBKEY_HEX, encrypted) == plaintext

    @patch(_PATCH_SHARED_X, return_value=_FIXED_SHARED_X)
    def test_nip44_detected_by_absence_of_iv_marker(self, _mock):
        plaintext = "nip44 test"
        encrypted = _nip44_encrypt_with_shared_x(plaintext, _FIXED_SHARED_X)
        assert "?iv=" not in encrypted
        assert _decrypt_auto(_DUMMY_SECRET_KEY, _DUMMY_PUBKEY_HEX, encrypted) == plaintext

    @patch(_PATCH_SHARED_X, return_value=_FIXED_SHARED_X)
    def test_both_formats_same_plaintext(self, _mock):
        plaintext = '{"method":"get_balance","params":{}}'
        nip04_enc = _nip04_encrypt_with_shared_x(plaintext, _FIXED_SHARED_X)
        nip44_enc = _nip44_encrypt_with_shared_x(plaintext, _FIXED_SHARED_X)
        assert _decrypt_auto(_DUMMY_SECRET_KEY, _DUMMY_PUBKEY_HEX, nip04_enc) == plaintext
        assert _decrypt_auto(_DUMMY_SECRET_KEY, _DUMMY_PUBKEY_HEX, nip44_enc) == plaintext


class TestCalcPaddedLen:
    @pytest.mark.parametrize(
        "input_len,expected",
        [
            (1, 32),
            (16, 32),
            (32, 32),
            (33, 64),
            (64, 64),
            (65, 96),
            (100, 128),
            (256, 256),
            (300, 320),
        ],
    )
    def test_padded_len_values(self, input_len, expected):
        assert _calc_padded_len(input_len) == expected

    def test_padded_len_zero_raises(self):
        with pytest.raises(ValueError):
            _calc_padded_len(0)

    def test_padded_len_negative_raises(self):
        with pytest.raises(ValueError):
            _calc_padded_len(-1)


class TestHKDFExpand:
    def test_output_length(self):
        prk = os.urandom(32)
        info = os.urandom(16)
        assert len(_hkdf_expand(prk, info, 32)) == 32
        assert len(_hkdf_expand(prk, info, 76)) == 76
        assert len(_hkdf_expand(prk, info, 64)) == 64
        assert len(_hkdf_expand(prk, info, 1)) == 1

    def test_deterministic(self):
        prk = b"\x01" * 32
        info = b"\x02" * 16
        assert _hkdf_expand(prk, info, 76) == _hkdf_expand(prk, info, 76)

    def test_different_info_gives_different_output(self):
        prk = b"\x01" * 32
        assert _hkdf_expand(prk, b"\x02" * 16, 76) != _hkdf_expand(prk, b"\x03" * 16, 76)

    def test_matches_rfc5869_structure(self):
        # T(1) = HMAC(PRK, info || 0x01)
        prk = b"\x0b" * 32
        info = b"\xf0\xf1\xf2\xf3"
        t1 = hmac.new(prk, info + b"\x01", hashlib.sha256).digest()
        assert _hkdf_expand(prk, info, 32) == t1


class TestPickEncryptionFromInfoTag:
    @pytest.mark.parametrize(
        "tag_value, expected",
        [
            ("nip04 nip44_v2", "nip44_v2"),
            ("nip44_v2 nip04", "nip44_v2"),
            ("nip04", "nip04"),
            ("nip44_v2", "nip44_v2"),
            ("nip04,nip44_v2", "nip44_v2"),  # tolerate comma separator
            ("NIP04 NIP44_V2", "nip44_v2"),  # case-insensitive
            ("nip04  nip44_v2", "nip44_v2"),  # double spaces
            ("", "nip04"),  # empty → fallback
            (None, "nip04"),  # null → fallback
            ("nip99_alpha", "nip04"),  # unknown → fallback
        ],
    )
    def test_pick(self, tag_value, expected):
        assert _pick_encryption_from_info_tag(tag_value) == expected


_TEST_NWC_URI = (
    "nostr+walletconnect://"
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    "?relay=wss://relay.example.com"
    "&secret=fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
)


class TestNWCEncryptionConfig:
    """``NWC_ENCRYPTION`` env override + default resolution."""

    def test_default_encryption_is_auto(self, monkeypatch):
        monkeypatch.delenv("NWC_ENCRYPTION", raising=False)
        wallet = NwcWallet(_TEST_NWC_URI)
        assert wallet._encryption == "auto"
        assert NWC_ENCRYPTION_DEFAULT == "auto"

    def test_nip44_env_var_honored(self, monkeypatch):
        monkeypatch.setenv("NWC_ENCRYPTION", "nip44_v2")
        wallet = NwcWallet(_TEST_NWC_URI)
        assert wallet._encryption == "nip44_v2"

    def test_nip04_env_var_honored(self, monkeypatch):
        monkeypatch.setenv("NWC_ENCRYPTION", "nip04")
        wallet = NwcWallet(_TEST_NWC_URI)
        assert wallet._encryption == "nip04"

    def test_uppercase_env_var_normalized(self, monkeypatch):
        monkeypatch.setenv("NWC_ENCRYPTION", "NIP44_V2")
        wallet = NwcWallet(_TEST_NWC_URI)
        assert wallet._encryption == "nip44_v2"

    def test_invalid_env_var_falls_back_to_default(self, monkeypatch, caplog):
        monkeypatch.setenv("NWC_ENCRYPTION", "nip-something-bogus")
        with caplog.at_level("WARNING"):
            wallet = NwcWallet(_TEST_NWC_URI)
        assert wallet._encryption == "auto"
        assert any(
            "nip-something-bogus" in rec.getMessage() for rec in caplog.records
        )


class TestResolveAutoEncryption:
    async def test_unreachable_relay_falls_back_to_nip04(self, monkeypatch):
        # INFO-event fetch must NEVER throw on operational failures — a missing
        # or unreachable relay falls back to nip04 so a real request can still
        # go out.
        monkeypatch.delenv("NWC_ENCRYPTION", raising=False)
        unreachable_uri = (
            "nostr+walletconnect://"
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            "?relay=ws://127.0.0.1:1"
            "&secret=fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
        )
        wallet = NwcWallet(unreachable_uri)
        resolved = await wallet._resolve_auto_encryption()
        assert resolved == "nip04"

    async def test_caches_result(self, monkeypatch):
        # Second call must be served from the cache without reaching the relay.
        monkeypatch.delenv("NWC_ENCRYPTION", raising=False)
        wallet = NwcWallet(_TEST_NWC_URI)

        call_count = 0

        async def _stub_fetch():
            nonlocal call_count
            call_count += 1
            return "nip44_v2"

        monkeypatch.setattr(wallet, "_fetch_encryption_from_info_event", _stub_fetch)

        first = await wallet._resolve_auto_encryption()
        assert call_count == 1
        second = await wallet._resolve_auto_encryption()
        assert call_count == 1, "second call must hit the cache"
        assert second == first == "nip44_v2"

    def test_explicit_env_var_pin_persists_literally(self, monkeypatch):
        # Explicit env-var pinning skips auto-detect entirely — the config holds
        # the literal scheme, not "auto".
        monkeypatch.setenv("NWC_ENCRYPTION", "nip04")
        wallet = NwcWallet(_TEST_NWC_URI)
        assert wallet._encryption == "nip04"
