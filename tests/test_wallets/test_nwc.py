"""Tests for NWC wallet adapter."""

import hashlib
import json

import pytest

from l402_requests.wallets.nwc import (
    NwcWallet,
    _compute_nostr_event_id,
    _normalize_xonly_pubkey,
    verify_nostr_event_signature,
)

# secp256k1 is an optional dependency ([nwc]/[all] extras) and has no pre-built
# wheel on some platforms (notably Windows without pkg-config + libsecp256k1).
# The structural-rejection tests below run everywhere (they short-circuit before
# any crypto import); the positive sign→verify round-trip needs the real library,
# so it is gated on availability.
try:
    import secp256k1 as _secp256k1  # noqa: F401

    HAS_SECP256K1 = True
except ImportError:  # pragma: no cover - depends on install environment
    HAS_SECP256K1 = False


def _compute_event_id(event: dict) -> str:
    """NIP-01 event id: SHA256 of the canonical serialization."""
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


class TestNwcResponseSignatureVerification:
    """Security: kind-23195 NWC response events must be BIP340-sig-verified and
    pubkey-matched before their content is decrypted/trusted. A malicious relay
    can otherwise forge a ``pay_invoice``/``get_balance`` response. Mirrors the
    F-11 fix shipped in the MCP server (v1.12.8)."""

    # ── Structural rejections (run on every platform — no crypto needed) ──

    def test_returns_false_on_empty_event(self):
        assert verify_nostr_event_signature({}, "a" * 64) is False

    def test_returns_false_on_missing_id(self):
        assert verify_nostr_event_signature(
            {
                "pubkey": "a" * 64,
                "sig": "b" * 128,
                "kind": 23195,
                "created_at": 0,
                "tags": [],
                "content": "",
            },
            "a" * 64,
        ) is False

    def test_returns_false_on_missing_pubkey(self):
        assert verify_nostr_event_signature(
            {
                "id": "a" * 64,
                "sig": "b" * 128,
                "kind": 23195,
                "created_at": 0,
                "tags": [],
                "content": "",
            },
            "a" * 64,
        ) is False

    def test_returns_false_on_missing_sig(self):
        assert verify_nostr_event_signature(
            {
                "id": "a" * 64,
                "pubkey": "a" * 64,
                "kind": 23195,
                "created_at": 0,
                "tags": [],
                "content": "",
            },
            "a" * 64,
        ) is False

    def test_returns_false_on_wrong_field_lengths(self):
        assert verify_nostr_event_signature(
            {
                "id": "abc",  # not 64 hex
                "pubkey": "a" * 64,
                "sig": "b" * 128,
                "kind": 23195,
                "created_at": 0,
                "tags": [],
                "content": "",
            },
            "a" * 64,
        ) is False

    def test_returns_false_on_pubkey_mismatch(self):
        # Event is internally consistent in shape but its pubkey is NOT the
        # expected wallet pubkey → reject before any signature math.
        expected_wallet_pubkey = "a" * 64
        forged_event = {
            "id": "0" * 64,
            "pubkey": "b" * 64,  # WRONG — attacker pubkey
            "sig": "c" * 128,
            "kind": 23195,
            "created_at": 1700000000,
            "tags": [["e", "x" * 64]],
            "content": "ciphertext-irrelevant",
        }
        assert verify_nostr_event_signature(
            forged_event, expected_wallet_pubkey
        ) is False

    @pytest.mark.skipif(
        not HAS_SECP256K1, reason="secp256k1 ([nwc]/[all] extra) not installed"
    )
    def test_returns_false_on_invalid_signature(self):
        # Pubkey matches the wallet, but the signature is bogus → reject.
        # fixture-secret-hex is a deterministic 32-byte key for the test only.
        fixture_privkey_hex = "11" * 32
        privkey = _secp256k1.PrivateKey(bytes.fromhex(fixture_privkey_hex))
        pubkey_xonly = privkey.pubkey.serialize(compressed=True)[1:].hex()

        event = {
            "kind": 23195,
            "pubkey": pubkey_xonly,
            "created_at": 1700000000,
            "tags": [["p", "f" * 64], ["e", "a" * 64]],
            "content": "ciphertext-irrelevant",
        }
        event["id"] = _compute_event_id(event)
        event["sig"] = "00" * 64  # invalid signature

        assert verify_nostr_event_signature(event, pubkey_xonly) is False

    @pytest.mark.skipif(
        not HAS_SECP256K1, reason="secp256k1 ([nwc]/[all] extra) not installed"
    )
    def test_returns_false_on_tampered_content(self):
        # A correctly-signed event whose content was mutated after signing must
        # fail because the recomputed id no longer matches event["id"].
        fixture_privkey_hex = "22" * 32
        privkey = _secp256k1.PrivateKey(bytes.fromhex(fixture_privkey_hex))
        pubkey_xonly = privkey.pubkey.serialize(compressed=True)[1:].hex()

        event = {
            "kind": 23195,
            "pubkey": pubkey_xonly,
            "created_at": 1700000000,
            "tags": [["p", "f" * 64], ["e", "a" * 64]],
            "content": "original-ciphertext",
        }
        event["id"] = _compute_event_id(event)
        event["sig"] = privkey.schnorr_sign(
            bytes.fromhex(event["id"]), bip340tag=None, raw=True
        ).hex()

        # Relay tampers with the content but keeps the original id+sig.
        event["content"] = "forged-ciphertext"

        assert verify_nostr_event_signature(event, pubkey_xonly) is False

    @pytest.mark.skipif(
        not HAS_SECP256K1, reason="secp256k1 ([nwc]/[all] extra) not installed"
    )
    def test_accepts_correctly_signed_event_from_expected_wallet(self):
        # Positive path: an event signed by the expected wallet pubkey passes.
        fixture_privkey_hex = "33" * 32
        privkey = _secp256k1.PrivateKey(bytes.fromhex(fixture_privkey_hex))
        pubkey_xonly = privkey.pubkey.serialize(compressed=True)[1:].hex()

        event = {
            "kind": 23195,
            "pubkey": pubkey_xonly,
            "created_at": 1700000000,
            "tags": [["p", "f" * 64], ["e", "a" * 64]],
            "content": "valid-ciphertext",
        }
        event["id"] = _compute_event_id(event)
        event["sig"] = privkey.schnorr_sign(
            bytes.fromhex(event["id"]), bip340tag=None, raw=True
        ).hex()

        assert verify_nostr_event_signature(event, pubkey_xonly) is True

    @pytest.mark.skipif(
        not HAS_SECP256K1, reason="secp256k1 ([nwc]/[all] extra) not installed"
    )
    def test_accepts_when_expected_pubkey_is_compressed_form(self):
        # A caller may pass the wallet pubkey in COMPRESSED form (66 hex with an
        # 02/03 parity prefix — the same form this module accepts in its NIP-04
        # encrypt/decrypt paths). The event itself carries the 64-hex x-only
        # pubkey (per NIP-01). The verifier must normalize the compressed
        # expected key to x-only before comparing, otherwise a legitimate,
        # correctly-signed wallet response is wrongly rejected and pay_invoice
        # times out. Show that the compressed form is ACCEPTED.
        fixture_privkey_hex = "44" * 32
        privkey = _secp256k1.PrivateKey(bytes.fromhex(fixture_privkey_hex))
        pubkey_compressed = privkey.pubkey.serialize(compressed=True).hex()
        pubkey_xonly = pubkey_compressed[2:]
        assert len(pubkey_compressed) == 66
        assert len(pubkey_xonly) == 64

        event = {
            "kind": 23195,
            "pubkey": pubkey_xonly,  # event carries x-only, per NIP-01
            "created_at": 1700000000,
            "tags": [["p", "f" * 64], ["e", "a" * 64]],
            "content": "valid-ciphertext",
        }
        event["id"] = _compute_event_id(event)
        event["sig"] = privkey.schnorr_sign(
            bytes.fromhex(event["id"]), bip340tag=None, raw=True
        ).hex()

        # Caller passes the COMPRESSED form → must still be accepted.
        assert verify_nostr_event_signature(event, pubkey_compressed) is True


class TestNormalizeXonlyPubkey:
    """The pubkey-normalization helper underpinning the compressed-form accept
    above. Pure string logic — runs on every platform (no crypto needed), so it
    is the deterministic red→green proof for the Copilot 'normalize before
    compare' finding."""

    def test_compressed_02_prefix_is_stripped_to_xonly(self):
        xonly = "a" * 64
        assert _normalize_xonly_pubkey("02" + xonly) == xonly

    def test_compressed_03_prefix_is_stripped_to_xonly(self):
        xonly = "b" * 64
        assert _normalize_xonly_pubkey("03" + xonly) == xonly

    def test_xonly_is_returned_unchanged(self):
        xonly = "c" * 64
        assert _normalize_xonly_pubkey(xonly) == xonly

    def test_normalization_is_case_insensitive_lowercased(self):
        # Mixed-case compressed in → lowercased x-only out, so the downstream
        # comparison is a clean case-insensitive match.
        assert _normalize_xonly_pubkey("02" + "AbCd" * 16) == ("abcd" * 16)

    def test_other_lengths_returned_lowercased_unchanged(self):
        # Not 64/66 hex → don't guess; just lowercase and let the caller's
        # length/equality checks reject it.
        assert _normalize_xonly_pubkey("XYZ") == "xyz"
        assert _normalize_xonly_pubkey("") == ""


class TestEventIdImplementationsAgree:
    """The signing path (NwcWallet._compute_event_id) and the verification path
    (_compute_nostr_event_id) must use the SAME NIP-01 canonical serialization
    so sign/verify can never diverge. Copilot flagged the duplication; this
    pins them to identical output."""

    def test_signing_and_verifying_id_helpers_match(self):
        event = {
            "kind": 23194,
            "pubkey": "d" * 64,
            "created_at": 1700000123,
            "tags": [["p", "e" * 64], ["e", "a" * 64]],
            "content": "some-encrypted-content?iv=AAAA",
        }
        # Both the module-level verification helper and the wallet's signing
        # helper must produce the same id for the same event.
        assert _compute_nostr_event_id(event) == NwcWallet._compute_event_id(event)

    def test_id_from_signing_path_verifies_via_verification_serialization(self):
        # The id the signing path computes is exactly the id the verification
        # path recomputes — proving an event signed over the signing-path id is
        # checked against the identical serialization on verify.
        event = {
            "kind": 23195,
            "pubkey": "f" * 64,
            "created_at": 1700000456,
            "tags": [["p", "1" * 64]],
            "content": "ciphertext?iv=BBBB",
        }
        signed_id = NwcWallet._compute_event_id(event)
        event["id"] = signed_id
        recomputed_id = _compute_nostr_event_id(event)
        assert recomputed_id == signed_id


class TestVersion:
    def test_version_matches_package_metadata(self):
        import importlib.metadata

        import l402_requests

        try:
            installed_version = importlib.metadata.version("l402-requests")
        except importlib.metadata.PackageNotFoundError:
            pytest.skip(
                "l402-requests is not pip-installed in this environment "
                "(run `pip install -e .` to exercise this check)"
            )

        assert l402_requests.__version__ == installed_version
