"""Golden-vector tests for the NWC coincurve crypto (ported from the LE MCP).

Ported from ``lightning-enable-mcp/tests/test_nwc_coincurve_vectors.py`` and
adapted to l402-requests' module API. These pin the curve operations in
``nwc.py`` against INDEPENDENT ground truth, so a green run proves coincurve
produces byte-correct output — not merely that it's self-consistent:

  1. Pubkey derivation  -> the canonical BIP340 test vector (seckey 3).
  2. Raw shared-X ECDH  -> cross-checked against ``cryptography``'s SECP256K1
                           ECDH (a second, unrelated implementation) AND symmetry.
  3. Schnorr sign/verify -> round-trips through the production verify gate, and a
                           one-bit-flipped signature is rejected (the F-11 gate).
  4. NIP-04 encrypt/decrypt -> raw-shared-X wire format round-trips.
"""

import time

from l402_requests.wallets.nwc import (
    NwcWallet,
    _compute_nostr_event_id,
    _compute_shared_x,
    _derive_xonly_pubkey,
    _nip04_decrypt,
    _nip04_encrypt,
    verify_nostr_event_signature,
)

# --- BIP340 canonical vector: secret scalar 3 -> known x-only pubkey ----------
SECKEY_3 = (3).to_bytes(32, "big")
BIP340_PUBKEY_X_FOR_3 = (
    "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"
)

# A second deterministic, valid scalar for ECDH tests.
SECKEY_A = b"\x01" + b"\x42" * 31


def _crypto_ecdh_shared_x(priv_bytes: bytes, pub_x_hex: str) -> bytes:
    """Independent raw shared-X via ``cryptography``'s SECP256K1 ECDH.

    Reconstructs the peer point as 02||X (even-Y) — the same convention the
    production code uses — and returns the X coordinate of priv*peer.
    """
    from cryptography.hazmat.primitives.asymmetric import ec

    priv = ec.derive_private_key(int.from_bytes(priv_bytes, "big"), ec.SECP256K1())
    comp = bytes.fromhex("02" + pub_x_hex)
    peer = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), comp)
    # exchange() returns the shared point's X coordinate, big-endian 32 bytes.
    return priv.exchange(ec.ECDH(), peer)


def test_derive_xonly_pubkey_matches_bip340_vector():
    assert _derive_xonly_pubkey(SECKEY_3) == BIP340_PUBKEY_X_FOR_3


def test_compute_shared_x_matches_independent_cryptography_ecdh():
    # priv = A, peer = BIP340 vector pubkey (even-Y x-only).
    got = _compute_shared_x(SECKEY_A, BIP340_PUBKEY_X_FOR_3)
    expected = _crypto_ecdh_shared_x(SECKEY_A, BIP340_PUBKEY_X_FOR_3)
    assert got == expected, (
        "raw shared-X must match an independent ECDH impl (CoinOS path)"
    )
    assert len(got) == 32


def test_compute_shared_x_is_symmetric():
    # ECDH(a, B) and ECDH(b, A) yield the same shared-X (even-Y convention both).
    # This is exactly what makes the client<->wallet NWC crypto interoperate.
    a_pub = _derive_xonly_pubkey(SECKEY_A)
    b_pub = BIP340_PUBKEY_X_FOR_3
    ab = _compute_shared_x(SECKEY_A, b_pub)
    ba = _compute_shared_x(SECKEY_3, a_pub)
    assert ab == ba


def _build_signed_event(secret_key: bytes, pubkey_hex: str, content: str) -> dict:
    event = {
        "kind": 13194,
        "pubkey": pubkey_hex,
        "created_at": int(time.time()),
        "tags": [["encryption", "nip04 nip44_v2"]],
        "content": content,
    }
    event["id"] = _compute_nostr_event_id(event)
    event["sig"] = NwcWallet._sign_event(secret_key, event["id"])
    return event


def test_sign_then_verify_round_trip():
    pub = _derive_xonly_pubkey(SECKEY_3)
    event = _build_signed_event(SECKEY_3, pub, "hello world")
    assert verify_nostr_event_signature(event, pub) is True


def test_one_bit_flipped_signature_is_rejected():
    pub = _derive_xonly_pubkey(SECKEY_3)
    event = _build_signed_event(SECKEY_3, pub, "hello world")
    # Flip the last nibble of the signature — a valid-length but wrong sig.
    sig = event["sig"]
    flipped = sig[:-1] + ("0" if sig[-1] != "0" else "1")
    event["sig"] = flipped
    assert verify_nostr_event_signature(event, pub) is False


def test_nip04_encrypt_decrypt_round_trip():
    # Alice encrypts to Bob; Bob decrypts with his secret + Alice's pubkey.
    alice_sec = SECKEY_A
    alice_pub = _derive_xonly_pubkey(alice_sec)
    bob_sec = SECKEY_3
    bob_pub = _derive_xonly_pubkey(bob_sec)

    ciphertext = _nip04_encrypt(
        alice_sec, bob_pub, "the magic words are squeamish ossifrage"
    )
    assert "?iv=" in ciphertext
    plaintext = _nip04_decrypt(bob_sec, alice_pub, ciphertext)
    assert plaintext == "the magic words are squeamish ossifrage"
