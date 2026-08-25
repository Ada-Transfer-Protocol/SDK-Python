"""AdaTP protocol v2 — client side of the authenticated (SIGMA-style) handshake.

Mirrors the Rust reference server (``core/src/session/handshake_v2.rs``) and the
ProVerif-verified design byte-for-byte. The security-relevant step is entirely
here: the client checks (1) the server key equals the pinned key, then (2) the
Ed25519 signature over the transcript, BEFORE deriving any key material.
"""
import hashlib
import hmac

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

PROTOCOL_V2 = 2
LABEL_HS = b"AdaTP-v2-handshake"
FINISHED_LABEL = b"AdaTP-v2-finished"
SERVER_HELLO_LEN = 128  # epk_s(32) || spk_s(32) || sig(64)


class AdaTPHandshakeError(Exception):
    """A handshake failure carrying a stable, machine-readable ``code``."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def transcript_hash(epk_c: bytes, epk_s: bytes, spk_s: bytes) -> bytes:
    """th = SHA-256(LABEL_HS || 0x02 || epk_c || epk_s || spk_s)."""
    h = hashlib.sha256()
    h.update(LABEL_HS)
    h.update(bytes([PROTOCOL_V2]))
    h.update(epk_c)
    h.update(epk_s)
    h.update(spk_s)
    return h.digest()


def verify_ed25519(public_key: bytes, message: bytes, signature: bytes) -> bool:
    if len(public_key) != 32 or len(signature) != 64:
        return False
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, message)
        return True
    except Exception:
        return False


def verify_server_hello(pinned_spk_s: bytes, epk_c: bytes, response: bytes):
    """Verify a v2 HandshakeResponse against the pinned server identity.

    Returns ``(epk_s, transcript_hash)`` on success; raises
    :class:`AdaTPHandshakeError` (``malformed_server_hello`` | ``unknown_identity``
    | ``signature_verification_failed``) otherwise. Derives no key material.
    """
    if len(response) != SERVER_HELLO_LEN:
        raise AdaTPHandshakeError(
            "malformed_server_hello",
            f"expected {SERVER_HELLO_LEN} bytes, got {len(response)}",
        )
    epk_s = bytes(response[0:32])
    spk_s = bytes(response[32:64])
    sig = bytes(response[64:128])

    # (1) Identity: constant-time compare against the pinned key.
    if len(pinned_spk_s) != 32 or not hmac.compare_digest(spk_s, pinned_spk_s):
        raise AdaTPHandshakeError("unknown_identity", "server key does not match the pinned key")
    # (2) Authenticity: re-derive th and check the signature under the pinned key.
    th = transcript_hash(epk_c, epk_s, spk_s)
    if not verify_ed25519(spk_s, th, sig):
        raise AdaTPHandshakeError("signature_verification_failed", "server signature did not verify")
    return epk_s, th


def finished_plaintext(th: bytes) -> bytes:
    """The client's key-confirmation plaintext: FINISHED_LABEL || th."""
    return FINISHED_LABEL + th


def normalize_pinned_key(key) -> bytes:
    """Accept a pinned key as a 64-char hex string or 32 raw bytes."""
    if isinstance(key, str):
        key = bytes.fromhex(key.strip())
    key = bytes(key)
    if len(key) != 32:
        raise AdaTPHandshakeError(
            "invalid_pinned_key", f"pinned server key must be 32 bytes (got {len(key)})"
        )
    return key
