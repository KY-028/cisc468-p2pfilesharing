"""
kdf.py — Key Derivation Functions.

Two KDFs are used in this application:

1. HKDF-SHA256 — for deriving session keys from ECDH shared secrets (Phase 3/8).
   HKDF is the right choice here because the input key material (ECDH output)
   already has high entropy; we just need to expand it into a usable key.

2. PBKDF2-HMAC-SHA256 — for deriving vault keys from user passwords (Phase 11).
   PBKDF2 is the right choice here because passwords have low entropy;
   we need the iteration count to make brute-force expensive.

Reading order: Read after keys.py and sign.py.
"""

import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


# ---------------------------------------------------------------------------
# HKDF — Session key derivation from ECDH shared secret
# ---------------------------------------------------------------------------

def hkdf_derive_key(shared_secret: bytes,
                    salt: bytes = None,
                    info: bytes = b"p2p-session-key",
                    length: int = 32) -> bytes:
    """
    Derive a symmetric key from an ECDH shared secret using HKDF-SHA256.

    Args:
        shared_secret: Raw bytes from ECDH key agreement.
        salt: Optional salt (random bytes). If None, HKDF uses a zero-filled
              salt of hash length, which is acceptable per RFC 5869.
        info: Context/application-specific info string.
              Default "p2p-session-key" to bind the key to this protocol.
        length: Desired output key length in bytes (default 32 = 256 bits).

    Returns:
        Derived key bytes of the specified length.
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
    )
    return hkdf.derive(shared_secret)


# ---------------------------------------------------------------------------
# PBKDF2 — Vault key derivation from user password
# ---------------------------------------------------------------------------

def generate_salt(length: int = 16) -> bytes:
    """Generate a cryptographically random salt."""
    return os.urandom(length)


def pbkdf2_derive_key(password: str,
                      salt: bytes,
                      iterations: int = 600_000,
                      length: int = 32) -> bytes:
    """
    Derive a symmetric key from a password using PBKDF2-HMAC-SHA256.

    The iteration count (600,000) follows OWASP 2023 recommendations
    for PBKDF2-HMAC-SHA256.

    Args:
        password: User's master password (string).
        salt: Random salt bytes (should be stored alongside the ciphertext).
        iterations: PBKDF2 iteration count.
        length: Desired output key length in bytes (default 32 = 256 bits).

    Returns:
        Derived key bytes of the specified length.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(password.encode("utf-8"))
