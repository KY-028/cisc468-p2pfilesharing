"""
encrypt.py — AES-256-GCM authenticated encryption.

AES-GCM is an AEAD cipher that provides both confidentiality and
integrity in a single API call. This replaces the manual CTR+HMAC
Encrypt-then-MAC approach — fewer moving parts, fewer errors.

Key points:
  - 12-byte random nonce (standard for GCM, NIST SP 800-38D)
  - 16-byte authentication tag (built into GCM)
  - Associated data (AAD) is optional metadata authenticated but not encrypted
  - Session keys come from the STS handshake (HKDF-derived, 32 bytes)

Reading order: Read kdf.py and session.py first, then this file.
"""

import os
import struct
from cryptography.hazmat.primitives.ciphers.aead import AESGCM



NONCE_SIZE = 12


def encrypt(key: bytes, plaintext: bytes,
            associated_data: bytes = None) -> bytes:
    """
    Encrypt data using AES-256-GCM.

    Args:
        key: 32-byte encryption key (from STS session key or vault KDF).
        plaintext: Data to encrypt.
        associated_data: Optional AAD — authenticated but not encrypted.
                         Useful for binding context (e.g., peer IDs, message type).

    Returns:
        Ciphertext blob: [12-byte nonce][ciphertext + 16-byte auth tag]
        The nonce is prepended so the recipient can extract it.

    Raises:
        ValueError: If the key length is wrong.
    """
    if len(key) != 32:
        raise ValueError(f"Key must be 32 bytes, got {len(key)}")

    nonce = os.urandom(NONCE_SIZE)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)

  
    return nonce + ciphertext


def decrypt(key: bytes, ciphertext_blob: bytes,
            associated_data: bytes = None) -> bytes:
    """
    Decrypt data using AES-256-GCM.

    Args:
        key: 32-byte encryption key (same key used for encryption).
        ciphertext_blob: Output from encrypt() — [nonce][ciphertext+tag].
        associated_data: Must match the AAD used during encryption,
                         or decryption will fail (integrity check).

    Returns:
        The decrypted plaintext.

    Raises:
        ValueError: If the key or ciphertext is invalid.
        cryptography.exceptions.InvalidTag: If the auth tag fails
            (tampered data, wrong key, or wrong AAD).
    """
    if len(key) != 32:
        raise ValueError(f"Key must be 32 bytes, got {len(key)}")

    if len(ciphertext_blob) < NONCE_SIZE + 16:
        raise ValueError("Ciphertext too short (must contain nonce + tag)")

   
    nonce = ciphertext_blob[:NONCE_SIZE]
    ciphertext = ciphertext_blob[NONCE_SIZE:]

    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, associated_data)


def encrypt_file_payload(key: bytes, file_data: bytes,
                          filename: str, file_hash: str) -> bytes:
    """
    Encrypt a file payload for transfer.

    Uses the filename + hash as associated data so the recipient can
    verify the ciphertext is bound to the correct file metadata.

    Args:
        key: 32-byte session key.
        file_data: Raw file bytes.
        filename: The filename (used as AAD).
        file_hash: The SHA-256 hash (used as AAD).

    Returns:
        Encrypted blob.
    """
    aad = f"{filename}:{file_hash}".encode("utf-8")
    return encrypt(key, file_data, associated_data=aad)


def decrypt_file_payload(key: bytes, ciphertext_blob: bytes,
                          filename: str, file_hash: str) -> bytes:
    """
    Decrypt a file payload received from a peer.

    Args:
        key: 32-byte session key.
        ciphertext_blob: The encrypted blob.
        filename: Expected filename (must match AAD from encryption).
        file_hash: Expected SHA-256 hash (must match AAD).

    Returns:
        Decrypted file bytes.

    Raises:
        InvalidTag: If the data was tampered with or AAD doesn't match.
    """
    aad = f"{filename}:{file_hash}".encode("utf-8")
    return decrypt(key, ciphertext_blob, associated_data=aad)
