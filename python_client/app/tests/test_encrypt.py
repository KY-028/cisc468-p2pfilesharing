"""
test_encrypt.py — Unit tests for AES-256-GCM encryption module.

Tests cover:
  - Basic encrypt/decrypt round-trip
  - Wrong key fails
  - Tampered ciphertext fails
  - Wrong AAD fails
  - File payload encryption with metadata binding
  - Short/invalid ciphertext rejection
  - Empty plaintext

Run:  pytest app/tests/test_encrypt.py -v
"""

import os
import pytest
from cryptography.exceptions import InvalidTag
from app.crypto.encrypt import (
    encrypt, decrypt,
    encrypt_file_payload, decrypt_file_payload,
    NONCE_SIZE,
)


class TestAESGCM:
    """Test basic encrypt/decrypt operations."""

    def test_round_trip(self):
        """Encrypt then decrypt should return original plaintext."""
        key = os.urandom(32)
        plaintext = b"Hello, secure world!"
        ciphertext = encrypt(key, plaintext)
        decrypted = decrypt(key, ciphertext)
        assert decrypted == plaintext

    def test_round_trip_with_aad(self):
        """Encrypt/decrypt with associated data should work."""
        key = os.urandom(32)
        plaintext = b"Secret data"
        aad = b"metadata-context"
        ciphertext = encrypt(key, plaintext, associated_data=aad)
        decrypted = decrypt(key, ciphertext, associated_data=aad)
        assert decrypted == plaintext

    def test_wrong_key_fails(self):
        """Decrypting with a different key should fail."""
        key1 = os.urandom(32)
        key2 = os.urandom(32)
        ciphertext = encrypt(key1, b"test data")
        with pytest.raises(InvalidTag):
            decrypt(key2, ciphertext)

    def test_tampered_ciphertext_fails(self):
        """Modifying even one byte of ciphertext should fail."""
        key = os.urandom(32)
        ciphertext = encrypt(key, b"important data")
        # Tamper with the last byte (part of the auth tag)
        tampered = ciphertext[:-1] + bytes([ciphertext[-1] ^ 0xFF])
        with pytest.raises(InvalidTag):
            decrypt(key, tampered)

    def test_wrong_aad_fails(self):
        """Using wrong AAD during decryption should fail."""
        key = os.urandom(32)
        ciphertext = encrypt(key, b"data", associated_data=b"correct-aad")
        with pytest.raises(InvalidTag):
            decrypt(key, ciphertext, associated_data=b"wrong-aad")

    def test_missing_aad_fails(self):
        """Omitting AAD during decryption when it was used for encryption should fail."""
        key = os.urandom(32)
        ciphertext = encrypt(key, b"data", associated_data=b"some-aad")
        with pytest.raises(InvalidTag):
            decrypt(key, ciphertext)  # No AAD

    def test_empty_plaintext(self):
        """Empty plaintext should encrypt and decrypt correctly."""
        key = os.urandom(32)
        ciphertext = encrypt(key, b"")
        decrypted = decrypt(key, ciphertext)
        assert decrypted == b""

    def test_large_data(self):
        """Should handle larger data (1 MB)."""
        key = os.urandom(32)
        plaintext = os.urandom(1024 * 1024)  # 1 MB
        ciphertext = encrypt(key, plaintext)
        decrypted = decrypt(key, ciphertext)
        assert decrypted == plaintext

    def test_ciphertext_has_nonce_prefix(self):
        """Ciphertext should be nonce + encrypted data (at least 28 bytes)."""
        key = os.urandom(32)
        ciphertext = encrypt(key, b"test")

        assert len(ciphertext) >= NONCE_SIZE + 16

    def test_invalid_key_length(self):
        """Keys must be exactly 32 bytes."""
        with pytest.raises(ValueError, match="32 bytes"):
            encrypt(b"short-key", b"data")
        with pytest.raises(ValueError, match="32 bytes"):
            decrypt(b"short-key", b"x" * 32)

    def test_ciphertext_too_short(self):
        """Ciphertext shorter than nonce + tag should be rejected."""
        key = os.urandom(32)
        with pytest.raises(ValueError, match="too short"):
            decrypt(key, b"short")

    def test_each_encryption_unique(self):
        """Same plaintext + key should produce different ciphertexts (random nonce)."""
        key = os.urandom(32)
        ct1 = encrypt(key, b"same data")
        ct2 = encrypt(key, b"same data")
        assert ct1 != ct2  # Different random nonces


class TestFilePayload:
    """Test file-specific encryption/decryption with metadata binding."""

    def test_file_round_trip(self):
        """Encrypt and decrypt a file payload."""
        key = os.urandom(32)
        data = b"File content here"
        filename = "test.txt"
        file_hash = "abc123def456"

        encrypted = encrypt_file_payload(key, data, filename, file_hash)
        decrypted = decrypt_file_payload(key, encrypted, filename, file_hash)
        assert decrypted == data

    def test_wrong_filename_aad_fails(self):
        """Decrypting with the wrong filename should fail (AAD mismatch)."""
        key = os.urandom(32)
        encrypted = encrypt_file_payload(key, b"data", "real.txt", "hash123")
        with pytest.raises(InvalidTag):
            decrypt_file_payload(key, encrypted, "fake.txt", "hash123")

    def test_wrong_hash_aad_fails(self):
        """Decrypting with the wrong hash should fail (AAD mismatch)."""
        key = os.urandom(32)
        encrypted = encrypt_file_payload(key, b"data", "file.txt", "real-hash")
        with pytest.raises(InvalidTag):
            decrypt_file_payload(key, encrypted, "file.txt", "fake-hash")
