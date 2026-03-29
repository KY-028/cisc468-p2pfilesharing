"""
test_vault.py — Tests for encrypted local storage vault.

Tests cover:
  - Basic encrypt/decrypt round-trip with password
  - Wrong password fails (InvalidTag)
  - File storage and retrieval
  - JSON data storage and retrieval
  - Trust records save/load
  - Vault file listing and deletion

Run:  pytest app/tests/test_vault.py -v
"""

import os
import pytest
from cryptography.exceptions import InvalidTag
from app.storage.vault import (
    vault_encrypt, vault_decrypt,
    vault_store_file, vault_retrieve_file,
    vault_store_json, vault_retrieve_json,
    vault_list_files, vault_delete_file,
    save_trust_records, load_trust_records,
    get_vault_dir, SALT_SIZE,
)
from app.crypto.encrypt import NONCE_SIZE


class TestVaultEncryption:
    """Test low-level vault encrypt/decrypt."""

    def test_round_trip(self):
        """Encrypt then decrypt with the same password should work."""
        password = "test-password-123"
        plaintext = b"Secret vault data"
        blob = vault_encrypt(password, plaintext)
        decrypted = vault_decrypt(password, blob)
        assert decrypted == plaintext

    def test_wrong_password_fails(self):
        """Decrypting with the wrong password should fail."""
        blob = vault_encrypt("correct-password", b"data")
        with pytest.raises(InvalidTag):
            vault_decrypt("wrong-password", blob)

    def test_blob_format(self):
        """Blob should contain salt + nonce + ciphertext + tag."""
        blob = vault_encrypt("pw", b"test")
        # Minimum: 16 salt + 12 nonce + 0 data + 16 tag = 44 bytes
        assert len(blob) >= SALT_SIZE + NONCE_SIZE + 16

    def test_each_encryption_unique(self):
        """Same password + data should produce different blobs (random salt + nonce)."""
        blob1 = vault_encrypt("pw", b"data")
        blob2 = vault_encrypt("pw", b"data")
        assert blob1 != blob2

    def test_empty_data(self):
        """Empty data should encrypt and decrypt correctly."""
        blob = vault_encrypt("pw", b"")
        assert vault_decrypt("pw", blob) == b""

    def test_blob_too_short(self):
        """Too-short blob should raise ValueError."""
        with pytest.raises(ValueError, match="too short"):
            vault_decrypt("pw", b"short")


class TestVaultFileStorage:
    """Test file-level vault operations."""

    def setup_method(self):
        # Use a temp vault directory
        self.vault_dir = get_vault_dir()

    def teardown_method(self):
        # Clean up test files
        for f in os.listdir(self.vault_dir):
            if f.startswith("test_") and f.endswith(".vault"):
                os.remove(os.path.join(self.vault_dir, f))

    def test_store_and_retrieve(self):
        """Store a file and retrieve it."""
        password = "file-test-pw"
        data = b"File content for testing"
        vault_store_file(password, "test_file.txt", data)
        retrieved = vault_retrieve_file(password, "test_file.txt")
        assert retrieved == data

    def test_retrieve_nonexistent(self):
        """Retrieving a non-existent file should return None."""
        result = vault_retrieve_file("pw", "test_nonexistent_file.txt")
        assert result is None

    def test_wrong_password_on_retrieve(self):
        """Retrieving with wrong password should raise InvalidTag."""
        vault_store_file("correct-pw", "test_badpw.txt", b"data")
        with pytest.raises(InvalidTag):
            vault_retrieve_file("wrong-pw", "test_badpw.txt")

    def test_list_files(self):
        """List should include stored files."""
        vault_store_file("pw", "test_list_a.txt", b"a")
        vault_store_file("pw", "test_list_b.txt", b"b")
        files = vault_list_files()
        assert "test_list_a.txt" in files
        assert "test_list_b.txt" in files

    def test_delete_file(self):
        """Delete should remove the vault file."""
        vault_store_file("pw", "test_del.txt", b"data")
        assert vault_delete_file("test_del.txt") is True
        assert vault_retrieve_file("pw", "test_del.txt") is None

    def test_delete_nonexistent(self):
        """Deleting non-existent file should return False."""
        assert vault_delete_file("test_nope.txt") is False


class TestVaultJSON:
    """Test JSON data vault operations."""

    def setup_method(self):
        self.vault_dir = get_vault_dir()

    def teardown_method(self):
        for f in os.listdir(self.vault_dir):
            if f.startswith("test_") and f.endswith(".vault"):
                os.remove(os.path.join(self.vault_dir, f))

    def test_json_round_trip(self):
        """Store and retrieve a JSON object."""
        data = {"key": "value", "numbers": [1, 2, 3]}
        vault_store_json("pw", "test_json_data", data)
        retrieved = vault_retrieve_json("pw", "test_json_data")
        assert retrieved == data

    def test_json_nonexistent(self):
        """Retrieving non-existent JSON should return None."""
        assert vault_retrieve_json("pw", "test_json_nope") is None


class TestTrustRecords:
    """Test trust record storage."""

    def setup_method(self):
        self.vault_dir = get_vault_dir()

    def teardown_method(self):
        for f in os.listdir(self.vault_dir):
            if f.startswith("trust_") and f.endswith(".vault"):
                os.remove(os.path.join(self.vault_dir, f))

    def test_save_and_load(self):
        """Save and load trust records."""
        records = {
            "peer-1": {
                "fingerprint": "abc123",
                "trusted": True,
                "last_verified": "2024-01-01",
            },
            "peer-2": {
                "fingerprint": "def456",
                "trusted": False,
                "last_verified": None,
            },
        }
        save_trust_records("pw", records)
        loaded = load_trust_records("pw")
        assert loaded == records

    def test_load_empty(self):
        """Loading when no records exist should return empty dict."""
        loaded = load_trust_records("nonexistent-pw-for-empty-trust")
        assert loaded == {}
