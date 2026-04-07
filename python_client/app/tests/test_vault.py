"""
test_vault.py — Tests for encrypted local storage vault.

Tests cover:
  - Password-based encrypt/decrypt round-trip (self-contained blobs)
  - Wrong password fails (InvalidTag)
  - Vault initialization and unlock lifecycle
  - Key-based file storage and retrieval
  - Nonce uniqueness (every encryption produces a different blob)
  - JSON data storage and retrieval
  - Trust records save/load
  - Vault file listing and deletion
  - Received-file manifest lookup by hash

Run:  pytest app/tests/test_vault.py -v
"""

import os
import json
import pytest
from cryptography.exceptions import InvalidTag
from app.crypto.kdf import pbkdf2_derive_key, generate_salt
from app.storage.vault import (
    vault_encrypt, vault_decrypt,
    vault_encrypt_data, vault_decrypt_data,
    vault_store_file, vault_retrieve_file,
    vault_store_json, vault_retrieve_json,
    vault_list_files, vault_delete_file,
    save_trust_records, load_trust_records,
    initialize_vault, unlock_vault, is_vault_initialized,
    change_vault_password,
    set_vault_key, get_vault_key, lock_vault,
    vault_record_received_file, vault_lookup_by_hash,
    get_vault_dir, SALT_SIZE, NONCE_SIZE, TAG_SIZE,
)



def _test_key() -> bytes:
    """Return a deterministic 32-byte key for testing."""
    return pbkdf2_derive_key("test-password", b"fixed-salt-16!!", iterations=1000)




class TestVaultPasswordEncryption:
    """Test the per-blob password-based encrypt/decrypt layer."""

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

        assert len(blob) >= SALT_SIZE + NONCE_SIZE + TAG_SIZE

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




class TestVaultKeyEncryption:
    """Test the key-based encryption used at runtime."""

    def test_round_trip(self):
        key = _test_key()
        plaintext = b"hello vault"
        blob = vault_encrypt_data(key, plaintext)
        assert vault_decrypt_data(key, blob) == plaintext

    def test_wrong_key_fails(self):
        key = _test_key()
        other_key = pbkdf2_derive_key("other", b"other-salt-16!!!", iterations=1000)
        blob = vault_encrypt_data(key, b"secret")
        with pytest.raises(InvalidTag):
            vault_decrypt_data(other_key, blob)

    def test_nonce_uniqueness(self):
        """Each encryption must produce a different nonce (first 12 bytes)."""
        key = _test_key()
        blob1 = vault_encrypt_data(key, b"data")
        blob2 = vault_encrypt_data(key, b"data")
        assert blob1[:NONCE_SIZE] != blob2[:NONCE_SIZE]

    def test_blob_layout(self):
        """Blob layout: nonce (12) + ciphertext + tag (16)."""
        key = _test_key()
        plaintext = b"x" * 100
        blob = vault_encrypt_data(key, plaintext)
        # nonce(12) + ciphertext(100) + tag(16) = 128
        assert len(blob) == NONCE_SIZE + len(plaintext) + TAG_SIZE

    def test_empty_data(self):
        key = _test_key()
        blob = vault_encrypt_data(key, b"")
        assert vault_decrypt_data(key, blob) == b""

    def test_blob_too_short(self):
        key = _test_key()
        with pytest.raises(ValueError, match="too short"):
            vault_decrypt_data(key, b"short")

    def test_tampered_ciphertext_fails(self):
        """Modifying ciphertext should cause InvalidTag."""
        key = _test_key()
        blob = vault_encrypt_data(key, b"important data")
        tampered = bytearray(blob)
        tampered[NONCE_SIZE] ^= 0xFF
        with pytest.raises(InvalidTag):
            vault_decrypt_data(key, bytes(tampered))




class TestVaultInitialization:
    """Test first-launch setup and subsequent unlock."""

    def setup_method(self):
        self.vault_dir = get_vault_dir()
        self._cleanup_config()
        lock_vault()

    def teardown_method(self):
        self._cleanup_config()
        lock_vault()

    def _cleanup_config(self):
        config_path = os.path.join(self.vault_dir, "vault_config.json")
        if os.path.isfile(config_path):
            os.remove(config_path)

    def test_not_initialized_initially(self):
        """Vault should not be initialized before setup."""
        assert is_vault_initialized() is False

    def test_initialize_creates_config(self):
        """initialize_vault should create vault_config.json and set key."""
        key = initialize_vault("my-secure-password")
        assert is_vault_initialized() is True
        assert get_vault_key() is not None
        assert len(key) == 32

    def test_unlock_with_correct_password(self):
        """unlock_vault with correct password should derive the same key."""
        key1 = initialize_vault("my-password-123")
        lock_vault()
        assert get_vault_key() is None
        key2 = unlock_vault("my-password-123")
        assert key1 == key2
        assert get_vault_key() is not None

    def test_unlock_with_wrong_password_raises(self):
        """Wrong password should raise InvalidTag (verification token check)."""
        initialize_vault("correct-password")
        lock_vault()
        with pytest.raises(InvalidTag):
            unlock_vault("wrong-password")

    def test_unlock_without_init_raises(self):
        """unlock_vault should raise if vault_config.json doesn't exist."""
        with pytest.raises(FileNotFoundError):
            unlock_vault("anything")

    def test_lock_clears_key(self):
        initialize_vault("pw")
        assert get_vault_key() is not None
        lock_vault()
        assert get_vault_key() is None

    def test_config_never_stores_password_or_key(self):
        """vault_config.json must contain ONLY salt and verify_token.

        The password and derived key must NEVER be written to disk.
        This is a critical security requirement (Requirement #9).
        """
        import json as _json
        password = "my-super-secret-password"
        key = initialize_vault(password)
        config_path = os.path.join(self.vault_dir, "vault_config.json")
        with open(config_path, "r") as f:
            config = _json.load(f)


        assert set(config.keys()) == {"salt", "verify_token"}


        config_raw = open(config_path).read()
        assert password not in config_raw


        assert key.hex() not in config_raw


        salt_bytes = bytes.fromhex(config["salt"])
        assert len(salt_bytes) == 16


        verify_bytes = bytes.fromhex(config["verify_token"])
        assert len(verify_bytes) >= NONCE_SIZE + TAG_SIZE


class TestVaultPasswordChange:
    """Test vault password change and full-file re-encryption."""

    def _set_temp_vault_dir(self, monkeypatch, tmp_path):
        temp_vault_dir = tmp_path / "vault"
        monkeypatch.setattr("app.storage.vault.VAULT_DIR", str(temp_vault_dir))
        os.makedirs(temp_vault_dir, exist_ok=True)
        lock_vault()
        return str(temp_vault_dir)

    def test_change_password_reencrypts_files_and_relocks_with_new_password(self, monkeypatch, tmp_path):
        vault_dir = self._set_temp_vault_dir(monkeypatch, tmp_path)
        initialize_vault("old-password-123")
        vault_store_file("test_rekey.txt", b"sensitive payload")

        vault_path = os.path.join(vault_dir, "test_rekey.txt.vault")
        with open(vault_path, "rb") as f:
            old_blob = f.read()

        skipped = change_vault_password("old-password-123", "new-password-456")
        assert skipped == []

        with open(vault_path, "rb") as f:
            new_blob = f.read()
        assert new_blob != old_blob

        lock_vault()
        with pytest.raises(InvalidTag):
            unlock_vault("old-password-123")

        unlock_vault("new-password-456")
        assert vault_retrieve_file("test_rekey.txt") == b"sensitive payload"

    def test_change_password_rejects_wrong_old_password(self, monkeypatch, tmp_path):
        self._set_temp_vault_dir(monkeypatch, tmp_path)
        initialize_vault("correct-password")
        vault_store_file("test_rekey_wrong_old.txt", b"abc")

        with pytest.raises(InvalidTag):
            change_vault_password("wrong-password", "new-password-789")

    def test_change_password_rolls_back_on_reencrypt_failure(self, monkeypatch, tmp_path):
        vault_dir = self._set_temp_vault_dir(monkeypatch, tmp_path)
        initialize_vault("rollback-old-password")
        vault_store_file("test_rekey_rollback.txt", b"rollback payload")

        config_path = os.path.join(vault_dir, "vault_config.json")
        with open(config_path, "r", encoding="utf-8") as f:
            old_config = json.load(f)

        vault_path = os.path.join(vault_dir, "test_rekey_rollback.txt.vault")
        with open(vault_path, "rb") as f:
            old_blob = f.read()

        call_count = {"n": 0}
        original_encrypt = vault_encrypt_data

        def fail_on_file_encrypt(key, plaintext):
            call_count["n"] += 1
            if call_count["n"] >= 2:
                raise RuntimeError("forced encryption failure")
            return original_encrypt(key, plaintext)

        monkeypatch.setattr("app.storage.vault.vault_encrypt_data", fail_on_file_encrypt)

        with pytest.raises(RuntimeError, match="Vault key change failed"):
            change_vault_password("rollback-old-password", "rollback-new-password")

        with open(config_path, "r", encoding="utf-8") as f:
            restored_config = json.load(f)
        with open(vault_path, "rb") as f:
            restored_blob = f.read()

        assert restored_config == old_config
        assert restored_blob == old_blob

        lock_vault()
        unlock_vault("rollback-old-password")
        assert vault_retrieve_file("test_rekey_rollback.txt") == b"rollback payload"

    def test_change_password_corrupt_existing_blob_raises_runtime_error(self, monkeypatch, tmp_path):
        self._set_temp_vault_dir(monkeypatch, tmp_path)
        initialize_vault("correct-old-password")
        vault_store_file("test_rekey_corrupt.txt", b"payload")

        call_count = {"n": 0}
        original_decrypt = vault_decrypt_data

        def fail_only_on_file_decrypt(key, blob):
            call_count["n"] += 1

            if call_count["n"] == 2:
                raise InvalidTag()
            return original_decrypt(key, blob)

        monkeypatch.setattr("app.storage.vault.vault_decrypt_data", fail_only_on_file_decrypt)

        skipped = change_vault_password("correct-old-password", "new-password-111")
        assert skipped == ["test_rekey_corrupt.txt.vault"]

    def test_change_password_skips_only_undecryptable_and_preserves_decryptable_files(self, monkeypatch, tmp_path):
        vault_dir = self._set_temp_vault_dir(monkeypatch, tmp_path)
        initialize_vault("mix-old-password")
        vault_store_file("test_good_a.txt", b"a")
        vault_store_file("test_good_b.txt", b"b")
        vault_store_file("test_bad.txt", b"bad")

        bad_path = os.path.join(vault_dir, "test_bad.txt.vault")
        with open(bad_path, "rb") as f:
            bad_blob = bytearray(f.read())
        bad_blob[20] ^= 0x01
        with open(bad_path, "wb") as f:
            f.write(bytes(bad_blob))

        skipped = change_vault_password("mix-old-password", "mix-new-password")
        assert skipped == ["test_bad.txt.vault"]

        lock_vault()
        unlock_vault("mix-new-password")
        assert vault_retrieve_file("test_good_a.txt") == b"a"
        assert vault_retrieve_file("test_good_b.txt") == b"b"
        with pytest.raises(InvalidTag):
            vault_retrieve_file("test_bad.txt")





class TestVaultFileStorage:
    """Test file-level vault operations."""

    def setup_method(self):
        self.vault_dir = get_vault_dir()
        self.key = _test_key()
        set_vault_key(self.key)

    def teardown_method(self):

        for f in os.listdir(self.vault_dir):
            if f.startswith("test_") and f.endswith(".vault"):
                os.remove(os.path.join(self.vault_dir, f))
        lock_vault()

    def test_store_and_retrieve(self):
        """Store a file and retrieve it."""
        data = b"File content for testing"
        vault_store_file("test_file.txt", data)
        retrieved = vault_retrieve_file("test_file.txt")
        assert retrieved == data

    def test_retrieve_nonexistent(self):
        """Retrieving a non-existent file should return None."""
        result = vault_retrieve_file("test_nonexistent_file.txt")
        assert result is None

    def test_wrong_key_on_retrieve(self):
        """Retrieving with wrong key should raise InvalidTag."""
        vault_store_file("test_badkey.txt", b"data")
        other_key = pbkdf2_derive_key("other", b"other-salt-16!!!", iterations=1000)
        with pytest.raises(InvalidTag):
            vault_retrieve_file("test_badkey.txt", key=other_key)

    def test_explicit_key_parameter(self):
        """Passing key= explicitly should bypass the module-level key."""
        lock_vault() 
        data = b"explicit key test"
        vault_store_file("test_explicit.txt", data, key=self.key)
        retrieved = vault_retrieve_file("test_explicit.txt", key=self.key)
        assert retrieved == data

    def test_no_key_raises(self):
        """Operations without any key should raise RuntimeError."""
        lock_vault()
        with pytest.raises(RuntimeError, match="locked"):
            vault_store_file("test_locked.txt", b"data")

    def test_list_files(self):
        """List should include stored files."""
        vault_store_file("test_list_a.txt", b"a")
        vault_store_file("test_list_b.txt", b"b")
        files = vault_list_files()
        assert "test_list_a.txt" in files
        assert "test_list_b.txt" in files

    def test_delete_file(self):
        """Delete should remove the vault file."""
        vault_store_file("test_del.txt", b"data")
        assert vault_delete_file("test_del.txt") is True
        assert vault_retrieve_file("test_del.txt") is None

    def test_delete_nonexistent(self):
        """Deleting non-existent file should return False."""
        assert vault_delete_file("test_nope.txt") is False

    def test_large_file(self):
        """Large files should encrypt and decrypt correctly."""
        data = os.urandom(1024 * 1024)  
        vault_store_file("test_large.bin", data)
        assert vault_retrieve_file("test_large.bin") == data




class TestVaultJSON:
    """Test JSON data vault operations."""

    def setup_method(self):
        self.vault_dir = get_vault_dir()
        self.key = _test_key()
        set_vault_key(self.key)

    def teardown_method(self):
        for f in os.listdir(self.vault_dir):
            if f.startswith("test_") and f.endswith(".vault"):
                os.remove(os.path.join(self.vault_dir, f))
        lock_vault()

    def test_json_round_trip(self):
        """Store and retrieve a JSON object."""
        data = {"key": "value", "numbers": [1, 2, 3]}
        vault_store_json("test_json_data", data)
        retrieved = vault_retrieve_json("test_json_data")
        assert retrieved == data

    def test_json_nonexistent(self):
        """Retrieving non-existent JSON should return None."""
        assert vault_retrieve_json("test_json_nope") is None




class TestTrustRecords:
    """Test trust record storage."""

    def setup_method(self):
        self.vault_dir = get_vault_dir()
        self.key = _test_key()
        set_vault_key(self.key)

    def teardown_method(self):
        for f in os.listdir(self.vault_dir):
            if f.startswith("trust_") and f.endswith(".vault"):
                os.remove(os.path.join(self.vault_dir, f))
        lock_vault()

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
        save_trust_records(records)
        loaded = load_trust_records()
        assert loaded == records

    def test_load_empty(self):
        """Loading when no records exist should return empty dict."""
        loaded = load_trust_records()
        assert loaded == {}




class TestVaultManifest:
    """Test the plaintext manifest that maps filenames to hashes."""

    def setup_method(self):
        self.vault_dir = get_vault_dir()
        self.key = _test_key()
        set_vault_key(self.key)

        manifest_path = os.path.join(self.vault_dir, "vault_manifest.json")
        if os.path.isfile(manifest_path):
            os.remove(manifest_path)

    def teardown_method(self):
        manifest_path = os.path.join(self.vault_dir, "vault_manifest.json")
        if os.path.isfile(manifest_path):
            os.remove(manifest_path)
        for f in os.listdir(self.vault_dir):
            if f.startswith("test_") and f.endswith(".vault"):
                os.remove(os.path.join(self.vault_dir, f))
        lock_vault()

    def test_record_and_lookup_by_hash(self):
        """Record a received file and look it up by hash."""
        vault_store_file("test_received.txt", b"content")
        vault_record_received_file(
            "test_received.txt", "abc123hash", 7, "peer-xyz"
        )
        result = vault_lookup_by_hash("abc123hash")
        assert result is not None
        assert result["filename"] == "test_received.txt"
        assert result["sha256_hash"] == "abc123hash"
        assert result["owner_id"] == "peer-xyz"

    def test_lookup_missing_hash(self):
        """Looking up a non-existent hash should return None."""
        assert vault_lookup_by_hash("nonexistent") is None

    def test_delete_removes_from_manifest(self):
        """Deleting a vault file should also remove it from the manifest."""
        vault_store_file("test_manifest_del.txt", b"data")
        vault_record_received_file(
            "test_manifest_del.txt", "hash123", 4, "peer-a"
        )
        vault_delete_file("test_manifest_del.txt")
        assert vault_lookup_by_hash("hash123") is None
