"""
vault.py — Encrypted local storage vault.

Protects sensitive data at rest using AES-256-GCM with a 256-bit key
derived from a user-supplied password via PBKDF2-HMAC-SHA256
(600,000 iterations).

Architecture
------------
On first launch the user creates a vault password.  A random 16-byte
salt is generated and saved to ``vault_config.json``.  The password is
**never** saved to disk — only the salt is persisted.

On every subsequent launch the user supplies the password, the saved
salt is read, and PBKDF2 derives a 32-byte AES key.  That key is held
**only in RAM** for the duration of the session.

Each file stored in the vault is encrypted with its own random 96-bit
nonce (IV).  The on-disk format of every vault file is::

    [12-byte nonce][ciphertext + 16-byte GCM authentication tag]

The vault also maintains a plaintext ``vault_manifest.json`` that maps
stored filenames to their original SHA-256 hashes, sizes, and owner IDs
so that other peers can look up files by hash without needing the key.

Reading order: Read encrypt.py and kdf.py first, then this file.
"""

import os
import json
import logging
from typing import Optional, Any
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
from app.crypto.kdf import pbkdf2_derive_key, generate_salt

logger = logging.getLogger(__name__)

# Default vault directory
VAULT_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "data", "vault")

# Sizes (bytes)
SALT_SIZE = 16       # PBKDF2 salt
NONCE_SIZE = 12      # 96-bit GCM nonce
TAG_SIZE = 16        # 128-bit GCM authentication tag

# ---------------------------------------------------------------------------
# In-memory vault key — derived from password + saved salt at startup.
# Cleared on shutdown.  Never written to disk.
# ---------------------------------------------------------------------------
_vault_key: Optional[bytes] = None


def get_vault_dir() -> str:
    """Get (and create if needed) the vault directory."""
    os.makedirs(VAULT_DIR, exist_ok=True)
    return os.path.abspath(VAULT_DIR)


# ---------------------------------------------------------------------------
# Vault initialization & key management
# ---------------------------------------------------------------------------

def is_vault_initialized() -> bool:
    """Return True if a vault password has been set up previously."""
    config_path = os.path.join(get_vault_dir(), "vault_config.json")
    return os.path.isfile(config_path)


def initialize_vault(password: str) -> bytes:
    """
    First-time vault setup.

    1. Generate a cryptographically random 16-byte salt.
    2. Derive a 32-byte AES key via PBKDF2-HMAC-SHA256 (600 000 iters).
    3. Encrypt a known sentinel value with the key so we can verify the
       password on subsequent unlocks.
    4. Save *only* the salt and the encrypted sentinel to
       ``vault_config.json`` — the password and key are **never** saved.
    5. Hold the derived key in RAM (``_vault_key``).

    Args:
        password: The user's chosen vault password.

    Returns:
        The derived 32-byte AES key.
    """
    salt = generate_salt(SALT_SIZE)
    key = pbkdf2_derive_key(password, salt)

    # Create a verification token: encrypt a known sentinel so we can
    # detect wrong passwords at unlock time instead of failing silently.
    sentinel = b"vault-password-ok"
    verify_blob = vault_encrypt_data(key, sentinel)

    config_path = os.path.join(get_vault_dir(), "vault_config.json")
    with open(config_path, "w", encoding="utf-8") as f:
        json.dump({
            "salt": salt.hex(),
            "verify_token": verify_blob.hex(),
        }, f)
    set_vault_key(key)
    logger.info("Vault initialized (salt saved, key derived and held in RAM).")
    return key


def unlock_vault(password: str) -> bytes:
    """
    Unlock the vault on subsequent launches.

    Reads the saved salt from ``vault_config.json``, derives the AES key,
    verifies it against the stored verification token, and stores the key
    in RAM.

    Args:
        password: The user's vault password.

    Returns:
        The derived 32-byte AES key.

    Raises:
        FileNotFoundError: If ``vault_config.json`` does not exist.
        cryptography.exceptions.InvalidTag: If the password is wrong.
    """
    config_path = os.path.join(get_vault_dir(), "vault_config.json")
    if not os.path.isfile(config_path):
        raise FileNotFoundError("Vault not initialized — no vault_config.json")
    with open(config_path, "r", encoding="utf-8") as f:
        config = json.load(f)
    salt = bytes.fromhex(config["salt"])
    key = pbkdf2_derive_key(password, salt)

    # Verify the password by decrypting the stored sentinel.
    # If the password is wrong, AESGCM will raise InvalidTag.
    verify_hex = config.get("verify_token")
    if verify_hex:
        verify_blob = bytes.fromhex(verify_hex)
        vault_decrypt_data(key, verify_blob)  # raises InvalidTag on wrong pw

    set_vault_key(key)
    logger.info("Vault unlocked (key derived from password + stored salt).")
    return key


def change_vault_password(old_password: str, new_password: str) -> list[str]:
    """
    Change the vault password by re-encrypting all vault files with a new key.

    The operation is fail-closed:
      1. Verify the old password against the stored verification token.
      2. Derive a new key using a fresh random salt.
      3. Re-encrypt all `.vault` files to temporary files first.
      4. Commit by atomically replacing files and config.
      5. On any failure, restore from backups and keep old config.

    Returns:
        A list of filenames that could not be re-encrypted because they
        were undecryptable with the current key.

    Raises:
        FileNotFoundError: vault config is missing.
        InvalidTag: old password is wrong.
        RuntimeError: re-encryption commit failed and was rolled back.
    """
    if len(new_password) < 8:
        raise ValueError("New password must be at least 8 characters.")

    config_path = os.path.join(get_vault_dir(), "vault_config.json")
    if not os.path.isfile(config_path):
        raise FileNotFoundError("Vault not initialized — no vault_config.json")

    with open(config_path, "r", encoding="utf-8") as f:
        config = json.load(f)

    old_salt = bytes.fromhex(config["salt"])
    old_key = pbkdf2_derive_key(old_password, old_salt)

    verify_hex = config.get("verify_token")
    if verify_hex:
        verify_blob = bytes.fromhex(verify_hex)
        vault_decrypt_data(old_key, verify_blob)

    new_salt = generate_salt(SALT_SIZE)
    new_key = pbkdf2_derive_key(new_password, new_salt)
    new_verify_blob = vault_encrypt_data(new_key, b"vault-password-ok")

    vault_dir = get_vault_dir()
    vault_files = [
        os.path.join(vault_dir, name)
        for name in os.listdir(vault_dir)
        if name.endswith(".vault")
    ]

    temp_map: list[tuple[str, str]] = []
    backup_map: list[tuple[str, str]] = []
    skipped_files: list[str] = []
    config_tmp = config_path + ".tmp"

    try:
        for original_path in vault_files:
            with open(original_path, "rb") as f:
                old_blob = f.read()
            try:
                plaintext = vault_decrypt_data(old_key, old_blob)
            except InvalidTag:
                # If one file is undecryptable (mixed legacy data or corruption),
                # continue re-encrypting decryptable files so valid password changes
                # do not fail entirely.
                skipped_files.append(os.path.basename(original_path))
                logger.warning(
                    "Skipping undecryptable vault file during key rotation: "
                    f"{os.path.basename(original_path)}"
                )
                continue
            new_blob = vault_encrypt_data(new_key, plaintext)

            tmp_path = original_path + ".rekeytmp"
            with open(tmp_path, "wb") as f:
                f.write(new_blob)
            temp_map.append((original_path, tmp_path))

        with open(config_tmp, "w", encoding="utf-8") as f:
            json.dump({
                "salt": new_salt.hex(),
                "verify_token": new_verify_blob.hex(),
            }, f)

        for original_path, tmp_path in temp_map:
            backup_path = original_path + ".rekeybak"
            if os.path.exists(backup_path):
                os.remove(backup_path)
            os.replace(original_path, backup_path)
            backup_map.append((original_path, backup_path))
            os.replace(tmp_path, original_path)

        os.replace(config_tmp, config_path)

    except InvalidTag:
        for _, tmp_path in temp_map:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
        if os.path.exists(config_tmp):
            os.remove(config_tmp)
        raise
    except Exception as exc:
        for original_path, backup_path in backup_map:
            if os.path.exists(backup_path):
                os.replace(backup_path, original_path)
        for _, tmp_path in temp_map:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
        if os.path.exists(config_tmp):
            os.remove(config_tmp)
        raise RuntimeError(f"Vault key change failed: {exc}") from exc
    finally:
        for _, backup_path in backup_map:
            if os.path.exists(backup_path):
                os.remove(backup_path)

    set_vault_key(new_key)
    logger.info("Vault key changed successfully (files re-encrypted with new key).")
    return skipped_files


def set_vault_key(key: bytes) -> None:
    """Store the derived AES key in process memory for the session."""
    global _vault_key
    _vault_key = key


def get_vault_key() -> Optional[bytes]:
    """Return the current in-memory vault key, or None if locked."""
    return _vault_key


def lock_vault() -> None:
    """Clear the vault key from memory (e.g. on shutdown)."""
    global _vault_key
    _vault_key = None


def _require_key(key: Optional[bytes] = None) -> bytes:
    """Return *key* if provided, else the module-level vault key, else raise."""
    k = key or _vault_key
    if k is None:
        raise RuntimeError("Vault is locked. Unlock with your password first.")
    return k


# ---------------------------------------------------------------------------
# Low-level encryption helpers
# ---------------------------------------------------------------------------

def vault_encrypt_data(key: bytes, plaintext: bytes) -> bytes:
    """
    Encrypt *plaintext* with AES-256-GCM.

    A brand-new random 96-bit nonce is generated for every call.

    Returns:
        ``nonce (12 B) || ciphertext || tag (16 B)``
    """
    nonce = os.urandom(NONCE_SIZE)
    aesgcm = AESGCM(key)
    ct_and_tag = aesgcm.encrypt(nonce, plaintext, None)
    return nonce + ct_and_tag


def vault_decrypt_data(key: bytes, blob: bytes) -> bytes:
    """
    Decrypt a blob produced by :func:`vault_encrypt_data`.

    Raises:
        ValueError: If the blob is too short.
        cryptography.exceptions.InvalidTag: If the key is wrong or data
            was tampered with.
    """
    if len(blob) < NONCE_SIZE + TAG_SIZE:
        raise ValueError("Vault blob too short")
    nonce = blob[:NONCE_SIZE]
    ct_and_tag = blob[NONCE_SIZE:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ct_and_tag, None)


# ---------------------------------------------------------------------------
# Password-based encrypt / decrypt  (self-contained blobs, used by tests)
# ---------------------------------------------------------------------------

def vault_encrypt(password: str, plaintext: bytes) -> bytes:
    """
    Encrypt with a per-blob salt so the blob is fully self-contained.

    Blob format: ``salt (16 B) || nonce (12 B) || ciphertext || tag (16 B)``

    This is useful for one-off encryption where you don't want to
    manage a separate config file (e.g. unit tests).
    """
    salt = generate_salt(SALT_SIZE)
    key = pbkdf2_derive_key(password, salt)
    nonce = os.urandom(NONCE_SIZE)
    aesgcm = AESGCM(key)
    ct_and_tag = aesgcm.encrypt(nonce, plaintext, None)
    return salt + nonce + ct_and_tag


def vault_decrypt(password: str, vault_blob: bytes) -> bytes:
    """
    Decrypt a blob produced by :func:`vault_encrypt`.

    Raises:
        ValueError: If the blob is too short.
        cryptography.exceptions.InvalidTag: On wrong password or tampering.
    """
    if len(vault_blob) < SALT_SIZE + NONCE_SIZE + TAG_SIZE:
        raise ValueError("Vault blob too short")
    salt = vault_blob[:SALT_SIZE]
    rest = vault_blob[SALT_SIZE:]
    key = pbkdf2_derive_key(password, salt)
    nonce = rest[:NONCE_SIZE]
    ct_and_tag = rest[NONCE_SIZE:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ct_and_tag, None)


# ---------------------------------------------------------------------------
# File-level vault operations  (use in-memory key by default)
# ---------------------------------------------------------------------------

def vault_store_file(filename: str, data: bytes,
                     key: Optional[bytes] = None) -> str:
    """
    Encrypt and store a file in the vault.

    Each file gets a fresh random nonce.  The on-disk blob is::

        nonce (12 B) || ciphertext || tag (16 B)

    Args:
        filename: Logical name to store the file under.
        data: Raw plaintext bytes.
        key: AES key to use.  Falls back to the in-memory vault key.

    Returns:
        The full path to the stored ``.vault`` file.
    """
    k = _require_key(key)
    vault_dir = get_vault_dir()
    blob = vault_encrypt_data(k, data)
    vault_path = os.path.join(vault_dir, f"{filename}.vault")
    with open(vault_path, "wb") as f:
        f.write(blob)
    logger.info(
        f"Vault: stored '{filename}' "
        f"({len(data)} bytes → {len(blob)} encrypted)"
    )
    return vault_path


def vault_retrieve_file(filename: str,
                        key: Optional[bytes] = None) -> Optional[bytes]:
    """
    Decrypt and retrieve a file from the vault.

    Args:
        filename: Logical name of the stored file.
        key: AES key to use.  Falls back to the in-memory vault key.

    Returns:
        Decrypted plaintext bytes, or ``None`` if the file does not exist.

    Raises:
        cryptography.exceptions.InvalidTag: On wrong key / tampering.
    """
    k = _require_key(key)
    vault_dir = get_vault_dir()
    vault_path = os.path.join(vault_dir, f"{filename}.vault")
    if not os.path.isfile(vault_path):
        logger.warning(f"Vault: file '{filename}' not found")
        return None
    with open(vault_path, "rb") as f:
        blob = f.read()
    return vault_decrypt_data(k, blob)


def vault_list_files() -> list[str]:
    """List all files stored in the vault (by logical name, no extension)."""
    vault_dir = get_vault_dir()
    if not os.path.isdir(vault_dir):
        return []
    return [
        f.replace(".vault", "")
        for f in os.listdir(vault_dir)
        if f.endswith(".vault")
    ]


def vault_delete_file(filename: str) -> bool:
    """Delete a file from the vault.  Returns True if it existed."""
    vault_dir = get_vault_dir()
    vault_path = os.path.join(vault_dir, f"{filename}.vault")
    if os.path.isfile(vault_path):
        os.remove(vault_path)
        logger.info(f"Vault: deleted '{filename}'")
        # Also remove from the received-files manifest
        _remove_from_manifest(filename)
        return True
    return False


# ---------------------------------------------------------------------------
# JSON data vault (structured data encrypted at rest)
# ---------------------------------------------------------------------------

def vault_store_json(name: str, data: Any,
                     key: Optional[bytes] = None) -> str:
    """Encrypt and store a JSON-serializable object in the vault."""
    json_bytes = json.dumps(data, indent=2).encode("utf-8")
    return vault_store_file(f"{name}.json", json_bytes, key=key)


def vault_retrieve_json(name: str,
                        key: Optional[bytes] = None) -> Optional[Any]:
    """Decrypt and retrieve a JSON object from the vault."""
    raw = vault_retrieve_file(f"{name}.json", key=key)
    if raw is None:
        return None
    return json.loads(raw.decode("utf-8"))


# ---------------------------------------------------------------------------
# Trust store (peer fingerprint trust records)
# ---------------------------------------------------------------------------

def save_trust_records(trust_records: dict,
                       key: Optional[bytes] = None) -> None:
    """Save peer trust records to the vault (encrypted)."""
    vault_store_json("trust_records", trust_records, key=key)
    logger.info(f"Vault: saved {len(trust_records)} trust records")


def load_trust_records(key: Optional[bytes] = None) -> dict:
    """Load peer trust records from the vault.  Returns ``{}`` if none."""
    records = vault_retrieve_json("trust_records", key=key)
    return records if records else {}


# ---------------------------------------------------------------------------
# Received-files manifest (plaintext metadata so peers can look up by hash)
# ---------------------------------------------------------------------------

def _get_manifest_path() -> str:
    return os.path.join(get_vault_dir(), "vault_manifest.json")


def _load_manifest() -> dict:
    path = _get_manifest_path()
    if not os.path.isfile(path):
        return {}
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _save_manifest(manifest: dict) -> None:
    path = _get_manifest_path()
    with open(path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)


def vault_record_received_file(filename: str, sha256_hash: str,
                                size: int, owner_id: str) -> None:
    """Record metadata about a received file stored in the vault."""
    manifest = _load_manifest()
    manifest[filename] = {
        "sha256_hash": sha256_hash,
        "size": size,
        "owner_id": owner_id,
    }
    _save_manifest(manifest)


def vault_lookup_by_hash(file_hash: str) -> Optional[dict]:
    """
    Look up a vault file by its original SHA-256 hash.

    Returns:
        ``{"filename": ..., "sha256_hash": ..., "size": ..., "owner_id": ...}``
        or ``None``.
    """
    manifest = _load_manifest()
    for filename, meta in manifest.items():
        if meta.get("sha256_hash") == file_hash:
            return {"filename": filename, **meta}
    return None


def _remove_from_manifest(filename: str) -> None:
    """Remove an entry from the received-files manifest."""
    manifest = _load_manifest()
    if filename in manifest:
        del manifest[filename]
        _save_manifest(manifest)
