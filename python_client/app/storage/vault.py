"""
vault.py — Encrypted local storage vault.

Protects sensitive data at rest using AES-256-GCM with a key derived
from a user-supplied password via PBKDF2-HMAC-SHA256 (600,000 iterations).

The vault stores:
  - Received files (encrypted)
  - Peer trust records (which fingerprints are trusted)
  - Any other sensitive local data

Vault file format:
  [16 bytes: salt][12 bytes: nonce][N bytes: ciphertext + 16 bytes tag]

Reading order: Read encrypt.py and kdf.py first, then this file.
"""

import os
import json
import logging
from typing import Optional, Any
from app.crypto.kdf import pbkdf2_derive_key, generate_salt
from app.crypto.encrypt import encrypt, decrypt, NONCE_SIZE

logger = logging.getLogger(__name__)

# Default vault directory
VAULT_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "data", "vault")

# Salt size for PBKDF2
SALT_SIZE = 16


def get_vault_dir() -> str:
    """Get (and create if needed) the vault directory."""
    os.makedirs(VAULT_DIR, exist_ok=True)
    return os.path.abspath(VAULT_DIR)


# ---------------------------------------------------------------------------
# Low-level vault encryption/decryption
# ---------------------------------------------------------------------------

def vault_encrypt(password: str, plaintext: bytes) -> bytes:
    """
    Encrypt data for vault storage.

    Derives a 32-byte key from the password using PBKDF2, then
    encrypts with AES-256-GCM.

    Args:
        password: The user's vault password.
        plaintext: Data to encrypt.

    Returns:
        Vault blob: [16-byte salt][encrypted data (nonce + ciphertext + tag)]
    """
    salt = generate_salt(SALT_SIZE)
    key = pbkdf2_derive_key(password, salt)
    ciphertext = encrypt(key, plaintext)
    # Prepend salt so we can re-derive the key for decryption
    return salt + ciphertext


def vault_decrypt(password: str, vault_blob: bytes) -> bytes:
    """
    Decrypt vault-encrypted data.

    Args:
        password: The user's vault password.
        vault_blob: Output from vault_encrypt().

    Returns:
        The decrypted plaintext.

    Raises:
        ValueError: If the blob is too short.
        InvalidTag: If the password is wrong or data is tampered.
    """
    if len(vault_blob) < SALT_SIZE + NONCE_SIZE + 16:
        raise ValueError("Vault blob too short")

    salt = vault_blob[:SALT_SIZE]
    ciphertext = vault_blob[SALT_SIZE:]
    key = pbkdf2_derive_key(password, salt)
    return decrypt(key, ciphertext)


# ---------------------------------------------------------------------------
# File-level vault operations
# ---------------------------------------------------------------------------

def vault_store_file(password: str, filename: str, data: bytes) -> str:
    """
    Encrypt and store a file in the vault.

    Args:
        password: Vault password.
        filename: Name to store the file under.
        data: Raw file bytes.

    Returns:
        The full path to the stored vault file.
    """
    vault_dir = get_vault_dir()
    vault_blob = vault_encrypt(password, data)
    # Use .vault extension to distinguish from plaintext
    vault_path = os.path.join(vault_dir, f"{filename}.vault")

    with open(vault_path, "wb") as f:
        f.write(vault_blob)

    logger.info(f"Vault: stored '{filename}' ({len(data)} bytes → {len(vault_blob)} encrypted)")
    return vault_path


def vault_retrieve_file(password: str, filename: str) -> Optional[bytes]:
    """
    Decrypt and retrieve a file from the vault.

    Args:
        password: Vault password.
        filename: Name of the stored file.

    Returns:
        The decrypted file bytes, or None if not found.

    Raises:
        InvalidTag: If the password is wrong.
    """
    vault_dir = get_vault_dir()
    vault_path = os.path.join(vault_dir, f"{filename}.vault")

    if not os.path.isfile(vault_path):
        logger.warning(f"Vault: file '{filename}' not found")
        return None

    with open(vault_path, "rb") as f:
        vault_blob = f.read()

    return vault_decrypt(password, vault_blob)


def vault_list_files() -> list[str]:
    """List all files stored in the vault."""
    vault_dir = get_vault_dir()
    if not os.path.isdir(vault_dir):
        return []
    return [
        f.replace(".vault", "")
        for f in os.listdir(vault_dir)
        if f.endswith(".vault")
    ]


def vault_delete_file(filename: str) -> bool:
    """
    Delete a file from the vault.

    Args:
        filename: Name of the file to delete.

    Returns:
        True if the file was found and deleted.
    """
    vault_dir = get_vault_dir()
    vault_path = os.path.join(vault_dir, f"{filename}.vault")
    if os.path.isfile(vault_path):
        os.remove(vault_path)
        logger.info(f"Vault: deleted '{filename}'")
        return True
    return False


# ---------------------------------------------------------------------------
# JSON data vault (for structured data like trust records)
# ---------------------------------------------------------------------------

def vault_store_json(password: str, name: str, data: Any) -> str:
    """
    Encrypt and store a JSON-serializable object in the vault.

    Args:
        password: Vault password.
        name: Name for this data (e.g., "trust_records").
        data: Any JSON-serializable Python object.

    Returns:
        Path to the stored vault file.
    """
    json_bytes = json.dumps(data, indent=2).encode("utf-8")
    return vault_store_file(password, f"{name}.json", json_bytes)


def vault_retrieve_json(password: str, name: str) -> Optional[Any]:
    """
    Decrypt and retrieve a JSON object from the vault.

    Args:
        password: Vault password.
        name: Name of the stored data.

    Returns:
        The deserialized Python object, or None if not found.
    """
    raw = vault_retrieve_file(password, f"{name}.json")
    if raw is None:
        return None
    return json.loads(raw.decode("utf-8"))


# ---------------------------------------------------------------------------
# Trust store (peer fingerprint trust records)
# ---------------------------------------------------------------------------

def save_trust_records(password: str, trust_records: dict) -> None:
    """
    Save peer trust records to the vault.

    Args:
        password: Vault password.
        trust_records: Dict mapping peer_id -> {fingerprint, trusted, last_verified}
    """
    vault_store_json(password, "trust_records", trust_records)
    logger.info(f"Vault: saved {len(trust_records)} trust records")


def load_trust_records(password: str) -> dict:
    """
    Load peer trust records from the vault.

    Returns:
        Dict of trust records, or empty dict if none stored.
    """
    records = vault_retrieve_json(password, "trust_records")
    return records if records else {}
