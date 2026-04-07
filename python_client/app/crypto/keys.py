"""
keys.py — RSA-2048 key generation, serialization, and fingerprinting.

This module manages long-term identity keys. Each peer generates one
RSA-2048 key pair that serves as their identity. The public key is
shared with other peers; the private key never leaves local storage.

The fingerprint is a SHA-256 hash of the DER-encoded public key,
displayed as hex for manual out-of-band verification.

Reading order: Read this FIRST in Phase 3 — it's the identity foundation.
"""

import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes




def generate_rsa_keypair():
    """
    Generate a fresh RSA-2048 key pair.

    Returns:
        (private_key, public_key) — cryptography RSAPrivateKey and RSAPublicKey objects.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    return private_key, public_key



def serialize_public_key(public_key) -> bytes:
    """
    Serialize an RSA public key to PEM-encoded bytes.
    This is the format exchanged over the network.
    """
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def deserialize_public_key(pem_bytes: bytes):
    """
    Deserialize PEM-encoded bytes into an RSA public key object.

    Args:
        pem_bytes: PEM-encoded public key.

    Returns:
        An RSAPublicKey object.

    Raises:
        ValueError: If the PEM data is invalid.
    """
    if isinstance(pem_bytes, str):
        pem_bytes = pem_bytes.encode("utf-8")
    return serialization.load_pem_public_key(pem_bytes)




def save_private_key(private_key, path: str, password: bytes = None) -> None:
    """
    Save an RSA private key to a PEM file.

    If password is provided, the key is encrypted with AES-256-CBC.
    Otherwise it is stored unencrypted (only acceptable during development).

    Args:
        private_key: RSAPrivateKey object.
        path: File path to write.
        password: Optional passphrase (bytes) for encryption.
    """
    if password is not None:
        encryption = serialization.BestAvailableEncryption(password)
    else:
        encryption = serialization.NoEncryption()

    pem_data = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption,
    )
   
    with open(path, "wb") as f:
        f.write(pem_data)


def load_private_key(path: str, password: bytes = None):
    """
    Load an RSA private key from a PEM file.

    Args:
        path: File path to read.
        password: Passphrase if the key is encrypted.

    Returns:
        An RSAPrivateKey object.

    Raises:
        FileNotFoundError: If the file doesn't exist.
        ValueError: If the password is wrong or PEM is invalid.
    """
    with open(path, "rb") as f:
        pem_data = f.read()
    return serialization.load_pem_private_key(pem_data, password=password)



def get_fingerprint(public_key) -> str:
    """
    Compute the SHA-256 fingerprint of a public key.

    The fingerprint is computed over the DER-encoded public key bytes,
    then formatted as a colon-separated hex string for easy visual
    comparison (e.g. "A1:B2:C3:D4:...").

    Args:
        public_key: An RSAPublicKey object.

    Returns:
        A string like "a1:b2:c3:d4:..." (64 hex chars + colons).
    """
    der_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    digest = hashes.Hash(hashes.SHA256())
    digest.update(der_bytes)
    hash_bytes = digest.finalize()

    # Format as colon-separated hex pairs
    return ":".join(f"{b:02x}" for b in hash_bytes)
