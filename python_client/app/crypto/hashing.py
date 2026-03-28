"""
hashing.py — SHA-256 hashing utilities.

Provides simple wrappers around SHA-256 for:
  - Hashing raw bytes
  - Hashing file contents (streaming, handles large files)

Reading order: Independent utility — read anytime.
"""

from cryptography.hazmat.primitives import hashes


def sha256_hash(data: bytes) -> str:
    """
    Compute the SHA-256 hash of raw bytes.

    Args:
        data: The bytes to hash.

    Returns:
        The hex digest string (64 characters).
    """
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)
    return digest.finalize().hex()


def sha256_hash_file(filepath: str, chunk_size: int = 8192) -> str:
    """
    Compute the SHA-256 hash of a file's contents.

    Reads the file in chunks to handle large files without loading
    the entire contents into memory.

    Args:
        filepath: Path to the file.
        chunk_size: Read buffer size in bytes (default 8 KB).

    Returns:
        The hex digest string (64 characters).

    Raises:
        FileNotFoundError: If the file doesn't exist.
        IOError: If the file can't be read.
    """
    digest = hashes.Hash(hashes.SHA256())
    with open(filepath, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            digest.update(chunk)
    return digest.finalize().hex()
