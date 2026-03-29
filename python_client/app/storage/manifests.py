"""
manifests.py — File manifest management.

A "manifest" is the list of files a peer is sharing, along with their
metadata (hash, size, owner signature). This module handles:
  - Storing manifests received from other peers
  - Verifying file integrity against manifest hashes
  - Verifying owner signatures on file hashes

Reading order: Read files.py first, then this file.
"""

import base64
import logging
from typing import Optional
from dataclasses import dataclass, field
from app.crypto.sign import verify_signature
from app.crypto.keys import deserialize_public_key
from app.crypto.hashing import sha256_hash

logger = logging.getLogger(__name__)


@dataclass
class ManifestEntry:
    """A single file entry in a peer's manifest."""
    filename: str
    size: int
    sha256_hash: str
    owner_id: str
    signature: Optional[str] = None  # Base64-encoded RSA-PSS signature


@dataclass
class PeerManifest:
    """The full file manifest for a single peer."""
    peer_id: str
    files: list[ManifestEntry] = field(default_factory=list)


# ---------------------------------------------------------------------------
# In-memory manifest store: peer_id -> PeerManifest
# ---------------------------------------------------------------------------
_peer_manifests: dict[str, PeerManifest] = {}


def store_manifest(peer_id: str, file_list: list[dict]) -> PeerManifest:
    """
    Store a file list received from a peer.

    Args:
        peer_id: The peer who sent the list.
        file_list: List of dicts from FILE_LIST_RESPONSE payload.

    Returns:
        The stored PeerManifest.
    """
    entries = []
    for f in file_list:
        entries.append(ManifestEntry(
            filename=f.get("filename", ""),
            size=f.get("size", 0),
            sha256_hash=f.get("sha256_hash", ""),
            owner_id=f.get("owner_id", peer_id),
            signature=f.get("signature"),
        ))

    manifest = PeerManifest(peer_id=peer_id, files=entries)
    _peer_manifests[peer_id] = manifest
    logger.info(f"Stored manifest for {peer_id}: {len(entries)} files")
    return manifest


def get_manifest(peer_id: str) -> Optional[PeerManifest]:
    """Get the stored manifest for a peer."""
    return _peer_manifests.get(peer_id)


def get_all_manifests() -> dict[str, PeerManifest]:
    """Get all stored peer manifests."""
    return dict(_peer_manifests)


def verify_file_hash(data: bytes, expected_hash: str) -> bool:
    """
    Verify that file data matches the expected SHA-256 hash.

    Args:
        data: The raw file bytes.
        expected_hash: The expected hex digest from the manifest.

    Returns:
        True if the hash matches.
    """
    actual = sha256_hash(data)
    matches = actual == expected_hash
    if not matches:
        logger.warning(f"Hash mismatch: expected {expected_hash[:12]}, got {actual[:12]}")
    return matches


def verify_file_signature(data_hash: str, signature_b64: str,
                           owner_public_key_pem: str) -> bool:
    """
    Verify the owner's signature on a file hash.

    This enables third-party verification: even if you received the
    file from a different peer, you can verify the original owner
    signed it.

    Args:
        data_hash: The SHA-256 hex digest of the file.
        signature_b64: Base64-encoded RSA-PSS signature.
        owner_public_key_pem: PEM-encoded public key of the owner.

    Returns:
        True if the signature is valid.
    """
    try:
        public_key = deserialize_public_key(owner_public_key_pem)
        signature_bytes = base64.b64decode(signature_b64)
        hash_bytes = data_hash.encode("utf-8")
        return verify_signature(public_key, hash_bytes, signature_bytes)
    except Exception as e:
        logger.error(f"Signature verification error: {e}")
        return False


def clear_manifest(peer_id: str) -> None:
    """Remove a peer's manifest (e.g., when they disconnect)."""
    _peer_manifests.pop(peer_id, None)
