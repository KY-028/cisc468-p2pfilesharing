"""
manifests.py — File manifest management.

A "manifest" is the list of files a peer is sharing, along with their
metadata (hash, size, owner signature). This module handles:
  - Storing manifests received from other peers
  - Persisting manifests to disk so they survive restarts
  - Verifying file integrity against manifest hashes
  - Verifying owner signatures on file hashes

Reading order: Read files.py first, then this file.
"""

import json
import os
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

# Directory for persisting manifests (set by init_manifest_storage)
_manifest_dir: Optional[str] = None


def init_manifest_storage(data_dir: str) -> None:
    """Set the directory where manifests are persisted and load any saved ones."""
    global _manifest_dir
    _manifest_dir = os.path.join(data_dir, "manifests")
    os.makedirs(_manifest_dir, exist_ok=True)
    _load_all_manifests()


def _manifest_path(peer_id: str) -> Optional[str]:
    if not _manifest_dir:
        return None
    safe_name = peer_id.replace(os.sep, "_").replace("/", "_")
    return os.path.join(_manifest_dir, f"{safe_name}.json")


def _save_manifest(peer_id: str, file_list: list[dict]) -> None:
    path = _manifest_path(peer_id)
    if not path:
        return
    try:
        # Ensure all values are JSON-serializable (signatures may be bytes
        # after protocol deserialization — convert back to base64 strings)
        safe_list = []
        for entry in file_list:
            safe_entry = {}
            for k, v in entry.items():
                if isinstance(v, bytes):
                    safe_entry[k] = base64.b64encode(v).decode("ascii")
                else:
                    safe_entry[k] = v
            safe_list.append(safe_entry)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(safe_list, f)
    except Exception as e:
        logger.error(f"Failed to persist manifest for {peer_id}: {e}")


def _load_all_manifests() -> None:
    if not _manifest_dir or not os.path.isdir(_manifest_dir):
        return
    for fname in os.listdir(_manifest_dir):
        if not fname.endswith(".json"):
            continue
        peer_id = fname[:-5]  # strip .json
        path = os.path.join(_manifest_dir, fname)
        try:
            with open(path, "r", encoding="utf-8") as f:
                file_list = json.load(f)
            # Store in memory without re-saving to disk
            entries = [
                ManifestEntry(
                    filename=e.get("filename", ""),
                    size=e.get("size", 0),
                    sha256_hash=e.get("sha256_hash", ""),
                    owner_id=e.get("owner_id", peer_id),
                    signature=e.get("signature"),
                )
                for e in file_list
            ]
            _peer_manifests[peer_id] = PeerManifest(peer_id=peer_id, files=entries)
            logger.info(f"Loaded saved manifest for {peer_id}: {len(entries)} files")
        except Exception as e:
            logger.error(f"Failed to load manifest {fname}: {e}")


def store_manifest(peer_id: str, file_list: list[dict]) -> PeerManifest:
    """
    Store a file list received from a peer.

    Args:
        peer_id: The peer who sent the list.
        file_list: List of dicts from FILE_LIST_RESPONSE payload.

    Returns:
        The stored PeerManifest.
    """
    logger.info(f"manifests.store_manifest → storing {len(file_list)} files from {peer_id}")
    entries = []
    for f in file_list:
        # Signature may arrive as bytes (after protocol base64 decoding)
        # — convert to base64 string for consistent in-memory storage
        sig = f.get("signature")
        if isinstance(sig, bytes):
            sig = base64.b64encode(sig).decode("ascii")
        entries.append(ManifestEntry(
            filename=f.get("filename", ""),
            size=f.get("size", 0),
            sha256_hash=f.get("sha256_hash", ""),
            owner_id=f.get("owner_id", peer_id),
            signature=sig,
        ))

    manifest = PeerManifest(peer_id=peer_id, files=entries)
    _peer_manifests[peer_id] = manifest
    logger.info(f"Stored manifest for {peer_id}: {len(entries)} files")

    # Persist to disk so it survives restarts
    _save_manifest(peer_id, file_list)

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
    logger.info(f"manifests.verify_file_hash → expected={expected_hash[:12]}…, actual={actual[:12]}…")
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
        logger.info(f"manifests.verify_file_signature → verifying owner sig for hash={data_hash[:12]}…")
        pub_pem = owner_public_key_pem
        if isinstance(pub_pem, str):
            pub_pem = pub_pem.encode("utf-8")
        public_key = deserialize_public_key(pub_pem)
        signature_bytes = base64.b64decode(signature_b64)
        hash_bytes = data_hash.encode("utf-8")
        return verify_signature(public_key, hash_bytes, signature_bytes)
    except Exception as e:
        logger.error(f"Signature verification error: {e}")
        return False


def clear_manifest(peer_id: str) -> None:
    """Remove a peer's manifest (e.g., when they disconnect)."""
    _peer_manifests.pop(peer_id, None)
