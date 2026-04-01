"""
verification.py — Third-party file verification.

Enables verifying file authenticity even when receiving from a peer
who is NOT the original owner. The original owner signs the file hash
with their RSA-PSS private key; any peer can verify that signature
using the owner's public key.

Flow:
  1. Owner shares file → signs SHA-256(file) with their private key
  2. File propagates to other peers (with signature attached)
  3. Any peer can verify: verify_signature(owner_pub, hash, sig)

This is already partly implemented in files.py (signing on add) and
manifests.py (verify_file_signature). This module adds higher-level
convenience functions and a route for on-demand verification.

Reading order: Read files.py and manifests.py first, then this file.
"""

import base64
import logging
from typing import Optional
from app.core.state import app_state, PeerInfo
from app.crypto.sign import verify_signature
from app.crypto.keys import deserialize_public_key
from app.crypto.hashing import sha256_hash
from app.storage.manifests import get_manifest, verify_file_signature

logger = logging.getLogger(__name__)


def verify_received_file(file_data: bytes, expected_hash: str,
                          signature_b64: str, owner_id: str) -> dict:
    """
    Perform full third-party verification of a received file.

    Checks:
      1. File hash matches the expected hash
      2. Owner's RSA-PSS signature over the hash is valid

    Args:
        file_data: The raw file bytes.
        expected_hash: SHA-256 hex digest from the manifest.
        signature_b64: Base64-encoded RSA-PSS signature from the owner.
        owner_id: The peer_id of the file's original owner.

    Returns:
        A dict with verification results:
        {
            "hash_valid": bool,
            "signature_valid": bool,
            "owner_id": str,
            "actual_hash": str,
            "errors": [str]
        }
    """
    result = {
        "hash_valid": False,
        "signature_valid": False,
        "owner_id": owner_id,
        "actual_hash": "",
        "errors": [],
    }
    logger.info(f"verification.verify_received_file → checking hash + owner sig for {owner_id}'s file (hash={expected_hash[:12]}…)")

    # Step 1: Verify hash
    actual_hash = sha256_hash(file_data)
    result["actual_hash"] = actual_hash
    result["hash_valid"] = actual_hash == expected_hash

    if not result["hash_valid"]:
        result["errors"].append(
            f"Hash mismatch: expected {expected_hash[:16]}…, "
            f"got {actual_hash[:16]}…"
        )
        return result  # No point checking signature if hash is wrong

    # Step 2: Verify owner signature
    if not signature_b64:
        result["errors"].append("No owner signature available.")
        return result

    # Look up the owner's public key
    owner_pub_pem = _get_owner_public_key(owner_id)
    if not owner_pub_pem:
        result["errors"].append(
            f"Owner '{owner_id}' public key not found. "
            "Cannot verify signature."
        )
        return result

    result["signature_valid"] = verify_file_signature(
        expected_hash, signature_b64, owner_pub_pem
    )

    if not result["signature_valid"]:
        result["errors"].append("Owner signature verification FAILED.")

    return result


def verify_manifest_entry(peer_id: str, filename: str) -> Optional[dict]:
    """
    Verify a file in a peer's manifest using the owner's signature.

    Looks up the manifest entry, finds the owner's public key, and
    verifies the signature over the hash.

    Args:
        peer_id: The peer whose manifest contains the file.
        filename: The filename to verify.

    Returns:
        Verification result dict, or None if the file isn't found.
    """
    logger.info(f"verification.verify_manifest_entry → verifying '{filename}' in {peer_id}'s manifest")
    manifest = get_manifest(peer_id)
    if not manifest:
        return None

    entry = None
    for e in manifest.files:
        if e.filename == filename:
            entry = e
            break

    if not entry:
        return None

    if not entry.signature:
        return {
            "filename": entry.filename,
            "hash": entry.sha256_hash,
            "owner_id": entry.owner_id,
            "signature_valid": None,
            "note": "No owner signature attached to this file.",
        }

    owner_pub_pem = _get_owner_public_key(entry.owner_id)
    if not owner_pub_pem:
        return {
            "filename": entry.filename,
            "hash": entry.sha256_hash,
            "owner_id": entry.owner_id,
            "signature_valid": None,
            "note": f"Owner '{entry.owner_id}' public key not available.",
        }

    sig_valid = verify_file_signature(
        entry.sha256_hash, entry.signature, owner_pub_pem
    )

    return {
        "filename": entry.filename,
        "hash": entry.sha256_hash,
        "owner_id": entry.owner_id,
        "signature_valid": sig_valid,
    }


def _get_owner_public_key(owner_id: str) -> Optional[str]:
    """
    Look up a peer's public key PEM from app_state.

    Checks:
      1. If owner_id is us, use our own key
      2. If owner is a known peer, use their key
    """
    if owner_id == app_state.peer_id:
        return app_state.public_key_pem

    peer = app_state.peers.get(owner_id)
    if peer and peer.public_key_pem:
        return peer.public_key_pem

    return None
