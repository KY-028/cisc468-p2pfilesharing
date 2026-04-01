"""
files.py — Local file management for sharing.

Handles adding files to the share directory, hashing them, and
managing the shared file list.

The "shared" directory is where users place files they want to share.
When a file is added, we compute its SHA-256 hash and add it to
app_state.shared_files.

Reading order: Read state.py first, then this file.
"""

import os
import logging
from typing import Optional
from app.core.state import app_state, SharedFile
from app.crypto.hashing import sha256_hash_file
from app.crypto.sign import sign_data

logger = logging.getLogger(__name__)

# Default shared directory (next to the data/ directory)
SHARED_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "shared")


def get_shared_dir() -> str:
    """Get (and create if needed) the shared files directory."""
    os.makedirs(SHARED_DIR, exist_ok=True)
    return os.path.abspath(SHARED_DIR)


def add_file(filepath: str) -> Optional[SharedFile]:
    """
    Add a file to the shared files list.

    Computes the SHA-256 hash, creates a SharedFile record, and adds
    it to app_state.shared_files.

    Args:
        filepath: Absolute or relative path to the file.

    Returns:
        The SharedFile record, or None if the file doesn't exist.
    """
    filepath = os.path.abspath(filepath)
    logger.info(f"files.add_file → adding '{os.path.basename(filepath)}' to shared list")
    if not os.path.isfile(filepath):
        logger.error(f"File not found: {filepath}")
        return None

    filename = os.path.basename(filepath)
    size = os.path.getsize(filepath)
    file_hash = sha256_hash_file(filepath)

    # Check if already shared (by hash)
    for existing in app_state.shared_files:
        if existing.sha256_hash == file_hash:
            logger.info(f"File already shared: {filename} ({file_hash[:12]})")
            return existing

    # Sign the hash with our private key (for third-party verification)
    signature = None
    if hasattr(app_state, '_private_key') and app_state._private_key:
        hash_bytes = file_hash.encode("utf-8")
        sig_bytes = sign_data(app_state._private_key, hash_bytes)
        import base64
        signature = base64.b64encode(sig_bytes).decode("ascii")

    shared = SharedFile(
        filename=filename,
        filepath=filepath,
        size=size,
        sha256_hash=file_hash,
        owner_id=app_state.peer_id,
        signature=signature,
    )
    app_state.shared_files.append(shared)
    logger.info(f"Added shared file: {filename} ({size} bytes, hash={file_hash[:12]})")
    return shared


def remove_file(filename: str) -> bool:
    """
    Remove a file from the shared list (does NOT delete the file on disk).

    Args:
        filename: The filename to remove.

    Returns:
        True if the file was found and removed, False otherwise.
    """
    before = len(app_state.shared_files)
    logger.info(f"files.remove_file → removing '{filename}' from shared list")
    app_state.shared_files = [
        f for f in app_state.shared_files if f.filename != filename
    ]
    removed = len(app_state.shared_files) < before
    if removed:
        logger.info(f"Removed shared file: {filename}")
    return removed


def scan_shared_directory() -> int:
    """
    Scan the shared directory and add any new files.

    Returns:
        The number of new files added.
    """
    shared_dir = get_shared_dir()
    added = 0
    for entry in os.listdir(shared_dir):
        if entry.startswith('.'):
            continue  # Skip hidden files like .DS_Store
        filepath = os.path.join(shared_dir, entry)
        if os.path.isfile(filepath):
            result = add_file(filepath)
            if result:
                added += 1
    return added


def get_file_by_hash(file_hash: str) -> Optional[SharedFile]:
    """Look up a shared file by its SHA-256 hash."""
    for f in app_state.shared_files:
        if f.sha256_hash == file_hash:
            return f
    return None


def get_file_by_name(filename: str) -> Optional[SharedFile]:
    """Look up a shared file by filename."""
    for f in app_state.shared_files:
        if f.filename == filename:
            return f
    return None


def get_file_list_for_network() -> list[dict]:
    """
    Build the file list payload for FILE_LIST_RESPONSE messages.

    Returns a list of dicts with filename, size, sha256_hash, and
    optionally signature.
    """
    return [
        {
            "filename": f.filename,
            "size": f.size,
            "sha256_hash": f.sha256_hash,
            "owner_id": f.owner_id,
            **({"signature": f.signature} if f.signature else {}),
        }
        for f in app_state.shared_files
    ]


def find_received_file_by_hash(file_hash: str) -> Optional[SharedFile]:
    """Search the received/ directory for a file matching the given hash."""
    received_dir = os.path.join(os.path.dirname(__file__), "..", "..", "received")
    received_dir = os.path.abspath(received_dir)
    if not os.path.isdir(received_dir):
        return None
    for entry in os.listdir(received_dir):
        filepath = os.path.join(received_dir, entry)
        if not os.path.isfile(filepath):
            continue
        h = sha256_hash_file(filepath)
        if h == file_hash:
            return SharedFile(
                filename=entry,
                filepath=filepath,
                size=os.path.getsize(filepath),
                sha256_hash=h,
                owner_id=app_state.peer_id,
                signature=None,
            )
    return None
