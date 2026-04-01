"""
consent.py — Consent-based file transfer logic.

This module manages the consent workflow:
  1. Peer A requests a file from Peer B (FILE_REQUEST)
  2. Peer B shows a consent prompt to the user
  3. User accepts or denies
  4. If accepted, Peer B sends the file (FILE_SEND)
  5. File is received, hash-verified, and saved

Also handles push offers (CONSENT_REQUEST) where a peer offers
to send you a file and you must approve first.

Reading order: Read files.py and transport.py first, then this file.
"""

import os
import uuid
import time
import logging
import socket
from typing import Optional
from app.core.state import app_state, TransferRecord, ConsentRequest
from app.core.protocol import MessageType, decode_bytes
from app.network.messages import (
    file_request, file_send, consent_request, consent_response,
    file_list_request, file_list_response, error_message,
)
from app.network.transport import send_message, receive_message
from app.storage.files import get_file_by_hash, get_file_by_name, get_file_list_for_network
from app.storage.manifests import store_manifest, verify_file_hash
from app.crypto.hashing import sha256_hash

logger = logging.getLogger(__name__)

# Directory where received files are saved
RECEIVED_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "received")


def get_received_dir() -> str:
    """Get (and create if needed) the received files directory."""
    os.makedirs(RECEIVED_DIR, exist_ok=True)
    return os.path.abspath(RECEIVED_DIR)


# ---------------------------------------------------------------------------
# Outgoing requests: we initiate
# ---------------------------------------------------------------------------

def request_file_from_peer(peer_id: str, filename: str, file_hash: str = "") -> Optional[TransferRecord]:
    """
    Send a FILE_REQUEST to a peer asking for a specific file.

    Creates a transfer record to track the request status.

    Args:
        peer_id: The peer to request from.
        filename: The filename to request.
        file_hash: Optional SHA-256 hash for verification.

    Returns:
        The TransferRecord, or None if the peer isn't known.
    """
    logger.info(f"consent.request_file_from_peer → requesting '{filename}' from {peer_id}")
    peer = app_state.peers.get(peer_id)
    if not peer:
        app_state.add_status(f"Unknown peer: {peer_id}", level="error")
        return None

    transfer_id = uuid.uuid4().hex[:12]
    record = TransferRecord(
        transfer_id=transfer_id,
        filename=filename,
        peer_id=peer_id,
        direction="incoming",
        status="pending",
        timestamp=time.time(),
    )
    app_state.transfers.append(record)

    # Send the FILE_REQUEST message
    try:
        msg = file_request(app_state.peer_id, filename, file_hash or "0" * 64)
        with socket.create_connection((peer.address, peer.port), timeout=10) as sock:
            send_message(sock, msg)
        app_state.add_status(f"Requested '{filename}' from {peer_id}", level="info")
    except Exception as e:
        record.status = "failed"
        record.error = str(e)
        app_state.add_status(f"Failed to request '{filename}': {e}", level="error")

    return record


def request_file_list_from_peer(peer_id: str) -> bool:
    """
    Send a FILE_LIST_REQUEST to a peer.

    Args:
        peer_id: The peer to query.

    Returns:
        True if the request was sent successfully.
    """
    logger.info(f"consent.request_file_list_from_peer → querying {peer_id}")
    peer = app_state.peers.get(peer_id)
    if not peer:
        app_state.add_status(f"Unknown peer: {peer_id}", level="error")
        return False

    try:
        msg = file_list_request(app_state.peer_id)
        with socket.create_connection((peer.address, peer.port), timeout=10) as sock:
            send_message(sock, msg)
            from app.network.transport import receive_message
            response = receive_message(sock)
            if response:
                from app.main import _handle_incoming_message
                _handle_incoming_message(response, sock, (peer.address, peer.port))
        app_state.add_status(f"Requested file list from {peer_id}", level="info")
        return True
    except Exception as e:
        app_state.add_status(f"Failed to request file list from {peer_id}: {e}", level="error")
        return False


# ---------------------------------------------------------------------------
# Incoming message handlers
# ---------------------------------------------------------------------------

def handle_file_list_request(msg: dict, sock, addr) -> None:
    """
    Handle an incoming FILE_LIST_REQUEST: respond with our file list.
    """
    peer_id = msg["payload"]["peer_id"]
    logger.info(f"consent.handle_file_list_request ← from {peer_id}, sending our file list")
    files = get_file_list_for_network()
    response = file_list_response(app_state.peer_id, files)
    try:
        send_message(sock, response)
        app_state.add_status(f"Sent file list ({len(files)} files) to {peer_id}", level="info")
    except Exception as e:
        logger.error(f"Failed to send file list: {e}")


def handle_file_list_response(msg: dict, sock, addr) -> None:
    """
    Handle an incoming FILE_LIST_RESPONSE: store the peer's manifest.
    """
    peer_id = msg["payload"]["peer_id"]
    files = msg["payload"].get("files", [])
    logger.info(f"consent.handle_file_list_response ← from {peer_id}, got {len(files)} files")
    store_manifest(peer_id, files)
    app_state.add_status(f"Received file list from {peer_id}: {len(files)} files", level="success")


def handle_file_request(msg: dict, sock, addr) -> None:
    """
    Handle an incoming FILE_REQUEST: create a consent prompt for the user.
    """
    payload = msg["payload"]
    peer_id = payload["peer_id"]
    filename = payload["filename"]
    file_hash = payload.get("file_hash", "")
    logger.info(f"consent.handle_file_request ← {peer_id} wants '{filename}', creating consent prompt")

    # Check if we have the file
    shared = get_file_by_name(filename) or get_file_by_hash(file_hash)
    if not shared:
        # Send error back
        err = error_message(app_state.peer_id, "FILE_NOT_FOUND",
                            f"File '{filename}' not found in shared files")
        try:
            send_message(sock, err)
        except Exception:
            pass
        app_state.add_status(f"Peer {peer_id} requested unknown file: {filename}", level="warning")
        return

    # Create a consent request for the user to approve
    peer_name = peer_id
    peer_info = app_state.peers.get(peer_id)
    if peer_info:
        peer_name = peer_info.display_name

    request_id = app_state.add_consent_request(
        peer_id=peer_id,
        peer_name=peer_name,
        action="file_request",
        filename=shared.filename,
        file_hash=shared.sha256_hash,
    )

    # Store the socket connection info so we can send the file later
    # We'll need the address for when the user approves
    app_state._pending_sends = getattr(app_state, '_pending_sends', {})
    app_state._pending_sends[request_id] = {
        "peer_id": peer_id,
        "address": addr[0],
        "port": app_state.peers[peer_id].port if peer_id in app_state.peers else addr[1],
        "filename": shared.filename,
        "file_hash": shared.sha256_hash,
        "filepath": shared.filepath,
    }

    app_state.add_status(
        f"Peer {peer_name} wants '{filename}' — awaiting your consent",
        level="warning"
    )


def handle_file_send(msg: dict, sock, addr) -> None:
    """
    Handle an incoming FILE_SEND: decrypt, verify, and save the file.

    Steps:
      1. Look up the session key for the sending peer
      2. Decrypt the file data (AES-256-GCM with filename:hash as AAD)
      3. Verify the SHA-256 hash of the decrypted data
      4. Save to the received/ directory
    """
    payload = msg["payload"]
    peer_id = payload["peer_id"]
    filename = payload["filename"]
    file_hash = payload.get("file_hash", "")
    encrypted_data = payload.get("data", b"")
    logger.info(f"consent.handle_file_send ← receiving '{filename}' from {peer_id}, decrypting…")

    # Decrypt using the session key
    from app.core.sessions import get_session_key
    from app.crypto.encrypt import decrypt_file_payload

    session_key = get_session_key(peer_id)
    if not session_key:
        app_state.add_status(
            f"Rejected '{filename}' from {peer_id}: no active session. "
            f"Handshake required before file transfer.",
            level="error"
        )
        return

    try:
        file_data = decrypt_file_payload(
            session_key, encrypted_data, filename, file_hash
        )
    except Exception as e:
        app_state.add_status(
            f"Decryption FAILED for '{filename}' from {peer_id}: {e}. "
            f"File may have been tampered with!",
            level="error"
        )
        return

    # Verify the hash of the decrypted plaintext
    actual_hash = sha256_hash(file_data)
    if file_hash and actual_hash != file_hash:
        app_state.add_status(
            f"Hash mismatch for '{filename}' from {peer_id}! File rejected.",
            level="error"
        )
        return

    # Save to received directory
    received_dir = get_received_dir()
    save_path = os.path.join(received_dir, filename)

    # Handle filename collision
    if os.path.exists(save_path):
        name, ext = os.path.splitext(filename)
        save_path = os.path.join(received_dir, f"{name}_{uuid.uuid4().hex[:6]}{ext}")

    with open(save_path, "wb") as f:
        f.write(file_data)

    app_state.add_status(
        f"Received '{filename}' ({len(file_data)} bytes) from {peer_id}. "
        f"Decrypted ✓ Hash verified ✓. Saved to received/",
        level="success"
    )

    # Update any matching transfer records
    for t in app_state.transfers:
        if t.filename == filename and t.peer_id == peer_id and t.status == "pending":
            t.status = "complete"
            break


def handle_consent_request(msg: dict, sock, addr) -> None:
    """
    Handle an incoming CONSENT_REQUEST (push offer from a peer).
    """
    payload = msg["payload"]
    peer_id = payload["peer_id"]
    filename = payload["filename"]
    action = payload["action"]
    logger.info(f"consent.handle_consent_request ← {peer_id} wants to {action} '{filename}'")

    peer_name = peer_id
    peer_info = app_state.peers.get(peer_id)
    if peer_info:
        peer_name = peer_info.display_name

    app_state.add_consent_request(
        peer_id=peer_id,
        peer_name=peer_name,
        action=action,
        filename=filename,
    )
    app_state.add_status(
        f"Peer {peer_name} wants to {action.replace('_', ' ')} '{filename}'",
        level="warning"
    )


def handle_consent_response(msg: dict, sock, addr) -> None:
    """
    Handle an incoming CONSENT_RESPONSE (peer approved/denied our request).
    """
    payload = msg["payload"]
    peer_id = payload["peer_id"]
    approved = payload["approved"]
    request_id = payload.get("request_id", "")
    logger.info(f"consent.handle_consent_response ← {peer_id} {'approved' if approved else 'denied'} request")

    if approved:
        app_state.add_status(f"Peer {peer_id} approved the request", level="success")
    else:
        app_state.add_status(f"Peer {peer_id} denied the request", level="warning")
        # Mark any pending transfers as denied
        for t in app_state.transfers:
            if t.peer_id == peer_id and t.status == "pending":
                t.status = "denied"


# ---------------------------------------------------------------------------
# Consent resolution (called when user clicks accept/deny in UI)
# ---------------------------------------------------------------------------

def on_consent_approved(request_id: str) -> None:
    """
    Called when the user approves a consent request.
    If it's a file_request, send the file to the peer.
    """
    logger.info(f"consent.on_consent_approved → user approved request {request_id}")
    pending_sends = getattr(app_state, '_pending_sends', {})
    send_info = pending_sends.pop(request_id, None)

    if send_info:
        # User approved sending a file
        _send_file_to_peer(
            peer_id=send_info["peer_id"],
            address=send_info["address"],
            port=send_info["port"],
            filepath=send_info["filepath"],
            filename=send_info["filename"],
            file_hash=send_info["file_hash"],
        )


def _send_file_to_peer(peer_id: str, address: str, port: int,
                        filepath: str, filename: str, file_hash: str) -> None:
    """
    Encrypt and send a file to a peer over TCP.

    Steps:
      1. Ensure an STS session exists (handshake if needed)
      2. Read the file data
      3. Encrypt with AES-256-GCM using the session key
      4. Send the encrypted blob via FILE_SEND
    """
    from app.core.sessions import get_session_key, initiate_handshake
    from app.crypto.encrypt import encrypt_file_payload

    logger.info(f"consent._send_file_to_peer → sending '{filename}' to {peer_id} at {address}:{port}")
    try:
        # Step 1: Ensure we have a session key (PFS via ephemeral ECDH)
        session_key = get_session_key(peer_id)
        if not session_key:
            app_state.add_status(
                f"No active session with {peer_id}. Initiating handshake…",
                level="info"
            )
            session_key = initiate_handshake(peer_id, address, port)
            if not session_key:
                app_state.add_status(
                    f"Cannot send '{filename}': handshake with {peer_id} failed.",
                    level="error"
                )
                return

        # Step 2: Read file
        with open(filepath, "rb") as f:
            file_data = f.read()

        # Step 3: Encrypt (AES-256-GCM, AAD = "filename:hash")
        encrypted_data = encrypt_file_payload(
            session_key, file_data, filename, file_hash
        )

        # Step 4: Send the encrypted blob
        msg = file_send(
            app_state.peer_id, filename, file_hash, data=encrypted_data
        )
        with socket.create_connection((address, port), timeout=30) as sock:
            send_message(sock, msg)

        app_state.add_status(
            f"Sent '{filename}' ({len(file_data)} bytes, encrypted) to {peer_id} ✓",
            level="success"
        )
    except Exception as e:
        app_state.add_status(
            f"Failed to send '{filename}' to {peer_id}: {e}",
            level="error"
        )
