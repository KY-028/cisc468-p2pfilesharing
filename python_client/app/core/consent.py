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
from app.storage.files import get_file_by_hash, get_file_by_name, get_file_list_for_network, find_received_file_by_hash
from app.storage.manifests import store_manifest, verify_file_hash, get_manifest, get_all_manifests
from app.crypto.hashing import sha256_hash

logger = logging.getLogger(__name__)

# Directory where received files are saved
RECEIVED_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "received")


def get_received_dir() -> str:
    """Get (and create if needed) the received files directory."""
    os.makedirs(RECEIVED_DIR, exist_ok=True)
    return os.path.abspath(RECEIVED_DIR)


def _verify_owner_signature(filename: str, file_hash: str, sender_id: str) -> None:
    """Check the file's owner signature from cached manifests and log the result."""
    from app.storage.manifests import verify_file_signature

    # Search all manifests for an entry matching this file hash
    for owner_id, manifest in get_all_manifests().items():
        for entry in manifest.files:
            if entry.sha256_hash != file_hash:
                continue
            if not entry.signature:
                app_state.add_status(
                    f"File '{filename}' owner ({owner_id}) did not sign this file. "
                    f"Cannot verify original owner authenticity.",
                    level="warning"
                )
                return
            # We need the owner's public key
            owner_peer = app_state.peers.get(owner_id)
            if not owner_peer or not owner_peer.public_key_pem:
                app_state.add_status(
                    f"File '{filename}' is owned by {owner_id} but their public key "
                    f"is not available. Owner signature cannot be verified.",
                    level="warning"
                )
                return
            ok = verify_file_signature(
                file_hash, entry.signature, owner_peer.public_key_pem
            )
            if ok:
                owner_name = owner_peer.display_name if owner_peer else owner_id
                app_state.add_status(
                    f"Owner signature verified ✓ — '{filename}' authenticity "
                    f"confirmed from original owner {owner_name}"
                    + (f" (served by {sender_id})" if sender_id != owner_id else ""),
                    level="success"
                )
            else:
                app_state.add_status(
                    f"Owner signature INVALID for '{filename}'! "
                    f"File may have been tampered with!",
                    level="error"
                )
            return


# ---------------------------------------------------------------------------
# Outgoing requests: we initiate
# ---------------------------------------------------------------------------

def request_file_from_peer(peer_id: str, filename: str, file_hash: str = "") -> Optional[TransferRecord]:
    """
    Send a FILE_REQUEST to a peer asking for a specific file.

    If the peer is offline, looks up the file hash from cached manifests
    and broadcasts the request to all online trusted peers that may have it.

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

    # If the peer is online, try a direct request
    if peer.online:
        try:
            msg = file_request(app_state.peer_id, filename, file_hash or "0" * 64)
            with socket.create_connection((peer.address, peer.port), timeout=10) as sock:
                send_message(sock, msg)
            app_state.add_status(f"Requested '{filename}' from {peer_id}", level="info")
            return record
        except Exception as e:
            logger.warning(f"Direct request to {peer_id} failed: {e}")
            app_state.add_status(
                f"Direct request to {peer_id} failed, searching other peers…",
                level="warning"
            )
            # Fall through to broadcast

    # Peer is offline (or direct request failed) — broadcast to other peers
    # First, resolve the file hash from the cached manifest if we don't have it
    if not file_hash:
        manifest = get_manifest(peer_id)
        if manifest:
            for entry in manifest.files:
                if entry.filename == filename:
                    file_hash = entry.sha256_hash
                    break

    if not file_hash:
        record.status = "failed"
        record.error = "Peer is offline and file hash is unknown"
        app_state.add_status(
            f"Cannot request '{filename}': {peer_id} is offline and no cached file hash available.",
            level="error"
        )
        return record

    app_state.add_status(
        f"Peer {peer_id} is offline. Broadcasting search for '{filename}' "
        f"(hash {file_hash[:12]}…) to all online peers…",
        level="info"
    )

    # Search all online trusted peers
    sent_to = []
    for other_id, other_peer in app_state.peers.items():
        if other_id == peer_id or other_id == app_state.peer_id:
            continue
        if not other_peer.online or not other_peer.trusted:
            continue
        try:
            msg = file_request(app_state.peer_id, filename, file_hash)
            with socket.create_connection(
                (other_peer.address, other_peer.port), timeout=10
            ) as sock:
                send_message(sock, msg)
            sent_to.append(other_peer.display_name or other_id)
            logger.info(f"Broadcast FILE_REQUEST to {other_id} for hash {file_hash[:12]}")
        except Exception as e:
            logger.warning(f"Failed to broadcast FILE_REQUEST to {other_id}: {e}")

    if sent_to:
        app_state.add_status(
            f"File request broadcast to {len(sent_to)} online peer(s): "
            f"{', '.join(sent_to)}. Waiting for responses…",
            level="info"
        )
    else:
        record.status = "failed"
        record.error = "No online trusted peers available"
        app_state.add_status(
            f"Cannot retrieve '{filename}': {peer_id} is offline and "
            f"no other trusted peers are online to serve it.",
            level="error"
        )

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


def send_consent_offer(peer_id: str, filename: str, file_hash: str) -> bool:
    """
    Send a CONSENT_REQUEST to the receiving peer, asking them to approve
    before we send the file. The file is only sent after they reply with
    CONSENT_RESPONSE(approved=True).
    """
    logger.info(f"consent.send_consent_offer → asking {peer_id} to accept '{filename}'")
    peer = app_state.peers.get(peer_id)
    if not peer:
        app_state.add_status(f"Unknown peer: {peer_id}", level="error")
        return False

    try:
        msg = consent_request(app_state.peer_id, "file_send", filename, file_hash)
        with socket.create_connection((peer.address, peer.port), timeout=10) as sock:
            send_message(sock, msg)

        # Store pending send info so we can send the file when they approve
        from app.storage.files import get_file_by_name
        shared = get_file_by_name(filename)
        if shared:
            pending = getattr(app_state, '_pending_outgoing', {})
            app_state._pending_outgoing = pending
            key = f"{peer_id}:{filename}"
            pending[key] = {
                "peer_id": peer_id,
                "address": peer.address,
                "port": peer.port,
                "filename": shared.filename,
                "file_hash": shared.sha256_hash,
                "filepath": shared.filepath,
            }

        app_state.add_status(
            f"Consent request sent to {peer_id} for '{filename}'. Waiting for approval…",
            level="info"
        )
        return True
    except Exception as e:
        app_state.add_status(
            f"Failed to send consent request to {peer_id}: {e}",
            level="error"
        )
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

    # Check if we have the file (shared files first, then received files)
    shared = get_file_by_name(filename) or get_file_by_hash(file_hash)
    if not shared and file_hash:
        shared = find_received_file_by_hash(file_hash)
        if shared:
            logger.info(f"File '{filename}' found in received/ directory (hash match)")
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
    Handle an incoming FILE_SEND: decrypt, verify, and either save
    immediately (if user already consented) or prompt for consent.

    Steps:
      1. Look up the session key for the sending peer
      2. Decrypt the file data (AES-256-GCM with filename:hash as AAD)
      3. Verify the SHA-256 hash of the decrypted data
      4. If prior consent exists (we requested the file or approved a
         consent offer), save immediately. Otherwise, create a consent
         prompt and buffer the data until approved.
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

    # Check if user already consented (they requested the file, or approved
    # a consent offer from this peer)
    has_consent = _check_prior_consent(peer_id, filename)

    if has_consent:
        _save_received_file(peer_id, filename, file_data, actual_hash)
    else:
        # Buffer the decrypted data and prompt the user
        peer_name = peer_id
        peer_info = app_state.peers.get(peer_id)
        if peer_info:
            peer_name = peer_info.display_name

        request_id = app_state.add_consent_request(
            peer_id=peer_id,
            peer_name=peer_name,
            action="file_send",
            filename=filename,
            file_hash=file_hash,
        )

        # Buffer the decrypted file data for later saving
        pending_receives = getattr(app_state, '_pending_receives', {})
        app_state._pending_receives = pending_receives
        pending_receives[request_id] = {
            "peer_id": peer_id,
            "filename": filename,
            "file_data": file_data,
            "file_hash": actual_hash,
        }

        app_state.add_status(
            f"Peer {peer_name} is sending '{filename}' ({len(file_data)} bytes) "
            f"— awaiting your consent to save",
            level="warning"
        )


def _check_prior_consent(peer_id: str, filename: str) -> bool:
    """Check if the user already consented to receive this file."""
    # Check 1: We have a pending transfer record (we requested the file)
    for t in app_state.transfers:
        if t.filename == filename and t.status == "pending":
            return True

    # Check 2: We recently approved a consent offer from this peer
    approved = getattr(app_state, '_approved_receives', set())
    key = f"{peer_id}:{filename}"
    if key in approved:
        approved.discard(key)
        return True

    return False


def _save_received_file(peer_id: str, filename: str, file_data: bytes,
                         actual_hash: str) -> None:
    """Save a decrypted and verified file to the received/ directory."""
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

    # Cross-peer verification: if the file was originally owned by someone
    # else, verify the owner's signature from the cached manifest.
    _verify_owner_signature(filename, actual_hash, peer_id)

    # Update any matching transfer records.
    # Match by filename and hash — the file may arrive from a different peer
    # than originally requested (broadcast fallback).
    matched = False
    for t in app_state.transfers:
        if t.filename == filename and t.status == "pending":
            t.status = "complete"
            if t.peer_id != peer_id:
                app_state.add_status(
                    f"File '{filename}' originally requested from {t.peer_id} "
                    f"was served by {peer_id} (cross-peer retrieval) ✓",
                    level="success"
                )
            matched = True
            break
    if not matched:
        # Still mark any same-filename transfer as complete
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

    If approved and we have a pending outgoing file send, send the file now.
    """
    payload = msg["payload"]
    peer_id = payload["peer_id"]
    approved = payload["approved"]
    request_id = payload.get("request_id", "")
    filename = payload.get("filename", "")
    logger.info(f"consent.handle_consent_response ← {peer_id} {'approved' if approved else 'denied'} request")

    if approved:
        app_state.add_status(f"Peer {peer_id} approved the request", level="success")

        # Check if we have a pending outgoing file for this peer
        pending = getattr(app_state, '_pending_outgoing', {})
        # Try to match by peer_id:filename
        send_info = None
        for key in list(pending.keys()):
            if key.startswith(f"{peer_id}:"):
                if not filename or key == f"{peer_id}:{filename}":
                    send_info = pending.pop(key)
                    break

        if send_info:
            logger.info(f"Peer {peer_id} approved — sending '{send_info['filename']}' now")
            _send_file_to_peer(
                peer_id=send_info["peer_id"],
                address=send_info["address"],
                port=send_info["port"],
                filepath=send_info["filepath"],
                filename=send_info["filename"],
                file_hash=send_info["file_hash"],
            )
    else:
        app_state.add_status(f"Peer {peer_id} denied the request", level="warning")
        # Clean up pending outgoing
        pending = getattr(app_state, '_pending_outgoing', {})
        for key in list(pending.keys()):
            if key.startswith(f"{peer_id}:"):
                if not filename or key == f"{peer_id}:{filename}":
                    pending.pop(key)
                    break
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
    - If it's a file_request: send the file to the peer.
    - If it's a file_send (push offer): send CONSENT_RESPONSE(approved)
      back to the sender so they proceed.
    - If it's a buffered receive: save the already-decrypted file.
    """
    logger.info(f"consent.on_consent_approved → user approved request {request_id}")

    # Case 1: We have buffered file data to save (FILE_SEND arrived before consent)
    pending_receives = getattr(app_state, '_pending_receives', {})
    recv_info = pending_receives.pop(request_id, None)
    if recv_info:
        _save_received_file(
            peer_id=recv_info["peer_id"],
            filename=recv_info["filename"],
            file_data=recv_info["file_data"],
            actual_hash=recv_info["file_hash"],
        )
        return

    # Case 2: Someone requested our file — send it
    pending_sends = getattr(app_state, '_pending_sends', {})
    send_info = pending_sends.pop(request_id, None)
    if send_info:
        _send_file_to_peer(
            peer_id=send_info["peer_id"],
            address=send_info["address"],
            port=send_info["port"],
            filepath=send_info["filepath"],
            filename=send_info["filename"],
            file_hash=send_info["file_hash"],
        )
        return

    # Case 3: Consent offer from a peer who wants to send us a file.
    # Send CONSENT_RESPONSE(approved) back so they proceed with FILE_SEND.
    # Find the resolved consent to get the peer_id and filename.
    # The consent was already resolved in routes.py, so we look it up
    # by request_id from recently resolved consents.
    consent_info = getattr(app_state, '_resolved_consents', {}).pop(request_id, None)
    if consent_info:
        peer_id = consent_info["peer_id"]
        filename = consent_info["filename"]
        peer = app_state.peers.get(peer_id)
        if peer and peer.online:
            # Mark that we approved receiving from this peer
            approved_set = getattr(app_state, '_approved_receives', set())
            app_state._approved_receives = approved_set
            approved_set.add(f"{peer_id}:{filename}")

            try:
                resp = consent_response(app_state.peer_id, request_id, True)
                # Include filename so sender can match it
                resp["payload"]["filename"] = filename
                with socket.create_connection((peer.address, peer.port), timeout=10) as sock:
                    send_message(sock, resp)
                app_state.add_status(
                    f"Approved receiving '{filename}' from {peer_id}. Waiting for file…",
                    level="info"
                )
            except Exception as e:
                app_state.add_status(
                    f"Failed to send approval to {peer_id}: {e}",
                    level="error"
                )


def on_consent_denied(request_id: str) -> None:
    """
    Called when the user denies a consent request.
    Cleans up buffered data and sends denial back to the peer if needed.
    """
    logger.info(f"consent.on_consent_denied → user denied request {request_id}")

    # Clean up buffered file data
    pending_receives = getattr(app_state, '_pending_receives', {})
    pending_receives.pop(request_id, None)

    # Clean up pending sends
    pending_sends = getattr(app_state, '_pending_sends', {})
    pending_sends.pop(request_id, None)

    # Send CONSENT_RESPONSE(denied) back to peer if this was a consent offer
    consent_info = getattr(app_state, '_resolved_consents', {}).pop(request_id, None)
    if consent_info:
        peer_id = consent_info["peer_id"]
        filename = consent_info["filename"]
        peer = app_state.peers.get(peer_id)
        if peer and peer.online:
            try:
                resp = consent_response(app_state.peer_id, request_id, False)
                resp["payload"]["filename"] = filename
                with socket.create_connection((peer.address, peer.port), timeout=10) as sock:
                    send_message(sock, resp)
            except Exception as e:
                logger.warning(f"Failed to send denial to {peer_id}: {e}")


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
