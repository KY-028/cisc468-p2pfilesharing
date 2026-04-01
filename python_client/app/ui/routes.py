"""
routes.py — Flask routes for the web UI.

All HTTP endpoints live here. This module handles:
  - Rendering the dashboard page
  - API endpoints for peer, file, and consent actions
  - Status message retrieval

Reading order: Read this THIRD (after state.py → main.py) to see all endpoints.
"""

import time
import uuid
import os
from flask import Blueprint, render_template, request, jsonify, redirect, url_for
from app.core.state import app_state
from app.storage.files import (
    add_file, remove_file, scan_shared_directory, get_shared_dir,
    get_file_list_for_network, get_file_by_hash, get_file_by_name,
)
from app.storage.manifests import get_manifest, get_all_manifests

import logging
logger = logging.getLogger(__name__)

# All UI routes are grouped under this blueprint.
ui_blueprint = Blueprint("ui", __name__)


# ---------------------------------------------------------------------------
# Pages
# ---------------------------------------------------------------------------

@ui_blueprint.route("/")
def index():
    """Redirect root to the dashboard."""
    return redirect(url_for("ui.dashboard"))


@ui_blueprint.route("/dashboard")
def dashboard():
    """
    Main dashboard page.
    Renders the full UI with all panels: identity, peers, files,
    request/send, consent prompts, and status log.
    """
    return render_template("dashboard.html")


# ---------------------------------------------------------------------------
# Peer API
# ---------------------------------------------------------------------------

@ui_blueprint.route("/api/refresh-peers", methods=["POST"])
def refresh_peers():
    """
    Trigger peer discovery refresh.
    Posts a status message; actual discovery runs via mDNS in the background.
    """
    app_state.add_status("Peer discovery refresh triggered.", level="info")
    return jsonify({"ok": True, "message": "Peer refresh triggered"})


# ---------------------------------------------------------------------------
# File API
# ---------------------------------------------------------------------------

@ui_blueprint.route("/api/add-shared-file", methods=["POST"])
def add_shared_file():
    """
    Add a file to the local share list.
    Accepts either a filename (must exist in shared/ dir) or scans the dir.
    """
    filename = request.form.get("filename", "").strip()
    logger.info(f"routes.add_shared_file → user adding '{filename}'")
    if not filename:
        app_state.add_status("No filename provided.", level="error")
        return jsonify({"ok": False, "error": "filename is required"}), 400

    # Look for the file in the shared directory
    shared_dir = get_shared_dir()
    filepath = os.path.join(shared_dir, filename)

    if not os.path.isfile(filepath):
        app_state.add_status(
            f"File '{filename}' not found in shared/ directory. "
            f"Place files in: {shared_dir}",
            level="error"
        )
        return jsonify({"ok": False, "error": f"File not found in {shared_dir}"}), 404

    shared = add_file(filepath)
    if shared:
        app_state.add_status(
            f"Sharing '{filename}' ({shared.size} bytes, hash={shared.sha256_hash[:12]}…)",
            level="success"
        )
        return jsonify({"ok": True, "filename": filename, "hash": shared.sha256_hash})
    else:
        app_state.add_status(f"Failed to add '{filename}'.", level="error")
        return jsonify({"ok": False, "error": "Failed to add file"}), 500


@ui_blueprint.route("/api/scan-shared", methods=["POST"])
def scan_shared():
    """Scan the shared/ directory and add any new files."""
    count = scan_shared_directory()
    app_state.add_status(f"Scanned shared directory: {count} file(s) found.", level="info")
    return jsonify({"ok": True, "files_found": count})


@ui_blueprint.route("/api/remove-shared-file", methods=["POST"])
def remove_shared_file():
    """Remove a file from the share list by filename."""
    filename = request.form.get("filename", "").strip()
    if remove_file(filename):
        app_state.add_status(f"Removed '{filename}' from shared files.", level="info")
        return jsonify({"ok": True})
    else:
        app_state.add_status(f"File '{filename}' not found in shared list.", level="warning")
        return jsonify({"ok": False, "error": "not found"}), 404


# ---------------------------------------------------------------------------
# File Request / Send
# ---------------------------------------------------------------------------

@ui_blueprint.route("/api/request-file", methods=["POST"])
def request_file():
    """Send a FILE_REQUEST to a peer asking for a specific file."""
    from app.core.consent import request_file_from_peer
    peer_id = request.form.get("peer_id", "").strip()
    filename = request.form.get("filename", "").strip()
    logger.info(f"routes.request_file → user requesting '{filename}' from {peer_id}")

    if not peer_id or not filename:
        app_state.add_status("Peer ID and filename are required to request a file.", level="error")
        return jsonify({"ok": False, "error": "peer_id and filename required"}), 400

    record = request_file_from_peer(peer_id, filename)
    if record:
        return jsonify({"ok": True, "peer_id": peer_id, "filename": filename,
                         "transfer_id": record.transfer_id})
    else:
        return jsonify({"ok": False, "error": "Failed to send request"}), 500


@ui_blueprint.route("/api/request-file-list", methods=["POST"])
def request_file_list():
    """Request a file list from a specific peer."""
    from app.core.consent import request_file_list_from_peer
    peer_id = request.form.get("peer_id", "").strip()
    if not peer_id:
        return jsonify({"ok": False, "error": "peer_id required"}), 400
    success = request_file_list_from_peer(peer_id)
    return jsonify({"ok": success})


@ui_blueprint.route("/api/send-file", methods=["POST"])
def send_file():
    """Send a consent request to a peer, offering to send them a file."""
    from app.core.consent import _send_file_to_peer
    peer_id = request.form.get("peer_id", "").strip()
    filename = request.form.get("filename", "").strip()
    logger.info(f"routes.send_file → user sending '{filename}' to {peer_id}")

    if not peer_id or not filename:
        app_state.add_status("Peer ID and filename are required to send a file.", level="error")
        return jsonify({"ok": False, "error": "peer_id and filename required"}), 400

    peer = app_state.peers.get(peer_id)
    if not peer:
        app_state.add_status(f"Unknown peer: {peer_id}", level="error")
        return jsonify({"ok": False, "error": "Unknown peer"}), 404

    shared = get_file_by_name(filename)
    if not shared:
        app_state.add_status(f"File '{filename}' not in shared files.", level="error")
        return jsonify({"ok": False, "error": "File not shared"}), 404

    # Send the file directly
    _send_file_to_peer(peer_id, peer.address, peer.port,
                        shared.filepath, shared.filename, shared.sha256_hash)
    return jsonify({"ok": True, "peer_id": peer_id, "filename": filename})


# ---------------------------------------------------------------------------
# Consent API
# ---------------------------------------------------------------------------

@ui_blueprint.route("/api/consent/<request_id>/<action>", methods=["POST"])
def handle_consent(request_id: str, action: str):
    """
    Accept or deny an incoming consent request.
    action must be 'accept' or 'deny'.
    If accepted and it was a file_request, triggers file send.
    """
    from app.core.consent import on_consent_approved
    logger.info(f"routes.handle_consent → user {action}ing consent {request_id}")
    if action not in ("accept", "deny"):
        return jsonify({"ok": False, "error": "action must be 'accept' or 'deny'"}), 400

    approved = action == "accept"
    consent = app_state.resolve_consent(request_id, approved)

    if consent is None:
        app_state.add_status(f"Consent request '{request_id}' not found.", level="warning")
        return jsonify({"ok": False, "error": "request not found"}), 404

    verb = "Accepted" if approved else "Denied"
    app_state.add_status(
        f"{verb} {consent.action} from '{consent.peer_name}' for '{consent.filename}'.",
        level="success" if approved else "info"
    )

    # If approved and it was a file request, send the file
    if approved:
        on_consent_approved(request_id)

    return jsonify({"ok": True, "action": action, "request_id": request_id})




# ---------------------------------------------------------------------------
# Key Rotation
# ---------------------------------------------------------------------------

@ui_blueprint.route("/api/rotate-key", methods=["POST"])
def rotate_key_route():
    """Rotate the identity key and notify all known peers."""
    from app.core.revocation import rotate_key
    logger.info("routes.rotate_key_route → user triggered key rotation")
    result = rotate_key()
    return jsonify({"ok": True, **result})


# ---------------------------------------------------------------------------
# File Verification
# ---------------------------------------------------------------------------

@ui_blueprint.route("/api/verify-file", methods=["POST"])
def verify_file_route():
    """Verify a file's owner signature (third-party verification)."""
    from app.core.verification import verify_manifest_entry
    peer_id = request.form.get("peer_id", "").strip()
    filename = request.form.get("filename", "").strip()
    logger.info(f"routes.verify_file_route → verifying '{filename}' from {peer_id}'s manifest")

    if not peer_id or not filename:
        return jsonify({"ok": False, "error": "peer_id and filename required"}), 400

    result = verify_manifest_entry(peer_id, filename)
    if result is None:
        return jsonify({"ok": False, "error": "File not found in peer's manifest"}), 404

    return jsonify({"ok": True, **result})


@ui_blueprint.route("/api/verify-peer", methods=["POST"])
def verify_peer_route():
    """
    Step 1 of peer verification: perform STS handshake and return a
    verification code.  The user must compare this code with the peer
    out-of-band (in person, phone, etc.) and then confirm.
    """
    from app.core.sessions import initiate_handshake, get_session_key
    import hashlib

    peer_id = request.form.get("peer_id", "").strip()
    if not peer_id:
        return jsonify({"ok": False, "error": "peer_id required"}), 400

    peer = app_state.peers.get(peer_id)
    if not peer:
        return jsonify({"ok": False, "error": "Unknown peer"}), 404

    if not peer.online:
        return jsonify({"ok": False, "error": "Peer is offline"}), 400

    if peer.trusted:
        return jsonify({"ok": True, "already_verified": True,
                        "message": "Peer is already verified."})

    # Ensure we have a session (handshake) so we have the peer's public key
    session_key = get_session_key(peer_id)
    if not session_key:
        session_key = initiate_handshake(peer_id, peer.address, peer.port)
        if not session_key:
            return jsonify({"ok": False, "error": "Handshake failed. Could not reach peer."}), 500

    # Generate the verification code from both fingerprints.
    # Both peers derive the SAME code because we sort the fingerprints
    # before hashing — order doesn't matter.
    my_fp = app_state.fingerprint or ""
    their_fp = peer.fingerprint or ""
    if not their_fp or their_fp == "unknown":
        return jsonify({"ok": False, "error": "Peer fingerprint not available. Handshake may have failed."}), 500

    combined = "\n".join(sorted([my_fp, their_fp]))
    code_hash = hashlib.sha256(combined.encode()).hexdigest()
    # Format as 6 groups of 5 digits (30 digits total) for easy reading
    code_int = int(code_hash[:24], 16)  # Use first 24 hex chars = 96 bits
    code_digits = str(code_int).zfill(30)[:30]
    verification_code = " ".join(
        code_digits[i:i+5] for i in range(0, 30, 5)
    )

    app_state.add_status(
        f"Verification code generated for {peer_id}. "
        f"Compare this code with the peer to confirm their identity.",
        level="warning"
    )

    return jsonify({
        "ok": True,
        "verification_code": verification_code,
        "my_fingerprint": my_fp,
        "their_fingerprint": their_fp,
        "peer_id": peer_id,
    })


@ui_blueprint.route("/api/confirm-verify", methods=["POST"])
def confirm_verify_route():
    """Step 2: User confirmed the verification code matches.

    Sends a VERIFY_CONFIRM to the peer and records local confirmation.
    The peer is only marked trusted once BOTH sides have confirmed.
    """
    import socket as _socket
    from app.network.messages import verify_confirm
    from app.network.transport import send_message as _send

    peer_id = request.form.get("peer_id", "").strip()
    if not peer_id:
        return jsonify({"ok": False, "error": "peer_id required"}), 400

    peer = app_state.peers.get(peer_id)
    if not peer:
        return jsonify({"ok": False, "error": "Unknown peer"}), 404

    # Record that *we* confirmed
    app_state.verify_confirmed_by_me.add(peer_id)
    app_state.pending_verifications = [pv for pv in app_state.pending_verifications if pv["peer_id"] != peer_id]

    # Notify the peer that we confirmed
    try:
        with _socket.create_connection((peer.address, peer.port), timeout=10) as sock:
            msg = verify_confirm(app_state.peer_id)
            _send(sock, msg)
    except Exception as e:
        logger.error(f"Failed to send VERIFY_CONFIRM to {peer_id}: {e}")

    # Check if the other side already confirmed too
    if peer_id in app_state.verify_confirmed_by_peer:
        peer.trusted = True
        app_state.verify_confirmed_by_me.discard(peer_id)
        app_state.verify_confirmed_by_peer.discard(peer_id)
        app_state.add_status(
            f"✓ Peer {peer_id} is now VERIFIED. Both sides confirmed.",
            level="success"
        )
        return jsonify({"ok": True, "verified": True})

    app_state.add_status(
        f"You confirmed verification for {peer_id}. Waiting for them to confirm…",
        level="info"
    )
    return jsonify({"ok": True, "verified": False, "waiting": True})


@ui_blueprint.route("/api/reject-verify", methods=["POST"])
def reject_verify_route():
    """User rejected the verification — codes didn't match. Possible MITM."""
    import socket as _socket
    from app.core.sessions import remove_session
    from app.network.messages import verify_reject
    from app.network.transport import send_message as _send

    peer_id = request.form.get("peer_id", "").strip()
    if not peer_id:
        return jsonify({"ok": False, "error": "peer_id required"}), 400

    peer = app_state.peers.get(peer_id)
    if peer:
        peer.trusted = False

    app_state.pending_verifications = [pv for pv in app_state.pending_verifications if pv["peer_id"] != peer_id]
    app_state.verify_confirmed_by_me.discard(peer_id)
    app_state.verify_confirmed_by_peer.discard(peer_id)

    # Notify the peer that we rejected, so they leave the "waiting" state
    if peer and peer.online:
        try:
            with _socket.create_connection((peer.address, peer.port), timeout=10) as sock:
                msg = verify_reject(app_state.peer_id)
                _send(sock, msg)
        except Exception as e:
            logger.error(f"Failed to send VERIFY_REJECT to {peer_id}: {e}")

    # Destroy the session — it may be compromised
    remove_session(peer_id)

    app_state.add_status(
        f"⚠ Verification REJECTED for {peer_id}. "
        f"Codes did not match — possible man-in-the-middle attack! "
        f"Session destroyed.",
        level="error"
    )
    return jsonify({"ok": True, "rejected": True})


# ---------------------------------------------------------------------------
# Status API
# ---------------------------------------------------------------------------

@ui_blueprint.route("/api/status")
def get_status():
    """
    Return the current status log, peers, files, consents, and transfers.
    The frontend polls this to update the UI.
    """
    return jsonify({
        "peer_id": app_state.peer_id,
        "fingerprint": app_state.fingerprint or "(not generated yet)",
        "peers": [
            {
                "peer_id": p.peer_id,
                "display_name": p.display_name,
                "address": p.address,
                "port": p.port,
                "trusted": p.trusted,
                "online": p.online,
                "fingerprint": p.fingerprint or "unknown",
                "last_seen": p.last_seen,
                "verify_pending": p.peer_id in app_state.verify_confirmed_by_me,
            }
            for p in app_state.peers.values()
        ],
        "shared_files": [
            {
                "filename": f.filename,
                "size": f.size,
                "sha256_hash": f.sha256_hash,
                "owner_id": f.owner_id,
            }
            for f in app_state.shared_files
        ],
        "peer_files": {
            peer_id: [
                {
                    "filename": e.filename,
                    "size": e.size,
                    "sha256_hash": e.sha256_hash,
                    "owner_id": e.owner_id,
                }
                for e in manifest.files
            ]
            for peer_id, manifest in get_all_manifests().items()
        },
        "transfers": [
            {
                "transfer_id": t.transfer_id,
                "filename": t.filename,
                "peer_id": t.peer_id,
                "direction": t.direction,
                "status": t.status,
                "error": t.error,
                "timestamp": t.timestamp,
            }
            for t in app_state.transfers
        ],
        "pending_consents": [
            {
                "request_id": c.request_id,
                "peer_id": c.peer_id,
                "peer_name": c.peer_name,
                "action": c.action,
                "filename": c.filename,
                "timestamp": c.timestamp,
            }
            for c in app_state.pending_consents
        ],
        "status_log": [
            {
                "message": s.message,
                "level": s.level,
                "timestamp": s.timestamp,
            }
            for s in reversed(app_state.status_log)
        ],
        "pending_verifications": app_state.pending_verifications,
    })
