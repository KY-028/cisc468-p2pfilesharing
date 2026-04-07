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
import io
from flask import (
    Blueprint, render_template, request, jsonify,
    redirect, url_for, send_file as flask_send_file,
)
from app.core.state import app_state
from app.storage.files import (
    add_file, remove_file, scan_shared_directory, get_shared_dir,
    get_file_list_for_network, get_file_by_hash, get_file_by_name,
)
from app.storage.manifests import get_manifest, get_all_manifests
from app.core.verification import generate_verification_code
from app.storage.vault import (
    is_vault_initialized, initialize_vault, unlock_vault,
    get_vault_key, vault_list_files, vault_retrieve_file, change_vault_password,
)

import logging
logger = logging.getLogger(__name__)

# All UI routes are grouped under this blueprint.
ui_blueprint = Blueprint("ui", __name__)



# Before-request guard: redirect to vault setup/unlock if key not loaded


_VAULT_EXEMPT_ENDPOINTS = frozenset({
    "ui.setup_page", "ui.unlock_page",
    "ui.vault_setup", "ui.vault_unlock",
    "static",
})


@ui_blueprint.before_request
def require_vault_unlocked():
    """Ensure the vault is unlocked before accessing any protected page."""
    if request.endpoint in _VAULT_EXEMPT_ENDPOINTS:
        return  # allow through
    if get_vault_key() is not None:
        return  # vault already unlocked
    if is_vault_initialized():
        return redirect(url_for("ui.unlock_page"))
    return redirect(url_for("ui.setup_page"))



# Vault setup / unlock pages


@ui_blueprint.route("/setup")
def setup_page():
    """First-launch: create a vault password."""
    if get_vault_key() is not None:
        return redirect(url_for("ui.dashboard"))
    if is_vault_initialized():
        return redirect(url_for("ui.unlock_page"))
    return render_template("vault_setup.html", is_unlock=False, error=None)


@ui_blueprint.route("/unlock")
def unlock_page():
    """Subsequent launches: unlock with existing password."""
    if get_vault_key() is not None:
        return redirect(url_for("ui.dashboard"))
    if not is_vault_initialized():
        return redirect(url_for("ui.setup_page"))
    return render_template("vault_setup.html", is_unlock=True, error=None)


@ui_blueprint.route("/api/vault/setup", methods=["POST"])
def vault_setup():
    """Handle first-time vault password creation."""
    password = request.form.get("password", "")
    confirm = request.form.get("confirm_password", "")

    if len(password) < 8:
        return render_template(
            "vault_setup.html", is_unlock=False,
            error="Password must be at least 8 characters.",
        )
    if password != confirm:
        return render_template(
            "vault_setup.html", is_unlock=False,
            error="Passwords do not match.",
        )

    initialize_vault(password)
    app_state.vault_unlocked = True
    app_state.add_status("Vault created and unlocked.", level="success")
    return redirect(url_for("ui.dashboard"))


@ui_blueprint.route("/api/vault/unlock", methods=["POST"])
def vault_unlock():
    """Handle vault unlock on subsequent launches."""
    from cryptography.exceptions import InvalidTag
    password = request.form.get("password", "")
    if not password:
        return render_template(
            "vault_setup.html", is_unlock=True,
            error="Please enter your vault password.",
        )
    try:
        unlock_vault(password)
    except (InvalidTag, Exception) as exc:
        logger.warning(f"Vault unlock failed: {exc}")
        return render_template(
            "vault_setup.html", is_unlock=True,
            error="Incorrect password or corrupted vault config.",
        )
    app_state.vault_unlocked = True
    app_state.add_status("Vault unlocked.", level="success")
    return redirect(url_for("ui.dashboard"))


@ui_blueprint.route("/api/vault/change-password", methods=["POST"])
def vault_change_password():
    """Change vault password and re-encrypt vault files with a new key."""
    from cryptography.exceptions import InvalidTag

    old_password = request.form.get("old_password", "")
    new_password = request.form.get("new_password", "")
    confirm_password = request.form.get("confirm_password", "")

    if not old_password or not new_password or not confirm_password:
        return jsonify({"ok": False, "error": "All password fields are required."}), 400

    if len(new_password) < 8:
        return jsonify({"ok": False, "error": "New password must be at least 8 characters."}), 400

    if new_password != confirm_password:
        return jsonify({"ok": False, "error": "New passwords do not match."}), 400

    if old_password == new_password:
        return jsonify({"ok": False, "error": "New password must be different from the current password."}), 400

    try:
        skipped_files = change_vault_password(old_password, new_password)
    except InvalidTag:
        app_state.add_status("Vault key change failed: incorrect current password.", level="error")
        return jsonify({"ok": False, "error": "Current password is incorrect."}), 403
    except FileNotFoundError:
        app_state.add_status("Vault key change failed: vault is not initialized.", level="error")
        return jsonify({"ok": False, "error": "Vault is not initialized."}), 400
    except RuntimeError as exc:
        logger.error(f"Vault key change failed: {exc}")
        app_state.add_status("Vault key change failed and was rolled back.", level="error")
        return jsonify({"ok": False, "error": "Vault re-encryption failed; previous key restored."}), 500
    except Exception as exc:
        logger.error(f"Vault key change unexpected error: {exc}")
        app_state.add_status("Vault key change failed due to an unexpected error.", level="error")
        return jsonify({"ok": False, "error": "Unexpected error while changing vault key."}), 500

    if skipped_files:
        app_state.add_status(
            "Vault key updated with warnings. Some undecryptable files were skipped: "
            + ", ".join(skipped_files[:5])
            + ("..." if len(skipped_files) > 5 else ""),
            level="warning"
        )
        return jsonify({
            "ok": True,
            "warning": "Some undecryptable vault files were skipped.",
            "skipped_files": skipped_files,
        })

    app_state.add_status("Vault key updated successfully.", level="success")
    return jsonify({"ok": True, "skipped_files": []})



# Vault file management API


@ui_blueprint.route("/api/vault/files")
def vault_files_api():
    """Return the list of files stored in the vault."""
    files = vault_list_files()
    return jsonify({"ok": True, "files": files})


@ui_blueprint.route("/api/vault/download/<path:filename>")
def vault_download(filename):
    """Decrypt a vault file and serve it as a download."""
    from cryptography.exceptions import InvalidTag
    try:
        data = vault_retrieve_file(filename)
    except RuntimeError:
        return jsonify({"ok": False, "error": "Vault is locked"}), 403
    except InvalidTag:
        return jsonify({
            "ok": False,
            "error": "Decryption failed — file may be corrupted or tampered with",
        }), 400
    if data is None:
        return jsonify({"ok": False, "error": "File not found in vault"}), 404
    return flask_send_file(
        io.BytesIO(data),
        download_name=filename,
        as_attachment=True,
    )


# Pages

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


# Peer API

@ui_blueprint.route("/api/refresh-peers", methods=["POST"])
def refresh_peers():
    """
    Trigger peer discovery refresh.
    Posts a status message; actual discovery runs via mDNS in the background.
    """
    app_state.add_status("Peer discovery refresh triggered.", level="info")
    return jsonify({"ok": True, "message": "Peer refresh triggered"})


# File API

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


# File Request / Send

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

    peer = app_state.peers.get(peer_id)
    if peer and not peer.trusted:
        app_state.add_status(f"Cannot request files from unverified peer {peer_id}. Verify first.", level="error")
        return jsonify({"ok": False, "error": "Peer is not verified"}), 403

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

    peer = app_state.peers.get(peer_id)
    if peer and not peer.trusted:
        app_state.add_status(f"Cannot fetch file list from unverified peer {peer_id}. Verify first.", level="error")
        return jsonify({"ok": False, "error": "Peer is not verified"}), 403

    success = request_file_list_from_peer(peer_id)
    return jsonify({"ok": success})


@ui_blueprint.route("/api/send-file", methods=["POST"])
def send_file_to_peer_route():
    """Send a consent request to the receiving peer before sending a file."""
    from app.core.consent import send_consent_offer
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

    if not peer.trusted:
        app_state.add_status(f"Cannot send files to unverified peer {peer_id}. Verify first.", level="error")
        return jsonify({"ok": False, "error": "Peer is not verified"}), 403

    shared = get_file_by_name(filename)
    if not shared:
        app_state.add_status(f"File '{filename}' not in shared files.", level="error")
        return jsonify({"ok": False, "error": "File not shared"}), 404


    send_consent_offer(peer_id, shared.filename, shared.sha256_hash)
    return jsonify({"ok": True, "peer_id": peer_id, "filename": filename})


# Consent API

@ui_blueprint.route("/api/consent/<request_id>/<action>", methods=["POST"])
def handle_consent(request_id: str, action: str):
    """
    Accept or deny an incoming consent request.
    action must be 'accept' or 'deny'.
    If accepted and it was a file_request, triggers file send.
    If accepted and it was a file_send (consent offer), sends approval back.
    """
    from app.core.consent import on_consent_approved, on_consent_denied
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

    resolved = getattr(app_state, '_resolved_consents', {})
    app_state._resolved_consents = resolved
    resolved[request_id] = {
        "peer_id": consent.peer_id,
        "peer_name": consent.peer_name,
        "action": consent.action,
        "filename": consent.filename,
        "file_hash": consent.file_hash,
    }

    if approved:
        on_consent_approved(request_id)
    else:
        on_consent_denied(request_id)

    return jsonify({"ok": True, "action": action, "request_id": request_id})




# Key Rotation

@ui_blueprint.route("/api/rotate-key", methods=["POST"])
def rotate_key_route():
    """Rotate the identity key and notify all known peers."""
    from app.core.revocation import rotate_key
    logger.info("routes.rotate_key_route → user triggered key rotation")
    result = rotate_key()
    return jsonify({"ok": True, **result})


# File Verification

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

    
    session_key = get_session_key(peer_id)
    if not session_key:
        session_key = initiate_handshake(peer_id, peer.address, peer.port)
        if not session_key:
            return jsonify({"ok": False, "error": "Handshake failed. Could not reach peer."}), 500

    # Generate the verification code from both fingerprints.

    my_fp = app_state.fingerprint or ""
    their_fp = peer.fingerprint or ""
    if not their_fp or their_fp == "unknown":
        return jsonify({"ok": False, "error": "Peer fingerprint not available. Handshake may have failed."}), 500

    verification_code = generate_verification_code(my_fp, their_fp)
    if not verification_code:
        return jsonify({"ok": False, "error": "Verification code generation failed."}), 500

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

    
    app_state.verify_confirmed_by_me.add(peer_id)
    app_state.pending_verifications = [pv for pv in app_state.pending_verifications if pv["peer_id"] != peer_id]

 
    try:
        with _socket.create_connection((peer.address, peer.port), timeout=10) as sock:
            msg = verify_confirm(app_state.peer_id)
            _send(sock, msg)
    except Exception as e:
        logger.error(f"Failed to send VERIFY_CONFIRM to {peer_id}: {e}")

   
    if peer_id in app_state.verify_confirmed_by_peer:
        peer.trusted = True
        app_state.verify_confirmed_by_me.discard(peer_id)
        app_state.verify_confirmed_by_peer.discard(peer_id)
        app_state.add_status(
            f"✓ Peer {peer_id} is now VERIFIED. Both sides confirmed.",
            level="success"
        )
        app_state.save_trusted_peers()
      
        from app.core.sessions import _auto_fetch_file_list
        _auto_fetch_file_list(peer_id)
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

   
    if peer and peer.online:
        try:
            with _socket.create_connection((peer.address, peer.port), timeout=10) as sock:
                msg = verify_reject(app_state.peer_id)
                _send(sock, msg)
        except Exception as e:
            logger.error(f"Failed to send VERIFY_REJECT to {peer_id}: {e}")

  
    remove_session(peer_id)

    app_state.add_status(
        f"⚠ Verification REJECTED for {peer_id}. "
        f"Codes did not match — possible man-in-the-middle attack! "
        f"Session destroyed.",
        level="error"
    )
    return jsonify({"ok": True, "rejected": True})


# Status API

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
        "vault_unlocked": app_state.vault_unlocked,
        "vault_files": vault_list_files() if app_state.vault_unlocked else [],
    })
