"""
routes.py — Flask routes for the web UI.

All HTTP endpoints live here. This module handles:
  - Rendering the dashboard page
  - Placeholder API endpoints for peer, file, and consent actions
  - Status message retrieval

Reading order: Read this THIRD (after state.py → main.py) to see all endpoints.
"""

import time
import uuid
from flask import Blueprint, render_template, request, jsonify, redirect, url_for
from app.core.state import app_state

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
# Peer API (placeholder actions for Phase 1)
# ---------------------------------------------------------------------------

@ui_blueprint.route("/api/refresh-peers", methods=["POST"])
def refresh_peers():
    """
    Placeholder: Trigger peer discovery refresh.
    In Phase 4, this will kick off an mDNS scan.
    """
    app_state.add_status("Peer discovery refresh triggered. (placeholder — no network yet)", level="info")
    return jsonify({"ok": True, "message": "Peer refresh triggered"})


# ---------------------------------------------------------------------------
# File API (placeholder actions for Phase 1)
# ---------------------------------------------------------------------------

@ui_blueprint.route("/api/add-shared-file", methods=["POST"])
def add_shared_file():
    """
    Placeholder: Add a file to the local share list.
    In Phase 5, this will hash the file and create a manifest entry.
    """
    filename = request.form.get("filename", "").strip()
    if not filename:
        app_state.add_status("No filename provided.", level="error")
        return jsonify({"ok": False, "error": "filename is required"}), 400

    # For now, create a dummy shared file record.
    from app.core.state import SharedFile
    dummy_file = SharedFile(
        filename=filename,
        filepath=f"/placeholder/{filename}",
        size=0,
        sha256_hash="0" * 64,
        owner_id=app_state.peer_id,
    )
    app_state.shared_files.append(dummy_file)
    app_state.add_status(f"Added '{filename}' to shared files. (placeholder)", level="success")
    return jsonify({"ok": True, "filename": filename})


@ui_blueprint.route("/api/remove-shared-file", methods=["POST"])
def remove_shared_file():
    """Remove a file from the share list by filename."""
    filename = request.form.get("filename", "").strip()
    before = len(app_state.shared_files)
    app_state.shared_files = [f for f in app_state.shared_files if f.filename != filename]
    if len(app_state.shared_files) < before:
        app_state.add_status(f"Removed '{filename}' from shared files.", level="info")
        return jsonify({"ok": True})
    else:
        app_state.add_status(f"File '{filename}' not found in shared list.", level="warning")
        return jsonify({"ok": False, "error": "not found"}), 404


# ---------------------------------------------------------------------------
# File Request / Send (placeholder for Phase 6)
# ---------------------------------------------------------------------------

@ui_blueprint.route("/api/request-file", methods=["POST"])
def request_file():
    """
    Placeholder: Request a file from a peer.
    In Phase 6, this will send a FILE_REQUEST message to the peer.
    """
    peer_id = request.form.get("peer_id", "").strip()
    filename = request.form.get("filename", "").strip()

    if not peer_id or not filename:
        app_state.add_status("Peer ID and filename are required to request a file.", level="error")
        return jsonify({"ok": False, "error": "peer_id and filename required"}), 400

    app_state.add_status(
        f"Requested '{filename}' from peer '{peer_id}'. (placeholder — no network yet)",
        level="info"
    )
    return jsonify({"ok": True, "peer_id": peer_id, "filename": filename})


@ui_blueprint.route("/api/send-file", methods=["POST"])
def send_file():
    """
    Placeholder: Send a file to a peer (push).
    In Phase 6, this will send a FILE_SEND offer to the peer.
    """
    peer_id = request.form.get("peer_id", "").strip()
    filename = request.form.get("filename", "").strip()

    if not peer_id or not filename:
        app_state.add_status("Peer ID and filename are required to send a file.", level="error")
        return jsonify({"ok": False, "error": "peer_id and filename required"}), 400

    app_state.add_status(
        f"Offered '{filename}' to peer '{peer_id}'. (placeholder — no network yet)",
        level="info"
    )
    return jsonify({"ok": True, "peer_id": peer_id, "filename": filename})


# ---------------------------------------------------------------------------
# Consent API (placeholder for Phase 6)
# ---------------------------------------------------------------------------

@ui_blueprint.route("/api/consent/<request_id>/<action>", methods=["POST"])
def handle_consent(request_id: str, action: str):
    """
    Accept or deny an incoming consent request.
    action must be 'accept' or 'deny'.
    """
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
    return jsonify({"ok": True, "action": action, "request_id": request_id})


@ui_blueprint.route("/api/test-consent", methods=["POST"])
def test_consent():
    """
    Debug helper: Create a fake consent request to test the modal.
    Remove this in production.
    """
    req_id = app_state.add_consent_request(
        peer_id="peer-test1234",
        peer_name="TestPeer",
        action="file_send",
        filename="example.txt",
        file_hash="abc123",
    )
    app_state.add_status("Test consent request created.", level="info")
    return jsonify({"ok": True, "request_id": req_id})


# ---------------------------------------------------------------------------
# Status API
# ---------------------------------------------------------------------------

@ui_blueprint.route("/api/status")
def get_status():
    """
    Return the current status log and pending consents as JSON.
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
                "fingerprint": p.fingerprint or "unknown",
                "last_seen": p.last_seen,
            }
            for p in app_state.peers.values()
        ],
        "shared_files": [
            {
                "filename": f.filename,
                "size": f.size,
                "sha256_hash": f.sha256_hash,
            }
            for f in app_state.shared_files
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
            for s in reversed(app_state.status_log)  # newest first
        ],
    })
