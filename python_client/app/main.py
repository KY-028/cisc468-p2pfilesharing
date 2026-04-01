"""
main.py — Entry point for the P2P file sharing application.

Run this to start the Flask server:
    python -m app.main
    python -m app.main --port 5002 --tcp-port 9001   # second instance

This module:
  1. Generates (or loads) the RSA-2048 identity key pair
  2. Starts the TCP server for incoming P2P connections
  3. Starts mDNS discovery to find other peers
  4. Runs the Flask web UI

Reading order: Read state.py first, then this file.
"""

import os
import sys
import argparse
import logging
import socket
from flask import Flask
from app.ui.routes import ui_blueprint
from app.core.state import app_state
from app.crypto.keys import (
    generate_rsa_keypair,
    serialize_public_key,
    save_private_key,
    load_private_key,
    get_fingerprint,
)
from app.network.transport import TCPServer, receive_message, send_message
from app.network.discovery import PeerDiscovery
from app.storage.files import scan_shared_directory
from app.storage.manifests import init_manifest_storage
from app.core.consent import (
    handle_file_list_request,
    handle_file_list_response,
    handle_file_request,
    handle_file_send,
    handle_consent_request,
    handle_consent_response,
)
from app.core.revocation import handle_revoke_key
from app.core.sessions import handle_handshake_init, handle_verify_confirm, handle_verify_reject
from app.core.protocol import MessageType

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
)
logger = logging.getLogger(__name__)

# Directory where keys and data are stored
DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "data")
KEY_FILE = os.path.join(DATA_DIR, "identity_key.pem")


def create_app(tcp_port: int = 9000) -> Flask:
    """
    Create and configure the Flask application.

    Also initializes:
      - RSA identity keys (generate or load)
      - TCP server for P2P connections
      - mDNS peer discovery
    """
    flask_app = Flask(
        __name__,
        template_folder="ui/templates",
        static_folder="ui/static",
    )
    flask_app.secret_key = "dev-secret-key-change-in-production"

    # Register the UI routes blueprint
    flask_app.register_blueprint(ui_blueprint)

    # Make app_state accessible in templates
    @flask_app.context_processor
    def inject_state():
        return {"state": app_state}

    # --- Initialize identity keys ---
    _init_identity(tcp_port)

    # --- Start TCP server ---
    tcp_server = _start_tcp_server(tcp_port)
    flask_app.config["tcp_server"] = tcp_server
    flask_app.config["tcp_port"] = tcp_port

    # --- Start mDNS discovery ---
    discovery = PeerDiscovery(peer_id=app_state.peer_id, tcp_port=tcp_port)
    discovery.start()
    flask_app.config["discovery"] = discovery

    # Cleanup on shutdown
    import atexit
    atexit.register(lambda: _shutdown(tcp_server, discovery))

    # --- Auto-scan shared directory ---
    count = scan_shared_directory()
    if count > 0:
        app_state.add_status(f"Auto-shared {count} file(s) from shared/ directory.", level="info")

    app_state.add_status("Application started.", level="success")
    return flask_app


# ---------------------------------------------------------------------------
# Identity key initialization
# ---------------------------------------------------------------------------

def _get_local_ip() -> str:
    """Get the local IP used for outbound network traffic."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def _init_identity(tcp_port: int) -> None:
    """Generate or load the RSA-2048 identity key pair."""
    # Use IP + port as the directory name so that different machines
    # (same port) and different local instances (same IP, different port)
    # each get a unique identity key.
    local_ip = _get_local_ip()
    ip_tag = local_ip.replace(".", "_")
    data_dir = os.path.join(os.path.dirname(__file__), "..", f"data_{ip_tag}_{tcp_port}")
    key_file = os.path.join(data_dir, "identity_key.pem")

    os.makedirs(data_dir, exist_ok=True)

    if os.path.exists(key_file):
        # Load existing key
        logger.info(f"Loading identity key from {key_file}")
        private_key = load_private_key(key_file)
        public_key = private_key.public_key()
        app_state.add_status("Loaded existing identity key.", level="info")
    else:
        # Generate new key pair
        logger.info("Generating new RSA-2048 identity key pair...")
        private_key, public_key = generate_rsa_keypair()
        save_private_key(private_key, key_file)
        app_state.add_status("Generated new identity key pair.", level="success")

    # Store in app state
    app_state.public_key_pem = serialize_public_key(public_key).decode("utf-8")
    app_state.private_key_pem = key_file  # Store path, not the key itself
    app_state.fingerprint = get_fingerprint(public_key)
    # Keep a reference to the key objects for crypto operations
    app_state._private_key = private_key
    app_state._public_key = public_key

    # Derive a deterministic peer ID from the public key fingerprint
    # so the ID stays the same across restarts.
    fp_short = app_state.fingerprint.replace(":", "")[:8].lower()
    app_state.peer_id = f"peer-{fp_short}"
    app_state.display_name = app_state.peer_id

    # Initialize persistent manifest storage in the same data dir
    init_manifest_storage(data_dir)

    # Initialize trust persistence in the same data dir
    app_state.init_trust_storage(data_dir)

    logger.info(f"Peer ID: {app_state.peer_id}")
    logger.info(f"Fingerprint: {app_state.fingerprint}")


# ---------------------------------------------------------------------------
# TCP server
# ---------------------------------------------------------------------------

def _start_tcp_server(port: int) -> TCPServer:
    """Start the TCP server for incoming P2P connections."""

    def handle_connection(sock, addr):
        """Handler for each incoming TCP connection."""
        logger.info(f"Incoming connection from {addr}")
        try:
            msg = receive_message(sock)
            if msg:
                _handle_incoming_message(msg, sock, addr)
        except Exception as e:
            logger.error(f"Error handling connection from {addr}: {e}")

    server = TCPServer("0.0.0.0", port, handle_connection)
    server.start()
    return server


def _handle_incoming_message(msg: dict, sock, addr) -> None:
    """
    Route an incoming message to the appropriate handler.

    This is the central message dispatcher. Each message type gets
    routed to the right handler function. Operations that involve file
    data or file listings require the peer to be verified (trusted).
    """
    msg_type = msg.get("type", "")
    peer_id = msg.get("payload", {}).get("peer_id", "unknown")
    logger.info(f"Received {msg_type} from {peer_id}")

    # Messages that require the peer to be verified first
    TRUST_REQUIRED = {
        MessageType.FILE_LIST_REQUEST,
        MessageType.FILE_LIST_RESPONSE,
        MessageType.FILE_REQUEST,
        MessageType.FILE_SEND,
        MessageType.CONSENT_REQUEST,
        MessageType.CONSENT_RESPONSE,
    }

    if msg_type in TRUST_REQUIRED:
        peer = app_state.peers.get(peer_id)
        if not peer or not peer.trusted:
            logger.warning(f"Rejected {msg_type} from unverified peer {peer_id}")
            app_state.add_status(
                f"Blocked {msg_type} from unverified peer {peer_id}. "
                f"Verify the peer first.",
                level="warning"
            )
            return

    # Route to the appropriate handler
    handlers = {
        MessageType.KEY_EXCHANGE_INIT:   handle_handshake_init,
        MessageType.FILE_LIST_REQUEST:   handle_file_list_request,
        MessageType.FILE_LIST_RESPONSE:  handle_file_list_response,
        MessageType.FILE_REQUEST:        handle_file_request,
        MessageType.FILE_SEND:           handle_file_send,
        MessageType.CONSENT_REQUEST:     handle_consent_request,
        MessageType.CONSENT_RESPONSE:    handle_consent_response,
        MessageType.REVOKE_KEY:          handle_revoke_key,
        MessageType.VERIFY_CONFIRM:      handle_verify_confirm,
        MessageType.VERIFY_REJECT:       handle_verify_reject,
    }

    handler = handlers.get(msg_type)
    if handler:
        handler(msg, sock, addr)
    else:
        # Log unhandled message types (key exchange, peer announce, etc.)
        app_state.add_status(
            f"Received {msg_type} from {peer_id} ({addr[0]}:{addr[1]})",
            level="info"
        )


# ---------------------------------------------------------------------------
# Shutdown
# ---------------------------------------------------------------------------

def _shutdown(tcp_server: TCPServer, discovery: PeerDiscovery) -> None:
    """Graceful shutdown of background services."""
    logger.info("Shutting down...")
    tcp_server.stop()
    discovery.stop()


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def parse_args():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description="P2P Secure File Sharing")
    parser.add_argument("--port", type=int, default=5001,
                        help="Flask web UI port (default: 5001)")
    parser.add_argument("--tcp-port", type=int, default=9000,
                        help="TCP port for P2P connections (default: 9000)")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    app = create_app(tcp_port=args.tcp_port)
    print(f"\n  P2P File Sharing — Peer ID: {app_state.peer_id}")
    print(f"  Fingerprint: {app_state.fingerprint}")
    print(f"  Web UI:  http://localhost:{args.port}")
    print(f"  TCP P2P: port {args.tcp_port}\n")
    app.run(host="127.0.0.1", port=args.port, debug=False)
