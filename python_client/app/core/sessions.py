"""
sessions.py — Active session management.

Bridges the STS handshake (session.py) with the file transfer pipeline
(consent.py). Manages established sessions and their derived keys.

Two roles:
  INITIATOR — called before sending a file to a peer:
      initiate_handshake(peer_id, address, port) → session_key

  RESPONDER — called when we receive a KEY_EXCHANGE_INIT:
      handle_handshake_init(msg, sock, addr) → stores session_key

After a handshake completes, both sides have the same 32-byte key in
_session_keys[peer_id], which consent.py uses for AES-256-GCM encryption.

Reading order: Read session.py first, then this file, then consent.py.
"""

import logging
import socket
from typing import Optional
from app.core.state import app_state
from app.core.session import STSSession
from app.core.protocol import MessageType, decode_bytes
from app.network.messages import (
    key_exchange_init,
    key_exchange_response,
    key_exchange_confirm,
)
from app.network.transport import send_message, receive_message
from app.crypto.keys import serialize_public_key, get_fingerprint

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Session key store: peer_id → 32-byte AES key
# ---------------------------------------------------------------------------
_session_keys: dict[str, bytes] = {}


def get_session_key(peer_id: str) -> Optional[bytes]:
    """Get the session key for a peer, if an active session exists."""
    return _session_keys.get(peer_id)


def store_session_key(peer_id: str, key: bytes) -> None:
    """Store a session key for a peer."""
    _session_keys[peer_id] = key


def remove_session(peer_id: str) -> None:
    """Remove a session (e.g., on peer disconnect or key rotation)."""
    _session_keys.pop(peer_id, None)


def clear_all_sessions() -> None:
    """Remove all sessions (e.g., after local key rotation)."""
    _session_keys.clear()


def _decode_field(value) -> bytes:
    """Decode a base64-encoded field if it's a string, pass through if bytes."""
    if isinstance(value, str):
        return decode_bytes(value)
    return value


def _update_peer_key(peer_id: str, sts: STSSession) -> None:
    """Store the peer's long-term RSA public key if we don't have it yet."""
    peer = app_state.peers.get(peer_id)
    if peer and sts.peer_rsa_public:
        peer.public_key_pem = serialize_public_key(sts.peer_rsa_public).decode("utf-8")
        peer.fingerprint = get_fingerprint(sts.peer_rsa_public)


# ---------------------------------------------------------------------------
# INITIATOR: we start the handshake before sending a file
# ---------------------------------------------------------------------------

def initiate_handshake(peer_id: str, address: str, port: int) -> Optional[bytes]:
    """
    Perform a full STS handshake as the INITIATOR.

    Opens a TCP connection and runs the 3-message exchange:
      1. → KEY_EXCHANGE_INIT     (our ephemeral pub)
      2. ← KEY_EXCHANGE_RESPONSE (peer's eph + long-term pub + signature)
      3. → KEY_EXCHANGE_CONFIRM  (our long-term pub + signature)

    On success, stores the session key and returns it.
    On failure, logs an error and returns None.
    """
    sts = STSSession(app_state._private_key, app_state._public_key)

    try:
        with socket.create_connection((address, port), timeout=15) as sock:
            # Step 1: Send our ephemeral public key
            init_payload = sts.create_init()
            msg = key_exchange_init(
                app_state.peer_id,
                init_payload["ephemeral_public_key"],
            )
            send_message(sock, msg)

            # Step 2: Receive and verify the responder's message
            response_msg = receive_message(sock)
            if not response_msg:
                raise ValueError("Connection closed, no response received")
            if response_msg["type"] != MessageType.KEY_EXCHANGE_RESPONSE:
                raise ValueError(
                    f"Expected KEY_EXCHANGE_RESPONSE, got {response_msg['type']}"
                )

            resp = response_msg["payload"]
            confirm_payload = sts.handle_response({
                "ephemeral_public_key": _decode_field(resp["ephemeral_public_key"]),
                "long_term_public_key": _decode_field(resp["long_term_public_key"]),
                "signature":           _decode_field(resp["signature"]),
            })

            # Step 3: Send our long-term key + signature
            confirm_msg = key_exchange_confirm(
                app_state.peer_id,
                confirm_payload["long_term_public_key"],
                confirm_payload["signature"],
            )
            send_message(sock, confirm_msg)

        # Handshake complete — store results
        session_key = sts.session_key
        store_session_key(peer_id, session_key)
        _update_peer_key(peer_id, sts)

        app_state.add_status(
            f"Session established with {peer_id} (initiator). "
            f"Encrypted channel ready ✓",
            level="success"
        )
        logger.info(f"STS handshake completed with {peer_id} (initiator)")

        sts.destroy()
        return session_key

    except Exception as e:
        app_state.add_status(
            f"Handshake with {peer_id} failed: {e}",
            level="error"
        )
        logger.error(f"STS handshake (initiator) with {peer_id} failed: {e}")
        sts.destroy()
        return None


# ---------------------------------------------------------------------------
# RESPONDER: handle an incoming KEY_EXCHANGE_INIT
# ---------------------------------------------------------------------------

def handle_handshake_init(msg: dict, sock, addr) -> None:
    """
    Handle an incoming KEY_EXCHANGE_INIT as the RESPONDER.

    Runs the remaining 2 messages of the handshake on the SAME connection:
      1. (already received) KEY_EXCHANGE_INIT
      2. → KEY_EXCHANGE_RESPONSE (our eph + long-term pub + signature)
      3. ← KEY_EXCHANGE_CONFIRM  (peer's long-term pub + signature)

    On success, stores the session key.
    """
    payload = msg["payload"]
    peer_id = payload["peer_id"]
    sts = STSSession(app_state._private_key, app_state._public_key)

    try:
        # Step 1: Process the INIT, create our RESPONSE
        eph_bytes = _decode_field(payload["ephemeral_public_key"])
        resp_payload = sts.handle_init({"ephemeral_public_key": eph_bytes})

        resp_msg = key_exchange_response(
            app_state.peer_id,
            resp_payload["ephemeral_public_key"],
            resp_payload["long_term_public_key"],
            resp_payload["signature"],
        )
        send_message(sock, resp_msg)

        # Step 2: Receive and verify the CONFIRM
        confirm_msg = receive_message(sock)
        if not confirm_msg:
            raise ValueError("Connection closed, no confirm received")
        if confirm_msg["type"] != MessageType.KEY_EXCHANGE_CONFIRM:
            raise ValueError(
                f"Expected KEY_EXCHANGE_CONFIRM, got {confirm_msg['type']}"
            )

        conf = confirm_msg["payload"]
        sts.handle_confirm({
            "long_term_public_key": _decode_field(conf["long_term_public_key"]),
            "signature":           _decode_field(conf["signature"]),
        })

        # Handshake complete — store results
        store_session_key(peer_id, sts.session_key)
        _update_peer_key(peer_id, sts)

        app_state.add_status(
            f"Session established with {peer_id} (responder). "
            f"Encrypted channel ready ✓",
            level="success"
        )
        logger.info(f"STS handshake completed with {peer_id} (responder)")

        sts.destroy()

    except Exception as e:
        app_state.add_status(
            f"Handshake (responder) with {peer_id} failed: {e}",
            level="error"
        )
        logger.error(f"STS handshake (responder) with {peer_id} failed: {e}")
        sts.destroy()
