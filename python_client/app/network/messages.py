"""
messages.py — High-level message builders for each protocol message type.

Each function constructs a properly formatted message dict using
protocol.create_message(). These are convenience wrappers so that
other modules don't have to build raw payload dicts.

Reading order: Read protocol.py FIRST, then this file.
"""

from app.core.protocol import MessageType, create_message


# ---------------------------------------------------------------------------
# Peer Discovery Messages
# ---------------------------------------------------------------------------

def peer_announce(peer_id: str, port: int,
                  public_key: bytes = None, display_name: str = None) -> dict:
    """
    Create a PEER_ANNOUNCE message.
    Sent when a peer comes online or responds to discovery.
    """
    payload = {
        "peer_id": peer_id,
        "port": port,
    }
    if public_key is not None:
        payload["public_key"] = public_key
    if display_name is not None:
        payload["display_name"] = display_name
    return create_message(MessageType.PEER_ANNOUNCE, payload)


# ---------------------------------------------------------------------------
# Key Exchange Messages
# ---------------------------------------------------------------------------

def key_exchange_init(peer_id: str, ephemeral_public_key: bytes) -> dict:
    """
    Create a KEY_EXCHANGE_INIT message (STS Step 1).
    Sends our ephemeral ECDH public key to begin the handshake.
    """
    return create_message(MessageType.KEY_EXCHANGE_INIT, {
        "peer_id": peer_id,
        "ephemeral_public_key": ephemeral_public_key,
    })


def key_exchange_response(peer_id: str, ephemeral_public_key: bytes,
                          long_term_public_key: bytes,
                          signature: bytes) -> dict:
    """
    Create a KEY_EXCHANGE_RESPONSE message (STS Step 2).
    Sends our ephemeral key, long-term key, and signature over
    (our_eph || their_eph) to prove identity.
    """
    return create_message(MessageType.KEY_EXCHANGE_RESPONSE, {
        "peer_id": peer_id,
        "ephemeral_public_key": ephemeral_public_key,
        "long_term_public_key": long_term_public_key,
        "signature": signature,
    })


def key_exchange_confirm(peer_id: str, long_term_public_key: bytes,
                         signature: bytes) -> dict:
    """
    Create a KEY_EXCHANGE_CONFIRM message (STS Step 3).
    Sends our long-term key and signature to complete mutual authentication.
    """
    return create_message(MessageType.KEY_EXCHANGE_CONFIRM, {
        "peer_id": peer_id,
        "long_term_public_key": long_term_public_key,
        "signature": signature,
    })


# ---------------------------------------------------------------------------
# File List Messages
# ---------------------------------------------------------------------------

def file_list_request(peer_id: str) -> dict:
    """Create a FILE_LIST_REQUEST message."""
    return create_message(MessageType.FILE_LIST_REQUEST, {
        "peer_id": peer_id,
    })


def file_list_response(peer_id: str, files: list[dict]) -> dict:
    """
    Create a FILE_LIST_RESPONSE message.

    Args:
        peer_id: This peer's ID.
        files: List of dicts with 'filename', 'size', 'sha256_hash',
               and optionally 'signature'.
    """
    return create_message(MessageType.FILE_LIST_RESPONSE, {
        "peer_id": peer_id,
        "files": files,
    })


# ---------------------------------------------------------------------------
# File Transfer Messages
# ---------------------------------------------------------------------------

def file_request(peer_id: str, filename: str, file_hash: str) -> dict:
    """
    Create a FILE_REQUEST message.
    Asks a peer to send a specific file (requires consent on their end).
    """
    return create_message(MessageType.FILE_REQUEST, {
        "peer_id": peer_id,
        "filename": filename,
        "file_hash": file_hash,
    })


def file_send(peer_id: str, filename: str, file_hash: str,
              data: bytes, signature: bytes = None,
              hmac_value: bytes = None) -> dict:
    """
    Create a FILE_SEND message.
    Contains the actual file data (or a chunk of it).
    """
    payload = {
        "peer_id": peer_id,
        "filename": filename,
        "file_hash": file_hash,
        "data": data,
    }
    if signature is not None:
        payload["signature"] = signature
    if hmac_value is not None:
        payload["hmac"] = hmac_value
    return create_message(MessageType.FILE_SEND, payload)


# ---------------------------------------------------------------------------
# Consent Messages
# ---------------------------------------------------------------------------

def consent_request(peer_id: str, action: str, filename: str,
                    file_hash: str = None) -> dict:
    """
    Create a CONSENT_REQUEST message.
    Asks the remote peer for permission before sending or receiving.
    """
    payload = {
        "peer_id": peer_id,
        "action": action,
        "filename": filename,
    }
    if file_hash is not None:
        payload["file_hash"] = file_hash
    return create_message(MessageType.CONSENT_REQUEST, payload)


def consent_response(peer_id: str, request_id: str, approved: bool) -> dict:
    """Create a CONSENT_RESPONSE message."""
    return create_message(MessageType.CONSENT_RESPONSE, {
        "peer_id": peer_id,
        "request_id": request_id,
        "approved": approved,
    })


# ---------------------------------------------------------------------------
# Key Revocation
# ---------------------------------------------------------------------------

def revoke_key(peer_id: str, new_public_key: bytes,
               reason: str = None) -> dict:
    """
    Create a REVOKE_KEY message.
    Announces that this peer's key has changed.
    """
    payload = {
        "peer_id": peer_id,
        "new_public_key": new_public_key,
    }
    if reason is not None:
        payload["reason"] = reason
    return create_message(MessageType.REVOKE_KEY, payload)


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------

def verify_confirm(peer_id: str) -> dict:
    """Create a VERIFY_CONFIRM message. Signals that this peer has accepted the verification code."""
    return create_message(MessageType.VERIFY_CONFIRM, {
        "peer_id": peer_id,
    })


def verify_reject(peer_id: str) -> dict:
    """Create a VERIFY_REJECT message. Signals that this peer rejected the verification code."""
    return create_message(MessageType.VERIFY_REJECT, {
        "peer_id": peer_id,
    })


# ---------------------------------------------------------------------------
# Error
# ---------------------------------------------------------------------------

def error_message(peer_id: str, code: str, description: str) -> dict:
    """
    Create an ERROR message.
    Sent when something goes wrong (bad signature, missing file, etc.).
    """
    return create_message(MessageType.ERROR, {
        "peer_id": peer_id,
        "code": code,
        "description": description,
    })
