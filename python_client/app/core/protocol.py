"""
protocol.py — Protocol constants, message schema, and serialization.

This is the single source of truth for the P2P message format.
Every message exchanged between peers goes through this module.

Message format (JSON):
{
    "version": "1.0",
    "type": "PEER_ANNOUNCE",
    "timestamp": 1711324800.0,
    "payload": { ... }
}

Binary fields (keys, signatures, ciphertext, etc.) are base64-encoded
in the JSON payload so the messages remain human-readable.

Reading order: Read this FIRST in Phase 2 to understand the protocol.
"""

import json
import time
import base64
from typing import Any


# ---------------------------------------------------------------------------
# Protocol version — included in every message for compatibility checks
# ---------------------------------------------------------------------------
PROTOCOL_VERSION = "1.0"


# ---------------------------------------------------------------------------
# Message types — all valid type strings used in the "type" field
# ---------------------------------------------------------------------------
class MessageType:
    """Enum-like class for message types. Not a real enum for JSON simplicity."""
    PEER_ANNOUNCE       = "PEER_ANNOUNCE"
    PEER_LIST_REQUEST   = "PEER_LIST_REQUEST"
    PEER_LIST_RESPONSE  = "PEER_LIST_RESPONSE"
    KEY_EXCHANGE_INIT    = "KEY_EXCHANGE_INIT"
    KEY_EXCHANGE_RESPONSE = "KEY_EXCHANGE_RESPONSE"
    KEY_EXCHANGE_CONFIRM  = "KEY_EXCHANGE_CONFIRM"
    FILE_LIST_REQUEST   = "FILE_LIST_REQUEST"
    FILE_LIST_RESPONSE  = "FILE_LIST_RESPONSE"
    FILE_REQUEST        = "FILE_REQUEST"
    FILE_SEND           = "FILE_SEND"
    CONSENT_REQUEST     = "CONSENT_REQUEST"
    CONSENT_RESPONSE    = "CONSENT_RESPONSE"
    REVOKE_KEY          = "REVOKE_KEY"
    VERIFY_CONFIRM      = "VERIFY_CONFIRM"
    VERIFY_REJECT       = "VERIFY_REJECT"
    ERROR               = "ERROR"


# Set of all valid message types (used for validation)
VALID_MESSAGE_TYPES = {
    v for k, v in vars(MessageType).items()
    if not k.startswith("_")
}


# ---------------------------------------------------------------------------
# Required payload fields per message type
# Messages without entries here only require version, type, and timestamp.
# ---------------------------------------------------------------------------
REQUIRED_PAYLOAD_FIELDS: dict[str, list[str]] = {
    MessageType.PEER_ANNOUNCE:         ["peer_id", "port"],
    MessageType.PEER_LIST_REQUEST:     ["peer_id"],
    MessageType.PEER_LIST_RESPONSE:    ["peer_id", "peers"],
    MessageType.KEY_EXCHANGE_INIT:     ["peer_id", "ephemeral_public_key"],
    MessageType.KEY_EXCHANGE_RESPONSE: ["peer_id", "ephemeral_public_key",
                                        "long_term_public_key", "signature"],
    MessageType.KEY_EXCHANGE_CONFIRM:  ["peer_id", "long_term_public_key", "signature"],
    MessageType.FILE_LIST_REQUEST:     ["peer_id"],
    MessageType.FILE_LIST_RESPONSE:    ["peer_id", "files"],
    MessageType.FILE_REQUEST:          ["peer_id", "filename", "file_hash"],
    MessageType.FILE_SEND:             ["peer_id", "filename", "file_hash", "data"],
    MessageType.CONSENT_REQUEST:       ["peer_id", "action", "filename"],
    MessageType.CONSENT_RESPONSE:      ["peer_id", "request_id", "approved"],
    MessageType.REVOKE_KEY:            ["peer_id", "new_public_key"],
    MessageType.VERIFY_CONFIRM:        ["peer_id"],
    MessageType.VERIFY_REJECT:         ["peer_id"],
    MessageType.ERROR:                 ["peer_id", "code", "description"],
}


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------
class ProtocolError(Exception):
    """Raised when a message fails validation."""
    pass


# ---------------------------------------------------------------------------
# Message construction
# ---------------------------------------------------------------------------
def create_message(msg_type: str, payload: dict[str, Any]) -> dict:
    """
    Build a protocol message dict.

    Args:
        msg_type: One of the MessageType constants.
        payload: The message-specific data.

    Returns:
        A dict with version, type, timestamp, and payload fields.

    Raises:
        ProtocolError: If msg_type is not a valid type.
    """
    if msg_type not in VALID_MESSAGE_TYPES:
        raise ProtocolError(f"Unknown message type: {msg_type}")

    return {
        "version": PROTOCOL_VERSION,
        "type": msg_type,
        "timestamp": time.time(),
        "payload": payload,
    }


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------
def validate_message(msg: dict) -> dict:
    """
    Validate a message dict.

    Checks:
      1. Has "version", "type", "timestamp", and "payload" fields.
      2. Version matches PROTOCOL_VERSION.
      3. Type is a known message type.
      4. Payload contains all required fields for the message type.

    Args:
        msg: The message dict to validate.

    Returns:
        The validated message dict (same object, for convenience).

    Raises:
        ProtocolError: If any validation check fails.
    """
    # Check top-level fields
    for field in ("version", "type", "timestamp", "payload"):
        if field not in msg:
            raise ProtocolError(f"Missing required field: '{field}'")

    # Check version
    if msg["version"] != PROTOCOL_VERSION:
        raise ProtocolError(
            f"Unsupported protocol version: {msg['version']} "
            f"(expected {PROTOCOL_VERSION})"
        )

    # Check type
    if msg["type"] not in VALID_MESSAGE_TYPES:
        raise ProtocolError(f"Unknown message type: {msg['type']}")

    # Check required payload fields
    required = REQUIRED_PAYLOAD_FIELDS.get(msg["type"], [])
    payload = msg["payload"]
    for field in required:
        if field not in payload:
            raise ProtocolError(
                f"Message type '{msg['type']}' requires payload field '{field}'"
            )

    return msg


# ---------------------------------------------------------------------------
# Serialization: dict <-> JSON string
# ---------------------------------------------------------------------------
def serialize(msg: dict) -> str:
    """
    Serialize a message dict to a JSON string.

    Validates the message before serializing. Binary values (bytes)
    in the payload are automatically base64-encoded.

    Args:
        msg: A valid message dict.

    Returns:
        A JSON string representation of the message.

    Raises:
        ProtocolError: If validation fails.
    """
    validate_message(msg)

    # Deep-copy the payload and encode any bytes values to base64
    encoded_payload = _encode_binary_fields(msg["payload"])

    serializable = {
        "version": msg["version"],
        "type": msg["type"],
        "timestamp": msg["timestamp"],
        "payload": encoded_payload,
    }
    return json.dumps(serializable, separators=(",", ":"))


def deserialize(json_str: str) -> dict:
    """
    Deserialize a JSON string into a validated message dict.

    Args:
        json_str: A JSON string from a peer.

    Returns:
        A validated message dict.

    Raises:
        ProtocolError: If the JSON is invalid or the message fails validation.
    """
    try:
        msg = json.loads(json_str)
    except json.JSONDecodeError as e:
        raise ProtocolError(f"Invalid JSON: {e}")

    if not isinstance(msg, dict):
        raise ProtocolError("Message must be a JSON object")

    validated_msg = validate_message(msg)
    validated_msg["payload"] = _decode_binary_fields(validated_msg["payload"])
    return validated_msg


# ---------------------------------------------------------------------------
# Binary field encoding helpers
# ---------------------------------------------------------------------------

# Fields that should be treated as base64-encoded binary data
BINARY_FIELD_NAMES = {"public_key", "signature", "data", "nonce",
                      "ciphertext", "hmac", "new_public_key",
                      "ephemeral_public_key", "long_term_public_key",
                      "cross_signature"}


def _encode_binary_fields(payload: dict) -> dict:
    """
    Recursively encode bytes values to base64 strings in a payload dict.
    Returns a new dict (does not mutate the input).
    """
    result: dict[str, Any] = {}
    for key, value in payload.items():
        if isinstance(value, bytes):
            result[key] = base64.b64encode(value).decode("ascii")
        elif isinstance(value, dict):
            result[key] = _encode_binary_fields(value)
        elif isinstance(value, list):
            result[key] = [
                _encode_binary_fields(item) if isinstance(item, dict) else item
                for item in value
            ]
        else:
            result[key] = value
    return result


def _decode_binary_fields(payload: dict) -> dict:
    """
    Recursively decode base64 strings back to bytes for known binary fields.
    Returns a new dict (does not mutate the input).
    """
    result: dict[str, Any] = {}
    for key, value in payload.items():
        if isinstance(value, dict):
            result[key] = _decode_binary_fields(value)
        elif isinstance(value, list):
            result[key] = [
                _decode_binary_fields(item) if isinstance(item, dict) else item
                for item in value
            ]
        elif key in BINARY_FIELD_NAMES and isinstance(value, str):
            result[key] = decode_bytes(value)
        else:
            result[key] = value
    return result


def encode_bytes(data: bytes) -> str:
    """Encode bytes to a base64 string. Convenience wrapper."""
    return base64.b64encode(data).decode("ascii")


def decode_bytes(b64_str: str) -> bytes:
    """Decode a base64 string to bytes. Convenience wrapper."""
    try:
        return base64.b64decode(b64_str)
    except Exception as e:
        raise ProtocolError(f"Invalid base64 data: {e}")
