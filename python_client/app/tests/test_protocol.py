"""
test_protocol.py — Unit tests for the protocol module.

Tests cover:
  - Message creation for each type
  - Serialization round-trip (serialize → deserialize)
  - Validation: missing fields, unknown types, wrong version
  - Base64 encoding/decoding of binary fields

Run:  pytest app/tests/test_protocol.py -v
"""

import json
import pytest
from app.core.protocol import (
    MessageType,
    PROTOCOL_VERSION,
    ProtocolError,
    create_message,
    validate_message,
    serialize,
    deserialize,
    encode_bytes,
    decode_bytes,
)
from app.network.messages import (
    peer_announce,
    peer_list_request,
    peer_list_response,
    key_exchange_init,
    key_exchange_response,
    key_exchange_confirm,
    file_list_request,
    file_list_response,
    file_request,
    file_send,
    consent_request,
    consent_response,
    revoke_key,
    error_message,
)


# ===================================================================
# Test: Message Creation
# ===================================================================

class TestCreateMessage:
    """Test that create_message builds valid message dicts."""

    def test_creates_peer_announce(self):
        msg = create_message(MessageType.PEER_ANNOUNCE, {
            "peer_id": "peer-abc",
            "port": 9000,
        })
        assert msg["version"] == PROTOCOL_VERSION
        assert msg["type"] == "PEER_ANNOUNCE"
        assert msg["payload"]["peer_id"] == "peer-abc"
        assert msg["payload"]["port"] == 9000
        assert "timestamp" in msg

    def test_rejects_unknown_type(self):
        with pytest.raises(ProtocolError, match="Unknown message type"):
            create_message("INVALID_TYPE", {"peer_id": "x"})


# ===================================================================
# Test: Validation
# ===================================================================

class TestValidateMessage:
    """Test that validate_message catches invalid messages."""

    def _make_valid(self) -> dict:
        """Helper: build a minimal valid message."""
        return create_message(MessageType.PEER_LIST_REQUEST, {
            "peer_id": "peer-test",
        })

    def test_valid_message_passes(self):
        msg = self._make_valid()
        result = validate_message(msg)
        assert result is msg  # Returns the same object

    def test_missing_version(self):
        msg = self._make_valid()
        del msg["version"]
        with pytest.raises(ProtocolError, match="version"):
            validate_message(msg)

    def test_missing_type(self):
        msg = self._make_valid()
        del msg["type"]
        with pytest.raises(ProtocolError, match="type"):
            validate_message(msg)

    def test_missing_timestamp(self):
        msg = self._make_valid()
        del msg["timestamp"]
        with pytest.raises(ProtocolError, match="timestamp"):
            validate_message(msg)

    def test_missing_payload(self):
        msg = self._make_valid()
        del msg["payload"]
        with pytest.raises(ProtocolError, match="payload"):
            validate_message(msg)

    def test_wrong_version(self):
        msg = self._make_valid()
        msg["version"] = "99.0"
        with pytest.raises(ProtocolError, match="Unsupported protocol version"):
            validate_message(msg)

    def test_unknown_type(self):
        msg = self._make_valid()
        msg["type"] = "BOGUS"
        with pytest.raises(ProtocolError, match="Unknown message type"):
            validate_message(msg)

    def test_missing_required_payload_field(self):
        msg = create_message(MessageType.FILE_REQUEST, {
            "peer_id": "peer-x",
            "filename": "test.txt",
            # missing "file_hash"
        })
        with pytest.raises(ProtocolError, match="file_hash"):
            validate_message(msg)


# ===================================================================
# Test: Serialization Round-Trip
# ===================================================================

class TestSerialization:
    """Test serialize → deserialize produces equivalent messages."""

    def test_round_trip_simple(self):
        msg = peer_announce("peer-1", port=9001, display_name="Alice")
        json_str = serialize(msg)
        restored = deserialize(json_str)
        assert restored["type"] == "PEER_ANNOUNCE"
        assert restored["payload"]["peer_id"] == "peer-1"
        assert restored["payload"]["port"] == 9001
        assert restored["payload"]["display_name"] == "Alice"

    def test_round_trip_with_binary(self):
        """Binary bytes fields should be base64-encoded then decoded."""
        raw_key = b"\x00\x01\x02\xff" * 8
        msg = key_exchange_init("peer-2", ephemeral_public_key=raw_key)
        json_str = serialize(msg)

        # Verify the JSON contains a base64 string, not raw bytes
        parsed = json.loads(json_str)
        assert isinstance(parsed["payload"]["ephemeral_public_key"], str)

        restored = deserialize(json_str)
        assert restored["payload"]["ephemeral_public_key"] == raw_key

    def test_round_trip_file_list(self):
        files = [
            {"filename": "a.txt", "size": 100, "sha256_hash": "abc123"},
            {"filename": "b.txt", "size": 200, "sha256_hash": "def456"},
        ]
        msg = file_list_response("peer-3", files)
        json_str = serialize(msg)
        restored = deserialize(json_str)
        assert len(restored["payload"]["files"]) == 2
        assert restored["payload"]["files"][0]["filename"] == "a.txt"

    def test_deserialize_invalid_json(self):
        with pytest.raises(ProtocolError, match="Invalid JSON"):
            deserialize("not json{{{")

    def test_deserialize_non_object(self):
        with pytest.raises(ProtocolError, match="JSON object"):
            deserialize('"just a string"')


# ===================================================================
# Test: Message Builders
# ===================================================================

class TestMessageBuilders:
    """Test that each message builder creates valid messages."""

    def test_peer_announce(self):
        msg = peer_announce("p1", 9000)
        validate_message(msg)
        assert msg["type"] == MessageType.PEER_ANNOUNCE

    def test_peer_list_request(self):
        msg = peer_list_request("p1")
        validate_message(msg)

    def test_peer_list_response(self):
        msg = peer_list_response("p1", [{"peer_id": "p2", "address": "1.2.3.4", "port": 9000}])
        validate_message(msg)

    def test_key_exchange_init(self):
        msg = key_exchange_init("p1", ephemeral_public_key=b"fake-eph-key")
        validate_message(msg)

    def test_key_exchange_response(self):
        msg = key_exchange_response("p1", ephemeral_public_key=b"fake-eph",
                                    long_term_public_key=b"fake-lt",
                                    signature=b"fake-sig")
        validate_message(msg)

    def test_key_exchange_confirm(self):
        msg = key_exchange_confirm("p1", long_term_public_key=b"fake-lt",
                                   signature=b"fake-sig")
        validate_message(msg)

    def test_file_list_request(self):
        msg = file_list_request("p1")
        validate_message(msg)

    def test_file_list_response(self):
        msg = file_list_response("p1", [])
        validate_message(msg)

    def test_file_request(self):
        msg = file_request("p1", "file.txt", "abc123")
        validate_message(msg)

    def test_file_send(self):
        msg = file_send("p1", "file.txt", "abc123", data=b"hello world")
        validate_message(msg)

    def test_consent_request(self):
        msg = consent_request("p1", "file_send", "file.txt")
        validate_message(msg)

    def test_consent_response(self):
        msg = consent_response("p1", "req-001", True)
        validate_message(msg)

    def test_revoke_key(self):
        msg = revoke_key("p1", new_public_key=b"new-key")
        validate_message(msg)

    def test_error_message(self):
        msg = error_message("p1", "INVALID_SIGNATURE", "Signature verification failed")
        validate_message(msg)


# ===================================================================
# Test: Base64 Helpers
# ===================================================================

class TestBase64Helpers:
    """Test encode_bytes and decode_bytes."""

    def test_encode_decode_round_trip(self):
        data = b"\x00\x01\x02\xfe\xff"
        encoded = encode_bytes(data)
        assert isinstance(encoded, str)
        decoded = decode_bytes(encoded)
        assert decoded == data

    def test_decode_invalid_base64(self):
        with pytest.raises(ProtocolError, match="Invalid base64"):
            decode_bytes("!!!not-base64!!!")
