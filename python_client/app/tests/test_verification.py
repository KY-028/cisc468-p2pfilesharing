"""
test_verification.py — Tests for third-party file verification.

Tests cover:
  - Verifying a file with correct hash + valid owner signature
  - Verifying with wrong hash
  - Verifying with tampered signature
  - Verifying with missing signature
  - Manifest entry verification

Run:  pytest app/tests/test_verification.py -v
"""

import base64
import pytest
from app.crypto.keys import generate_rsa_keypair, serialize_public_key, get_fingerprint
from app.crypto.sign import sign_data
from app.crypto.hashing import sha256_hash
from app.core.state import app_state, PeerInfo
from app.core.verification import verify_received_file, verify_manifest_entry
from app.storage.manifests import store_manifest, clear_manifest


class TestVerifyReceivedFile:
    """Test full file verification (hash + signature)."""

    def setup_method(self):
        """Generate a test key pair and set up app_state."""
        self.priv_key, self.pub_key = generate_rsa_keypair()
        self.pub_pem = serialize_public_key(self.pub_key).decode("utf-8")
        self.owner_id = "owner-test"


        app_state.peers[self.owner_id] = PeerInfo(
            peer_id=self.owner_id,
            display_name="Owner",
            address="127.0.0.1",
            port=9000,
            public_key_pem=self.pub_pem,
            fingerprint=get_fingerprint(self.pub_key),
        )

    def teardown_method(self):
        app_state.peers.pop(self.owner_id, None)

    def test_valid_file(self):
        """File with correct hash and valid signature should pass."""
        data = b"Test file content"
        file_hash = sha256_hash(data)
        sig = sign_data(self.priv_key, file_hash.encode("utf-8"))
        sig_b64 = base64.b64encode(sig).decode("ascii")

        result = verify_received_file(data, file_hash, sig_b64, self.owner_id)
        assert result["hash_valid"] is True
        assert result["signature_valid"] is True
        assert len(result["errors"]) == 0

    def test_wrong_hash(self):
        """File with wrong hash should fail."""
        data = b"Real content"
        wrong_hash = "a" * 64

        result = verify_received_file(data, wrong_hash, "", self.owner_id)
        assert result["hash_valid"] is False
        assert len(result["errors"]) > 0

    def test_tampered_signature(self):
        """Valid hash but tampered signature should fail."""
        data = b"Test data"
        file_hash = sha256_hash(data)
        bad_sig = base64.b64encode(b"fake-signature").decode("ascii")

        result = verify_received_file(data, file_hash, bad_sig, self.owner_id)
        assert result["hash_valid"] is True
        assert result["signature_valid"] is False

    def test_missing_signature(self):
        """Valid hash but no signature should note the absence."""
        data = b"Some data"
        file_hash = sha256_hash(data)

        result = verify_received_file(data, file_hash, "", self.owner_id)
        assert result["hash_valid"] is True
        assert result["signature_valid"] is False
        assert any("No owner signature" in e for e in result["errors"])

    def test_unknown_owner(self):
        """Valid hash but unknown owner should note the issue."""
        data = b"Data"
        file_hash = sha256_hash(data)
        sig = sign_data(self.priv_key, file_hash.encode("utf-8"))
        sig_b64 = base64.b64encode(sig).decode("ascii")

        result = verify_received_file(data, file_hash, sig_b64, "unknown-peer")
        assert result["hash_valid"] is True
        assert result["signature_valid"] is False
        assert any("not found" in e for e in result["errors"])


class TestVerifyManifestEntry:
    """Test manifest-level verification."""

    def setup_method(self):
        self.priv_key, self.pub_key = generate_rsa_keypair()
        self.pub_pem = serialize_public_key(self.pub_key).decode("utf-8")
        self.peer_id = "manifest-peer"
        app_state.peers[self.peer_id] = PeerInfo(
            peer_id=self.peer_id,
            display_name="ManifestPeer",
            address="127.0.0.1",
            port=9000,
            public_key_pem=self.pub_pem,
        )

    def teardown_method(self):
        app_state.peers.pop(self.peer_id, None)
        clear_manifest(self.peer_id)

    def test_manifest_with_valid_signature(self):
        """File in manifest with valid signature should verify."""
        file_hash = sha256_hash(b"file content")
        sig = sign_data(self.priv_key, file_hash.encode("utf-8"))
        sig_b64 = base64.b64encode(sig).decode("ascii")

        store_manifest(self.peer_id, [{
            "filename": "test.txt",
            "size": 100,
            "sha256_hash": file_hash,
            "owner_id": self.peer_id,
            "signature": sig_b64,
        }])

        result = verify_manifest_entry(self.peer_id, "test.txt")
        assert result is not None
        assert result["signature_valid"] is True

    def test_manifest_without_signature(self):
        """File without signature should note the absence."""
        store_manifest(self.peer_id, [{
            "filename": "nosig.txt",
            "size": 50,
            "sha256_hash": "abc123",
            "owner_id": self.peer_id,
        }])

        result = verify_manifest_entry(self.peer_id, "nosig.txt")
        assert result is not None
        assert result["signature_valid"] is None  

    def test_manifest_file_not_found(self):
        """Non-existent file should return None."""
        store_manifest(self.peer_id, [])
        result = verify_manifest_entry(self.peer_id, "nonexistent.txt")
        assert result is None
