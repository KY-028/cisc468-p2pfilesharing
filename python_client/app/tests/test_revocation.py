"""
test_revocation.py — Tests for identity key rotation and revocation handling.

Covers Requirement 6 behaviors:
  - Local key rotation changes identity key/fingerprint
  - Existing sessions are cleared on rotation
  - Peers are notified and accounting is returned
  - Incoming revocations must carry a valid cross-signature
  - Peer trust is reset and sessions invalidated after valid rotation notice
"""

from app.core.revocation import rotate_key, handle_revoke_key
from app.core.state import app_state, PeerInfo
from app.crypto.keys import (
    generate_rsa_keypair,
    serialize_public_key,
    save_private_key,
    get_fingerprint,
)
from app.crypto.sign import sign_data
from app.storage.manifests import store_manifest


class TestRotateKey:
    def setup_method(self):
        self._saved = {
            "peers": dict(app_state.peers),
            "private_key_pem": app_state.private_key_pem,
            "public_key_pem": app_state.public_key_pem,
            "fingerprint": app_state.fingerprint,
            "_private_key": getattr(app_state, "_private_key", None),
            "_public_key": getattr(app_state, "_public_key", None),
            "status_log": list(app_state.status_log),
        }
        app_state.peers = {}
        app_state.status_log = []

    def teardown_method(self):
        app_state.peers = self._saved["peers"]
        app_state.private_key_pem = self._saved["private_key_pem"]
        app_state.public_key_pem = self._saved["public_key_pem"]
        app_state.fingerprint = self._saved["fingerprint"]
        app_state._private_key = self._saved["_private_key"]
        app_state._public_key = self._saved["_public_key"]
        app_state.status_log = self._saved["status_log"]

    def test_rotate_key_updates_identity_and_notifies_peers(self, tmp_path, monkeypatch):
        initial_private, initial_public = generate_rsa_keypair()
        key_file = tmp_path / "identity_key.pem"
        save_private_key(initial_private, str(key_file))

        app_state.private_key_pem = str(key_file)
        app_state._private_key = initial_private
        app_state._public_key = initial_public
        app_state.public_key_pem = serialize_public_key(initial_public).decode("utf-8")
        app_state.fingerprint = get_fingerprint(initial_public)

        app_state.peers = {
            "peer-a": PeerInfo("peer-a", "Peer A", "127.0.0.1", 9000, trusted=True),
            "peer-b": PeerInfo("peer-b", "Peer B", "127.0.0.1", 9001, trusted=True),
        }

        notified = []
        cleared = {"called": False}

        def fake_notify(peer, new_pub_pem, cross_signature):
            assert isinstance(new_pub_pem, bytes)
            assert isinstance(cross_signature, bytes)
            notified.append(peer.peer_id)

        def fake_clear_all_sessions():
            cleared["called"] = True

        monkeypatch.setattr("app.core.revocation._notify_peer_of_revocation", fake_notify)
        monkeypatch.setattr("app.core.sessions.clear_all_sessions", fake_clear_all_sessions)

        old_fingerprint = app_state.fingerprint
        result = rotate_key()

        assert result["old_fingerprint"] == old_fingerprint
        assert result["new_fingerprint"]
        assert result["new_fingerprint"] != old_fingerprint
        assert result["peers_notified"] == 2
        assert result["errors"] == []
        assert set(notified) == {"peer-a", "peer-b"}
        assert cleared["called"] is True
        assert app_state.peers["peer-a"].trusted is False
        assert app_state.peers["peer-b"].trusted is False

        assert key_file.is_file()
        assert (tmp_path / "identity_key.old.pem").is_file()

    def test_rotate_key_removes_offline_peers_and_clears_verify_tracking(self, tmp_path, monkeypatch):
        initial_private, initial_public = generate_rsa_keypair()
        key_file = tmp_path / "identity_key.pem"
        save_private_key(initial_private, str(key_file))

        manifest_dir = tmp_path / "manifests"
        manifest_dir.mkdir(parents=True, exist_ok=True)
        monkeypatch.setattr("app.storage.manifests._manifest_dir", str(manifest_dir), raising=False)

        app_state.private_key_pem = str(key_file)
        app_state._private_key = initial_private
        app_state._public_key = initial_public
        app_state.public_key_pem = serialize_public_key(initial_public).decode("utf-8")
        app_state.fingerprint = get_fingerprint(initial_public)

        app_state.peers = {
            "peer-online": PeerInfo("peer-online", "Online", "127.0.0.1", 9000, trusted=True, online=True),
            "peer-offline": PeerInfo("peer-offline", "Offline", "127.0.0.1", 9001, trusted=True, online=False),
        }
        app_state.pending_verifications = [{"peer_id": "peer-online"}, {"peer_id": "peer-offline"}]
        app_state.verify_confirmed_by_me = {"peer-online", "peer-offline"}
        app_state.verify_confirmed_by_peer = {"peer-online", "peer-offline"}
        store_manifest("peer-offline", [{
            "filename": "a.txt",
            "size": 1,
            "sha256_hash": "abc",
            "owner_id": "peer-offline",
        }])
        offline_manifest_path = manifest_dir / "peer-offline.json"
        assert offline_manifest_path.is_file()

        monkeypatch.setattr("app.core.revocation._notify_peer_of_revocation", lambda *args, **kwargs: None)
        monkeypatch.setattr("app.core.sessions.clear_all_sessions", lambda: None)

        rotate_key()

        assert "peer-online" in app_state.peers
        assert app_state.peers["peer-online"].trusted is False
        assert "peer-offline" not in app_state.peers
        assert not offline_manifest_path.exists()
        assert app_state.pending_verifications == []
        assert app_state.verify_confirmed_by_me == set()
        assert app_state.verify_confirmed_by_peer == set()

    def test_rotate_key_requires_existing_private_key(self):
        app_state._private_key = None
        app_state.fingerprint = "00:11:22"

        result = rotate_key()
        assert "No existing private key found." in result["errors"]


class TestHandleRevokeKey:
    def setup_method(self):
        self._saved = {
            "peers": dict(app_state.peers),
            "status_log": list(app_state.status_log),
        }
        app_state.peers = {}
        app_state.status_log = []

    def teardown_method(self):
        app_state.peers = self._saved["peers"]
        app_state.status_log = self._saved["status_log"]

    def test_handle_revoke_key_valid_signature_updates_peer_and_resets_trust(self, monkeypatch):
        old_private, old_public = generate_rsa_keypair()
        _, new_public = generate_rsa_keypair()

        peer_id = "peer-rotating"
        old_public_pem = serialize_public_key(old_public).decode("utf-8")
        new_public_pem = serialize_public_key(new_public)
        cross_sig = sign_data(old_private, new_public_pem)

        app_state.peers[peer_id] = PeerInfo(
            peer_id=peer_id,
            display_name="Rotating Peer",
            address="127.0.0.1",
            port=9010,
            public_key_pem=old_public_pem,
            fingerprint=get_fingerprint(old_public),
            trusted=True,
            online=True,
        )

        removed = {"peer_id": None}

        def fake_remove_session(pid):
            removed["peer_id"] = pid

        monkeypatch.setattr("app.core.sessions.remove_session", fake_remove_session)

        msg = {
            "type": "REVOKE_KEY",
            "payload": {
                "peer_id": peer_id,
                "new_public_key": new_public_pem,
                "cross_signature": cross_sig,
            },
        }

        handle_revoke_key(msg, None, ("127.0.0.1", 9000))

        peer = app_state.peers[peer_id]
        assert peer.public_key_pem == new_public_pem.decode("utf-8")
        assert peer.fingerprint == get_fingerprint(new_public)
        assert peer.trusted is False
        assert removed["peer_id"] == peer_id

    def test_handle_revoke_key_invalid_signature_keeps_existing_trust_state(self, monkeypatch):
        old_private, old_public = generate_rsa_keypair()
        _, new_public = generate_rsa_keypair()

        peer_id = "peer-invalid"
        old_public_pem = serialize_public_key(old_public).decode("utf-8")
        new_public_pem = serialize_public_key(new_public)

        app_state.peers[peer_id] = PeerInfo(
            peer_id=peer_id,
            display_name="Invalid Signature Peer",
            address="127.0.0.1",
            port=9011,
            public_key_pem=old_public_pem,
            fingerprint=get_fingerprint(old_public),
            trusted=True,
            online=True,
        )

        removed = {"called": False}

        def fake_remove_session(_):
            removed["called"] = True

        monkeypatch.setattr("app.core.sessions.remove_session", fake_remove_session)

        msg = {
            "type": "REVOKE_KEY",
            "payload": {
                "peer_id": peer_id,
                "new_public_key": new_public_pem,
                "cross_signature": b"invalid-signature",
            },
        }

        handle_revoke_key(msg, None, ("127.0.0.1", 9000))

        peer = app_state.peers[peer_id]
        assert peer.public_key_pem == old_public_pem
        assert peer.fingerprint == get_fingerprint(old_public)
        assert peer.trusted is True
        assert removed["called"] is False
