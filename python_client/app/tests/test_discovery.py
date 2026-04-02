"""Tests for mDNS discovery peer deduplication behavior."""

from zeroconf import ServiceStateChange
from app.network.discovery import PeerDiscovery
from app.core.state import app_state, PeerInfo


class _FakeServiceInfo:
    def __init__(self, peer_id: str, address: str, port: int):
        self.properties = {b"peer_id": peer_id.encode("utf-8")}
        self._address = address
        self.port = port
        self.name = f"{peer_id}._p2pshare._tcp.local."

    def parsed_addresses(self):
        return [self._address]


class _FakeZeroconf:
    def __init__(self, info):
        self._info = info

    def get_service_info(self, service_type, name, timeout=3000):
        return self._info


class TestDiscoveryDeduplication:
    def setup_method(self):
        self._saved = {
            "peers": dict(app_state.peers),
            "pending_verifications": list(app_state.pending_verifications),
            "verify_confirmed_by_me": set(app_state.verify_confirmed_by_me),
            "verify_confirmed_by_peer": set(app_state.verify_confirmed_by_peer),
            "status_log": list(app_state.status_log),
        }
        app_state.peers = {}
        app_state.pending_verifications = []
        app_state.verify_confirmed_by_me = set()
        app_state.verify_confirmed_by_peer = set()
        app_state.status_log = []

    def teardown_method(self):
        app_state.peers = self._saved["peers"]
        app_state.pending_verifications = self._saved["pending_verifications"]
        app_state.verify_confirmed_by_me = self._saved["verify_confirmed_by_me"]
        app_state.verify_confirmed_by_peer = self._saved["verify_confirmed_by_peer"]
        app_state.status_log = self._saved["status_log"]

    def test_added_peer_deduplicates_existing_same_endpoint(self, monkeypatch):
        app_state.peers = {
            "peer-old": PeerInfo("peer-old", "Old", "192.168.2.14", 9000, trusted=True, online=True),
        }
        app_state.pending_verifications = [{"peer_id": "peer-old", "code": "12345"}]
        app_state.verify_confirmed_by_me = {"peer-old"}
        app_state.verify_confirmed_by_peer = {"peer-old"}

        removed_manifests = []
        monkeypatch.setattr(
            "app.storage.manifests.clear_manifest",
            lambda peer_id: removed_manifests.append(peer_id),
        )

        discovery = PeerDiscovery(peer_id="self-peer", tcp_port=9000)
        info = _FakeServiceInfo("peer-new", "192.168.2.14", 9000)
        zc = _FakeZeroconf(info)

        discovery._on_service_state_change(
            zc,
            "_p2pshare._tcp.local.",
            info.name,
            ServiceStateChange.Added,
        )

        assert "peer-old" not in app_state.peers
        assert "peer-new" in app_state.peers
        assert app_state.peers["peer-new"].address == "192.168.2.14"
        assert app_state.peers["peer-new"].port == 9000
        assert removed_manifests == ["peer-old"]
        assert app_state.pending_verifications == []
        assert app_state.verify_confirmed_by_me == set()
        assert app_state.verify_confirmed_by_peer == set()
