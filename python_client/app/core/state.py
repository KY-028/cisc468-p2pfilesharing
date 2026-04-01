"""
state.py — In-memory application state for the P2P client.

This module holds all runtime state in a single AppState object.
Every other module reads/writes state through this object.
Nothing here touches disk, network, or crypto — it's just data.

Reading order: Read this FIRST to understand the data model.
"""

import uuid
import json
import os
import time
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class PeerInfo:
    """Represents a discovered peer on the network."""
    peer_id: str                    # Unique identifier for this peer
    display_name: str               # Human-readable name
    address: str                    # IP address
    port: int                       # TCP port for P2P communication
    public_key_pem: Optional[str] = None   # PEM-encoded RSA public key (set after key exchange)
    fingerprint: Optional[str] = None      # SHA-256 fingerprint of the public key
    trusted: bool = False           # True if user has verified the fingerprint
    online: bool = True             # True if the peer is currently reachable
    last_seen: float = 0.0         # Timestamp of last contact


@dataclass
class SharedFile:
    """Represents a file available for sharing."""
    filename: str                   # Original filename
    filepath: str                   # Full path on disk
    size: int                       # File size in bytes
    sha256_hash: str                # SHA-256 hash of the file contents
    owner_id: str                   # Peer ID of the original owner
    signature: Optional[str] = None # Owner's signature over the hash (base64)


@dataclass
class TransferRecord:
    """Tracks the status of a file transfer."""
    transfer_id: str                # Unique transfer ID
    filename: str                   # Name of the file being transferred
    peer_id: str                    # The other peer involved
    direction: str                  # "incoming" or "outgoing"
    status: str                     # "pending", "approved", "denied", "transferring", "complete", "failed"
    error: Optional[str] = None     # Error message if status is "failed"
    timestamp: float = 0.0         # When the transfer was initiated


@dataclass
class ConsentRequest:
    """An incoming request that needs user approval."""
    request_id: str                 # Unique ID for this consent request
    peer_id: str                    # Who is asking
    peer_name: str                  # Display name of the peer
    action: str                     # "file_request" or "file_send"
    filename: str                   # Which file
    file_hash: Optional[str] = None # Hash of the file (for verification)
    timestamp: float = 0.0         # When the request arrived


@dataclass
class StatusMessage:
    """A status or error message for the UI."""
    message: str                    # The message text
    level: str                      # "info", "success", "warning", "error"
    timestamp: float = 0.0         # When it was created


class AppState:
    """
    Central application state.

    All mutable state lives here. Modules that need to read or update state
    receive a reference to this object. This keeps state management in one
    place and makes the app easier to reason about.
    """

    def __init__(self):
        # --- Identity ---
        # Generate a random peer ID on startup.
        # In later phases, this will be tied to the RSA key pair.
        self.peer_id: str = f"peer-{uuid.uuid4().hex[:8]}"
        self.display_name: str = self.peer_id
        self.public_key_pem: Optional[str] = None    # RSA-2048 public key (PEM)
        self.private_key_pem: Optional[str] = None   # RSA-2048 private key (PEM)
        self.fingerprint: Optional[str] = None       # SHA-256 fingerprint of public key

        # --- Peers ---
        # Maps peer_id -> PeerInfo for all discovered peers.
        self.peers: dict[str, PeerInfo] = {}

        # --- Files ---
        # List of files this peer is sharing.
        self.shared_files: list[SharedFile] = []

        # --- Transfers ---
        # List of all transfer records (active and completed).
        self.transfers: list[TransferRecord] = []

        # --- Consent ---
        # Pending consent requests from other peers.
        self.pending_consents: list[ConsentRequest] = []

        # --- Status log ---
        # Recent status/error messages for the UI.
        self.status_log: list[StatusMessage] = []

        # List of peers awaiting manual verification code confirmation
        self.pending_verifications: list[dict] = []

        # Mutual verification tracking
        self.verify_confirmed_by_me: set[str] = set()    # peer_ids we locally confirmed
        self.verify_confirmed_by_peer: set[str] = set()  # peer_ids that sent us VERIFY_CONFIRM

        # Directory for persisting trust records (set by init_trust_storage)
        self._trust_file: Optional[str] = None

    # ----- Trust persistence -----

    def init_trust_storage(self, data_dir: str) -> None:
        """Set the file path for trust persistence and load saved records."""
        self._trust_file = os.path.join(data_dir, "trusted_peers.json")
        self._load_trusted_peers()

    def _load_trusted_peers(self) -> None:
        """Load trusted peer records from disk."""
        if not self._trust_file or not os.path.isfile(self._trust_file):
            return
        try:
            with open(self._trust_file, "r", encoding="utf-8") as f:
                records = json.load(f)
            for peer_id, info in records.items():
                peer = self.peers.get(peer_id)
                if not peer:
                    # Create an offline placeholder so trust survives until
                    # the peer is re-discovered via mDNS.
                    peer = PeerInfo(
                        peer_id=peer_id,
                        display_name=peer_id,
                        address=info.get("address", ""),
                        port=info.get("port", 0),
                        trusted=True,
                        online=False,
                        fingerprint=info.get("fingerprint"),
                        public_key_pem=info.get("public_key_pem"),
                    )
                    self.peers[peer_id] = peer
                else:
                    peer.trusted = True
                    if info.get("fingerprint"):
                        peer.fingerprint = info["fingerprint"]
                    if info.get("public_key_pem"):
                        peer.public_key_pem = info["public_key_pem"]
        except Exception:
            pass

    def save_trusted_peers(self) -> None:
        """Persist all trusted peer records to disk."""
        if not self._trust_file:
            return
        records = {}
        for peer_id, peer in self.peers.items():
            if peer.trusted:
                records[peer_id] = {
                    "address": peer.address,
                    "port": peer.port,
                    "fingerprint": peer.fingerprint,
                    "public_key_pem": peer.public_key_pem,
                }
        try:
            with open(self._trust_file, "w", encoding="utf-8") as f:
                json.dump(records, f)
        except Exception:
            pass

    def add_status(self, message: str, level: str = "info") -> None:
        """Add a status message to the log."""
        self.status_log.append(StatusMessage(
            message=message,
            level=level,
            timestamp=time.time()
        ))
        # Keep only the last 50 messages to avoid unbounded growth.
        if len(self.status_log) > 50:
            self.status_log = self.status_log[-50:]

    def add_consent_request(self, peer_id: str, peer_name: str,
                            action: str, filename: str,
                            file_hash: str = None) -> str:
        """
        Create a new consent request and return its ID.
        The UI will display this and let the user accept or deny.
        """
        request_id = uuid.uuid4().hex[:12]
        self.pending_consents.append(ConsentRequest(
            request_id=request_id,
            peer_id=peer_id,
            peer_name=peer_name,
            action=action,
            filename=filename,
            file_hash=file_hash,
            timestamp=time.time()
        ))
        return request_id

    def resolve_consent(self, request_id: str, approved: bool) -> Optional[ConsentRequest]:
        """
        Remove a consent request and return it.
        Returns None if the request_id wasn't found.
        """
        for i, req in enumerate(self.pending_consents):
            if req.request_id == request_id:
                return self.pending_consents.pop(i)
        return None


# ---------------------------------------------------------------------------
# Module-level singleton.
# Import `from app.core.state import app_state` anywhere to access it.
# ---------------------------------------------------------------------------
app_state = AppState()
