"""
discovery.py — mDNS peer discovery using zeroconf.

Advertises this peer as a service on the local network and discovers
other peers running the same service. Uses the `_p2pshare._tcp.local.`
service type.

When a peer is discovered, it's added to app_state.peers.
When a peer disappears, it's removed.

Reading order: Read transport.py first, then this file.
"""

import socket
import logging
import threading
import time
from zeroconf import ServiceBrowser, ServiceInfo, Zeroconf, ServiceStateChange
from app.core.state import app_state, PeerInfo

logger = logging.getLogger(__name__)

# mDNS service type for our P2P application
SERVICE_TYPE = "_p2pshare._tcp.local."


class PeerDiscovery:
    """
    Handles mDNS service advertisement and peer discovery.

    Usage:
        discovery = PeerDiscovery(peer_id="peer-abc", tcp_port=9000)
        discovery.start()     # Advertise + start browsing
        # ... peers appear in app_state.peers ...
        discovery.stop()      # Cleanup
    """

    def __init__(self, peer_id: str, tcp_port: int):
        """
        Args:
            peer_id: This peer's unique identifier.
            tcp_port: The TCP port this peer listens on for P2P connections.
        """
        self.peer_id = peer_id
        self.tcp_port = tcp_port
        self._zeroconf: Zeroconf = None
        self._browser: ServiceBrowser = None
        self._service_info: ServiceInfo = None

    def start(self) -> None:
        """
        Start advertising our service and browsing for others.

        Creates a Zeroconf instance, registers our service, and starts
        a ServiceBrowser that watches for other peers.
        """
        self._zeroconf = Zeroconf()

        # Get our local IP address for the service registration
        local_ip = self._get_local_ip()

        # Build the service info for this peer
        service_name = f"{self.peer_id}.{SERVICE_TYPE}"
        self._service_info = ServiceInfo(
            type_=SERVICE_TYPE,
            name=service_name,
            addresses=[socket.inet_aton(local_ip)],
            port=self.tcp_port,
            properties={
                b"peer_id": self.peer_id.encode("utf-8"),
            },
        )

        # Register our service (advertise)
        self._zeroconf.register_service(self._service_info)
        logger.info(f"mDNS: Advertising as '{service_name}' on {local_ip}:{self.tcp_port}")
        app_state.add_status(
            f"Advertising on network as {self.peer_id} ({local_ip}:{self.tcp_port})",
            level="success"
        )

        # Start browsing for other peers
        self._browser = ServiceBrowser(
            self._zeroconf,
            SERVICE_TYPE,
            handlers=[self._on_service_state_change],
        )
        logger.info("mDNS: Browsing for peers...")

    def stop(self) -> None:
        """Stop discovery and unregister our service."""
        if self._service_info and self._zeroconf:
            self._zeroconf.unregister_service(self._service_info)
        if self._zeroconf:
            self._zeroconf.close()
            self._zeroconf = None
        self._browser = None
        logger.info("mDNS: Discovery stopped")

    def _on_service_state_change(self, zeroconf: Zeroconf,
                                  service_type: str,
                                  name: str,
                                  state_change: ServiceStateChange) -> None:
        """
        Callback fired when a service is added, removed, or updated.

        This runs on zeroconf's internal thread, so updates to app_state
        should be thread-safe (Python's GIL makes dict ops atomic enough
        for our purposes).
        """
        if state_change == ServiceStateChange.Added:
            # Peer appeared — look up its details
            info = zeroconf.get_service_info(service_type, name, timeout=3000)
            if info is None:
                return

            peer_id = self._extract_peer_id(info)
            if peer_id == self.peer_id:
                return  # Don't discover ourselves

            # Get the first IPv4 address
            addresses = info.parsed_addresses()
            if not addresses:
                return
            address = addresses[0]  # Use the first address

            # Preserve trusted status if peer was previously known
            existing = app_state.peers.get(peer_id)
            trusted = existing.trusted if existing else False
            fingerprint = existing.fingerprint if existing else None
            public_key_pem = existing.public_key_pem if existing else None

            peer = PeerInfo(
                peer_id=peer_id,
                display_name=peer_id,
                address=address,
                port=info.port,
                trusted=trusted,
                online=True,
                fingerprint=fingerprint,
                public_key_pem=public_key_pem,
                last_seen=time.time(),
            )
            app_state.peers[peer_id] = peer
            if trusted:
                app_state.add_status(
                    f"Trusted peer back online: {peer_id} at {address}:{info.port}",
                    level="success"
                )
            else:
                app_state.add_status(
                    f"Discovered peer: {peer_id} at {address}:{info.port}",
                    level="success"
                )
            logger.info(f"mDNS: Discovered {peer_id} at {address}:{info.port}")

        elif state_change == ServiceStateChange.Removed:
            # Peer disappeared — mark offline instead of removing
            peer_id = self._extract_peer_id_from_name(name)
            if peer_id and peer_id in app_state.peers:
                app_state.peers[peer_id].online = False
                app_state.add_status(f"Peer went offline: {peer_id}", level="warning")
                logger.info(f"mDNS: Peer offline: {peer_id}")

    def _extract_peer_id(self, info: ServiceInfo) -> str:
        """Extract the peer_id from service properties or name."""
        props = info.properties or {}
        if b"peer_id" in props:
            return props[b"peer_id"].decode("utf-8")
        return self._extract_peer_id_from_name(info.name)

    def _extract_peer_id_from_name(self, name: str) -> str:
        """Extract peer_id from the service name (the part before the service type)."""
        # Name format: "peer-abc._p2pshare._tcp.local."
        return name.replace(f".{SERVICE_TYPE}", "").strip(".")

    def _get_local_ip(self) -> str:
        """
        Get this machine's local IP address.

        Connects to a well-known address to determine which local interface
        would be used, without actually sending any data.
        """
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"
