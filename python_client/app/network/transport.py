"""
transport.py — TCP socket transport layer for P2P communication.

Wire format:
  [4 bytes: big-endian uint32 length] [N bytes: UTF-8 JSON]

This module provides:
  - TCPServer: listens for incoming connections on a background thread
  - send_message(): connects to a peer and sends a single message
  - receive_message(): reads a single message from a connection

The transport layer is protocol-agnostic — it just moves JSON messages.
Message validation happens in protocol.py.

Reading order: Read protocol.py first, then this file.
"""

import socket
import struct
import threading
import logging
from typing import Callable, Optional
from app.core.protocol import serialize, deserialize, ProtocolError

logger = logging.getLogger(__name__)


MAX_MESSAGE_SIZE = 64 * 1024 * 1024


HEADER_FORMAT = "!I"
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)



def send_message(sock: socket.socket, msg: dict) -> None:
    """
    Send a protocol message over a TCP socket.

    Serializes the message to JSON, prepends a 4-byte length header,
    and sends everything.

    Args:
        sock: An open, connected socket.
        msg: A valid protocol message dict.

    Raises:
        ProtocolError: If serialization fails.
        OSError: If the send fails.
    """
    json_str = serialize(msg)
    payload = json_str.encode("utf-8")
    logger.info(f"transport.send_message → type={msg.get('type', '?')}, {len(payload)} bytes")
    header = struct.pack(HEADER_FORMAT, len(payload))
    sock.sendall(header + payload)


def receive_message(sock: socket.socket) -> Optional[dict]:
    """
    Receive a single protocol message from a TCP socket.

    Reads the 4-byte length header, then reads exactly that many bytes,
    deserializes the JSON, and validates the message.

    Args:
        sock: An open, connected socket.

    Returns:
        A validated message dict, or None if the connection closed cleanly.

    Raises:
        ProtocolError: If the message is invalid.
        ConnectionError: If the connection is broken mid-read.
    """
   
    header_data = _recv_exactly(sock, HEADER_SIZE)
    if header_data is None:
        return None  

    length = struct.unpack(HEADER_FORMAT, header_data)[0]

    if length > MAX_MESSAGE_SIZE:
        raise ProtocolError(f"Message too large: {length} bytes (max {MAX_MESSAGE_SIZE})")

    if length == 0:
        raise ProtocolError("Empty message received")

    
    payload_data = _recv_exactly(sock, length)
    if payload_data is None:
        raise ConnectionError("Connection closed while reading message body")

    json_str = payload_data.decode("utf-8")
    return deserialize(json_str)


def _recv_exactly(sock: socket.socket, num_bytes: int) -> Optional[bytes]:
    """
    Read exactly num_bytes from a socket.

    Returns None if the connection closes before any data is read.
    Raises ConnectionError if the connection closes partway through.
    """
    data = bytearray()
    while len(data) < num_bytes:
        chunk = sock.recv(num_bytes - len(data))
        if not chunk:
            if not data:
                return None  
            raise ConnectionError("Connection closed mid-read")
        data.extend(chunk)
    return bytes(data)



def send_to_peer(address: str, port: int, msg: dict, timeout: float = 10.0) -> None:
    """
    Open a TCP connection, send one message, and close.

    This is the simplest way to send a message to a peer.
    For multi-message exchanges (like the STS handshake), use
    the socket directly.

    Args:
        address: Peer's IP address.
        port: Peer's TCP port.
        msg: The protocol message to send.
        timeout: Connection timeout in seconds.
    """
    with socket.create_connection((address, port), timeout=timeout) as sock:
        send_message(sock, msg)



class TCPServer:
    """
    A TCP server that listens for incoming peer connections.

    Each incoming connection is handled in a separate thread.
    The handler callback receives the client socket and address.

    Usage:
        def on_connection(sock, addr):
            msg = receive_message(sock)
            # ... handle message ...

        server = TCPServer("0.0.0.0", 9000, on_connection)
        server.start()   # starts listening in background
        # ... later ...
        server.stop()     # stops accepting new connections
    """

    def __init__(self, host: str, port: int,
                 handler: Callable[[socket.socket, tuple], None]):
        """
        Args:
            host: Address to bind (e.g., "0.0.0.0" for all interfaces).
            port: Port to listen on.
            handler: Callback function(sock, address) for each connection.
        """
        self.host = host
        self.port = port
        self.handler = handler
        self._server_socket: Optional[socket.socket] = None
        self._running = False
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        """Start listening in a background thread."""
        self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_socket.bind((self.host, self.port))
        self._server_socket.listen(5)
        self._server_socket.settimeout(1.0)  
        self._running = True

        self._thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._thread.start()
        logger.info(f"TCP server listening on {self.host}:{self.port}")

    def stop(self) -> None:
        """Stop accepting new connections and close the server socket."""
        self._running = False
        if self._server_socket:
            self._server_socket.close()
            self._server_socket = None
        if self._thread:
            self._thread.join(timeout=3.0)
            self._thread = None
        logger.info("TCP server stopped")

    @property
    def is_running(self) -> bool:
        return self._running

    def _accept_loop(self) -> None:
        """Main accept loop, runs in the background thread."""
        while self._running:
            try:
                client_sock, client_addr = self._server_socket.accept()
               
                t = threading.Thread(
                    target=self._handle_client,
                    args=(client_sock, client_addr),
                    daemon=True,
                )
                t.start()
            except socket.timeout:
                continue 
            except OSError:
                if self._running:
                    logger.error("Server socket error", exc_info=True)
                break  
    def _handle_client(self, client_sock: socket.socket, client_addr: tuple) -> None:
        """Wrapper that calls the handler and ensures the socket is closed."""
        try:
            self.handler(client_sock, client_addr)
        except Exception as e:
            logger.error(f"Error handling connection from {client_addr}: {e}")
        finally:
            try:
                client_sock.close()
            except OSError:
                pass
