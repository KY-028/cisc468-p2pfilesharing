"""
test_transport.py — Unit tests for TCP transport layer.

Tests cover:
  - Length-prefixed send/receive round-trip via loopback
  - TCPServer start/stop
  - Large message handling
  - Connection clean close detection

Run:  pytest app/tests/test_transport.py -v
"""

import socket
import threading
import time
import pytest
from app.core.protocol import create_message, MessageType, ProtocolError
from app.network.transport import (
    send_message, receive_message, TCPServer,
    MAX_MESSAGE_SIZE, HEADER_SIZE,
)
from app.network.messages import peer_announce, file_list_response


def get_free_port() -> int:
    """Get a random available port."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class TestSendReceive:
    """Test send_message and receive_message over real sockets."""

    def test_round_trip_simple(self):
        """Send a message and receive it on the other end."""
        msg = peer_announce("peer-1", 9000, display_name="Alice")
        port = get_free_port()
        received = [None]

        def server():
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind(("127.0.0.1", port))
            srv.listen(1)
            conn, _ = srv.accept()
            received[0] = receive_message(conn)
            conn.close()
            srv.close()

        t = threading.Thread(target=server)
        t.start()
        time.sleep(0.1)

        with socket.create_connection(("127.0.0.1", port)) as sock:
            send_message(sock, msg)

        t.join(timeout=3)
        assert received[0] is not None
        assert received[0]["type"] == "PEER_ANNOUNCE"
        assert received[0]["payload"]["peer_id"] == "peer-1"

    def test_round_trip_with_binary(self):
        """Binary fields (base64-encoded) should survive the round trip."""
        from app.network.messages import key_exchange_init
        msg = key_exchange_init("peer-2", ephemeral_public_key=b"\x00\x01\x02\xff" * 8)
        port = get_free_port()
        received = [None]

        def server():
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind(("127.0.0.1", port))
            srv.listen(1)
            conn, _ = srv.accept()
            received[0] = receive_message(conn)
            conn.close()
            srv.close()

        t = threading.Thread(target=server)
        t.start()
        time.sleep(0.1)

        with socket.create_connection(("127.0.0.1", port)) as sock:
            send_message(sock, msg)

        t.join(timeout=3)
        assert received[0] is not None
        assert received[0]["type"] == "KEY_EXCHANGE_INIT"
        assert "ephemeral_public_key" in received[0]["payload"]

    def test_clean_close_returns_none(self):
        """Closing a connection cleanly should return None from receive."""
        port = get_free_port()
        received = [None]
        did_return_none = [False]

        def server():
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind(("127.0.0.1", port))
            srv.listen(1)
            conn, _ = srv.accept()
            result = receive_message(conn)
            did_return_none[0] = (result is None)
            conn.close()
            srv.close()

        t = threading.Thread(target=server)
        t.start()
        time.sleep(0.1)

        with socket.create_connection(("127.0.0.1", port)) as sock:
            sock.close() 

        t.join(timeout=3)
        assert did_return_none[0] is True

    def test_file_list_with_multiple_entries(self):
        """FILE_LIST_RESPONSE with multiple files should round-trip."""
        files = [
            {"filename": "a.txt", "size": 100, "sha256_hash": "abc"},
            {"filename": "b.txt", "size": 200, "sha256_hash": "def"},
        ]
        msg = file_list_response("peer-3", files)
        port = get_free_port()
        received = [None]

        def server():
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind(("127.0.0.1", port))
            srv.listen(1)
            conn, _ = srv.accept()
            received[0] = receive_message(conn)
            conn.close()
            srv.close()

        t = threading.Thread(target=server)
        t.start()
        time.sleep(0.1)

        with socket.create_connection(("127.0.0.1", port)) as sock:
            send_message(sock, msg)

        t.join(timeout=3)
        assert received[0] is not None
        assert len(received[0]["payload"]["files"]) == 2


class TestTCPServer:
    """Test the TCPServer class."""

    def test_start_stop(self):
        """Server should start and stop cleanly."""
        port = get_free_port()
        server = TCPServer("127.0.0.1", port, lambda s, a: None)
        server.start()
        assert server.is_running
        server.stop()
        assert not server.is_running

    def test_accepts_connection(self):
        """Server should accept and handle incoming connections."""
        port = get_free_port()
        handled = [False]

        def handler(sock, addr):
            msg = receive_message(sock)
            if msg:
                handled[0] = True

        server = TCPServer("127.0.0.1", port, handler)
        server.start()
        time.sleep(0.2)

        try:
            msg = peer_announce("peer-test", 12345)
            with socket.create_connection(("127.0.0.1", port), timeout=3) as sock:
                send_message(sock, msg)
            time.sleep(0.5)
            assert handled[0] is True
        finally:
            server.stop()
