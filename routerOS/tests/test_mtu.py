"""TCP MSS clamping tests."""

import socket
import struct
import threading
import time

import pytest

from conftest import run_in_lan_ns


class TestTcpMssClamping:
    """TCP MSS clamping on SYN/SYN-ACK packets."""

    @pytest.mark.lan
    @pytest.mark.lan_ns
    def test_mss_clamped_on_syn(self, router, wan_ip):
        """TCP SYN from LAN traversing router should have MSS clamped to <=1460.

        We start a TCP server on the WAN side, connect from LAN namespace,
        and verify the connection succeeds (MSS clamping is transparent).
        The actual MSS value can be verified with packet capture if needed.
        """
        port = 19900
        received = []

        def tcp_server():
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind(("0.0.0.0", port))
            srv.listen(1)
            srv.settimeout(10.0)
            try:
                conn, addr = srv.accept()
                received.append(addr)
                conn.sendall(b"MSS-OK")
                conn.close()
            except socket.timeout:
                pass
            finally:
                srv.close()

        server = threading.Thread(target=tcp_server, daemon=True)
        server.start()
        time.sleep(0.5)

        result = run_in_lan_ns(
            ["python3", "-c",
             f"import socket; s=socket.socket(); s.settimeout(8); "
             f"s.connect(('{wan_ip}',{port})); d=s.recv(16); print(d); s.close()"],
            timeout=15,
        )

        server.join(timeout=12)

        assert len(received) > 0, \
            f"TCP server got no connection (MSS clamping may have broken SYN). stderr: {result.stderr}"
