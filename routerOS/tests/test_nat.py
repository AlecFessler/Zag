"""NAT tests: verify TCP/UDP/ICMP translation through the router.

Tests that route traffic through the router require the lan_test namespace
(created by setup_sudo.sh) so the host kernel doesn't short-circuit routing.
"""

import socket
import subprocess
import threading
import time

import pytest

from conftest import ping_from_lan_ns, run_in_lan_ns


class TestNatTable:
    """Verify NAT table is accessible."""

    def test_nat_table_accessible(self, router):
        """NAT table command returns entries or (empty) marker."""
        entries = router.get_nat_table()
        assert isinstance(entries, list)
        assert len(entries) > 0, "NAT table returned no output"
        # Entries should be formatted: "proto ip:port -> :port -> ip:port" or "(empty)"
        data = [e for e in entries if e != "---"]
        for e in data:
            assert ":" in e or "empty" in e.lower(), \
                f"Unexpected NAT entry format: {e}"


class TestIcmpNat:
    """ICMP packets from LAN should be NATed through to WAN."""

    @pytest.mark.lan
    @pytest.mark.lan_ns
    def test_lan_ping_through_router(self, router, wan_ip):
        """LAN namespace pings WAN gateway through router (ICMP NAT)."""
        assert ping_from_lan_ns(wan_ip), \
            "LAN could not ping WAN gateway through the router"

        time.sleep(0.5)
        entries = router.get_nat_table()
        icmp_entries = [e for e in entries if "icmp" in e.lower()]
        assert len(icmp_entries) > 0, f"No ICMP NAT entry after ping: {entries}"


class TestTcpNat:
    """TCP connections from LAN should be NATed."""

    @pytest.mark.lan
    @pytest.mark.lan_ns
    def test_tcp_nat_connection(self, router, wan_ip):
        """TCP from LAN namespace to WAN server goes through NAT."""
        port = 19876
        received = []

        def tcp_server():
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind(("0.0.0.0", port))
            srv.listen(1)
            srv.settimeout(15.0)
            try:
                conn, addr = srv.accept()
                received.append(addr)
                conn.sendall(b"OK")
                conn.close()
            except socket.timeout:
                pass
            finally:
                srv.close()

        # Warm ARP: namespace pings router to ensure .60 MAC is known
        from conftest import ping_from_lan_ns
        ping_from_lan_ns("192.168.1.1", count=1)
        time.sleep(1)

        server = threading.Thread(target=tcp_server, daemon=True)
        server.start()
        time.sleep(1)

        # Connect from LAN namespace — traffic goes through router NAT
        result = run_in_lan_ns(
            ["python3", "-c",
             f"import socket; s=socket.socket(); s.settimeout(8); "
             f"s.connect(('{wan_ip}',{port})); s.recv(16); s.close()"],
            timeout=15,
        )

        server.join(timeout=16)

        # Check NAT table for TCP entry regardless
        nat_entries = router.get_nat_table()
        tcp_entries = [e for e in nat_entries if "tcp" in e.lower()]

        assert len(received) > 0, \
            f"TCP server got no connection. NAT table: {tcp_entries}, client stderr: {result.stderr}"
        assert received[0][0] == "10.0.2.15", \
            f"Connection source was {received[0][0]}, expected 10.0.2.15 (NATed)"

    @pytest.mark.lan
    def test_tcp_nat_state_tracking(self, router):
        """TCP NAT entries show protocol and port information."""
        entries = router.get_nat_table()
        assert isinstance(entries, list)
        # After the TCP NAT test above, there should be at least one TCP entry
        tcp_entries = [e for e in entries if "tcp" in e.lower()]
        assert len(tcp_entries) > 0, \
            f"No TCP NAT entries after TCP connection test: {entries}"


class TestUdpNat:
    """UDP traffic from LAN should be NATed to WAN."""

    @pytest.mark.lan
    @pytest.mark.lan_ns
    def test_udp_nat(self, router, wan_ip):
        """UDP from LAN namespace is NATed and forwarded to WAN."""
        port = 19878
        received = []

        def udp_server():
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind((wan_ip, port))
            sock.settimeout(5.0)
            try:
                data, addr = sock.recvfrom(1024)
                received.append((data, addr))
                sock.sendto(b"reply", addr)
            except socket.timeout:
                pass
            finally:
                sock.close()

        server = threading.Thread(target=udp_server, daemon=True)
        server.start()
        time.sleep(0.5)

        # Send UDP from LAN namespace
        run_in_lan_ns(
            ["python3", "-c",
             f"import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); "
             f"s.settimeout(3); s.sendto(b'nat-test',('{wan_ip}',{port})); s.close()"],
            timeout=8,
        )

        server.join(timeout=6)

        assert len(received) > 0, "UDP server got no data through NAT"
        assert received[0][1][0] == "10.0.2.15", \
            f"UDP source was {received[0][1][0]}, expected 10.0.2.15"

        entries = router.get_nat_table()
        udp_entries = [e for e in entries if "udp" in e.lower()]
        assert len(udp_entries) > 0, f"No UDP NAT entry: {entries}"
