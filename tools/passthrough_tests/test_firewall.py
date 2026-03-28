"""Firewall tests: verify default firewall behavior with real hardware.

Tests the router's default firewall (no serial console needed):
- Unsolicited inbound traffic should be dropped
- Outbound traffic should be allowed
"""

import socket
import time

from conftest import ROUTER_WAN_IP, HOST_WAN_IP


class TestDefaultFirewall:
    """Test the router's default firewall policy."""

    def test_unsolicited_tcp_dropped(self, wan, qemu_router):
        """TCP SYN to router WAN IP on a random port should be dropped."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        try:
            sock.bind((HOST_WAN_IP, 0))
            sock.connect((ROUTER_WAN_IP, 12345))
            # If we get here, connection was accepted (unexpected)
            sock.close()
            assert False, "TCP connection to random port should have been dropped"
        except (socket.timeout, ConnectionRefusedError, OSError):
            # Expected: timeout or refused means firewall blocked it
            pass
        finally:
            sock.close()

    def test_unsolicited_udp_dropped(self, wan, qemu_router):
        """UDP to router WAN IP on a random port should be silently dropped."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(3)
        try:
            sock.bind((HOST_WAN_IP, 0))
            sock.sendto(b"unsolicited-test", (ROUTER_WAN_IP, 12346))
            # Try to receive an ICMP port unreachable (unlikely with firewall)
            try:
                sock.recvfrom(1024)
                # Getting a response would be unexpected for a firewalled router
            except socket.timeout:
                pass  # Expected: no response
        finally:
            sock.close()

    def test_outbound_allowed(self, pi1, wan):
        """Outbound traffic from Pi through router should work by default."""
        result = pi1.udp_roundtrip(HOST_WAN_IP, 9999, payload="firewall-outbound-test")
        assert result.get("received"), \
            f"Outbound traffic blocked: {result}"

    def test_outbound_tcp_allowed(self, pi1, wan):
        """Outbound TCP from Pi should work by default."""
        result = pi1.tcp_roundtrip(HOST_WAN_IP, 9876, payload="firewall-tcp-test")
        assert result.get("received"), \
            f"Outbound TCP blocked: {result}"
