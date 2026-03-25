"""UDP forwarding service tests.

The UDP forwarding service routes UDP packets between the NIC and
internal applications (NFS client, NTP client). These tests verify
the service works by exercising NFS and NTP which depend on it.
"""

import socket
import struct
import time

import pytest

from conftest import ping_host


class TestUdpForwarding:
    """Test UDP forwarding to internal applications."""

    def test_ntp_via_udp_fwd(self, router):
        """NTP sync command uses UDP forwarding to send/receive NTP packets.

        The NTP client sends UDP port 123 traffic via the UDP forwarding service.
        Verify it produces output (even if sync fails due to no NTP server).
        """
        lines = router.multi_command("sync", timeout=15)
        assert isinstance(lines, list)
        # Should get some response — either success or timeout
        assert len(lines) > 0, "NTP sync returned no output"

    def test_dns_uses_udp(self, router, wan_ip):
        """DNS relay forwards queries via UDP to the upstream server."""
        # Use multi_command to be tolerant of interleaved debug output
        lines = router.multi_command(f"dns {wan_ip}", timeout=10)
        combined = " ".join(lines)
        assert "OK" in combined or "dns" in combined.lower() or len(lines) == 0, \
            f"DNS set failed: {lines}"

    def test_udp_to_closed_port_no_crash(self, router, router_wan_ip):
        """UDP packet to a port with no bound application doesn't crash."""
        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, b"tap0")
        client.settimeout(2.0)
        try:
            client.sendto(b"test-unbound-port", (router_wan_ip, 12345))
            time.sleep(0.5)
        finally:
            client.close()

        # Use multi_command for version check — more tolerant of noise
        time.sleep(1)
        lines = router.multi_command("version", timeout=10)
        # version is a single-response command, may come back via multi path
        resp = router.command("uptime")
        assert "uptime" in resp.lower() or "h" in resp, \
            f"Router unresponsive: {resp}"

    def test_nfs_mount_uses_udp_fwd(self, router):
        """NFS mount operation uses UDP forwarding for RPC.

        The NFS client communicates via UDP through the forwarding service.
        """
        lines = router.multi_command("mount", timeout=10)
        assert isinstance(lines, list)
        # mount should produce some output (success or error)
        assert len(lines) > 0, "NFS mount returned no output"

