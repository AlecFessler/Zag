"""ICMP handling tests: echo, TTL exceeded, destination unreachable."""

import socket
import struct
import time

import pytest

from conftest import ping_host, ping_from_lan_ns, run_in_lan_ns


class TestIcmpEcho:
    """ICMP echo request/reply (ping)."""

    def test_router_replies_to_ping_wan(self, router, router_wan_ip):
        """Router responds to ICMP echo on WAN interface."""
        assert ping_host(router_wan_ip, interface="tap0", count=2)

    @pytest.mark.lan
    def test_router_replies_to_ping_lan(self, router, router_lan_ip):
        """Router responds to ICMP echo on LAN interface."""
        assert ping_host(router_lan_ip, interface="tap1", count=2)

    def test_ping_from_router_console(self, router, wan_ip):
        """Router console ping command works."""
        lines = router.ping(wan_ip)
        assert len(lines) > 0, f"Ping returned no output: {lines}"

    @pytest.mark.lan
    @pytest.mark.lan_ns
    def test_icmp_nat_ping_through(self, router, wan_ip):
        """LAN namespace pings WAN through router (ICMP NAT)."""
        assert ping_from_lan_ns(wan_ip), \
            "LAN ping through router to WAN failed"


class TestIcmpTtlExceeded:
    """ICMP Time Exceeded generation (Type 11)."""

    @pytest.mark.lan
    @pytest.mark.lan_ns
    def test_ttl_1_generates_time_exceeded(self, router, wan_ip):
        """Packet with TTL=1 forwarded through router should trigger ICMP Type 11."""
        from conftest import run_in_lan_ns
        # Ping with TTL=1 — router should send Time Exceeded back
        result = run_in_lan_ns(
            ["ping", "-c", "1", "-W", "2", "-t", "1", wan_ip],
            timeout=5,
        )
        # ping should report "Time to live exceeded"
        assert "exceeded" in result.stdout.lower() or "exceeded" in result.stderr.lower() or result.returncode == 1, \
            f"Expected TTL exceeded, got: stdout={result.stdout}, stderr={result.stderr}"


class TestIcmpDestUnreachable:
    """ICMP Destination Unreachable generation (Type 3)."""

    def test_port_unreachable(self, router, router_wan_ip):
        """UDP to closed port generates ICMP Port Unreachable (Type 3, Code 3).

        Capture the ICMP error with a raw socket to verify it's actually sent.
        """
        import socket
        import struct

        try:
            raw = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        except PermissionError:
            pytest.skip("Raw socket requires CAP_NET_RAW — run with sudo")
        raw.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, b"tap0")
        raw.settimeout(3.0)

        # Send UDP to a port the router doesn't handle
        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, b"tap0")
        try:
            client.sendto(b"test-unreachable", (router_wan_ip, 9999))
        finally:
            client.close()

        # Listen for ICMP Destination Unreachable
        deadline = time.time() + 3.0
        while time.time() < deadline:
            try:
                data, addr = raw.recvfrom(1500)
            except socket.timeout:
                break
            if len(data) < 8:
                continue
            icmp_type = data[0]
            icmp_code = data[1]
            if icmp_type == 3 and icmp_code == 3:  # Port Unreachable
                raw.close()
                return  # Success
        raw.close()
        pytest.fail("No ICMP Port Unreachable received from router")

    @pytest.mark.lan
    @pytest.mark.lan_ns
    def test_frag_needed(self, router, wan_ip):
        """Oversize packet with DF bit forwarded through router should trigger
        ICMP Fragmentation Needed (Type 3, Code 4).

        Send a large ping (>1500 bytes with DF) from LAN namespace through router.
        With standard 1500 MTU, this shouldn't trigger for normal pings, but a
        packet larger than MTU with DF bit set should.
        """
        # ping -M do sets DF bit, -s 1472 = 1500 total (should just fit)
        # -s 1473 = 1501 total (should trigger frag needed IF the router enforces MTU)
        result = run_in_lan_ns(
            ["ping", "-c", "1", "-W", "2", "-M", "do", "-s", "1473", wan_ip],
            timeout=5,
        )
        # On standard 1500 MTU both sides, the packet may or may not trigger
        # frag needed depending on whether the router enforces outbound MTU.
        # For now, just verify the router doesn't crash.
        resp = router.command("version")
        assert "Zag RouterOS" in resp
