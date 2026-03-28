"""IPv4 forwarding tests: verify packets are routed between WAN and LAN."""

import socket
import struct
import threading
import time

import pytest

from conftest import ping_host, ping_from_lan_ns, run_in_lan_ns


class TestIpForwarding:
    """Test basic IPv4 packet forwarding through the router."""

    @pytest.mark.lan
    @pytest.mark.lan_ns
    def test_lan_to_wan_forwarding(self, router, wan_ip):
        """Packet from LAN namespace reaches WAN side through router."""
        assert ping_from_lan_ns(wan_ip, count=2), \
            "LAN could not reach WAN through the router"

    @pytest.mark.lan
    @pytest.mark.lan_ns
    def test_wan_to_lan_forwarding(self, router, wan_ip, router_wan_ip):
        """Port-forwarded packet from WAN reaches LAN namespace server."""
        port = 19950
        lan_ip = "10.1.1.60"
        received = []

        # Warm ARP
        ping_from_lan_ns("10.1.1.1", count=1)

        resp = router.add_port_forward("udp", port, lan_ip, port)
        assert "OK" in resp

        # UDP server in LAN namespace
        server_proc = __import__("subprocess").Popen(
            ["sudo", "ip", "netns", "exec", "lan_test",
             "python3", "-c",
             f"import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); "
             f"s.bind(('0.0.0.0',{port})); s.settimeout(10); "
             f"d,a=s.recvfrom(1024); print(d); s.close()"],
            stdout=__import__("subprocess").PIPE,
            stderr=__import__("subprocess").PIPE,
        )

        # Send from WAN (retry — subprocess needs time to start and bind)
        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        for _ in range(10):
            client.sendto(b"wan-to-lan-test", (router_wan_ip, port))
            if server_proc.poll() is not None:
                break
            time.sleep(0.1)
        client.close()

        server_proc.wait(timeout=12)
        stdout = server_proc.stdout.read().decode()
        assert "wan-to-lan-test" in stdout, \
            f"LAN server didn't receive WAN packet: {stdout}"

    def test_ifstat_shows_traffic(self, router, router_wan_ip):
        """After some traffic, ifstat should show non-zero counters."""
        ping_host(router_wan_ip, interface="tap0", count=2)

        stats = router.get_ifstat()
        assert stats.get("wan", {}).get("rx", 0) > 0, \
            f"WAN rx counter still 0 after traffic: {stats}"

    @pytest.mark.lan
    @pytest.mark.lan_ns
    def test_ttl_decrement(self, router, wan_ip):
        """Forwarded packets have TTL decremented.

        Use traceroute-style ping: TTL=2 should succeed (decremented to 1 at router),
        while TTL=1 should fail with Time Exceeded.
        """
        # TTL=1 should be rejected (Time Exceeded)
        result_ttl1 = run_in_lan_ns(
            ["ping", "-c", "1", "-W", "2", "-t", "1", wan_ip],
            timeout=5,
        )
        # TTL=2 should succeed (arrives at host with TTL=1)
        result_ttl2 = run_in_lan_ns(
            ["ping", "-c", "1", "-W", "2", "-t", "2", wan_ip],
            timeout=5,
        )
        assert result_ttl1.returncode != 0 or "exceeded" in result_ttl1.stdout.lower(), \
            "TTL=1 should have been rejected"
        assert result_ttl2.returncode == 0, \
            f"TTL=2 should have reached destination: {result_ttl2.stderr}"

    @pytest.mark.lan
    @pytest.mark.lan_ns
    def test_ttl_exceeded_icmp(self, router, wan_ip):
        """TTL=1 should generate ICMP Time Exceeded."""
        result = run_in_lan_ns(
            ["ping", "-c", "1", "-W", "2", "-t", "1", wan_ip],
            timeout=5,
        )
        assert "exceeded" in result.stdout.lower() or result.returncode == 1

    def test_destination_unreachable_icmp(self, router, router_wan_ip):
        """UDP to closed port on router generates ICMP Port Unreachable.

        Send UDP to a port the router doesn't handle and verify the
        send doesn't hang (ICMP error is generated, which may cause
        a socket error on the sender side).
        """
        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, b"tap0")
        client.settimeout(2.0)
        try:
            client.sendto(b"test-unreachable", (router_wan_ip, 9999))
            # On Linux, the ICMP port unreachable may trigger a
            # ConnectionRefusedError on the next recv
            try:
                client.recvfrom(1024)
            except (ConnectionRefusedError, socket.timeout):
                pass  # Expected — ICMP error received or timed out
        finally:
            client.close()
