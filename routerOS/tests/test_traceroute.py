"""Traceroute tests: verify console traceroute command works."""

import re
import time

import pytest

from conftest import ping_host


class TestTraceroute:
    """Test traceroute functionality."""

    def test_traceroute_to_wan_gateway(self, router, wan_ip):
        """Traceroute to WAN gateway (1 hop) should show the gateway IP and RTT."""
        # Warm ARP so the router already knows the gateway MAC
        ping_host(wan_ip, interface="tap0", count=1)

        lines = router.multi_command(f"traceroute {wan_ip}", timeout=30)
        assert len(lines) > 0, f"Traceroute returned no output: {lines}"

        # First line should be the header: "traceroute to <ip>, 30 hops max"
        header = [l for l in lines if "traceroute to" in l]
        assert len(header) > 0, f"No traceroute header in: {lines}"
        assert wan_ip in header[0], f"Header missing target IP: {header[0]}"
        assert "30 hops max" in header[0], f"Header missing hop count: {header[0]}"

        # Should have at least one hop line with the gateway IP and RTT
        hop_lines = [l for l in lines if re.match(r"^\d+\s+", l)]
        assert len(hop_lines) > 0, f"No hop lines found in: {lines}"

        # The gateway (1 hop away) should show up with an RTT
        first_hop = hop_lines[0]
        assert wan_ip in first_hop or "us" in first_hop, \
            f"First hop doesn't show gateway or RTT: {first_hop}"

    def test_traceroute_shows_rtt(self, router, wan_ip):
        """Traceroute hop lines include RTT in microseconds."""
        ping_host(wan_ip, interface="tap0", count=1)

        lines = router.multi_command(f"traceroute {wan_ip}", timeout=30)
        hop_lines = [l for l in lines if re.match(r"^\d+\s+", l)]
        assert len(hop_lines) > 0, f"No hop lines: {lines}"

        # At least one hop should have "us" (microseconds)
        rtt_hops = [l for l in hop_lines if "us" in l]
        assert len(rtt_hops) > 0, \
            f"No hops with RTT found in: {hop_lines}"

    def test_traceroute_invalid_ip(self, router):
        """Traceroute with invalid IP returns an error."""
        lines = router.multi_command("traceroute notanip", timeout=10)
        combined = " ".join(lines)
        assert "invalid" in combined.lower(), \
            f"Expected 'invalid IP' error, got: {lines}"

