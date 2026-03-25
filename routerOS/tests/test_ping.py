"""Smoke tests: ping the router from both WAN and LAN sides."""

import pytest

from conftest import ping_host


class TestPingFromHost:
    """Verify the router responds to ICMP echo from the host."""

    def test_ping_router_wan(self, router, router_wan_ip):
        """Ping the router's WAN IP from the host via tap0."""
        assert ping_host(router_wan_ip, interface="tap0"), \
            f"Router WAN {router_wan_ip} did not respond to ping on tap0"

    @pytest.mark.lan
    def test_ping_router_lan(self, router, router_lan_ip):
        """Ping the router's LAN IP from the host via tap1."""
        assert ping_host(router_lan_ip, interface="tap1"), \
            f"Router LAN {router_lan_ip} did not respond to ping on tap1"


class TestPingFromRouter:
    """Verify the router can ping external hosts (via serial console)."""

    def test_router_pings_wan_gateway(self, router, wan_ip):
        """Router pings the WAN gateway (host on tap0)."""
        lines = router.ping(wan_ip)
        replies = [l for l in lines if "time=" in l.lower() or "ms" in l.lower()]
        assert len(replies) > 0, f"Router got no ping replies from {wan_ip}: {lines}"

    @pytest.mark.lan
    def test_router_pings_lan_host(self, router, lan_ip):
        """Router pings the LAN host (host on tap1)."""
        lines = router.ping(lan_ip)
        replies = [l for l in lines if "time=" in l.lower() or "ms" in l.lower()]
        assert len(replies) > 0, f"Router got no ping replies from {lan_ip}: {lines}"
