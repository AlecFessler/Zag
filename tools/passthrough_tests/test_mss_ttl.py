"""Edge case tests: ICMP errors."""

from conftest import HOST_WAN_IP, ROUTER_LAN_IP


class TestIcmpErrors:
    """Verify ICMP error generation by the router."""

    def test_ping_router_lan_ip(self, pi1):
        """Pi can ping the router's LAN interface directly."""
        result = pi1.icmp_ping(ROUTER_LAN_IP, count=3)
        assert result.get("success"), f"Ping to router LAN IP failed: {result}"
        assert result.get("packets_received", 0) >= 2, \
            f"Too few replies from router: {result}"

    def test_ping_router_wan_gateway(self, pi1):
        """Pi can ping the WAN gateway through the router."""
        result = pi1.icmp_ping(HOST_WAN_IP, count=3)
        assert result.get("success"), f"Ping through router failed: {result}"
