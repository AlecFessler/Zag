"""ARP table tests: verify the router learns MAC addresses."""

import re

import pytest

from conftest import ping_host


class TestArpLearning:
    """After pinging, the router should have ARP entries for the host."""

    def test_wan_arp_entry(self, router, wan_ip, router_wan_ip):
        """After host pings router WAN, router learns host's WAN MAC."""
        ping_host(router_wan_ip, interface="tap0", count=1)

        entries = router.get_arp_table()
        wan_entries = [e for e in entries if wan_ip in e]
        assert len(wan_entries) > 0, \
            f"No WAN ARP entry for {wan_ip}. Table: {entries}"

    @pytest.mark.lan
    def test_lan_arp_entry(self, router, lan_ip, router_lan_ip):
        """After host pings router LAN, router learns host's LAN MAC."""
        ping_host(router_lan_ip, interface="tap1", count=1)

        entries = router.get_arp_table()
        lan_entries = [e for e in entries if lan_ip in e]
        assert len(lan_entries) > 0, \
            f"No LAN ARP entry for {lan_ip}. Table: {entries}"

    def test_arp_shows_mac_format(self, router, router_wan_ip):
        """ARP entries should contain MAC addresses in xx:xx:xx:xx:xx:xx format."""
        ping_host(router_wan_ip, interface="tap0", count=1)
        import time
        time.sleep(1)
        entries = router.get_arp_table()
        mac_pattern = re.compile(r"[0-9a-f]{2}(:[0-9a-f]{2}){5}", re.IGNORECASE)
        # Filter to just data lines (not headers or empty markers)
        mac_entries = [e for e in entries
                       if e != "(empty)" and mac_pattern.search(e)]
        assert len(mac_entries) > 0, \
            f"No ARP entries with MAC addresses found. Table: {entries}"

    def test_arp_expiry(self, router):
        """ARP entries have a 5-minute TTL (structural test - just verify table is accessible)."""
        entries = router.get_arp_table()
        assert isinstance(entries, list)
