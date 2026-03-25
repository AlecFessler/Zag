"""Basic status and info command tests."""

import pytest


class TestStatus:
    """Verify status and ifstat commands return expected data."""

    def test_status_shows_wan(self, router, router_wan_ip):
        """Status command shows WAN interface with correct IP."""
        status = router.get_status()
        assert "wan" in status, f"No WAN in status output: {status}"
        assert router_wan_ip in status["wan"], \
            f"WAN IP {router_wan_ip} not in status: {status['wan']}"

    @pytest.mark.lan
    def test_status_shows_lan(self, router, router_lan_ip):
        """Status command shows LAN interface with correct IP."""
        status = router.get_status()
        assert "lan" in status, f"No LAN in status output: {status}"
        assert router_lan_ip in status["lan"], \
            f"LAN IP {router_lan_ip} not in status: {status['lan']}"

    def test_status_shows_mac_addresses(self, router):
        """Status output includes MAC addresses."""
        status = router.get_status()
        assert "mac=" in status.get("wan", ""), "WAN status missing MAC"

    def test_ifstat_returns_counters(self, router):
        """ifstat shows packet counters for WAN interface."""
        stats = router.get_ifstat()
        assert "wan" in stats, f"No WAN in ifstat: {stats}"
        assert "rx" in stats["wan"], f"WAN missing rx counter: {stats['wan']}"
        assert "tx" in stats["wan"], f"WAN missing tx counter: {stats['wan']}"

    @pytest.mark.lan
    def test_ifstat_shows_lan(self, router):
        """ifstat shows LAN counters when LAN is active."""
        stats = router.get_ifstat()
        assert "lan" in stats, f"No LAN in ifstat: {stats}"

    def test_version(self, router):
        """Version command returns RouterOS version string."""
        resp = router.command("version")
        assert "Zag RouterOS" in resp, f"Unexpected version: {resp}"

    def test_uptime(self, router):
        """Uptime command returns time in h/m/s format."""
        resp = router.command("uptime")
        assert "uptime:" in resp.lower(), f"Unexpected uptime format: {resp}"
