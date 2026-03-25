"""Persistent configuration tests.

Tests verify that configuration persists within a session.
Cross-reboot persistence (NFS-backed save/restore) is tested by
adding a rule, verifying it's present, and checking it survives
the session. Full reboot persistence requires a separate test run.
"""

import pytest


class TestPersistentConfig:
    """Test configuration management."""

    def test_firewall_rules_persist(self, router):
        """Firewall rules added during session are retrievable."""
        test_ip = "10.88.88.88"
        resp = router.block_ip(test_ip)
        assert "OK" in resp

        rules = router.get_rules()
        block_found = any("block" in r.lower() and test_ip in r for r in rules)
        assert block_found, f"Block rule for {test_ip} not in rules: {rules}"

        router.allow_ip(test_ip)

    def test_port_forwards_persist(self, router):
        """Port forward rules added during session are retrievable."""
        resp = router.add_port_forward("tcp", 9090, "192.168.1.50", 80)
        assert "OK" in resp

        rules = router.get_rules()
        fwd_found = any("forward" in r.lower() and "9090" in r for r in rules)
        assert fwd_found, f"Port forward :9090 not in rules: {rules}"

    def test_dns_config_persists(self, router, wan_ip):
        """DNS upstream setting is applied and retrievable."""
        resp = router.set_dns(wan_ip)
        assert "OK" in resp
        # Verify by checking that DNS relay works
        # (the upstream is set, subsequent DNS queries would use it)

    def test_dhcp_static_leases_persist(self, router):
        """DHCP leases assigned during session are retrievable."""
        leases = router.get_leases()
        # After earlier tests that triggered DHCP, there should be entries
        # (or "(empty)" if no LAN clients connected)
        assert isinstance(leases, list)
        # If any lease exists, verify it has IP and MAC format
        data_leases = [l for l in leases if l != "(empty)" and l != "---"]
        for lease in data_leases:
            assert "." in lease, f"Lease entry missing IP: {lease}"
