"""DHCP server tests: verify Pis get IPs from the router."""

import time


class TestDhcpAssignment:
    """Verify router's DHCP server assigns IPs to physical Pi clients."""

    def test_all_pis_got_dhcp_ip(self, pis):
        """Each Pi should have received a DHCP IP in the 10.1.1.100+ range."""
        for pi in pis:
            info = pi.dhcp_info()
            eth_ip = info.get("eth_ip")
            assert eth_ip is not None, f"{pi.name}: no ethernet IP"
            assert eth_ip.startswith("10.1.1."), \
                f"{pi.name}: unexpected IP {eth_ip} (expected 10.1.1.x)"
            octets = eth_ip.split(".")
            last = int(octets[3])
            assert last >= 100, \
                f"{pi.name}: IP {eth_ip} not in DHCP range (expected >= 10.1.1.100)"

    def test_pis_have_correct_gateway(self, pis):
        """Each Pi's default gateway should be the router LAN IP."""
        for pi in pis:
            info = pi.dhcp_info()
            gateway = info.get("gateway")
            assert gateway == "10.1.1.1", \
                f"{pi.name}: gateway is {gateway}, expected 10.1.1.1"

    def test_pis_have_unique_ips(self, pis):
        """All 3 Pis should have different DHCP-assigned IPs."""
        ips = [pi.eth_ip for pi in pis]
        assert len(set(ips)) == len(ips), \
            f"Duplicate IPs assigned: {ips}"

    def test_dhcp_lease_stable(self, pis):
        """IPs should remain stable over a short period (lease not expiring)."""
        ips_before = [pi.eth_ip for pi in pis]
        time.sleep(5)
        ips_after = [pi.dhcp_info().get("eth_ip") for pi in pis]
        assert ips_before == ips_after, \
            f"IPs changed: {ips_before} -> {ips_after}"
