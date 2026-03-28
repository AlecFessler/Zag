"""DNS relay tests: verify the router forwards DNS queries from Pis to WAN.

The router's upstream DNS defaults to 10.0.2.1, which is the WAN responder's
DNS service. No serial console configuration needed.
"""

from conftest import ROUTER_LAN_IP, HOST_WAN_IP


class TestDnsRelay:
    """Test the router's DNS relay with real Pi clients."""

    def test_dns_query_resolves(self, pi1):
        """Pi sends DNS query to router, gets an answer back."""
        result = pi1.dns_query(ROUTER_LAN_IP, "example.com")
        assert result.get("resolved"), f"DNS query failed: {result}"
        assert len(result.get("answers", [])) > 0, \
            f"No DNS answers: {result}"

    def test_dns_query_correct_answer(self, pi1, wan):
        """DNS response contains the canned A record from WAN responder."""
        wan.clear_logs()
        # Use a domain not queried by prior tests to avoid cache hit
        result = pi1.dns_query(ROUTER_LAN_IP, "test.example.com")
        assert result.get("resolved"), f"DNS query failed: {result}"
        # WAN responder returns 93.184.216.34 for test.example.com
        assert "93.184.216.34" in result.get("answers", []), \
            f"Expected 93.184.216.34 in answers: {result}"

        # Verify WAN DNS received the forwarded query
        logs = wan.get_logs()
        dns_logs = [l for l in logs if l["protocol"] == "dns"]
        assert len(dns_logs) > 0, f"WAN DNS didn't receive query: {logs}"

    def test_dns_multiple_domains(self, pi1):
        """Multiple different domain queries all resolve."""
        domains = ["example.com", "test.example.com", "router.test"]
        for domain in domains:
            result = pi1.dns_query(ROUTER_LAN_IP, domain)
            assert result.get("resolved"), \
                f"DNS query for {domain} failed: {result}"

    def test_dns_from_all_pis(self, pis):
        """All 3 Pis can resolve DNS through the router."""
        for pi in pis:
            result = pi.dns_query(ROUTER_LAN_IP, "example.com")
            assert result.get("resolved"), \
                f"{pi.name}: DNS query failed: {result}"

    def test_dns_cache_hit(self, pi1, wan):
        """Second identical query should be served from cache (no new upstream query)."""
        wan.clear_logs()

        # First query - warms the cache
        result1 = pi1.dns_query(ROUTER_LAN_IP, "wan.test")
        assert result1.get("resolved"), f"First DNS query failed: {result1}"

        # Check upstream received it
        logs1 = wan.get_logs()
        dns_count_before = len([l for l in logs1 if l["protocol"] == "dns"])

        wan.clear_logs()

        # Second query - should come from cache
        result2 = pi1.dns_query(ROUTER_LAN_IP, "wan.test")
        assert result2.get("resolved"), f"Second DNS query failed: {result2}"

        # Upstream should NOT have received a new query
        logs2 = wan.get_logs()
        dns_count_after = len([l for l in logs2 if l["protocol"] == "dns"])
        assert dns_count_after == 0, \
            f"Cache miss: upstream received {dns_count_after} queries on second lookup"
