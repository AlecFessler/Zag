"""PCP (Port Control Protocol) tests via real Pi clients."""


class TestPcpProtocol:
    """Test PCP MAP request/response."""

    def test_pcp_map_creates_forward(self, pi1):
        """PCP MAP request creates a port mapping."""
        result = pi1.pcp_map("tcp", 8282, external_port=18282, lifetime=300)
        assert result.get("success"), f"PCP MAP failed: {result}"

        # If we got a parsed response, validate it
        if result.get("is_response"):
            assert result.get("result_code") == 0, \
                f"PCP error code: {result.get('result_code')}"

        # Cleanup
        pi1.pcp_map("tcp", 8282, external_port=18282, lifetime=0)

    def test_pcp_map_delete(self, pi1):
        """PCP MAP with lifetime=0 removes a mapping."""
        # Create
        pi1.pcp_map("udp", 7272, external_port=17272, lifetime=300)

        # Delete
        result = pi1.pcp_map("udp", 7272, external_port=17272, lifetime=0)
        assert result.get("success"), f"PCP delete failed: {result}"

    def test_pcp_udp_mapping(self, pi1):
        """PCP MAP for UDP protocol works."""
        result = pi1.pcp_map("udp", 5555, external_port=15555, lifetime=300)
        assert result.get("success"), f"PCP UDP MAP failed: {result}"
        pi1.pcp_map("udp", 5555, external_port=15555, lifetime=0)
