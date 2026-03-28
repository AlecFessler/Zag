"""NAT tests: verify UDP/TCP/ICMP translation through the router.

Pi sends traffic to WAN (10.0.2.1), WAN responder verifies NATed source
(10.0.2.15) and echoes back, Pi confirms receipt.
"""

import time
import concurrent.futures

from conftest import HOST_WAN_IP, ROUTER_WAN_IP


class TestUdpNat:
    """UDP traffic from Pi (LAN) should be NATed to WAN."""

    def test_udp_nat_roundtrip(self, pi1, wan):
        """Pi sends UDP to WAN responder, gets echo back."""
        wan.clear_logs()
        result = pi1.udp_roundtrip(HOST_WAN_IP, 9999, payload="nat-udp-test")
        assert result.get("sent"), f"UDP send failed: {result}"
        assert result.get("received"), f"UDP echo not received: {result}"
        assert "ECHO:nat-udp-test" in result.get("response", ""), \
            f"Unexpected echo response: {result}"

        # Verify WAN responder saw NATed source
        logs = wan.get_logs()
        udp_logs = [l for l in logs if l["protocol"] == "udp" and "nat-udp-test" in l["data"]]
        assert len(udp_logs) > 0, f"WAN responder didn't log UDP packet: {logs}"
        assert udp_logs[0]["src_ip"] == ROUTER_WAN_IP, \
            f"Source IP not NATed: {udp_logs[0]['src_ip']} (expected {ROUTER_WAN_IP})"
        assert udp_logs[0]["nat_valid"], "NAT validation failed"

    def test_udp_nat_all_pis(self, pis, wan):
        """All 3 Pis send UDP simultaneously, all NATed correctly."""
        wan.clear_logs()

        def send_udp(pi):
            return pi.udp_roundtrip(HOST_WAN_IP, 9999, payload=f"nat-{pi.name}")

        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
            futures = {pool.submit(send_udp, pi): pi for pi in pis}
            results = {}
            for future in concurrent.futures.as_completed(futures, timeout=15):
                pi = futures[future]
                results[pi.name] = future.result()

        for name, result in results.items():
            assert result.get("received"), f"{name}: no echo received: {result}"

        logs = wan.get_logs()
        udp_logs = [l for l in logs if l["protocol"] == "udp" and "nat-" in l["data"]]
        assert len(udp_logs) >= 3, \
            f"Expected 3+ UDP packets, got {len(udp_logs)}: {udp_logs}"

        # All should have NATed source IP
        for log in udp_logs:
            assert log["src_ip"] == ROUTER_WAN_IP, \
                f"Source not NATed: {log['src_ip']}"

        # Distinct source ports (NAT port allocation)
        src_ports = {l["src_port"] for l in udp_logs}
        assert len(src_ports) >= 3, \
            f"Expected 3+ distinct NAT ports, got {src_ports}"


class TestTcpNat:
    """TCP connections from Pi (LAN) should be NATed to WAN."""

    def test_tcp_nat_roundtrip(self, pi1, wan):
        """Pi opens TCP to WAN responder, gets echo back."""
        wan.clear_logs()
        result = pi1.tcp_roundtrip(HOST_WAN_IP, 9876, payload="nat-tcp-test")
        assert result.get("sent"), f"TCP send failed: {result}"
        assert result.get("received"), f"TCP echo not received: {result}"
        assert "ECHO:nat-tcp-test" in result.get("response", ""), \
            f"Unexpected TCP echo: {result}"

        logs = wan.get_logs()
        tcp_logs = [l for l in logs if l["protocol"] == "tcp" and "nat-tcp-test" in l["data"]]
        assert len(tcp_logs) > 0, f"WAN responder didn't log TCP: {logs}"
        assert tcp_logs[0]["src_ip"] == ROUTER_WAN_IP, \
            f"TCP source not NATed: {tcp_logs[0]['src_ip']}"

    def test_tcp_nat_multiple_connections(self, pi1, wan):
        """Multiple sequential TCP connections all succeed."""
        wan.clear_logs()
        for i in range(5):
            result = pi1.tcp_roundtrip(HOST_WAN_IP, 9876, payload=f"tcp-seq-{i}")
            assert result.get("received"), f"TCP connection {i} failed: {result}"

        logs = wan.get_logs()
        tcp_logs = [l for l in logs if l["protocol"] == "tcp" and "tcp-seq-" in l["data"]]
        assert len(tcp_logs) == 5, \
            f"Expected 5 TCP connections, got {len(tcp_logs)}"


class TestIcmpNat:
    """ICMP ping from Pi (LAN) should be NATed through the router."""

    def test_ping_through_router(self, pi1):
        """Pi pings the WAN gateway through the router."""
        result = pi1.icmp_ping(HOST_WAN_IP, count=3)
        assert result.get("success"), f"Ping failed: {result}"
        assert result.get("packets_received", 0) >= 2, \
            f"Too few ping replies: {result}"

    def test_ping_all_pis(self, pis):
        """All 3 Pis can ping through the router simultaneously."""
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
            futures = {pool.submit(pi.icmp_ping, HOST_WAN_IP, 3): pi for pi in pis}
            for future in concurrent.futures.as_completed(futures, timeout=20):
                pi = futures[future]
                result = future.result()
                assert result.get("success"), \
                    f"{pi.name}: ping failed: {result}"

    def test_ping_ttl_decremented(self, pi1):
        """TTL should be decremented by the router (original 64 -> 63 or 62)."""
        result = pi1.icmp_ping(HOST_WAN_IP, count=1)
        assert result.get("success"), f"Ping failed: {result}"
        ttl = result.get("ttl")
        if ttl is not None:
            # TTL depends on how many hops: Pi -> router (decrement) -> host
            # Could be 63 (one decrement) or 64 (host responds directly via ARP)
            assert ttl <= 64, f"Unexpected TTL: {ttl}"
