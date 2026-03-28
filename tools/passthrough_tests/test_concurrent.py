"""Concurrent and stress tests: hammer the router with simultaneous traffic."""

import concurrent.futures

from conftest import HOST_WAN_IP


class TestConcurrentTraffic:
    """Multiple Pis sending traffic simultaneously."""

    def test_concurrent_udp_all_pis(self, pis, wan):
        """All 3 Pis do UDP roundtrips simultaneously."""
        wan.clear_logs()
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
            futures = {
                pool.submit(pi.udp_roundtrip, HOST_WAN_IP, 9999, f"conc-{pi.name}"): pi
                for pi in pis
            }
            for future in concurrent.futures.as_completed(futures, timeout=15):
                pi = futures[future]
                result = future.result()
                assert result.get("received"), \
                    f"{pi.name}: concurrent UDP failed: {result}"

    def test_concurrent_tcp_all_pis(self, pis, wan):
        """All 3 Pis do TCP roundtrips simultaneously."""
        wan.clear_logs()
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
            futures = {
                pool.submit(pi.tcp_roundtrip, HOST_WAN_IP, 9876, f"conc-tcp-{pi.name}"): pi
                for pi in pis
            }
            for future in concurrent.futures.as_completed(futures, timeout=15):
                pi = futures[future]
                result = future.result()
                assert result.get("received"), \
                    f"{pi.name}: concurrent TCP failed: {result}"

    def test_concurrent_mixed_protocols(self, pis, wan):
        """Pi1: UDP, Pi2: TCP, Pi3: ICMP ping — all simultaneously."""
        wan.clear_logs()
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
            f_udp = pool.submit(pis[0].udp_roundtrip, HOST_WAN_IP, 9999, "mixed-udp")
            f_tcp = pool.submit(pis[1].tcp_roundtrip, HOST_WAN_IP, 9876, "mixed-tcp")
            f_ping = pool.submit(pis[2].icmp_ping, HOST_WAN_IP, 3)

            udp_result = f_udp.result(timeout=15)
            tcp_result = f_tcp.result(timeout=15)
            ping_result = f_ping.result(timeout=15)

        assert udp_result.get("received"), f"pi1 UDP failed: {udp_result}"
        assert tcp_result.get("received"), f"pi2 TCP failed: {tcp_result}"
        assert ping_result.get("success"), f"pi3 ping failed: {ping_result}"


class TestUdpFlood:
    """Stress test with rapid UDP traffic."""

    def test_udp_flood_single_pi(self, pi1, wan):
        """Single Pi sends 1000 rapid UDP packets, verify high delivery."""
        wan.clear_logs()

        flood_result = pi1.udp_flood(HOST_WAN_IP, 9999, count=1000, interval_ms=1)
        assert flood_result.get("sent") == 1000, \
            f"Flood send failed: {flood_result}"

        # Check how many the WAN responder received
        stats = wan.get_stats()
        udp_received = stats.get("udp", 0)
        # Allow some loss — 10GbE to 1GbE might drop some
        assert udp_received >= 900, \
            f"Too much packet loss: sent 1000, received {udp_received}"

    def test_concurrent_flood_all_pis(self, pis, wan):
        """All 3 Pis flood simultaneously (3000 total packets)."""
        wan.clear_logs()

        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
            futures = {
                pool.submit(pi.udp_flood, HOST_WAN_IP, 9999, 1000, 1, f"flood-{pi.name}"): pi
                for pi in pis
            }
            for future in concurrent.futures.as_completed(futures, timeout=30):
                pi = futures[future]
                result = future.result()
                assert result.get("sent") == 1000, \
                    f"{pi.name}: flood failed: {result}"

        stats = wan.get_stats()
        udp_received = stats.get("udp", 0)
        # 3000 sent, allow some loss
        assert udp_received >= 2500, \
            f"Too much loss in concurrent flood: sent 3000, received {udp_received}"
