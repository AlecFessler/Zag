"""Bidirectional round-trip tests: verify full data path in both directions.

Pi -> switch -> x550 LAN -> router NAT -> x550 WAN -> loopback -> eno1
-> echo -> eno1 -> loopback -> x550 WAN -> router reverse NAT
-> x550 LAN -> switch -> Pi

Pi confirms receipt over WiFi (out-of-band).
"""

import time
import threading

from conftest import HOST_WAN_IP, ROUTER_WAN_IP


class TestBidirectionalRoundTrip:
    """Full round-trip verification through the router."""

    def test_udp_full_roundtrip(self, pi1, wan):
        """Pi sends UDP, WAN echoes, Pi confirms receipt — full physical path."""
        wan.clear_logs()
        result = pi1.udp_roundtrip(HOST_WAN_IP, 9999, payload="bidi-udp-test")

        assert result.get("sent"), f"Pi failed to send: {result}"
        assert result.get("received"), \
            f"Pi did not receive echo (full roundtrip failed): {result}"
        assert "ECHO:bidi-udp-test" in result.get("response", ""), \
            f"Echo data corrupted: {result}"

        # Verify the packet made it to the WAN side
        logs = wan.get_logs()
        assert any("bidi-udp-test" in l.get("data", "") for l in logs), \
            "WAN responder never saw the packet"

    def test_tcp_full_roundtrip(self, pi1, wan):
        """Pi opens TCP, sends data, WAN echoes, Pi reads echo — full path."""
        wan.clear_logs()
        result = pi1.tcp_roundtrip(HOST_WAN_IP, 9876, payload="bidi-tcp-test")

        assert result.get("sent"), f"Pi failed to send: {result}"
        assert result.get("received"), \
            f"Pi did not receive TCP echo (full roundtrip failed): {result}"
        assert "ECHO:bidi-tcp-test" in result.get("response", ""), \
            f"TCP echo data corrupted: {result}"

    def test_port_forward_roundtrip(self, pi1, wan):
        """WAN initiates -> router port forward -> Pi -> Pi responds -> WAN reads response."""
        wan_port = 28080
        pi_port = 8888

        # Create port forward via UPnP
        pi1.upnp_map("TCP", wan_port, pi_port, lease=300)
        time.sleep(1)

        # Pi listens and will send response data
        listen_result = [None]

        def pi_listen():
            listen_result[0] = pi1.listen_tcp(pi_port, timeout=15, response="pi1-response-data")

        t = threading.Thread(target=pi_listen)
        t.start()
        time.sleep(1)

        # WAN initiates TCP to router, which forwards to Pi
        send_result = wan.send_tcp(ROUTER_WAN_IP, wan_port, data="wan-to-pi")
        t.join(timeout=20)

        # Pi should have received the WAN data
        assert listen_result[0] is not None, "Pi listen timed out"
        assert listen_result[0].get("received"), \
            f"Pi didn't receive forwarded data: {listen_result[0]}"
        assert "wan-to-pi" in listen_result[0].get("data", ""), \
            f"Pi got wrong data: {listen_result[0]}"

        # WAN should have received Pi's response
        assert send_result.get("received"), \
            f"WAN didn't get Pi's response: {send_result}"
        assert "pi1-response-data" in send_result.get("response", ""), \
            f"WAN got wrong response: {send_result}"

        # Cleanup
        pi1.upnp_delete("TCP", wan_port)

    def test_udp_roundtrip_all_pis(self, pis, wan):
        """All 3 Pis do full UDP roundtrips, all confirmed via WiFi."""
        wan.clear_logs()
        for pi in pis:
            result = pi.udp_roundtrip(HOST_WAN_IP, 9999, payload=f"bidi-{pi.name}")
            assert result.get("received"), \
                f"{pi.name}: full roundtrip failed: {result}"
            assert f"ECHO:bidi-{pi.name}" in result.get("response", ""), \
                f"{pi.name}: echo corrupted: {result}"
