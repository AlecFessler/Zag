"""Port forwarding tests: WAN traffic reaches Pis through the router.

Port forwards are created via UPnP SOAP and PCP MAP from the Pis themselves
(no serial console interaction needed).
"""

import time
import threading

from conftest import ROUTER_WAN_IP


class TestTcpPortForward:
    """TCP port forwarding from WAN to Pi."""

    def test_tcp_port_forward_via_upnp(self, pi1, wan):
        """Pi creates UPnP mapping, listens, WAN sends TCP, Pi receives."""
        wan_port = 18090
        pi_port = 9080

        # Create port forward via UPnP
        map_result = pi1.upnp_map("TCP", wan_port, pi_port, lease=300)
        assert "error" not in map_result or map_result.get("status") == 200, \
            f"UPnP map failed: {map_result}"
        time.sleep(1)

        # Pi listens for incoming TCP connection
        listen_result = [None]

        def pi_listen():
            listen_result[0] = pi1.listen_tcp(pi_port, timeout=15, response="pi1-ack")

        t = threading.Thread(target=pi_listen)
        t.start()
        time.sleep(1)  # let Pi bind

        # WAN sends TCP to router's WAN IP on forwarded port
        send_result = wan.send_tcp(ROUTER_WAN_IP, wan_port, data="hello-port-forward")
        t.join(timeout=20)

        assert listen_result[0] is not None, "Pi listen timed out"
        assert listen_result[0].get("received"), \
            f"Pi didn't receive forwarded TCP: {listen_result[0]}"
        assert "hello-port-forward" in listen_result[0].get("data", ""), \
            f"Wrong data received: {listen_result[0]}"

        # Cleanup
        pi1.upnp_delete("TCP", wan_port)

    def test_udp_port_forward_via_upnp(self, pi1, wan):
        """Pi creates UPnP UDP mapping, listens, WAN sends UDP, Pi receives."""
        wan_port = 18081
        pi_port = 8081

        map_result = pi1.upnp_map("UDP", wan_port, pi_port, lease=300)
        assert "error" not in map_result or map_result.get("status") == 200, \
            f"UPnP map failed: {map_result}"
        time.sleep(1)

        listen_result = [None]

        def pi_listen():
            listen_result[0] = pi1.listen_udp(pi_port, timeout=15)

        t = threading.Thread(target=pi_listen)
        t.start()
        time.sleep(1)

        wan.send_udp(ROUTER_WAN_IP, wan_port, data="udp-forward-test")
        t.join(timeout=20)

        assert listen_result[0] is not None, "Pi listen timed out"
        assert listen_result[0].get("received"), \
            f"Pi didn't receive forwarded UDP: {listen_result[0]}"
        assert "udp-forward-test" in listen_result[0].get("data", ""), \
            f"Wrong data: {listen_result[0]}"

        pi1.upnp_delete("UDP", wan_port)


class TestPcpPortForward:
    """Port forwarding via PCP MAP requests."""

    def test_pcp_tcp_forward(self, pi1, wan):
        """Pi creates PCP mapping, listens, WAN sends TCP, Pi receives."""
        wan_port = 19090
        pi_port = 9090

        pcp_result = pi1.pcp_map("tcp", pi_port, external_port=wan_port, lifetime=300)
        time.sleep(1)

        listen_result = [None]

        def pi_listen():
            listen_result[0] = pi1.listen_tcp(pi_port, timeout=15, response="pcp-ack")

        t = threading.Thread(target=pi_listen)
        t.start()
        time.sleep(1)

        wan.send_tcp(ROUTER_WAN_IP, wan_port, data="pcp-forward-test")
        t.join(timeout=20)

        assert listen_result[0] is not None, "Pi listen timed out"
        assert listen_result[0].get("received"), \
            f"Pi didn't receive PCP-forwarded TCP: {listen_result[0]}"

        # Cleanup: delete PCP mapping
        pi1.pcp_map("tcp", pi_port, external_port=wan_port, lifetime=0)

    def test_port_forward_cleanup(self, pi1, wan):
        """After deleting a mapping, traffic should no longer reach Pi."""
        wan_port = 19091
        pi_port = 9091

        # Create and immediately delete
        pi1.pcp_map("tcp", pi_port, external_port=wan_port, lifetime=300)
        time.sleep(1)
        pi1.pcp_map("tcp", pi_port, external_port=wan_port, lifetime=0)
        time.sleep(1)

        # Pi listens — should NOT receive anything
        listen_result = [None]

        def pi_listen():
            listen_result[0] = pi1.listen_tcp(pi_port, timeout=5)

        t = threading.Thread(target=pi_listen)
        t.start()
        time.sleep(1)

        wan.send_tcp(ROUTER_WAN_IP, wan_port, data="should-not-arrive")
        t.join(timeout=10)

        assert listen_result[0] is not None
        assert not listen_result[0].get("received"), \
            f"Pi received data after mapping deleted: {listen_result[0]}"
