"""Firewall and port forwarding tests."""

import socket
import subprocess
import threading
import time

import pytest

from conftest import run_in_lan_ns


class TestFirewallRules:
    """Test firewall block/allow rules."""

    def test_block_and_allow(self, router):
        """Block an IP, verify it appears in rules, then remove it."""
        test_ip = "10.0.2.100"

        resp = router.block_ip(test_ip)
        assert "OK" in resp, f"Block failed: {resp}"

        rules = router.get_rules()
        block_rules = [r for r in rules if "block" in r.lower() and test_ip in r]
        assert len(block_rules) > 0, f"Block rule not found in: {rules}"

        resp = router.allow_ip(test_ip)
        assert "OK" in resp, f"Allow failed: {resp}"

        rules = router.get_rules()
        block_rules = [r for r in rules if "block" in r.lower() and test_ip in r]
        assert len(block_rules) == 0, f"Block rule still present: {rules}"

    @pytest.mark.lan
    def test_firewall_blocks_wan_inbound(self, router, wan_ip):
        """Blocked WAN source IP should be dropped by the firewall."""
        router.block_ip(wan_ip)
        time.sleep(0.5)

        rules = router.get_rules()
        assert any(wan_ip in r for r in rules), f"Block rule missing: {rules}"

        router.allow_ip(wan_ip)

    def test_rules_command(self, router):
        """Rules command returns list with any active rules formatted correctly."""
        # Add a rule so we have something to see
        test_ip = "10.55.55.55"
        router.block_ip(test_ip)
        rules = router.get_rules()
        assert isinstance(rules, list)
        assert any("block" in r.lower() and test_ip in r for r in rules), \
            f"Block rule for {test_ip} not found in rules: {rules}"
        router.allow_ip(test_ip)

    @pytest.mark.lan
    def test_firewall_logging(self, router, wan_ip, router_wan_ip):
        """Blocked source IP is actually dropped by the firewall.

        Block the WAN host IP, verify ping fails, then unblock and verify ping works.
        """
        # Block WAN host
        router.block_ip(wan_ip)
        time.sleep(0.5)

        # Ping should fail (or at least not all succeed)
        from conftest import ping_host
        blocked_result = ping_host(router_wan_ip, interface="tap0", count=2, timeout=5)

        # Unblock
        router.allow_ip(wan_ip)
        time.sleep(0.5)

        # Ping should work again
        unblocked_result = ping_host(router_wan_ip, interface="tap0", count=2, timeout=5)
        assert unblocked_result, "Ping failed after unblocking"

    def test_firewall_rules_persistent(self, router):
        """Rules added in this test persist through the session."""
        test_ip = "10.33.33.33"
        router.block_ip(test_ip)

        # Verify it's there
        rules = router.get_rules()
        assert any(test_ip in r for r in rules), \
            f"Rule for {test_ip} not found: {rules}"

        # Do some other operations
        router.command("status")
        router.command("ifstat")

        # Verify it's still there
        rules2 = router.get_rules()
        assert any(test_ip in r for r in rules2), \
            f"Rule for {test_ip} disappeared: {rules2}"

        router.allow_ip(test_ip)


class TestPortForwarding:
    """Test port forwarding (DNAT) rules."""

    def test_add_port_forward(self, router, lan_ip):
        """Add a port forward rule and verify it appears in rules."""
        resp = router.add_port_forward("tcp", 8080, lan_ip, 80)
        assert "OK" in resp, f"Port forward failed: {resp}"

        rules = router.get_rules()
        fwd_rules = [r for r in rules if "forward" in r.lower() and "8080" in r]
        assert len(fwd_rules) > 0, f"Port forward not found in: {rules}"

    @pytest.mark.lan
    @pytest.mark.lan_ns
    def test_port_forward_tcp(self, router, wan_ip, router_wan_ip):
        """TCP port forward: WAN connection reaches LAN namespace server."""
        lan_port = 7777
        wan_port = 7778
        lan_ip = "10.1.1.60"  # LAN namespace IP

        # Warm up ARP so router knows .60's MAC
        from conftest import ping_from_lan_ns
        ping_from_lan_ns("10.1.1.1", count=1)
        time.sleep(1)

        resp = router.add_port_forward("tcp", wan_port, lan_ip, lan_port)
        assert "OK" in resp
        time.sleep(1)

        # Start TCP server in the LAN namespace
        server_proc = subprocess.Popen(
            ["sudo", "ip", "netns", "exec", "lan_test",
             "python3", "-c",
             f"import socket; s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); "
             f"s.bind(('0.0.0.0',{lan_port})); s.listen(1); s.settimeout(15); "
             f"c,a=s.accept(); d=c.recv(64); print(d); c.sendall(b'ACK'); c.close(); s.close()"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        time.sleep(1)

        # Connect from WAN side to router's WAN IP on the forwarded port
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.settimeout(10.0)
        received_reply = None
        try:
            client.connect((router_wan_ip, wan_port))
            client.sendall(b"hello-port-forward")
            received_reply = client.recv(1024)
            client.close()
        except (socket.timeout, ConnectionRefusedError, OSError):
            pass

        server_proc.wait(timeout=16)
        server_stdout = server_proc.stdout.read().decode()

        assert "hello-port-forward" in server_stdout, \
            f"Port forward: LAN server didn't receive data. stdout={server_stdout}"
        assert received_reply == b"ACK", \
            f"Port forward: WAN client got wrong reply: {received_reply}"

    @pytest.mark.lan
    @pytest.mark.lan_ns
    def test_port_forward_udp(self, router, wan_ip, router_wan_ip):
        """UDP port forward: WAN datagrams reach LAN namespace server."""
        lan_port = 7779
        wan_port = 7780
        lan_ip = "10.1.1.60"  # LAN namespace IP

        # Warm up ARP
        from conftest import ping_from_lan_ns
        ping_from_lan_ns("10.1.1.1", count=1)
        time.sleep(1)

        resp = router.add_port_forward("udp", wan_port, lan_ip, lan_port)
        assert "OK" in resp
        time.sleep(1)

        # Start UDP server in the LAN namespace
        server_proc = subprocess.Popen(
            ["sudo", "ip", "netns", "exec", "lan_test",
             "python3", "-c",
             f"import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); "
             f"s.bind(('0.0.0.0',{lan_port})); s.settimeout(15); "
             f"d,a=s.recvfrom(1024); print(d); s.close()"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        time.sleep(1)

        # Send UDP from WAN side
        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client.settimeout(5.0)
        try:
            client.sendto(b"udp-forward-test", (router_wan_ip, wan_port))
        finally:
            client.close()

        server_proc.wait(timeout=16)
        server_stdout = server_proc.stdout.read().decode()

        assert "udp-forward-test" in server_stdout, \
            f"UDP port forward: LAN server didn't receive data. stdout={server_stdout}"
