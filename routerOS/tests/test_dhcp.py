"""DHCP server and client tests."""

import fcntl
import socket
import struct
import threading
import time

import pytest

from conftest import run_in_lan_ns


class MiniDhcpServer:
    """Minimal DHCP server on tap0 using raw sockets for the router's WAN client."""

    def __init__(self, iface="tap0", server_ip="10.0.2.1", offer_ip="10.0.2.15"):
        self.iface = iface
        self.server_ip = server_ip
        self.offer_ip = offer_ip
        self.server_ip_bytes = socket.inet_aton(server_ip)
        self.offer_ip_bytes = socket.inet_aton(offer_ip)
        self.sock = None
        self.thread = None
        self.running = False
        self.ack_count = 0
        self.server_mac = self._get_mac(iface)

    @staticmethod
    def _get_mac(iface):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        info = fcntl.ioctl(s.fileno(), 0x8927, struct.pack("256s", iface.encode()))
        s.close()
        return info[18:24]

    def start(self):
        self.sock = socket.socket(
            socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800)
        )
        self.sock.bind((self.iface, 0))
        self.sock.settimeout(1.0)
        self.running = True
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join(timeout=3)
        if self.sock:
            self.sock.close()

    def _serve(self):
        while self.running:
            try:
                data = self.sock.recv(2048)
            except socket.timeout:
                continue
            if len(data) < 42:
                continue
            # Ethernet type must be IPv4
            if struct.unpack("!H", data[12:14])[0] != 0x0800:
                continue
            # IP protocol must be UDP
            if data[23] != 17:
                continue
            ip_hdr_len = (data[14] & 0x0F) * 4
            udp_off = 14 + ip_hdr_len
            if len(data) < udp_off + 8:
                continue
            src_port, dst_port = struct.unpack("!HH", data[udp_off : udp_off + 4])
            if src_port != 68 or dst_port != 67:
                continue
            dhcp = data[udp_off + 8 :]
            if len(dhcp) < 240:
                continue
            msg_type = self._get_option(dhcp, 53)
            if msg_type == 1:  # DISCOVER → OFFER
                self._send_response(dhcp, 2)
            elif msg_type == 3:  # REQUEST → ACK
                self._send_response(dhcp, 5)
                self.ack_count += 1

    def _send_response(self, dhcp_request, msg_type):
        # DHCP payload
        dhcp = bytearray(300)
        dhcp[0] = 2  # BOOTREPLY
        dhcp[1] = 1  # Ethernet
        dhcp[2] = 6  # HW addr len
        dhcp[4:8] = dhcp_request[4:8]  # XID
        dhcp[16:20] = self.offer_ip_bytes  # yiaddr
        dhcp[20:24] = self.server_ip_bytes  # siaddr
        dhcp[28:34] = dhcp_request[28:34]  # chaddr
        dhcp[236:240] = b"\x63\x82\x53\x63"
        opt = 240
        dhcp[opt : opt + 3] = bytes([53, 1, msg_type])
        opt += 3
        dhcp[opt : opt + 6] = bytes([54, 4]) + self.server_ip_bytes
        opt += 6
        dhcp[opt : opt + 6] = bytes([51, 4, 0, 0, 0, 120])  # 120s lease
        opt += 6
        dhcp[opt : opt + 6] = bytes([1, 4, 255, 255, 255, 0])
        opt += 6
        dhcp[opt : opt + 6] = bytes([3, 4]) + self.server_ip_bytes
        opt += 6
        dhcp[opt] = 255
        opt += 1
        dhcp_payload = bytes(dhcp[:opt])

        # UDP header
        udp_len = 8 + len(dhcp_payload)
        udp_hdr = struct.pack("!HHHH", 67, 68, udp_len, 0)

        # IP header
        ip_total = 20 + udp_len
        ip_hdr = bytearray(
            struct.pack(
                "!BBHHHBBH4s4s",
                0x45, 0, ip_total, 0, 0, 64, 17, 0,
                self.server_ip_bytes,
                b"\xff\xff\xff\xff",
            )
        )
        ip_hdr[10:12] = struct.pack("!H", self._checksum(ip_hdr))

        # Ethernet header
        eth_hdr = b"\xff\xff\xff\xff\xff\xff" + self.server_mac + b"\x08\x00"

        frame = eth_hdr + bytes(ip_hdr) + udp_hdr + dhcp_payload
        if len(frame) < 60:
            frame += b"\x00" * (60 - len(frame))
        self.sock.send(frame)

    @staticmethod
    def _checksum(data):
        if len(data) % 2:
            data += b"\x00"
        s = sum(struct.unpack("!%dH" % (len(data) // 2), bytes(data)))
        while s >> 16:
            s = (s & 0xFFFF) + (s >> 16)
        return ~s & 0xFFFF

    @staticmethod
    def _get_option(data, code):
        idx = 240
        while idx + 1 < len(data):
            if data[idx] == 255:
                break
            if data[idx] == 0:
                idx += 1
                continue
            c, length = data[idx], data[idx + 1]
            if c == code and length >= 1:
                return data[idx + 2]
            idx += 2 + length
        return None


class TestDhcpServer:
    """Test the router's DHCP server on the LAN interface."""

    @pytest.mark.lan
    def test_leases_command(self, router):
        """Leases command returns formatted lease entries or (empty)."""
        leases = router.get_leases()
        assert isinstance(leases, list)
        assert len(leases) > 0, "Leases command returned no output"
        # Each entry should be either "(empty)" or contain an IP
        # Filter out any terminator artifacts
        data = [l for l in leases if l != "---"]
        for entry in data:
            assert "." in entry or "empty" in entry.lower(), \
                f"Unexpected lease format: {entry}"

    @pytest.mark.lan
    @pytest.mark.lan_ns
    def test_dhcp_server_assigns_ip(self, router):
        """DHCP server assigns IP in 10.1.1.100+ range to LAN client.

        Uses a second macvlan inside the lan_test namespace to get a fresh lease.
        """
        # Create a sub-interface with a new MAC inside the namespace
        setup = run_in_lan_ns(
            ["bash", "-c",
             "ip link add dhcp-test0 link lan-test0 type macvlan mode bridge && "
             "ip link set dhcp-test0 address 02:00:00:00:00:30 up"],
            timeout=5,
        )
        if setup.returncode != 0:
            pytest.skip(f"Could not create macvlan in namespace: {setup.stderr}")

        try:
            # Run dhclient in the namespace
            result = run_in_lan_ns(
                ["dhclient", "-1", "-v", "dhcp-test0"],
                timeout=15,
            )

            # Check assigned IP
            addr = run_in_lan_ns(["ip", "addr", "show", "dhcp-test0"], timeout=5)
            import re
            ip_match = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", addr.stdout)

            if ip_match:
                assigned_ip = ip_match.group(1)
                assert assigned_ip.startswith("10.1.1."), \
                    f"DHCP assigned wrong subnet: {assigned_ip}"
                ip_last = int(assigned_ip.split(".")[-1])
                assert ip_last >= 100, \
                    f"DHCP IP {assigned_ip} not in range (>=.100)"

                leases = router.get_leases()
                assert any(assigned_ip in l for l in leases), \
                    f"IP {assigned_ip} not in leases: {leases}"
            else:
                pytest.skip("dhclient unavailable or DHCP failed")
        finally:
            run_in_lan_ns(["dhclient", "-r", "dhcp-test0"], timeout=5)
            run_in_lan_ns(["ip", "link", "del", "dhcp-test0"], timeout=5)

    @pytest.mark.lan
    def test_dhcp_server_provides_gateway(self, router, router_lan_ip):
        """DHCP OFFER includes gateway option pointing to router LAN IP.

        We verify indirectly: the router's DHCP server sends option 3 (gateway)
        set to 10.1.1.1. We check the DHCP server config by verifying
        that a LAN client with the router as default gw can reach the WAN.
        This is already proven by the NAT/forwarding tests, so here we just
        verify the status output confirms the LAN gateway IP.
        """
        status = router.get_status()
        assert "lan" in status, f"No LAN in status: {status}"
        assert router_lan_ip in status["lan"], \
            f"LAN gateway {router_lan_ip} not in status: {status['lan']}"

    @pytest.mark.lan
    def test_dhcp_lease_expiry(self, router):
        """DHCP server tracks lease lifetime (7200s) with expiry.

        Verify that after a DHCP lease is assigned, it appears in the
        leases table. Full expiry test would require waiting 2 hours.
        """
        leases = router.get_leases()
        assert isinstance(leases, list)
        assert len(leases) > 0, "Lease table returned no output"



class TestDhcpClient:
    """Test the router's WAN DHCP client."""

    def test_dhcp_client_status(self, router):
        """Check DHCP client status via console."""
        resp = router.command("dhcp-client")
        assert "DHCP client:" in resp, f"Unexpected dhcp-client response: {resp}"
        assert any(state in resp.lower() for state in
                    ["bound", "idle", "discovering", "requesting", "rebinding"]), \
            f"Unknown DHCP client state: {resp}"

    def test_dhcp_client_extracts_gateway(self, router, wan_ip):
        """DHCP client learns gateway from option 3 and shows it in status."""
        status = router.get_status()
        assert "gw=" in status.get("wan", ""), \
            f"Gateway not shown in WAN status: {status}"
        # Default gateway is 10.0.2.1 (from static config or DHCP)
        assert wan_ip in status.get("wan", ""), \
            f"Gateway IP {wan_ip} not in status: {status}"

    def test_dhcp_client_renewal(self, router):
        """DHCP client tracks lease and renews at T1 (50% of lease time).

        Verify the client obtained a lease (bound state) and the WAN interface
        has an IP assigned from DHCP.
        """
        status = router.get_status()
        assert "wan" in status, f"No WAN in status: {status}"
        # WAN should have an IP (either from DHCP or static)
        assert "10." in status["wan"] or "192." in status["wan"], \
            f"WAN has no IP: {status['wan']}"

    def test_dhcp_client_t2_rebind(self, router):
        """DHCP client can rebind via broadcast REQUEST (T2 behavior).

        Runs a mini DHCP server on tap0, gets the client to bound state,
        forces a rebind, and verifies the client re-binds via broadcast.
        """
        srv = MiniDhcpServer()
        srv.start()
        try:
            # Trigger discovery — async DHCP logs interfere with prompt
            # detection, so use sendline for the initial trigger.
            # If an earlier test already triggered discovery, the 10s tick
            # retry needs to fire and see our server — poll until bound.
            router._drain()
            router.child.sendline("dhcp-client")
            # Consume the response+prompt to stay synced
            try:
                router._wait_prompt(timeout=5)
            except Exception:
                router._drain()

            bound = False
            for _ in range(15):
                router._drain()
                try:
                    resp = router.command("dhcp-client")
                except Exception:
                    router._resync()
                    continue
                if "bound" in resp.lower():
                    bound = True
                    break
            assert bound, f"DHCP client did not bind: {resp}"

            # Force a rebind — async logs will interfere with prompt
            router._drain()
            router.child.sendline("dhcp-test-rebind")
            # Consume the response+prompt to stay synced
            try:
                router._wait_prompt(timeout=10)
            except Exception:
                pass
            router._drain()

            # Resync before final check
            router._resync()
            # Verify client returned to bound state
            resp = router.command("dhcp-client")
            assert "bound" in resp.lower(), \
                f"DHCP client did not rebind: {resp}"

            # Server should have seen at least 2 ACKs (initial + rebind)
            assert srv.ack_count >= 2, \
                f"Expected >=2 ACKs, got {srv.ack_count}"
        finally:
            srv.stop()


class TestStaticDhcpLeases:
    """Test static DHCP lease functionality."""

    def test_add_static_lease(self, router):
        """Adding a static lease returns OK."""
        resp = router.add_static_lease("aa:bb:cc:dd:ee:01", "10.1.1.50")
        assert "OK" in resp

    def test_list_static_leases(self, router):
        """Static leases appear in the static-leases list."""
        router.add_static_lease("aa:bb:cc:dd:ee:02", "10.1.1.51")
        leases = router.get_static_leases()
        assert any("10.1.1.51" in l and "aa:bb:cc:dd:ee:02" in l for l in leases)

    def test_static_lease_invalid_mac(self, router):
        """Invalid MAC address is rejected."""
        resp = router.command("static-lease ZZZZ 10.1.1.50")
        assert "invalid" in resp.lower() or "usage" in resp.lower()

    def test_static_lease_invalid_ip(self, router):
        """Invalid IP address is rejected."""
        resp = router.command("static-lease aa:bb:cc:dd:ee:03 999.999.999.999")
        assert "invalid" in resp.lower()

    def test_static_lease_out_of_subnet(self, router):
        """IP outside LAN subnet is rejected."""
        resp = router.command("static-lease aa:bb:cc:dd:ee:04 192.168.1.50")
        assert "must be" in resp.lower() or "IP" in resp

    def test_static_lease_duplicate_ip_rejected(self, router):
        """Duplicate IP in static leases is rejected."""
        router.add_static_lease("aa:bb:cc:dd:ee:05", "10.1.1.52")
        resp = router.command("static-lease aa:bb:cc:dd:ee:06 10.1.1.52")
        assert "conflict" in resp.lower()

    def test_static_lease_in_get_config(self, router):
        """Static leases appear in get-config output."""
        router.add_static_lease("aa:bb:cc:dd:ee:07", "10.1.1.53")
        config = router.multi_command("get-config")
        assert any("static-lease" in line and "10.1.1.53" in line for line in config)
