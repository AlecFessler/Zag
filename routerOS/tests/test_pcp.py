"""PCP (Port Control Protocol) tests."""

import socket
import struct
import time

import pytest

from conftest import ping_from_lan_ns, run_in_lan_ns


PCP_PORT = 5351
PCP_VERSION = 2
OPCODE_MAP = 1
RESULT_SUCCESS = 0


def build_pcp_map_request(
    client_ip,
    protocol,
    internal_port,
    external_port=0,
    lifetime=3600,
    nonce=b"\x00" * 12,
):
    """Build a PCP MAP request packet (binary)."""
    # PCP header: version(1) + opcode(1) + reserved(2) + lifetime(4) + client_ip(16)
    header = struct.pack(
        "!BBH I",
        PCP_VERSION,
        OPCODE_MAP,
        0,
        lifetime,
    )
    ip_parts = [int(x) for x in client_ip.split(".")]
    client_ip_bytes = b"\x00" * 10 + b"\xff\xff" + bytes(ip_parts)
    header += client_ip_bytes

    proto_num = 6 if protocol == "tcp" else 17
    map_data = nonce
    map_data += struct.pack("!B3x HH", proto_num, internal_port, external_port)
    map_data += b"\x00" * 16

    return header + map_data


def send_pcp_from_lan_ns(router_ip, pcp_bytes, expect_response=True):
    """Send PCP request from lan_test namespace, return response bytes or None."""
    import binascii
    hex_data = binascii.hexlify(pcp_bytes).decode()

    script = (
        "import socket, sys, binascii\n"
        f"data = binascii.unhexlify('{hex_data}')\n"
        "s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n"
        "s.settimeout(5)\n"
        f"s.sendto(data, ('{router_ip}', {PCP_PORT}))\n"
    )
    if expect_response:
        script += (
            "try:\n"
            "    resp, addr = s.recvfrom(256)\n"
            "    sys.stdout.buffer.write(binascii.hexlify(resp))\n"
            "except socket.timeout:\n"
            "    print('TIMEOUT', file=sys.stderr)\n"
        )
    script += "s.close()\n"

    result = run_in_lan_ns(
        ["python3", "-c", script],
        timeout=10,
    )

    if result.returncode != 0:
        import sys
        print(f"PCP script failed (rc={result.returncode}): stderr={result.stderr}", file=sys.stderr)
    if expect_response and result.stdout and result.stdout.strip():
        import binascii as b
        try:
            return b.unhexlify(result.stdout.strip())
        except ValueError:
            return None
    return None


def parse_pcp_response(data):
    """Parse a PCP response."""
    if data is None or len(data) < 24:
        return None
    version = data[0]
    opcode = data[1] & 0x7F
    is_response = (data[1] & 0x80) != 0
    result_code = data[3]
    lifetime = struct.unpack("!I", data[4:8])[0]

    resp = {
        "version": version,
        "opcode": opcode,
        "is_response": is_response,
        "result_code": result_code,
        "lifetime": lifetime,
    }

    if len(data) >= 60 and opcode == OPCODE_MAP:
        map_data = data[24:]
        resp["nonce"] = map_data[0:12]
        resp["protocol"] = map_data[12]
        resp["internal_port"] = struct.unpack("!H", map_data[16:18])[0]
        resp["external_port"] = struct.unpack("!H", map_data[18:20])[0]

    return resp


class TestPCPProtocol:
    """Test PCP MAP request/response."""

    @pytest.mark.lan
    @pytest.mark.lan_ns
    def test_pcp_map_response(self, router, router_lan_ip):
        """Send PCP MAP request and verify the mapping is created (response optional)."""
        ping_from_lan_ns("10.1.1.1", count=1)
        time.sleep(1)

        wan_port = 18181
        req = build_pcp_map_request(
            client_ip="10.1.1.60",
            protocol="tcp",
            internal_port=8181,
            external_port=wan_port,
            lifetime=300,
        )

        # Send the PCP request (response may not arrive due to macvlan layer-2)
        resp_bytes = send_pcp_from_lan_ns(router_lan_ip, req)
        time.sleep(1)

        # Verify the port forward was created even if response wasn't received
        rules = router.get_rules()
        assert any(str(wan_port) in r for r in rules), \
            f"PCP mapping not created for port {wan_port}: {rules}"

        # If we got a response, validate it
        if resp_bytes is not None:
            resp = parse_pcp_response(resp_bytes)
            assert resp is not None, "Could not parse PCP response"
            assert resp["is_response"], "Response bit not set"
            assert resp["version"] == PCP_VERSION

    @pytest.mark.lan
    @pytest.mark.lan_ns
    def test_pcp_map_creates_forward(self, router, router_lan_ip):
        """PCP MAP should create a port forward visible in rules."""
        ping_from_lan_ns("10.1.1.1", count=1)
        time.sleep(1)

        wan_port = 19876

        req = build_pcp_map_request(
            client_ip="10.1.1.60",
            protocol="tcp",
            internal_port=9999,
            external_port=wan_port,
            lifetime=300,
        )

        send_pcp_from_lan_ns(router_lan_ip, req)
        time.sleep(1)

        rules = router.get_rules()
        fwd_rules = [r for r in rules if str(wan_port) in r]
        assert len(fwd_rules) > 0, f"PCP port forward for {wan_port} not found in rules: {rules}"

    @pytest.mark.lan
    @pytest.mark.lan_ns
    def test_pcp_map_delete(self, router, router_lan_ip):
        """PCP MAP with lifetime=0 should delete a mapping."""
        ping_from_lan_ns("10.1.1.1", count=1)
        time.sleep(1)

        wan_port = 19877

        # Create mapping
        req_create = build_pcp_map_request(
            client_ip="10.1.1.60",
            protocol="udp",
            internal_port=7777,
            external_port=wan_port,
            lifetime=300,
        )
        send_pcp_from_lan_ns(router_lan_ip, req_create)
        time.sleep(1)

        rules = router.get_rules()
        assert any(str(wan_port) in r for r in rules), \
            f"Forward not created: {rules}"

        # Delete mapping (lifetime=0)
        req_delete = build_pcp_map_request(
            client_ip="10.1.1.60",
            protocol="udp",
            internal_port=7777,
            external_port=wan_port,
            lifetime=0,
        )
        send_pcp_from_lan_ns(router_lan_ip, req_delete)
        time.sleep(1)

        rules = router.get_rules()
        fwd_rules = [r for r in rules if str(wan_port) in r and "forward" in r.lower()]
        assert len(fwd_rules) == 0, f"Forward still present after delete: {rules}"
