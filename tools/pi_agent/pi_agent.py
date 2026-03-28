#!/usr/bin/env python3
"""Pi test agent for router passthrough testing.

HTTP server running on each Pi's WiFi interface. Accepts test commands
over WiFi, executes network operations over ethernet (through router),
returns JSON results. Python stdlib only — no pip dependencies.
"""

import json
import http.client
import http.server
import os
import socket
import struct
import subprocess
import threading
import time
import xml.etree.ElementTree as ET


AGENT_PORT = 8080


# ── Helpers ──────────────────────────────────────────────────────────────

def get_eth_iface():
    """Detect the wired ethernet interface name."""
    out = subprocess.check_output(
        "ip -o link show | grep -v lo | grep -v wlan | awk -F': ' '{print $2}' | head -1",
        shell=True, text=True,
    ).strip()
    return out or "eth0"


def get_eth_ip(iface):
    """Get the IPv4 address on the ethernet interface."""
    try:
        out = subprocess.check_output(
            ["ip", "-4", "-o", "addr", "show", iface], text=True,
        )
        for line in out.splitlines():
            parts = line.split()
            for i, p in enumerate(parts):
                if p == "inet":
                    return parts[i + 1].split("/")[0]
    except Exception:
        pass
    return None


def get_wifi_ip():
    """Get the IPv4 address on the WiFi interface."""
    try:
        out = subprocess.check_output(
            ["ip", "-4", "-o", "addr", "show"], text=True,
        )
        for line in out.splitlines():
            if "wlan" in line:
                parts = line.split()
                for i, p in enumerate(parts):
                    if p == "inet":
                        return parts[i + 1].split("/")[0]
    except Exception:
        pass
    return None


def get_gateway():
    """Get the default gateway."""
    try:
        out = subprocess.check_output(
            ["ip", "route", "show", "default"], text=True,
        )
        parts = out.split()
        if "via" in parts:
            return parts[parts.index("via") + 1]
    except Exception:
        pass
    return None


def get_mac(iface):
    """Get MAC address of an interface."""
    try:
        with open(f"/sys/class/net/{iface}/address") as f:
            return f.read().strip()
    except Exception:
        return None


def json_response(obj):
    """Encode a dict as JSON bytes."""
    return json.dumps(obj).encode()


def error_response(msg):
    return json_response({"error": str(msg)})


# ── DNS packet builder ──────────────────────────────────────────────────

def build_dns_query(domain, query_id=0x1234):
    """Build a minimal DNS A-record query."""
    header = struct.pack("!HHHHHH", query_id, 0x0100, 1, 0, 0, 0)
    question = b""
    for label in domain.split("."):
        question += bytes([len(label)]) + label.encode()
    question += b"\x00"
    question += struct.pack("!HH", 1, 1)  # QTYPE=A, QCLASS=IN
    return header + question


def parse_dns_response(data):
    """Parse a DNS response, extract A record answers."""
    if len(data) < 12:
        return None
    qid, flags, qdcount, ancount = struct.unpack("!HHHH", data[:8])
    # Skip question section
    offset = 12
    for _ in range(qdcount):
        while offset < len(data) and data[offset] != 0:
            if data[offset] & 0xC0 == 0xC0:
                offset += 2
                break
            offset += data[offset] + 1
        else:
            offset += 1
        offset += 4  # QTYPE + QCLASS

    answers = []
    for _ in range(ancount):
        if offset >= len(data):
            break
        # Skip name (may be pointer)
        if data[offset] & 0xC0 == 0xC0:
            offset += 2
        else:
            while offset < len(data) and data[offset] != 0:
                offset += data[offset] + 1
            offset += 1
        if offset + 10 > len(data):
            break
        rtype, rclass, rttl, rdlen = struct.unpack("!HHIH", data[offset:offset + 10])
        offset += 10
        if rtype == 1 and rdlen == 4 and offset + 4 <= len(data):
            ip = socket.inet_ntoa(data[offset:offset + 4])
            answers.append(ip)
        offset += rdlen

    return {"query_id": qid, "answers": answers, "ancount": ancount}


# ── PCP packet builder ──────────────────────────────────────────────────

PCP_VERSION = 2
PCP_OPCODE_MAP = 1


def build_pcp_map_request(client_ip, protocol, internal_port, external_port=0,
                          lifetime=3600, nonce=b"\x00" * 12):
    """Build a PCP MAP request packet."""
    header = struct.pack("!BBH I", PCP_VERSION, PCP_OPCODE_MAP, 0, lifetime)
    ip_parts = [int(x) for x in client_ip.split(".")]
    client_ip_bytes = b"\x00" * 10 + b"\xff\xff" + bytes(ip_parts)
    header += client_ip_bytes

    proto_num = 6 if protocol.lower() == "tcp" else 17
    map_data = nonce
    map_data += struct.pack("!B3x HH", proto_num, internal_port, external_port)
    map_data += b"\x00" * 16  # suggested external address (any)

    return header + map_data


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

    if len(data) >= 60 and opcode == PCP_OPCODE_MAP:
        map_data = data[24:]
        resp["protocol"] = map_data[12]
        resp["internal_port"] = struct.unpack("!H", map_data[16:18])[0]
        resp["external_port"] = struct.unpack("!H", map_data[18:20])[0]

    return resp


# ── UPnP SOAP helpers ───────────────────────────────────────────────────

def upnp_soap_request(router_ip, action_name, soap_body, timeout=10):
    """Send a SOAP request to the router's UPnP control endpoint."""
    conn = http.client.HTTPConnection(router_ip, 80, timeout=timeout)
    headers = {
        "Content-Type": "text/xml",
        "SOAPAction": f'"urn:schemas-upnp-org:service:WANIPConnection:1#{action_name}"',
    }
    try:
        conn.request("POST", "/upnp/control/WANIPConn1", soap_body.encode(), headers)
        resp = conn.getresponse()
        body = resp.read().decode("utf-8", errors="replace")
        return {"status": resp.status, "body": body}
    except Exception as e:
        return {"error": str(e)}
    finally:
        conn.close()


# ── Request handler ─────────────────────────────────────────────────────

class AgentHandler(http.server.BaseHTTPRequestHandler):
    """HTTP request handler for the Pi test agent."""

    eth_iface = None

    def log_message(self, format, *args):
        pass  # suppress default logging

    def _read_body(self):
        length = int(self.headers.get("Content-Length", 0))
        if length == 0:
            return {}
        return json.loads(self.rfile.read(length))

    def _send_json(self, obj, code=200):
        body = json_response(obj)
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    # ── Routes ───────────────────────────────────────────────────────

    def do_GET(self):
        if self.path == "/health":
            self._handle_health()
        elif self.path == "/net/dhcp_info":
            self._handle_dhcp_info()
        else:
            self._send_json({"error": "not found"}, 404)

    def do_POST(self):
        routes = {
            "/net/dhcp_renew": self._handle_dhcp_renew,
            "/test/udp_roundtrip": self._handle_udp_roundtrip,
            "/test/tcp_roundtrip": self._handle_tcp_roundtrip,
            "/test/icmp_ping": self._handle_icmp_ping,
            "/test/dns_query": self._handle_dns_query,
            "/test/listen_tcp": self._handle_listen_tcp,
            "/test/listen_udp": self._handle_listen_udp,
            "/test/upnp_discover": self._handle_upnp_discover,
            "/test/upnp_map": self._handle_upnp_map,
            "/test/upnp_delete": self._handle_upnp_delete,
            "/test/upnp_get_external_ip": self._handle_upnp_get_external_ip,
            "/test/pcp_map": self._handle_pcp_map,
            "/test/traceroute": self._handle_traceroute,
            "/test/udp_flood": self._handle_udp_flood,
        }
        handler = routes.get(self.path)
        if handler:
            try:
                handler()
            except Exception as e:
                self._send_json({"error": str(e)}, 500)
        else:
            self._send_json({"error": "not found"}, 404)

    # ── Endpoint implementations ─────────────────────────────────────

    def _handle_health(self):
        iface = self.__class__.eth_iface or get_eth_iface()
        self._send_json({
            "status": "ok",
            "hostname": socket.gethostname(),
            "eth_ip": get_eth_ip(iface),
            "wifi_ip": get_wifi_ip(),
            "gateway": get_gateway(),
            "mac": get_mac(iface),
        })

    def _handle_dhcp_info(self):
        iface = self.__class__.eth_iface or get_eth_iface()
        self._send_json({
            "eth_ip": get_eth_ip(iface),
            "gateway": get_gateway(),
            "eth_iface": iface,
            "mac": get_mac(iface),
        })

    def _handle_dhcp_renew(self):
        """Force DHCP renewal on the ethernet interface."""
        iface = self.__class__.eth_iface or get_eth_iface()
        errors = []

        # Remove any existing static IP on the interface
        subprocess.run(["ip", "addr", "flush", "dev", iface],
                       capture_output=True, timeout=5)

        # Try dhcpcd first (Raspberry Pi OS default)
        result = subprocess.run(
            ["dhcpcd", "--release", iface],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode == 0 or "dhcpcd" in result.stderr:
            # dhcpcd is available, rebind
            result = subprocess.run(
                ["dhcpcd", "-n", iface],
                capture_output=True, text=True, timeout=15,
            )
            if result.returncode != 0:
                errors.append(f"dhcpcd -n: {result.stderr.strip()}")
        else:
            errors.append(f"dhcpcd release: {result.stderr.strip()}")
            # Try nmcli (Bookworm)
            result = subprocess.run(
                ["nmcli", "device", "reapply", iface],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode != 0:
                errors.append(f"nmcli: {result.stderr.strip()}")
                # Last resort: dhclient
                subprocess.run(["dhclient", "-r", iface],
                               capture_output=True, timeout=5)
                result = subprocess.run(["dhclient", iface],
                                        capture_output=True, text=True, timeout=15)
                if result.returncode != 0:
                    errors.append(f"dhclient: {result.stderr.strip()}")

        # Wait for IP assignment
        time.sleep(5)
        new_ip = get_eth_ip(iface)
        new_gw = get_gateway()

        self._send_json({
            "eth_ip": new_ip,
            "gateway": new_gw,
            "errors": errors if errors else None,
        })

    def _handle_udp_roundtrip(self):
        params = self._read_body()
        target = params["target"]
        port = params["port"]
        payload = params.get("payload", f"{socket.gethostname()} udp-test")
        timeout = params.get("timeout", 5)

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        try:
            start = time.monotonic()
            sock.sendto(payload.encode(), (target, port))
            try:
                data, addr = sock.recvfrom(2048)
                rtt_ms = (time.monotonic() - start) * 1000
                self._send_json({
                    "sent": True,
                    "received": True,
                    "response": data.decode("utf-8", errors="replace"),
                    "rtt_ms": round(rtt_ms, 2),
                    "from_ip": addr[0],
                    "from_port": addr[1],
                })
            except socket.timeout:
                self._send_json({"sent": True, "received": False, "error": "timeout"})
        finally:
            sock.close()

    def _handle_tcp_roundtrip(self):
        params = self._read_body()
        target = params["target"]
        port = params["port"]
        payload = params.get("payload", f"{socket.gethostname()} tcp-test")
        timeout = params.get("timeout", 5)

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            start = time.monotonic()
            sock.connect((target, port))
            sock.sendall(payload.encode())
            data = sock.recv(2048)
            rtt_ms = (time.monotonic() - start) * 1000
            self._send_json({
                "sent": True,
                "received": True,
                "response": data.decode("utf-8", errors="replace"),
                "rtt_ms": round(rtt_ms, 2),
            })
        except socket.timeout:
            self._send_json({"sent": True, "received": False, "error": "timeout"})
        except ConnectionRefusedError:
            self._send_json({"sent": False, "received": False, "error": "connection_refused"})
        finally:
            sock.close()

    def _handle_icmp_ping(self):
        params = self._read_body()
        target = params["target"]
        count = params.get("count", 3)
        timeout_s = params.get("timeout", 10)

        try:
            result = subprocess.run(
                ["ping", "-c", str(count), "-W", "2", target],
                capture_output=True, text=True, timeout=timeout_s,
            )
            output = result.stdout
            # Parse ping output
            sent = received = 0
            rtt_avg = None
            ttl = None
            for line in output.splitlines():
                if "packets transmitted" in line:
                    parts = line.split(",")
                    sent = int(parts[0].strip().split()[0])
                    received = int(parts[1].strip().split()[0])
                if "rtt" in line or "round-trip" in line:
                    # min/avg/max/mdev
                    vals = line.split("=")[-1].strip().split("/")
                    if len(vals) >= 2:
                        rtt_avg = float(vals[1])
                if "ttl=" in line.lower():
                    for part in line.split():
                        if part.lower().startswith("ttl="):
                            ttl = int(part.split("=")[1])

            self._send_json({
                "success": received > 0,
                "packets_sent": sent,
                "packets_received": received,
                "rtt_avg_ms": rtt_avg,
                "ttl": ttl,
            })
        except subprocess.TimeoutExpired:
            self._send_json({"success": False, "error": "timeout"})

    def _handle_dns_query(self):
        params = self._read_body()
        server = params["server"]
        domain = params["domain"]
        timeout = params.get("timeout", 5)
        query_id = params.get("query_id", 0x1234)

        query = build_dns_query(domain, query_id)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        try:
            start = time.monotonic()
            sock.sendto(query, (server, 53))
            data, _ = sock.recvfrom(512)
            rtt_ms = (time.monotonic() - start) * 1000
            parsed = parse_dns_response(data)
            if parsed:
                self._send_json({
                    "resolved": len(parsed["answers"]) > 0,
                    "answers": parsed["answers"],
                    "query_id": parsed["query_id"],
                    "rtt_ms": round(rtt_ms, 2),
                })
            else:
                self._send_json({"resolved": False, "error": "parse_failed"})
        except socket.timeout:
            self._send_json({"resolved": False, "error": "timeout"})
        finally:
            sock.close()

    def _handle_listen_tcp(self):
        params = self._read_body()
        port = params["port"]
        timeout = params.get("timeout", 10)
        response_data = params.get("response", "ACK")

        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.settimeout(timeout)
        try:
            srv.bind(("0.0.0.0", port))
            srv.listen(1)
            conn, addr = srv.accept()
            conn.settimeout(timeout)
            data = conn.recv(2048)
            conn.sendall(response_data.encode())
            conn.close()
            self._send_json({
                "received": True,
                "data": data.decode("utf-8", errors="replace"),
                "from_ip": addr[0],
                "from_port": addr[1],
            })
        except socket.timeout:
            self._send_json({"received": False, "error": "timeout"})
        finally:
            srv.close()

    def _handle_listen_udp(self):
        params = self._read_body()
        port = params["port"]
        timeout = params.get("timeout", 10)

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(timeout)
        try:
            sock.bind(("0.0.0.0", port))
            data, addr = sock.recvfrom(2048)
            self._send_json({
                "received": True,
                "data": data.decode("utf-8", errors="replace"),
                "from_ip": addr[0],
                "from_port": addr[1],
            })
        except socket.timeout:
            self._send_json({"received": False, "error": "timeout"})
        finally:
            sock.close()

    def _handle_upnp_discover(self):
        ssdp_msg = (
            "M-SEARCH * HTTP/1.1\r\n"
            "HOST: 239.255.255.250:1900\r\n"
            "ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n"
            'MAN: "ssdp:discover"\r\n'
            "MX: 3\r\n"
            "\r\n"
        )
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(5)
        try:
            sock.sendto(ssdp_msg.encode(), ("239.255.255.250", 1900))
            data, addr = sock.recvfrom(2048)
            response_text = data.decode("utf-8", errors="replace")
            location = None
            for line in response_text.splitlines():
                if line.lower().startswith("location:"):
                    location = line.split(":", 1)[1].strip()
            self._send_json({
                "found": True,
                "location": location,
                "from_ip": addr[0],
                "raw": response_text,
            })
        except socket.timeout:
            self._send_json({"found": False, "error": "timeout"})
        finally:
            sock.close()

    def _handle_upnp_map(self):
        params = self._read_body()
        router_ip = params.get("router_ip", get_gateway() or "10.1.1.1")
        protocol = params.get("protocol", "TCP")
        external_port = params["external_port"]
        internal_ip = params.get("internal_ip", get_eth_ip(self.__class__.eth_iface or get_eth_iface()))
        internal_port = params["internal_port"]
        description = params.get("description", "passthrough-test")
        lease = params.get("lease", 3600)

        soap_body = (
            '<?xml version="1.0"?>'
            '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
            's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">'
            '<s:Body><u:AddPortMapping xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">'
            '<NewRemoteHost></NewRemoteHost>'
            f'<NewExternalPort>{external_port}</NewExternalPort>'
            f'<NewProtocol>{protocol}</NewProtocol>'
            f'<NewInternalPort>{internal_port}</NewInternalPort>'
            f'<NewInternalClient>{internal_ip}</NewInternalClient>'
            '<NewEnabled>1</NewEnabled>'
            f'<NewPortMappingDescription>{description}</NewPortMappingDescription>'
            f'<NewLeaseDuration>{lease}</NewLeaseDuration>'
            '</u:AddPortMapping></s:Body></s:Envelope>'
        )

        result = upnp_soap_request(router_ip, "AddPortMapping", soap_body)
        self._send_json(result)

    def _handle_upnp_delete(self):
        params = self._read_body()
        router_ip = params.get("router_ip", get_gateway() or "10.1.1.1")
        protocol = params.get("protocol", "TCP")
        external_port = params["external_port"]

        soap_body = (
            '<?xml version="1.0"?>'
            '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
            's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">'
            '<s:Body><u:DeletePortMapping xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">'
            '<NewRemoteHost></NewRemoteHost>'
            f'<NewExternalPort>{external_port}</NewExternalPort>'
            f'<NewProtocol>{protocol}</NewProtocol>'
            '</u:DeletePortMapping></s:Body></s:Envelope>'
        )

        result = upnp_soap_request(router_ip, "DeletePortMapping", soap_body)
        self._send_json(result)

    def _handle_upnp_get_external_ip(self):
        params = self._read_body()
        router_ip = params.get("router_ip", get_gateway() or "10.1.1.1")

        soap_body = (
            '<?xml version="1.0"?>'
            '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
            's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">'
            '<s:Body><u:GetExternalIPAddress xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">'
            '</u:GetExternalIPAddress></s:Body></s:Envelope>'
        )

        result = upnp_soap_request(router_ip, "GetExternalIPAddress", soap_body)
        # Try to extract the IP from the response
        if "body" in result and "NewExternalIPAddress" in result["body"]:
            try:
                root = ET.fromstring(result["body"].split("\r\n\r\n")[-1] if "\r\n\r\n" in result["body"] else result["body"])
                for elem in root.iter():
                    if "NewExternalIPAddress" in (elem.tag or ""):
                        result["external_ip"] = elem.text
            except ET.ParseError:
                # Try simple string extraction
                body = result["body"]
                start = body.find("<NewExternalIPAddress>")
                end = body.find("</NewExternalIPAddress>")
                if start != -1 and end != -1:
                    result["external_ip"] = body[start + len("<NewExternalIPAddress>"):end]
        self._send_json(result)

    def _handle_pcp_map(self):
        params = self._read_body()
        router_ip = params.get("router_ip", get_gateway() or "10.1.1.1")
        protocol = params.get("protocol", "tcp")
        internal_port = params["internal_port"]
        external_port = params.get("external_port", 0)
        lifetime = params.get("lifetime", 3600)

        iface = self.__class__.eth_iface or get_eth_iface()
        client_ip = get_eth_ip(iface) or "0.0.0.0"

        req = build_pcp_map_request(
            client_ip=client_ip,
            protocol=protocol,
            internal_port=internal_port,
            external_port=external_port,
            lifetime=lifetime,
        )

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(5)
        try:
            sock.sendto(req, (router_ip, 5351))
            try:
                data, _ = sock.recvfrom(256)
                parsed = parse_pcp_response(data)
                if parsed:
                    self._send_json({"success": True, **parsed})
                else:
                    self._send_json({"success": False, "error": "parse_failed"})
            except socket.timeout:
                # PCP request may still have been processed even without response
                self._send_json({"success": True, "response_received": False})
        finally:
            sock.close()

    def _handle_traceroute(self):
        params = self._read_body()
        target = params["target"]
        max_hops = params.get("max_hops", 5)
        timeout = params.get("timeout", 15)

        try:
            result = subprocess.run(
                ["traceroute", "-n", "-m", str(max_hops), "-w", "2", target],
                capture_output=True, text=True, timeout=timeout,
            )
            hops = []
            for line in result.stdout.splitlines():
                line = line.strip()
                if not line or line.startswith("traceroute"):
                    continue
                parts = line.split()
                if len(parts) >= 2:
                    ttl = parts[0]
                    ip = parts[1] if parts[1] != "*" else None
                    rtt = None
                    for p in parts[2:]:
                        try:
                            rtt = float(p)
                            break
                        except ValueError:
                            continue
                    hops.append({"ttl": int(ttl), "ip": ip, "rtt_ms": rtt})
            self._send_json({"hops": hops, "target": target})
        except subprocess.TimeoutExpired:
            self._send_json({"hops": [], "error": "timeout"})
        except FileNotFoundError:
            # traceroute not installed, fall back to error
            self._send_json({"hops": [], "error": "traceroute not installed"})

    def _handle_udp_flood(self):
        params = self._read_body()
        target = params["target"]
        port = params["port"]
        count = params.get("count", 1000)
        interval_ms = params.get("interval_ms", 1)
        payload = params.get("payload", "flood").encode()

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            start = time.monotonic()
            for i in range(count):
                sock.sendto(payload, (target, port))
                if interval_ms > 0 and i < count - 1:
                    time.sleep(interval_ms / 1000.0)
            elapsed_ms = (time.monotonic() - start) * 1000
            self._send_json({
                "sent": count,
                "elapsed_ms": round(elapsed_ms, 2),
                "pps": round(count / (elapsed_ms / 1000), 1) if elapsed_ms > 0 else 0,
            })
        finally:
            sock.close()


# ── Main ─────────────────────────────────────────────────────────────────

def main():
    AgentHandler.eth_iface = get_eth_iface()
    print(f"Pi agent starting on port {AGENT_PORT}")
    print(f"  Hostname: {socket.gethostname()}")
    print(f"  Eth iface: {AgentHandler.eth_iface}")
    print(f"  Eth IP: {get_eth_ip(AgentHandler.eth_iface)}")
    print(f"  WiFi IP: {get_wifi_ip()}")
    print(f"  Gateway: {get_gateway()}")

    server = http.server.HTTPServer(("0.0.0.0", AGENT_PORT), AgentHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    server.server_close()


if __name__ == "__main__":
    main()
