#!/usr/bin/env python3
"""WAN responder for passthrough testing.

Runs on the host, binds to eno1 (10.0.2.1). Provides echo services that
Pis send traffic to through the router, plus a localhost control API for
test coordination.

Services:
  - UDP echo on 10.0.2.1:9999
  - TCP echo on 10.0.2.1:9876
  - DNS responder on 10.0.2.1:53 (canned A records)
  - Control API on 127.0.0.1:8877
"""

import http.server
import json
import socket
import socketserver
import struct
import sys
import threading
import time

BIND_IP = "10.0.2.1"
BIND_DEV = b"eno1"
UDP_ECHO_PORT = 9999
TCP_ECHO_PORT = 9876
DNS_PORT = 53
CONTROL_PORT = 8877

EXPECTED_NAT_IP = "10.0.2.15"

# DNS canned responses: domain -> IP
DNS_RECORDS = {
    "example.com": "93.184.216.34",
    "test.example.com": "93.184.216.34",
    "router.test": "10.0.2.15",
    "wan.test": "10.0.2.1",
}
DNS_DEFAULT_IP = "1.2.3.4"

# ── Shared log ───────────────────────────────────────────────────────────

log_lock = threading.Lock()
packet_log = []
stats = {"udp": 0, "tcp": 0, "dns": 0}


def add_log(protocol, src_ip, src_port, data_preview, nat_valid):
    with log_lock:
        packet_log.append({
            "time": time.time(),
            "protocol": protocol,
            "src_ip": src_ip,
            "src_port": src_port,
            "data": data_preview[:200],
            "nat_valid": nat_valid,
        })
        stats[protocol] = stats.get(protocol, 0) + 1


def get_logs():
    with log_lock:
        return list(packet_log)


def get_stats():
    with log_lock:
        return dict(stats)


def clear_logs():
    with log_lock:
        packet_log.clear()
        for k in stats:
            stats[k] = 0


# ── UDP Echo Server ──────────────────────────────────────────────────────

def udp_echo_server():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, BIND_DEV)
    sock.bind((BIND_IP, UDP_ECHO_PORT))
    print(f"  UDP echo listening on {BIND_IP}:{UDP_ECHO_PORT}")

    while True:
        try:
            data, addr = sock.recvfrom(2048)
            nat_valid = addr[0] == EXPECTED_NAT_IP
            preview = data.decode("utf-8", errors="replace")
            add_log("udp", addr[0], addr[1], preview, nat_valid)
            # Echo back with prefix
            sock.sendto(b"ECHO:" + data, addr)
        except Exception as e:
            print(f"UDP echo error: {e}", file=sys.stderr)


# ── TCP Echo Server ──────────────────────────────────────────────────────

def tcp_echo_server():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, BIND_DEV)
    srv.bind((BIND_IP, TCP_ECHO_PORT))
    srv.listen(16)
    print(f"  TCP echo listening on {BIND_IP}:{TCP_ECHO_PORT}")

    while True:
        try:
            conn, addr = srv.accept()
            threading.Thread(target=_handle_tcp_client, args=(conn, addr), daemon=True).start()
        except Exception as e:
            print(f"TCP accept error: {e}", file=sys.stderr)


def _handle_tcp_client(conn, addr):
    try:
        conn.settimeout(10)
        data = conn.recv(2048)
        if data:
            nat_valid = addr[0] == EXPECTED_NAT_IP
            preview = data.decode("utf-8", errors="replace")
            add_log("tcp", addr[0], addr[1], preview, nat_valid)
            conn.sendall(b"ECHO:" + data)
    except Exception as e:
        print(f"TCP client error: {e}", file=sys.stderr)
    finally:
        conn.close()


# ── DNS Responder ────────────────────────────────────────────────────────

def dns_server():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, BIND_DEV)
    sock.bind((BIND_IP, DNS_PORT))
    print(f"  DNS responder listening on {BIND_IP}:{DNS_PORT}")

    while True:
        try:
            data, addr = sock.recvfrom(512)
            nat_valid = addr[0] == EXPECTED_NAT_IP
            # Parse domain from query
            domain = _parse_dns_domain(data)
            add_log("dns", addr[0], addr[1], f"DNS:{domain}", nat_valid)
            # Build response
            response = _build_dns_response(data, domain)
            sock.sendto(response, addr)
        except Exception as e:
            print(f"DNS error: {e}", file=sys.stderr)


def _parse_dns_domain(data):
    """Extract the queried domain from a DNS packet."""
    if len(data) < 12:
        return "?"
    offset = 12
    labels = []
    while offset < len(data) and data[offset] != 0:
        length = data[offset]
        if length & 0xC0 == 0xC0:
            break
        offset += 1
        labels.append(data[offset:offset + length].decode("ascii", errors="replace"))
        offset += length
    return ".".join(labels)


def _build_dns_response(query, domain):
    """Build a DNS response with a canned A record."""
    if len(query) < 12:
        return query
    query_id = struct.unpack("!H", query[:2])[0]
    question = query[12:]

    # Look up IP
    ip_str = DNS_RECORDS.get(domain, DNS_DEFAULT_IP)

    header = struct.pack("!HHHHHH", query_id, 0x8180, 1, 1, 0, 0)
    answer = struct.pack("!HHHIH", 0xC00C, 1, 1, 300, 4)
    answer += socket.inet_aton(ip_str)
    return header + question + answer


# ── Control API ──────────────────────────────────────────────────────────

class ControlHandler(http.server.BaseHTTPRequestHandler):
    """Localhost control API for test coordination."""

    def log_message(self, format, *args):
        pass

    def _send_json(self, obj, code=200):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self):
        length = int(self.headers.get("Content-Length", 0))
        if length == 0:
            return {}
        return json.loads(self.rfile.read(length))

    def do_GET(self):
        if self.path == "/health":
            self._send_json({"status": "ok"})
        elif self.path == "/logs":
            self._send_json(get_logs())
        elif self.path == "/stats":
            self._send_json(get_stats())
        else:
            self._send_json({"error": "not found"}, 404)

    def do_POST(self):
        if self.path == "/clear":
            clear_logs()
            self._send_json({"ok": True})
        elif self.path == "/send_udp":
            self._handle_send_udp()
        elif self.path == "/send_tcp":
            self._handle_send_tcp()
        else:
            self._send_json({"error": "not found"}, 404)

    def _handle_send_udp(self):
        params = self._read_body()
        target = params["target"]
        port = params["port"]
        data = params.get("data", "hello-from-wan").encode()

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, BIND_DEV)
            sock.bind((BIND_IP, 0))
            sock.sendto(data, (target, port))
            self._send_json({"sent": True, "target": target, "port": port})
        except Exception as e:
            self._send_json({"sent": False, "error": str(e)})
        finally:
            sock.close()

    def _handle_send_tcp(self):
        params = self._read_body()
        target = params["target"]
        port = params["port"]
        data = params.get("data", "hello-from-wan").encode()
        timeout = params.get("timeout", 5)

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, BIND_DEV)
            sock.bind((BIND_IP, 0))
            sock.connect((target, port))
            sock.sendall(data)
            try:
                response = sock.recv(2048)
                self._send_json({
                    "sent": True,
                    "received": True,
                    "response": response.decode("utf-8", errors="replace"),
                })
            except socket.timeout:
                self._send_json({"sent": True, "received": False})
        except Exception as e:
            self._send_json({"sent": False, "error": str(e)})
        finally:
            sock.close()


# ── Main ─────────────────────────────────────────────────────────────────

def main():
    print("WAN responder starting...")

    # Start service threads
    threading.Thread(target=udp_echo_server, daemon=True).start()
    threading.Thread(target=tcp_echo_server, daemon=True).start()
    threading.Thread(target=dns_server, daemon=True).start()

    # Control API on localhost
    control_server = http.server.HTTPServer(("127.0.0.1", CONTROL_PORT), ControlHandler)
    print(f"  Control API on 127.0.0.1:{CONTROL_PORT}")
    print("WAN responder ready.")

    try:
        control_server.serve_forever()
    except KeyboardInterrupt:
        pass
    control_server.server_close()


if __name__ == "__main__":
    main()
