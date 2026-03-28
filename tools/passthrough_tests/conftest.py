"""pytest fixtures for x550 passthrough end-to-end tests.

Manages QEMU lifecycle, Pi agent connections, and WAN responder.
"""

import json
import os
import subprocess
import sys
import time
import urllib.request
import urllib.error

import pytest

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
TOOLS_DIR = os.path.dirname(SCRIPT_DIR)
REPO_ROOT = os.path.dirname(TOOLS_DIR)

VFIO_BIND = os.path.join(TOOLS_DIR, "vfio-bind.sh")
VFIO_UNBIND = os.path.join(TOOLS_DIR, "vfio-unbind.sh")
WAN_RESPONDER = os.path.join(TOOLS_DIR, "wan_responder.py")

SERIAL_LOG = "/dev/null"

PI_HOSTS = [
    {"wifi_ip": "192.168.86.79", "name": "pi1"},
    {"wifi_ip": "192.168.86.78", "name": "pi2"},
    {"wifi_ip": "192.168.86.104", "name": "pi3"},
]

ROUTER_WAN_IP = "10.0.2.15"
ROUTER_LAN_IP = "10.1.1.1"
HOST_WAN_IP = "10.0.2.1"


# ── Pi Agent Client ─────────────────────────────────────────────────────

class PiClient:
    """HTTP client for communicating with a Pi test agent over WiFi."""

    def __init__(self, wifi_ip, name):
        self.wifi_ip = wifi_ip
        self.name = name
        self.base_url = f"http://{wifi_ip}:8080"
        self._eth_ip = None

    @property
    def eth_ip(self):
        if self._eth_ip is None:
            h = self.health()
            self._eth_ip = h.get("eth_ip")
        return self._eth_ip

    def _get(self, path, timeout=10):
        url = f"{self.base_url}{path}"
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read())

    def _post(self, path, data=None, timeout=15):
        url = f"{self.base_url}{path}"
        body = json.dumps(data or {}).encode()
        req = urllib.request.Request(url, data=body, method="POST")
        req.add_header("Content-Type", "application/json")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read())

    def health(self):
        return self._get("/health")

    def dhcp_info(self):
        return self._get("/net/dhcp_info")

    def dhcp_renew(self):
        return self._post("/net/dhcp_renew", timeout=25)

    def udp_roundtrip(self, target, port, payload=None, timeout=5):
        data = {"target": target, "port": port, "timeout": timeout}
        if payload:
            data["payload"] = payload
        return self._post("/test/udp_roundtrip", data, timeout=timeout + 5)

    def tcp_roundtrip(self, target, port, payload=None, timeout=5):
        data = {"target": target, "port": port, "timeout": timeout}
        if payload:
            data["payload"] = payload
        return self._post("/test/tcp_roundtrip", data, timeout=timeout + 5)

    def icmp_ping(self, target, count=3, timeout=10):
        return self._post("/test/icmp_ping", {"target": target, "count": count, "timeout": timeout},
                          timeout=timeout + 5)

    def dns_query(self, server, domain, timeout=5):
        return self._post("/test/dns_query", {"server": server, "domain": domain, "timeout": timeout},
                          timeout=timeout + 5)

    def listen_tcp(self, port, timeout=10, response="ACK"):
        return self._post("/test/listen_tcp", {"port": port, "timeout": timeout, "response": response},
                          timeout=timeout + 5)

    def listen_udp(self, port, timeout=10):
        return self._post("/test/listen_udp", {"port": port, "timeout": timeout},
                          timeout=timeout + 5)

    def upnp_discover(self):
        return self._post("/test/upnp_discover", timeout=10)

    def upnp_map(self, protocol, external_port, internal_port, internal_ip=None,
                 router_ip=None, lease=3600):
        data = {
            "protocol": protocol,
            "external_port": external_port,
            "internal_port": internal_port,
        }
        if internal_ip:
            data["internal_ip"] = internal_ip
        if router_ip:
            data["router_ip"] = router_ip
        data["lease"] = lease
        return self._post("/test/upnp_map", data, timeout=15)

    def upnp_delete(self, protocol, external_port, router_ip=None):
        data = {"protocol": protocol, "external_port": external_port}
        if router_ip:
            data["router_ip"] = router_ip
        return self._post("/test/upnp_delete", data, timeout=15)

    def upnp_get_external_ip(self, router_ip=None):
        data = {}
        if router_ip:
            data["router_ip"] = router_ip
        return self._post("/test/upnp_get_external_ip", data, timeout=15)

    def pcp_map(self, protocol, internal_port, external_port=0, lifetime=3600, router_ip=None):
        data = {
            "protocol": protocol,
            "internal_port": internal_port,
            "external_port": external_port,
            "lifetime": lifetime,
        }
        if router_ip:
            data["router_ip"] = router_ip
        return self._post("/test/pcp_map", data, timeout=10)

    def traceroute(self, target, max_hops=5, timeout=15):
        return self._post("/test/traceroute", {"target": target, "max_hops": max_hops, "timeout": timeout},
                          timeout=timeout + 5)

    def udp_flood(self, target, port, count=1000, interval_ms=1, payload="flood"):
        return self._post("/test/udp_flood", {
            "target": target, "port": port, "count": count,
            "interval_ms": interval_ms, "payload": payload,
        }, timeout=max(30, count * interval_ms / 1000 + 10))


# ── WAN Responder Client ────────────────────────────────────────────────

class WanResponderClient:
    """Client for the WAN responder's localhost control API."""

    def __init__(self, process):
        self.process = process
        self.base_url = "http://127.0.0.1:8877"

    def _get(self, path, timeout=5):
        url = f"{self.base_url}{path}"
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read())

    def _post(self, path, data=None, timeout=10):
        url = f"{self.base_url}{path}"
        body = json.dumps(data or {}).encode()
        req = urllib.request.Request(url, data=body, method="POST")
        req.add_header("Content-Type", "application/json")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read())

    def health(self):
        return self._get("/health")

    def get_logs(self):
        return self._get("/logs")

    def get_stats(self):
        return self._get("/stats")

    def clear_logs(self):
        return self._post("/clear")

    def send_udp(self, target, port, data="hello-from-wan"):
        return self._post("/send_udp", {"target": target, "port": port, "data": data})

    def send_tcp(self, target, port, data="hello-from-wan", timeout=5):
        return self._post("/send_tcp", {"target": target, "port": port, "data": data, "timeout": timeout})


# ── Fixtures ─────────────────────────────────────────────────────────────

@pytest.fixture(scope="session")
def wan(qemu_router):
    """Start WAN responder on eno1, yield client, stop on teardown."""
    proc = subprocess.Popen(
        ["sudo", sys.executable, WAN_RESPONDER],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    client = WanResponderClient(proc)

    # Wait for readiness
    deadline = time.time() + 10
    while time.time() < deadline:
        try:
            client.health()
            break
        except Exception:
            if proc.poll() is not None:
                stderr = proc.stderr.read().decode()
                pytest.fail(f"WAN responder died: {stderr}")
            time.sleep(0.5)
    else:
        proc.terminate()
        pytest.fail("WAN responder did not start within 10s")

    yield client

    proc.terminate()
    proc.wait(timeout=5)


@pytest.fixture(scope="session")
def qemu_router():
    """Build x550, bind VFIO, launch QEMU, wait for boot, yield, cleanup."""
    routeros_dir = os.path.join(REPO_ROOT, "routerOS")

    # 1. Build
    print("Building routerOS with x550...")
    subprocess.run(["zig", "build", "-Dnic=x550"], cwd=routeros_dir, check=True, timeout=120)
    subprocess.run(["zig", "build", "-Dprofile=router", "-Dnet=passthrough"],
                   cwd=REPO_ROOT, check=True, timeout=120)

    # 2. Remove stale NvVars (OVMF corruption workaround)
    nvvars = os.path.join(REPO_ROOT, "zig-out", "img", "NvVars")
    if os.path.exists(nvvars):
        os.remove(nvvars)

    # 3. Bind VFIO
    print("Binding x550 to vfio-pci...")
    subprocess.run(["sudo", VFIO_BIND], check=True, timeout=30)

    # 4. Set up eno1 as mock gateway
    subprocess.run(["sudo", "ip", "addr", "add", "10.0.2.1/24", "dev", "eno1"],
                   capture_output=True)  # may already exist
    subprocess.run(["sudo", "ip", "link", "set", "eno1", "up"], check=True)

    # 5. Launch QEMU
    print("Launching QEMU with x550 passthrough...")
    img_dir = os.path.join(REPO_ROOT, "zig-out", "img")
    qemu_cmd = [
        "sudo", "qemu-system-x86_64",
        "-m", "1G",
        "-bios", "/usr/share/ovmf/x64/OVMF.4m.fd",
        f"-drive", f"file=fat:rw:{img_dir},format=raw",
        "-serial", f"file:{SERIAL_LOG}",
        "-display", "none",
        "-no-reboot",
        "-enable-kvm", "-cpu", "host,+invtsc",
        "-machine", "q35",
        "-net", "none",
        "-device", "pcie-root-port,id=rp1,slot=1",
        "-device", "pcie-pci-bridge,id=br1,bus=rp1",
        "-device", "vfio-pci,host=05:00.0,bus=br1,addr=1.0",
        "-device", "vfio-pci,host=05:00.1,bus=br1,addr=2.0",
        "-smp", "cores=4",
    ]
    qemu_proc = subprocess.Popen(qemu_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    # 7. Wait for boot — poll Pi over WiFi until it can ping the router LAN IP
    print("Waiting for router to boot (polling Pi1 over WiFi)...")
    time.sleep(5)  # let QEMU start and x550 link come up
    pi_probe = PiClient(PI_HOSTS[0]["wifi_ip"], "pi1-probe")
    deadline = time.time() + 60
    booted = False
    while time.time() < deadline:
        if qemu_proc.poll() is not None:
            stderr = qemu_proc.stderr.read().decode()
            subprocess.run(["sudo", VFIO_UNBIND], capture_output=True)
            pytest.fail(f"QEMU exited prematurely: {stderr}")
        try:
            result = pi_probe.icmp_ping(ROUTER_LAN_IP, count=1, timeout=2)
            if result.get("success"):
                booted = True
                break
        except Exception:
            pass
        time.sleep(2)

    if not booted:
        qemu_proc.terminate()
        try:
            qemu_proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            qemu_proc.kill()
            qemu_proc.wait()
        subprocess.run(["sudo", VFIO_UNBIND], capture_output=True)
        pytest.fail("Router did not boot within 60s (Pi1 could not ping 10.1.1.1)")

    print("Router is up (Pi1 can ping LAN IP).")

    yield qemu_proc

    # Cleanup
    print("Stopping QEMU...")
    qemu_proc.terminate()
    try:
        qemu_proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        qemu_proc.kill()
        qemu_proc.wait()

    print("Restoring ixgbe driver...")
    subprocess.run(["sudo", VFIO_UNBIND], capture_output=True)


@pytest.fixture(scope="session")
def pis(qemu_router):
    """Wait for all 3 Pi agents to be healthy with DHCP IPs, return list of PiClient."""
    clients = [PiClient(p["wifi_ip"], p["name"]) for p in PI_HOSTS]

    # Trigger DHCP renewal on each Pi now that the router is up
    print("Triggering DHCP renewal on Pis...")
    for pi in clients:
        try:
            result = pi.dhcp_renew()
            print(f"  {pi.name}: dhcp_renew -> eth_ip={result.get('eth_ip')}, gw={result.get('gateway')}")
        except Exception as e:
            print(f"  {pi.name}: dhcp_renew failed: {e}")

    print("Waiting for Pi agents to get DHCP IPs...")
    deadline = time.time() + 90

    for pi in clients:
        while time.time() < deadline:
            try:
                h = pi.health()
                eth_ip = h.get("eth_ip")
                if eth_ip and eth_ip.startswith("10.1.1."):
                    pi._eth_ip = eth_ip
                    print(f"  {pi.name} ({pi.wifi_ip}): eth={eth_ip}")
                    break
            except Exception:
                pass
            time.sleep(2)
        else:
            # Last resort: try another DHCP renewal
            try:
                pi.dhcp_renew()
                time.sleep(5)
                h = pi.health()
                eth_ip = h.get("eth_ip")
                if eth_ip and eth_ip.startswith("10.1.1."):
                    pi._eth_ip = eth_ip
                    print(f"  {pi.name} ({pi.wifi_ip}): eth={eth_ip} (after retry)")
                    continue
            except Exception:
                pass
            pytest.fail(f"Pi {pi.name} ({pi.wifi_ip}) never got DHCP IP within timeout")

    return clients


@pytest.fixture(scope="session")
def pi1(pis):
    return pis[0]


@pytest.fixture(scope="session")
def pi2(pis):
    return pis[1]


@pytest.fixture(scope="session")
def pi3(pis):
    return pis[2]
