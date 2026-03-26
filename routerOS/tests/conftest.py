"""pytest fixtures for RouterOS end-to-end tests."""

import os
import subprocess
import time

import pytest

from harness import QemuRouter

ROUTER_BOOT_TIMEOUT = 30.0


def pytest_configure(config):
    config.addinivalue_line("markers", "lan: tests requiring LAN NIC initialization")
    config.addinivalue_line("markers", "lan_ns: tests requiring lan_test network namespace (sudo setup)")
    config.addinivalue_line("markers", "unimplemented: tests for features not yet implemented")


def pytest_collection_modifyitems(config, items):
    """Auto-skip tests marked @lan_ns if the namespace doesn't exist."""
    if not lan_ns_exists():
        skip = pytest.mark.skip(reason="lan_test namespace not found — run: sudo routerOS/tests/setup_sudo.sh")
        for item in items:
            if "lan_ns" in item.keywords:
                item.add_marker(skip)


def _run_ip(args: list[str]):
    """Run an ip command via sudo -n (passwordless, via sudoers rule)."""
    cmd = args if os.geteuid() == 0 else ["sudo", "-n"] + args
    return subprocess.run(cmd, capture_output=True, text=True)


def _setup_lan_macvlan():
    """Set up macvlan on tap1 inside the existing lan_test namespace (after QEMU boots).

    The namespace itself must be created beforehand via setup_sudo.sh.
    This only configures the macvlan interface, which needs CAP_NET_ADMIN.
    """
    if not lan_ns_exists():
        return
    # Check if already configured
    r = _run_ip(["ip", "netns", "exec", "lan_test", "ip", "addr", "show", "lan-test0"])
    if r.returncode == 0 and "10.1.1.60" in r.stdout:
        return
    cmds = [
        ["ip", "link", "add", "lan-test0", "link", "tap1",
         "type", "macvlan", "mode", "bridge"],
        ["ip", "link", "set", "lan-test0", "address", "02:00:00:00:00:20"],
        ["ip", "link", "set", "lan-test0", "netns", "lan_test"],
        ["ip", "netns", "exec", "lan_test", "ip", "link", "set", "lo", "up"],
        ["ip", "netns", "exec", "lan_test", "ip", "link", "set", "lan-test0", "up"],
        ["ip", "netns", "exec", "lan_test", "ip", "addr", "add",
         "10.1.1.60/24", "dev", "lan-test0"],
        ["ip", "netns", "exec", "lan_test", "ip", "route", "add",
         "default", "via", "10.1.1.1"],
    ]
    for cmd in cmds:
        r = _run_ip(cmd)
        if r.returncode != 0:
            import sys
            print(f"[conftest] macvlan setup failed: {' '.join(cmd)}: {r.stderr.strip()}", file=sys.stderr)
            return


def _teardown_lan_macvlan():
    """Remove macvlan interface (namespace persists for reuse)."""
    _run_ip(["ip", "netns", "exec", "lan_test", "ip", "link", "del", "lan-test0"])


@pytest.fixture(scope="session")
def router():
    """Session-scoped fixture: build, boot, and yield a QemuRouter."""
    r = QemuRouter(build=False, boot_timeout=ROUTER_BOOT_TIMEOUT)
    r.start()
    time.sleep(2)
    # Create macvlan AFTER QEMU boots (tap1 must be open first)
    _setup_lan_macvlan()
    time.sleep(1)  # Let macvlan settle
    yield r
    _teardown_lan_macvlan()
    r.stop()


@pytest.fixture(scope="session")
def wan_ip():
    """The host's WAN-side IP (on tap0)."""
    return "10.0.2.1"


@pytest.fixture(scope="session")
def lan_ip():
    """The host's LAN-side IP (on tap1)."""
    return "10.1.1.50"


@pytest.fixture(scope="session")
def router_wan_ip():
    """The router's WAN IP."""
    return "10.0.2.15"


@pytest.fixture(scope="session")
def router_lan_ip():
    """The router's LAN gateway IP."""
    return "10.1.1.1"


@pytest.fixture(scope="session")
def lan_ns_ip():
    """The IP of the lan_test namespace interface."""
    return "10.1.1.60"


def run_on_host(cmd: list[str], timeout: float = 10.0) -> subprocess.CompletedProcess:
    """Run a command on the host and return the result."""
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def _lan_iface() -> str:
    """Return the LAN interface name: br-lan if bridged, tap1 otherwise."""
    result = subprocess.run(
        ["ip", "link", "show", "br-lan"],
        capture_output=True, text=True,
    )
    return "br-lan" if result.returncode == 0 else "tap1"


LAN_IFACE = _lan_iface()


def _resolve_interface(interface: str | None) -> str | None:
    """If tap1 is in a bridge, use the bridge interface instead."""
    if interface == "tap1":
        return LAN_IFACE
    return interface


def ping_host(target: str, interface: str | None = None, count: int = 3,
              timeout: float = 10.0) -> bool:
    """Ping a target from the host. Returns True if at least one reply received."""
    interface = _resolve_interface(interface)
    cmd = ["ping", "-c", str(count), "-W", "2", target]
    if interface:
        cmd.extend(["-I", interface])
    result = run_on_host(cmd, timeout=timeout)
    return result.returncode == 0


def lan_ns_exists() -> bool:
    """Check if the lan_test network namespace exists."""
    result = subprocess.run(
        ["ip", "netns", "list"], capture_output=True, text=True,
    )
    return "lan_test" in result.stdout


def run_in_lan_ns(cmd: list[str], timeout: float = 10.0) -> subprocess.CompletedProcess:
    """Run a command inside the lan_test network namespace."""
    prefix = ["ip", "netns", "exec", "lan_test"] if os.geteuid() == 0 \
        else ["sudo", "-n", "ip", "netns", "exec", "lan_test"]
    return subprocess.run(
        prefix + cmd,
        capture_output=True, text=True, timeout=timeout,
    )


def ping_from_lan_ns(target: str, count: int = 3, timeout: float = 10.0) -> bool:
    """Ping from inside the lan_test namespace (traffic goes through router)."""
    result = run_in_lan_ns(
        ["ping", "-c", str(count), "-W", "2", target],
        timeout=timeout,
    )
    return result.returncode == 0
