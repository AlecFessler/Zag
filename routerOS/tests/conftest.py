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
    """Auto-skip tests marked @lan_ns if the lan_test namespace doesn't exist."""
    if not lan_ns_exists():
        skip = pytest.mark.skip(reason="lan_test namespace not found — run sudo ./routerOS/tests/setup_sudo.sh")
        for item in items:
            if "lan_ns" in item.keywords:
                item.add_marker(skip)


@pytest.fixture(scope="session")
def router():
    """Session-scoped fixture: build, boot, and yield a QemuRouter."""
    r = QemuRouter(build=True, boot_timeout=ROUTER_BOOT_TIMEOUT)
    r.start()
    time.sleep(2)
    yield r
    r.stop()


@pytest.fixture(scope="session")
def wan_ip():
    """The host's WAN-side IP (on tap0)."""
    return "10.0.2.1"


@pytest.fixture(scope="session")
def lan_ip():
    """The host's LAN-side IP (on tap1)."""
    return "192.168.1.50"


@pytest.fixture(scope="session")
def router_wan_ip():
    """The router's WAN IP."""
    return "10.0.2.15"


@pytest.fixture(scope="session")
def router_lan_ip():
    """The router's LAN gateway IP."""
    return "192.168.1.1"


@pytest.fixture(scope="session")
def lan_ns_ip():
    """The IP of the lan_test namespace interface."""
    return "192.168.1.60"


def run_on_host(cmd: list[str], timeout: float = 10.0) -> subprocess.CompletedProcess:
    """Run a command on the host and return the result."""
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def ping_host(target: str, interface: str | None = None, count: int = 3,
              timeout: float = 10.0) -> bool:
    """Ping a target from the host. Returns True if at least one reply received."""
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
    return subprocess.run(
        ["sudo", "ip", "netns", "exec", "lan_test"] + cmd,
        capture_output=True, text=True, timeout=timeout,
    )


def ping_from_lan_ns(target: str, count: int = 3, timeout: float = 10.0) -> bool:
    """Ping from inside the lan_test namespace (traffic goes through router)."""
    result = run_in_lan_ns(
        ["ping", "-c", str(count), "-W", "2", target],
        timeout=timeout,
    )
    return result.returncode == 0
