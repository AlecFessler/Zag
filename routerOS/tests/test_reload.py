"""Software reload tests: reload a process via NFS and verify it works."""

import os
import shutil
import time

import pytest

from harness import QemuRouter

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
NFS_EXPORT = "/export/zagtest"
BUILDS_DIR = os.path.join(NFS_EXPORT, "builds")
CHILDREN_DIR = os.path.join(REPO_ROOT, "routerOS", "bin", "children")


def nfs_export_available():
    return os.path.isdir(NFS_EXPORT)


def children_built():
    return os.path.isdir(CHILDREN_DIR)


@pytest.fixture(autouse=True)
def skip_if_unavailable():
    if not nfs_export_available():
        pytest.skip("NFS export not available at /export/zagtest")
    if not children_built():
        pytest.skip("Child ELFs not built (missing bin/children/)")


@pytest.fixture(autouse=True, scope="session")
def setup_builds_dir():
    """Copy child ELFs to NFS export builds/ directory."""
    if not nfs_export_available() or not children_built():
        return
    os.makedirs(BUILDS_DIR, exist_ok=True)
    for name in os.listdir(CHILDREN_DIR):
        if name.endswith(".elf"):
            src = os.path.join(CHILDREN_DIR, name)
            dst = os.path.join(BUILDS_DIR, name)
            shutil.copy2(src, dst)
    yield
    # Cleanup
    if os.path.isdir(BUILDS_DIR):
        shutil.rmtree(BUILDS_DIR)


def ensure_arp(router):
    """Ensure ARP is warm for the NFS server."""
    import subprocess
    subprocess.run(["ip", "neigh", "replace", "10.0.2.15", "lladdr",
                    "52:54:00:12:34:56", "dev", "tap0", "nud", "permanent"],
                   capture_output=True)
    router.ping("10.0.2.1")
    router._drain()


class TestReload:
    """Test software reload via NFS."""

    def test_reload_ntp_client(self, router):
        """Reload ntp_client and verify it still works."""
        ensure_arp(router)

        # Reload
        lines = router.multi_command("reload ntp_client", timeout=30)
        output = " ".join(lines)
        assert "OK" in output, f"reload failed: {lines}"

        # Give the new process time to initialize and broadcast
        time.sleep(1)

        # Verify NTP client is responsive
        lines = router.multi_command("time", timeout=10)
        assert len(lines) > 0, f"time command failed after reload: {lines}"

    def test_reload_unknown_process(self, router):
        """Reload a nonexistent process returns an error."""
        lines = router.multi_command("reload nonexistent", timeout=10)
        output = " ".join(lines)
        assert "error" in output.lower() or "unknown" in output.lower(), \
            f"expected error for unknown process: {lines}"

    def test_reload_preserves_other_services(self, router):
        """After reloading ntp_client, router commands still work."""
        ensure_arp(router)

        # Reload ntp_client
        lines = router.multi_command("reload ntp_client", timeout=30)
        output = " ".join(lines)
        assert "OK" in output, f"reload failed: {lines}"

        time.sleep(1)

        # Verify router is still responsive
        status = router.command("status", timeout=5)
        assert "WAN" in status or "LAN" in status, \
            f"router status failed after reload: {status}"

    def test_reload_http_server(self, router):
        """Reload http_server (no console dependency)."""
        ensure_arp(router)

        lines = router.multi_command("reload http_server", timeout=30)
        output = " ".join(lines)
        assert "OK" in output, f"reload http_server failed: {lines}"
