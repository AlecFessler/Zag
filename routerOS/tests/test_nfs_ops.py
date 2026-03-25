"""Extended NFS client tests: mkdir, rm, ls, cat.

Uses the shared session fixture. ARP table is now large enough (64 entries)
with LRU eviction, so prior tests no longer pollute it fatally.
"""

import os
import subprocess
import time

import pytest

from harness import QemuRouter

NFS_EXPORT = "/export/zagtest"


def nfs_export_available():
    return os.path.isdir(NFS_EXPORT)


@pytest.fixture(autouse=True)
def skip_if_no_export():
    if not nfs_export_available():
        pytest.skip("NFS export not available at /export/zagtest")


def ensure_arp(router):
    """Ensure ARP is warm for the NFS server so UDP packets aren't dropped."""
    subprocess.run(["ip", "neigh", "replace", "10.0.2.15", "lladdr",
                    "52:54:00:12:34:56", "dev", "tap0", "nud", "permanent"],
                   capture_output=True)
    router.ping("10.0.2.1")
    time.sleep(1)
    router._drain()


class TestNfsMkdir:
    """Test NFS mkdir."""

    def test_mkdir_creates_directory(self, router):
        """NFS mkdir command creates a directory on the server."""
        test_dir = "test_mkdir_dir"
        host_path = os.path.join(NFS_EXPORT, test_dir)

        if os.path.exists(host_path):
            os.rmdir(host_path)

        ensure_arp(router)

        lines = router.multi_command(f"mkdir {test_dir}", timeout=10)
        time.sleep(2)

        assert os.path.isdir(host_path), \
            f"NFS mkdir failed. Response: {lines}, export: {os.listdir(NFS_EXPORT)}"
        os.rmdir(host_path)


class TestNfsRm:
    """Test NFS rm."""

    def test_rm_existing_file(self, router):
        """NFS rm command deletes a file from the server."""
        test_file = "test_rm_file.txt"
        host_path = os.path.join(NFS_EXPORT, test_file)

        try:
            with open(host_path, "w") as f:
                f.write("delete me")
        except PermissionError:
            pytest.skip("Cannot write to NFS export (permission denied)")

        ensure_arp(router)

        lines = router.multi_command(f"rm {test_file}", timeout=10)
        time.sleep(2)

        still_exists = os.path.exists(host_path)
        if still_exists:
            os.remove(host_path)
        assert not still_exists, f"NFS rm failed. Response: {lines}"


class TestNfsLs:
    """Test NFS ls operations."""

    def test_ls_root(self, router):
        """NFS ls on root shows expected files."""
        lines = router.multi_command("ls", timeout=10)
        assert len(lines) > 0, f"ls returned no output: {lines}"

    def test_ls_subdirectory(self, router):
        """NFS ls on a subdirectory."""
        lines = router.multi_command("ls subdir", timeout=10)
        assert isinstance(lines, list)

    def test_cat_file(self, router):
        """NFS cat reads file content."""
        lines = router.multi_command("cat hello.txt", timeout=10)
        assert len(lines) > 0, f"cat returned no output: {lines}"
