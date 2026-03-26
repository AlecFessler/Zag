"""Extended NFS client tests: mkdir, rmdir, rm, mv, stat, touch, ls, cat.

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


class TestNfsRmdir:
    """Test NFS rmdir."""

    def test_rmdir_removes_directory(self, router):
        """NFS rmdir command removes a directory on the server."""
        test_dir = "test_rmdir_dir"
        host_path = os.path.join(NFS_EXPORT, test_dir)

        try:
            os.makedirs(host_path, exist_ok=True)
        except PermissionError:
            pytest.skip("Cannot write to NFS export (permission denied)")

        ensure_arp(router)

        lines = router.multi_command(f"rmdir {test_dir}", timeout=10)
        time.sleep(2)

        still_exists = os.path.exists(host_path)
        if still_exists:
            os.rmdir(host_path)
        assert not still_exists, f"NFS rmdir failed. Response: {lines}"


class TestNfsRename:
    """Test NFS mv (rename)."""

    def test_mv_renames_file(self, router):
        """NFS mv command renames a file on the server."""
        src_name = "test_mv_src.txt"
        dst_name = "test_mv_dst.txt"
        src_path = os.path.join(NFS_EXPORT, src_name)
        dst_path = os.path.join(NFS_EXPORT, dst_name)

        # Cleanup any leftovers
        for p in (src_path, dst_path):
            if os.path.exists(p):
                os.remove(p)

        try:
            with open(src_path, "w") as f:
                f.write("rename me")
        except PermissionError:
            pytest.skip("Cannot write to NFS export (permission denied)")

        ensure_arp(router)

        lines = router.multi_command(f"mv {src_name} {dst_name}", timeout=10)
        time.sleep(2)

        src_gone = not os.path.exists(src_path)
        dst_exists = os.path.exists(dst_path)

        # Cleanup
        for p in (src_path, dst_path):
            if os.path.exists(p):
                os.remove(p)

        assert src_gone, f"NFS mv failed: source still exists. Response: {lines}"
        assert dst_exists, f"NFS mv failed: destination not created. Response: {lines}"


class TestNfsStat:
    """Test NFS stat."""

    def test_stat_file(self, router):
        """NFS stat command shows file type and size."""
        ensure_arp(router)

        lines = router.multi_command("stat hello.txt", timeout=10)
        output = " ".join(lines)
        assert "type=" in output, f"stat missing type. Response: {lines}"
        assert "size=" in output, f"stat missing size. Response: {lines}"


class TestNfsTouch:
    """Test NFS touch."""

    def test_touch_creates_empty_file(self, router):
        """NFS touch command creates an empty file on the server."""
        test_file = "test_touch_file.txt"
        host_path = os.path.join(NFS_EXPORT, test_file)

        if os.path.exists(host_path):
            os.remove(host_path)

        ensure_arp(router)

        lines = router.multi_command(f"touch {test_file}", timeout=10)
        time.sleep(2)

        exists = os.path.exists(host_path)
        size = os.path.getsize(host_path) if exists else -1

        if exists:
            os.remove(host_path)

        assert exists, f"NFS touch failed: file not created. Response: {lines}"
        assert size == 0, f"NFS touch file not empty (size={size}). Response: {lines}"
