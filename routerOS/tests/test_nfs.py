"""NFS client tests."""

import time

import pytest


def wait_for_nfs_mount(router, retries=5, delay=2):
    """Wait for NFS auto-mount to complete, retrying if needed."""
    for attempt in range(retries):
        lines = router.multi_command("ls", timeout=10)
        # Filter out error/status messages that indicate NFS isn't ready
        real_lines = [
            l for l in lines
            if not l.startswith("NFS:") and not l.startswith("nfs:")
        ]
        if real_lines:
            return real_lines
        # If NFS isn't mounted yet, try explicit mount then wait
        if attempt < retries - 1:
            router.multi_command("mount", timeout=10)
            time.sleep(delay)
    return []


class TestNfsClient:
    """Test NFS client operations via serial console."""

    def test_mount(self, router):
        """NFS auto-mounts at boot — verify by listing files."""
        lines = wait_for_nfs_mount(router)
        assert len(lines) > 0, "NFS ls returned nothing — mount may have failed"

    def test_ls(self, router):
        """NFS ls command lists directory contents."""
        lines = router.multi_command("ls", timeout=10)
        assert isinstance(lines, list)
        assert len(lines) > 0

    def test_cat_file(self, router):
        """NFS cat reads a file."""
        lines = router.multi_command("cat hello.txt", timeout=10)
        assert isinstance(lines, list)
        assert len(lines) > 0, "cat returned no output"
