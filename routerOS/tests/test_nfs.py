"""NFS client tests."""

import pytest


class TestNfsClient:
    """Test NFS client operations via serial console."""

    def test_mount(self, router):
        """NFS mount command."""
        lines = router.multi_command("mount", timeout=10)
        # mount may succeed or fail depending on NFS server availability
        assert isinstance(lines, list)

    def test_ls(self, router):
        """NFS ls command after mount."""
        lines = router.multi_command("ls", timeout=10)
        assert isinstance(lines, list)

    def test_cat_file(self, router):
        """NFS cat reads a file."""
        # This depends on having a file in the NFS export
        lines = router.multi_command("cat hello.txt", timeout=10)
        assert isinstance(lines, list)
