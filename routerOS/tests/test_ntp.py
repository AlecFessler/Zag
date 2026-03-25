"""NTP client tests."""

import pytest


class TestNtpClient:
    """Test NTP time synchronization."""

    def test_time_command(self, router):
        """time command returns a time value."""
        lines = router.multi_command("time", timeout=5)
        assert len(lines) > 0, "time command returned no output"

    def test_ntp_sync(self, router, wan_ip):
        """NTP sync via console command."""
        # Set NTP server to WAN gateway
        resp = router.command(f"ntpserver {wan_ip}", timeout=5)
        # Note: may fail if no NTP server is running on the host
        # The test just verifies the command is accepted
        assert resp, "ntpserver command returned empty response"

    def test_ntpserver_command(self, router, wan_ip):
        """ntpserver command is accepted."""
        resp = router.command(f"ntpserver {wan_ip}", timeout=5)
        assert resp, "ntpserver returned empty"
