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
        lines = router.multi_command(f"ntpserver {wan_ip}", timeout=5)
        assert len(lines) > 0, "ntpserver command returned no output"

    def test_ntpserver_command(self, router, wan_ip):
        """ntpserver command is accepted."""
        lines = router.multi_command(f"ntpserver {wan_ip}", timeout=5)
        output = " ".join(lines)
        assert "OK" in output or "invalid" not in output.lower(), \
            f"ntpserver not accepted: {lines}"


class TestTimezone:
    """Test timezone setting and display."""

    def test_set_timezone(self, router):
        """Setting timezone returns OK with correct label."""
        lines = router.multi_command("timezone -5", timeout=5)
        output = " ".join(lines)
        assert "OK" in output, f"timezone not accepted: {lines}"
        assert "UTC-5" in output, f"timezone label wrong: {lines}"

    def test_time_reflects_timezone(self, router):
        """time command shows the timezone that was set."""
        # Set timezone first
        router.multi_command("timezone -5", timeout=5)
        lines = router.multi_command("time", timeout=5)
        output = " ".join(lines)
        assert "UTC-5" in output, f"time doesn't reflect timezone: {lines}"

    def test_timezone_positive(self, router):
        """Positive timezone offset works."""
        lines = router.multi_command("timezone +3", timeout=5)
        output = " ".join(lines)
        assert "OK" in output, f"timezone not accepted: {lines}"
        assert "UTC+3" in output, f"timezone label wrong: {lines}"

    def test_timezone_with_minutes(self, router):
        """Timezone with minute offset (e.g. +5:30) works."""
        lines = router.multi_command("timezone +5:30", timeout=5)
        output = " ".join(lines)
        assert "OK" in output, f"timezone not accepted: {lines}"
        assert "UTC+5:30" in output, f"timezone label wrong: {lines}"

    def test_timezone_invalid(self, router):
        """Invalid timezone returns error."""
        lines = router.multi_command("timezone abc", timeout=5)
        output = " ".join(lines)
        assert "invalid" in output.lower(), f"expected error for invalid tz: {lines}"

    def test_restore_default_timezone(self, router):
        """Restore default CST timezone to not affect other tests."""
        lines = router.multi_command("timezone -6", timeout=5)
        output = " ".join(lines)
        assert "OK" in output, f"timezone restore failed: {lines}"
        assert "UTC-6" in output, f"timezone label wrong: {lines}"
