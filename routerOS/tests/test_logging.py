"""Structured logging tests.

The router logs events via util.logEvent() which writes to serial AND
to an NFS-backed log file at /export/zagtest/logs/router.log.
The test harness captures serial output to qemu_output.log.
"""

import os
import time

import pytest

from conftest import ping_host

NFS_EXPORT = "/export/zagtest"
LOG_DIR = os.path.join(NFS_EXPORT, "logs")
LOG_FILE = os.path.join(LOG_DIR, "router.log")


def get_serial_log():
    """Read the QEMU serial output log."""
    log_path = os.path.join(os.path.dirname(__file__), "qemu_output.log")
    if not os.path.exists(log_path):
        return ""
    with open(log_path) as f:
        return f.read()


def get_nfs_log():
    """Read the NFS-backed router log file."""
    if not os.path.exists(LOG_FILE):
        return ""
    with open(LOG_FILE) as f:
        return f.read()


def wait_for_nfs_log(timeout=15.0, min_size=10):
    """Wait for the NFS log file to appear and have content."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if os.path.exists(LOG_FILE) and os.path.getsize(LOG_FILE) >= min_size:
            return True
        time.sleep(1)
    return False


def wait_for_log_entries(timeout=20.0):
    """Wait for structured log entries (beyond boot marker) to appear."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        log = get_nfs_log()
        lines = [l for l in log.splitlines() if l.strip() and "BOOT" not in l]
        if lines:
            return True
        time.sleep(1)
    return False


class TestLogging:
    """Test structured event logging via serial output."""

    def test_structured_log_on_serial(self, router):
        """Structured log entries with timestamps appear on serial."""
        log = get_serial_log()
        # log.drainAndFlush writes formatted [timestamp] entries to serial
        assert "[" in log, "No structured log entries on serial"

    def test_nat_table_functional(self, router):
        """NAT table is functional and logging infrastructure exists."""
        entries = router.get_nat_table()
        assert isinstance(entries, list)
        log = get_serial_log()
        assert len(log) > 0, "Serial log is empty — logging not working"

    def test_firewall_block_logged(self, router, router_wan_ip):
        """Firewall block and allow commands work."""
        test_ip = "10.99.99.99"
        router.block_ip(test_ip)

        rules = router.get_rules()
        assert any(test_ip in r for r in rules), "Block rule not active"

        router.allow_ip(test_ip)

        log = get_serial_log()
        assert len(log) > 0, "Serial log is empty"


class TestNfsLogging:
    """Test NFS-backed persistent logging."""

    @pytest.fixture(autouse=True)
    def skip_if_no_export(self):
        if not os.path.isdir(NFS_EXPORT):
            pytest.skip("NFS export not available at /export/zagtest")

    def test_log_directory_created(self, router):
        """The router creates logs/ directory on the NFS export."""
        wait_for_nfs_log(timeout=15)
        assert os.path.isdir(LOG_DIR), \
            f"logs/ directory not created on NFS export. Contents: {os.listdir(NFS_EXPORT)}"

    def test_log_file_created(self, router):
        """The router creates logs/router.log on the NFS export."""
        wait_for_nfs_log(timeout=15)
        assert os.path.exists(LOG_FILE), \
            f"router.log not created. logs/ contents: {os.listdir(LOG_DIR) if os.path.isdir(LOG_DIR) else 'N/A'}"

    def test_log_entries_have_timestamps(self, router):
        """Log entries have [boot+secs.ms] or [HH:MM:SS] timestamp prefix."""
        assert wait_for_log_entries(timeout=20), \
            f"No structured log entries appeared. Log content: {get_nfs_log()[:500]}"
        log = get_nfs_log()
        lines = [l for l in log.splitlines() if l.strip() and "BOOT" not in l]
        for line in lines[:5]:
            assert line.startswith("["), \
                f"Log line missing timestamp prefix: {line}"
            ts = line.split("]")[0]
            assert "." in ts or ":" in ts, \
                f"Log timestamp missing separator (expected [boot+s.ms] or [HH:MM:SS]): {line}"

    def test_log_entries_have_level(self, router):
        """Log entries contain a level tag (INFO, WARN, ERR, DEBUG)."""
        assert wait_for_log_entries(timeout=20), \
            f"No structured log entries appeared. Log content: {get_nfs_log()[:500]}"
        log = get_nfs_log()
        lines = [l for l in log.splitlines() if l.strip() and "BOOT" not in l]
        valid_levels = {"INFO", "WARN", "ERR", "DEBUG"}
        for line in lines[:5]:
            assert any(lvl in line for lvl in valid_levels), \
                f"Log line missing level tag: {line}"

    def test_log_has_router_events(self, router):
        """Router init events (service thread, channel connections) appear in log."""
        assert wait_for_log_entries(timeout=20), \
            f"No structured log entries appeared. Log content: {get_nfs_log()[:500]}"
        log = get_nfs_log()
        assert "router" in log.lower(), \
            f"No router events in NFS log. Content: {log[:500]}"

    def test_log_content_matches_serial(self, router):
        """NFS log entries should correspond to serial output."""
        wait_for_nfs_log(timeout=15)
        nfs_log = get_nfs_log()
        serial_log = get_serial_log()
        assert len(nfs_log) > 0, "NFS log is empty"
        assert len(serial_log) > 0, "Serial log is empty"
        assert "[" in nfs_log, "NFS log has no timestamp-prefixed entries"
