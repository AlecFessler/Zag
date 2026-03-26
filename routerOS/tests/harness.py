"""QEMU Router harness: build, launch, serial console I/O."""

import os
import re
import signal
import subprocess
import time

import pexpect

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
INSTALL_DIR = os.path.join(REPO_ROOT, "zig-out")
IMG_DIR = "img"  # relative to zig-out, the FAT image dir used by QEMU
OVMF_BIOS = "/usr/share/ovmf/x64/OVMF.4m.fd"

QEMU_CMD = (
    "qemu-system-x86_64"
    " -m 1G"
    f" -bios {OVMF_BIOS}"
    f" -drive file=fat:rw:{INSTALL_DIR}/{IMG_DIR},format=raw"
    " -serial mon:stdio"
    " -display none"
    " -no-reboot"
    " -enable-kvm -cpu host,+invtsc"
    " -machine q35"
    " -device intel-iommu,intremap=off"
    " -netdev tap,id=net0,ifname=tap0,script=no,downscript=no,vhost=off"
    " -device e1000e,netdev=net0,mac=52:54:00:12:34:56"
    " -netdev tap,id=net1,ifname=tap1,script=no,downscript=no,vhost=off"
    " -device e1000e,netdev=net1,mac=52:54:00:12:34:57"
    " -smp cores=4"
)

BOOT_BANNER = "load-config"
PROMPT = "\n> "

# Debug lines from syscall.write that get mixed into serial output
DEBUG_PREFIXES = [
    "router:", "root:", "console:", "serial_driver:", "nfs_client:",
    "ntp_client:", "http_server:", "BdsDxe:", "[",
]


def is_debug_line(line: str) -> bool:
    """Check if a line is debug output (not console response)."""
    stripped = line.strip()
    return any(stripped.startswith(p) for p in DEBUG_PREFIXES)


def filter_debug(lines: list[str]) -> list[str]:
    """Remove debug/boot messages from response lines."""
    return [l for l in lines if not is_debug_line(l)]


class QemuRouter:
    """Manages a QEMU instance running Zag RouterOS with serial console access."""

    def __init__(self, build: bool = True, boot_timeout: float = 30.0):
        self.build = build
        self.boot_timeout = boot_timeout
        self.child: pexpect.spawn | None = None

    def start(self) -> None:
        """Build the router (optionally) and launch QEMU."""
        if self.build:
            self._build()
        self.child = pexpect.spawn(
            "/bin/sh", ["-c", QEMU_CMD],
            encoding="utf-8",
            timeout=self.boot_timeout,
            cwd=REPO_ROOT,
        )
        # Log everything for debugging
        self.child.logfile_read = open(
            os.path.join(os.path.dirname(__file__), "qemu_output.log"), "w"
        )
        # Wait for the console banner
        self.child.expect(re.escape(BOOT_BANNER), timeout=self.boot_timeout)
        # Wait for first prompt - use a pattern that matches "> " at line start
        self._wait_prompt(timeout=15)
        # Give services time to connect (NFS, NTP debug messages arrive late)
        time.sleep(3)
        # Drain any pending debug output
        self._drain()

    def stop(self) -> None:
        """Send QEMU monitor quit command and wait for exit."""
        if self.child is None or not self.child.isalive():
            return
        # Ctrl-A c switches to QEMU monitor, then quit
        self.child.send("\x01c")
        time.sleep(0.3)
        self.child.sendline("quit")
        try:
            self.child.expect(pexpect.EOF, timeout=5)
        except pexpect.TIMEOUT:
            self.child.kill(signal.SIGKILL)
        if self.child.logfile_read:
            self.child.logfile_read.close()
        self.child.close()
        self.child = None

    def command(self, cmd: str, timeout: float = 5.0) -> str:
        """Send a single-response console command, return the response line.

        Single-response commands (status, ifstat, block, allow, forward, dns,
        dhcp-client, version, uptime) return one response then a new prompt.
        """
        assert self.child is not None
        self._drain()
        self.child.sendline(cmd)
        # Wait for prompt after response
        self._wait_prompt(timeout=timeout)
        raw = self.child.before or ""
        # Parse: echoed command, then response lines, then prompt
        lines = raw.splitlines()
        response_lines = []
        found_echo = False
        for line in lines:
            stripped = line.strip()
            if not stripped:
                continue
            if not found_echo and cmd.strip() in stripped:
                found_echo = True
                continue
            if is_debug_line(stripped):
                continue
            response_lines.append(stripped)
        return "\n".join(response_lines)

    def multi_command(self, cmd: str, timeout: float = 10.0) -> list[str]:
        """Send a multi-response console command (arp, nat, leases, rules, ping).

        Multi-response commands send multiple channel messages, terminated by '---'.
        Returns list of response lines (excluding the '---' terminator).
        """
        assert self.child is not None
        self._drain()
        self.child.sendline(cmd)

        lines: list[str] = []
        deadline = time.time() + timeout

        # Read all output until we see '---' line and then the prompt
        try:
            # Wait for the --- terminator followed eventually by prompt
            while time.time() < deadline:
                remaining = max(0.1, deadline - time.time())
                idx = self.child.expect(
                    [r"---\r?\n", r"\n> ", pexpect.TIMEOUT],
                    timeout=min(remaining, 2.0),
                )
                before = self.child.before or ""
                for line in before.splitlines():
                    stripped = line.strip()
                    if stripped and not is_debug_line(stripped) and stripped != cmd.strip():
                        lines.append(stripped)
                if idx == 0:
                    # Got terminator - now wait for prompt
                    self._wait_prompt(timeout=3)
                    break
                elif idx == 1:
                    # Got prompt directly (single-response or empty)
                    break
                else:
                    # Timeout - keep trying
                    continue
        except pexpect.TIMEOUT:
            pass

        return lines

    def ping(self, ip: str, timeout: float = 20.0) -> list[str]:
        """Run ping command (multi-response with long timeout)."""
        return self.multi_command(f"ping {ip}", timeout=timeout)

    def get_status(self) -> dict[str, str]:
        """Parse 'status' output into a dict with WAN/LAN info."""
        raw = self.command("status")
        result = {}
        for line in raw.splitlines():
            line = line.strip()
            if line.startswith("WAN:"):
                result["wan"] = line
            elif line.startswith("LAN:"):
                result["lan"] = line
        return result

    def get_ifstat(self) -> dict[str, dict[str, int]]:
        """Parse 'ifstat' output into structured stats."""
        raw = self.command("ifstat")
        result = {}
        for line in raw.splitlines():
            line = line.strip()
            iface = "wan" if line.startswith("WAN") else "lan" if line.startswith("LAN") else None
            if iface is None:
                continue
            stats = {}
            for match in re.finditer(r"(\w+)=(\d+)", line):
                stats[match.group(1)] = int(match.group(2))
            result[iface] = stats
        return result

    def get_nat_table(self) -> list[str]:
        """Get NAT table entries."""
        return self.multi_command("nat")

    def get_leases(self) -> list[str]:
        """Get DHCP leases."""
        return self.multi_command("leases")

    def get_arp_table(self) -> list[str]:
        """Get ARP table entries."""
        return self.multi_command("arp")

    def get_rules(self) -> list[str]:
        """Get firewall rules and port forwards."""
        return self.multi_command("rules")

    def block_ip(self, ip: str) -> str:
        """Add a firewall block rule."""
        return self.command(f"block {ip}")

    def allow_ip(self, ip: str) -> str:
        """Remove a firewall block rule."""
        return self.command(f"allow {ip}")

    def add_port_forward(self, proto: str, wan_port: int, lan_ip: str, lan_port: int) -> str:
        """Add a port forward rule."""
        return self.command(f"forward {proto} {wan_port} {lan_ip} {lan_port}")

    def set_dns(self, ip: str) -> str:
        """Set upstream DNS server."""
        return self.command(f"dns {ip}")

    def wait_for_output(self, pattern: str, timeout: float = 10.0) -> str:
        """Wait for a pattern in serial output (regex)."""
        assert self.child is not None
        self.child.expect(pattern, timeout=timeout)
        return self.child.after or ""

    def _wait_prompt(self, timeout: float = 5.0) -> None:
        """Wait for the '> ' prompt."""
        assert self.child is not None
        # Match "> " that appears after a newline or at start of line
        self.child.expect(r"(?:^|\n)> ", timeout=timeout)

    def _drain(self) -> None:
        """Drain any pending output (debug messages arriving late)."""
        assert self.child is not None
        while True:
            try:
                self.child.expect(r".+", timeout=0.2)
            except pexpect.TIMEOUT:
                break

    def _build(self) -> None:
        """Build routerOS, then the main project."""
        # Build routerOS (produces routerOS.elf)
        result = subprocess.run(
            ["zig", "build"],
            cwd=os.path.join(REPO_ROOT, "routerOS"),
            capture_output=True,
            text=True,
            timeout=120,
        )
        if result.returncode != 0:
            raise RuntimeError(
                f"Userspace build failed (exit {result.returncode}):\n"
                f"stdout: {result.stdout}\nstderr: {result.stderr}"
            )
        # Build main project (copies ELF into FAT image, builds kernel+bootloader)
        result = subprocess.run(
            ["zig", "build", "-Dprofile=router"],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            timeout=120,
        )
        if result.returncode != 0:
            raise RuntimeError(
                f"Main build failed (exit {result.returncode}):\n"
                f"stdout: {result.stdout}\nstderr: {result.stderr}"
            )
