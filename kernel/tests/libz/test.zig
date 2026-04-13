const perm_view = @import("perm_view.zig");
const syscall = @import("syscall.zig");

const hex_chars = "0123456789abcdef";

/// Canonical "obviously-bogus" handle value for negative-path tests that need
/// a never-allocated handle id. All-ones is chosen because the kernel handle
/// table cannot plausibly produce this id and it's visually distinct in dumps.
pub const BOGUS_HANDLE: u64 = ~@as(u64, 0);

// --- Device lookup helpers ---
//
// The test rig runs under QEMU q35 with a fixed set of PCI devices that the
// kernel registers at boot. Tests that exercise device-region syscalls must
// resolve a real device handle from the root service's permission view; any
// loose filter ("find the first MMIO device") is fragile and silently passes
// if the filter misses. `requireDevice*` helpers fail hard instead of skipping.
//
// Stable QEMU q35 devices (confirmed via inventory probe):
//
//   MMIO  vendor=0x8086 device=0x2922  Intel ICH9 AHCI (bus 0 dev 31 fn 2)
//                                      4 KiB MBAR (pci_class=0x01/0x06)
//   PIO   vendor=0x8086 device=0x2922  Intel ICH9 AHCI (same function)
//                                      32 ports PIO BAR
//   MMIO  vendor=0x1234 device=0x1111  QEMU stdvga / bochs display
//                                      16 MiB BAR (pci_class=0x03/0x00)
//   PIO   vendor=0x8086 device=0x2930  Intel ICH9 SMBus
//                                      64 ports PIO BAR (pci_class=0x0c/0x05)
//
// Tests that need "some MMIO device" use the AHCI MMIO BAR; tests that need
// "some PIO device" use the AHCI PIO BAR. Both live on the same PCI function
// so an MMIO + PIO pair is always available simultaneously. DMA tests also
// use the AHCI MMIO BAR (the AHCI controller supports bus-mastering and the
// kernel grants the `dma` right on MMIO devices).

pub const AHCI_VENDOR: u16 = 0x8086;
pub const AHCI_DEVICE: u16 = 0x2922;
pub const BOCHS_VENDOR: u16 = 0x1234;
pub const BOCHS_DEVICE: u16 = 0x1111;

fn dieMissingDevice(name: []const u8) noreturn {
    syscall.write("[FAIL] ");
    syscall.write(name);
    syscall.write(" missing required device — test rig misconfigured (QEMU q35 device inventory changed?)\n");
    syscall.shutdown();
}

/// Find a device entry matching the given PCI vendor/device IDs and device_type
/// (0 = MMIO, 1 = port_io). Aborts the test with a hard failure if not found.
pub fn requireDevice(
    view: [*]const perm_view.UserViewEntry,
    name: []const u8,
    vendor: u16,
    device: u16,
    device_type: u8,
) *const perm_view.UserViewEntry {
    for (0..128) |i| {
        const e = &view[i];
        if (e.entry_type != perm_view.ENTRY_TYPE_DEVICE_REGION) continue;
        if (e.deviceType() != device_type) continue;
        if (e.pciVendor() != vendor) continue;
        if (e.pciDevice() != device) continue;
        return e;
    }
    dieMissingDevice(name);
}

/// Find an MMIO device (AHCI). Aborts the test if not found.
pub fn requireMmioDevice(view: [*]const perm_view.UserViewEntry, name: []const u8) *const perm_view.UserViewEntry {
    return requireDevice(view, name, AHCI_VENDOR, AHCI_DEVICE, 0);
}

/// Find a PIO device (AHCI PIO BAR). Aborts the test if not found.
pub fn requirePioDevice(view: [*]const perm_view.UserViewEntry, name: []const u8) *const perm_view.UserViewEntry {
    return requireDevice(view, name, AHCI_VENDOR, AHCI_DEVICE, 1);
}

/// Find any device region (defaults to MMIO AHCI). Aborts the test if not found.
pub fn requireAnyDevice(view: [*]const perm_view.UserViewEntry, name: []const u8) *const perm_view.UserViewEntry {
    return requireMmioDevice(view, name);
}

pub fn printHex(val: u64) void {
    var buf: [18]u8 = undefined;
    buf[0] = '0';
    buf[1] = 'x';
    var v = val;
    var i: usize = 17;
    while (i >= 2) : (i -= 1) {
        buf[i] = hex_chars[@as(usize, @truncate(v & 0xf))];
        v >>= 4;
    }
    syscall.write(&buf);
}

pub fn printDec(val: u64) void {
    if (val == 0) {
        syscall.write("0");
        return;
    }
    var buf: [20]u8 = undefined;
    var v = val;
    var i: usize = 20;
    while (v > 0) {
        i -= 1;
        buf[i] = '0' + @as(u8, @truncate(v % 10));
        v /= 10;
    }
    syscall.write(buf[i..20]);
}

pub fn printI64(val: i64) void {
    if (val < 0) {
        syscall.write("-");
        printHex(@bitCast(-val));
    } else {
        printHex(@bitCast(val));
    }
}

pub fn pass(name: []const u8) void {
    syscall.write("[PASS] ");
    syscall.write(name);
    syscall.write("\n");
}

pub fn fail(name: []const u8) void {
    syscall.write("[FAIL] ");
    syscall.write(name);
    syscall.write("\n");
}

pub fn failWithVal(name: []const u8, expected: i64, actual: i64) void {
    syscall.write("[FAIL] ");
    syscall.write(name);
    syscall.write(" expected=");
    printI64(expected);
    syscall.write(" actual=");
    printI64(actual);
    syscall.write("\n");
}

pub fn expectEqual(name: []const u8, expected: i64, actual: i64) void {
    if (expected == actual) {
        pass(name);
    } else {
        failWithVal(name, expected, actual);
    }
}

pub fn expectOk(name: []const u8, result: i64) void {
    if (result >= 0) {
        pass(name);
    } else {
        failWithVal(name, 0, result);
    }
}

pub fn section(name: []const u8) void {
    syscall.write("\n--- ");
    syscall.write(name);
    syscall.write(" ---\n");
}

const MAX_TIMEOUT: u64 = @bitCast(@as(i64, -1));

pub fn waitUntilNonZero(ptr: *u64) void {
    while (ptr.* == 0) {
        _ = syscall.futex_wait(@ptrFromInt(@intFromPtr(ptr)), 0, MAX_TIMEOUT);
    }
}

pub fn waitUntilAtLeast(ptr: *u64, min: u64) void {
    while (ptr.* < min) {
        _ = syscall.futex_wait(@ptrFromInt(@intFromPtr(ptr)), ptr.*, MAX_TIMEOUT);
    }
}

pub fn waitForCleanup(handle: u64) void {
    while (syscall.revoke_perm(handle) != -3) {
        syscall.thread_yield();
    }
}

// --- PMU test prerequisites ---
//
// The test rig runs under QEMU with KVM on Intel and AMD hosts, both of
// which expose a performance monitoring unit (architectural PMU on Intel,
// AMD PerfCtr/PerfEvtSel on AMD). A PMU test that silently skips with
// `t.pass()` when `pmu_info` returns `num_counters == 0` hides real
// regressions: any break in vendor detection, CPUID reading, or KVM PMU
// emulation would turn into a green run. `requirePmu` and
// `requirePmuOverflow` hard-fail instead, matching the `requireDevice*`
// philosophy above — the rig is known-good, so absence is a misconfig.

pub const PmuPrereq = struct {
    info: syscall.PmuInfo,
    event: syscall.PmuEvent,
};

/// Require PMU support with at least one supported event. Hard-fails the
/// test (no output pass) if pmu_info errors, num_counters is zero, or no
/// event is supported.
pub fn requirePmu(name: []const u8) PmuPrereq {
    var info: syscall.PmuInfo = undefined;
    const rc = syscall.pmu_info(@intFromPtr(&info));
    if (rc != syscall.E_OK) {
        failWithVal(name, syscall.E_OK, rc);
        syscall.shutdown();
    }
    if (info.num_counters == 0) {
        fail(name);
        syscall.write("  requirePmu: num_counters == 0 — test rig misconfigured (PMU absent on KVM x86_64?)\n");
        syscall.shutdown();
    }
    const evt = syscall.pickSupportedEvent(info) orelse {
        fail(name);
        syscall.write("  requirePmu: no supported events — test rig misconfigured\n");
        syscall.shutdown();
    };
    return .{ .info = info, .event = evt };
}

/// Require PMU support AND overflow-capable counters. Used by overflow /
/// sampling-profiler tests.
pub fn requirePmuOverflow(name: []const u8) PmuPrereq {
    const r = requirePmu(name);
    if (!r.info.overflow_support) {
        fail(name);
        syscall.write("  requirePmuOverflow: overflow_support == false — test rig misconfigured\n");
        syscall.shutdown();
    }
    return r;
}
