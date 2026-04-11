const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

/// §2.15.2 — `SysInfo.mem_total` is the total physical page count managed by the kernel.
///
/// Verify `mem_total` is non-zero and plausibly sized (anything under 8 pages
/// / 32 KiB of managed physical memory is impossible on a functioning host),
/// that `mem_free <= mem_total`, and that `mem_total` is stable across two
/// calls (total managed pages is a boot-time constant — only `mem_free`
/// changes at runtime).
pub fn main(_: u64) void {
    var a: syscall.SysInfo = undefined;
    var b: syscall.SysInfo = undefined;

    const rc_a = syscall.sys_info(@intFromPtr(&a), 0);
    if (rc_a != syscall.E_OK) {
        t.failWithVal("§2.15.2 first call", syscall.E_OK, rc_a);
        syscall.shutdown();
    }

    // Force some allocator churn so a kernel that accidentally ties
    // mem_total to the free list would drift between calls.
    const rw = lib.perms.VmReservationRights{ .read = true, .write = true };
    const r = syscall.mem_reserve(0, 4096, rw.bits());
    const vaddr: u64 = r.val2;
    const page: [*]volatile u8 = @ptrFromInt(vaddr);
    page[0] = 0x42;

    const rc_b = syscall.sys_info(@intFromPtr(&b), 0);
    if (rc_b != syscall.E_OK) {
        t.failWithVal("§2.15.2 second call", syscall.E_OK, rc_b);
        syscall.shutdown();
    }

    if (a.mem_total == 0) {
        t.fail("§2.15.2 mem_total == 0");
        syscall.shutdown();
    }
    if (a.mem_total < 8) {
        t.failWithVal("§2.15.2 mem_total implausibly small", 8, @intCast(a.mem_total));
        syscall.shutdown();
    }
    if (a.mem_free > a.mem_total) {
        t.failWithVal(
            "§2.15.2 mem_free > mem_total",
            @intCast(a.mem_total),
            @intCast(a.mem_free),
        );
        syscall.shutdown();
    }
    if (a.mem_total != b.mem_total) {
        t.failWithVal(
            "§2.15.2 mem_total not stable",
            @intCast(a.mem_total),
            @intCast(b.mem_total),
        );
        syscall.shutdown();
    }

    t.pass("§2.15.2");
    syscall.shutdown();
}
