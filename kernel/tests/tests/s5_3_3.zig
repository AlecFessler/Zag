const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

// 256 pages = 1 MiB. Large enough to dwarf any incidental allocator noise
// between the three sys_info samples (stack usage, scheduler bookkeeping)
// but still well under any reasonable host's physical memory.
const LARGE_PAGES: u64 = 256;
const LARGE_SIZE: u64 = LARGE_PAGES * 4096;

/// §5.3.3 — `SysInfo.mem_free` is the number of physical pages currently free for allocation, sampled at the time of the call.
///
/// 1) Sample `mem_free` baseline.
/// 2) Reserve a 256-page VM region RW and touch every page to force the
///    kernel to commit physical pages (§3.4 demand-paging).
/// 3) Sample `mem_free` again and verify it decreased by at least some
///    plausible fraction of `LARGE_PAGES`. We don't demand exact equality:
///    the kernel may allocate page tables, the scheduler tick may steal a
///    page, etc. A decrease of at least `LARGE_PAGES / 2` is easily
///    satisfied by a correct implementation and catches a kernel that
///    returns a hard-coded or stale `mem_free`.
/// 4) We do not try to assert `mem_free` recovers after unmap — the test
///    kernel doesn't expose an "unreserve" syscall and the process exits
///    shortly anyway. The monotonic decrease after commit is sufficient
///    evidence that the value tracks live free-page count.
pub fn main(_: u64) void {
    var before: syscall.SysInfo = undefined;
    var after: syscall.SysInfo = undefined;

    if (syscall.sys_info(@intFromPtr(&before), 0) != syscall.E_OK) {
        t.fail("§5.3.3 sys_info before");
        syscall.shutdown();
    }

    const rw = perms.VmReservationRights{ .read = true, .write = true };
    const result = syscall.mem_reserve(0, LARGE_SIZE, rw.bits());
    if (result.val < 0) {
        t.failWithVal("§5.3.3 mem_reserve", 0, result.val);
        syscall.shutdown();
    }
    const base: u64 = result.val2;

    // Touch every page to force physical commits.
    var p: u64 = 0;
    while (p < LARGE_PAGES) : (p += 1) {
        const page: [*]volatile u8 = @ptrFromInt(base + p * 4096);
        page[0] = @truncate(p);
    }

    if (syscall.sys_info(@intFromPtr(&after), 0) != syscall.E_OK) {
        t.fail("§5.3.3 sys_info after");
        syscall.shutdown();
    }

    // mem_free must have dropped. Ignore the extreme edge case where an
    // unrelated deallocation between samples releases more than it should —
    // we only require *at least half* of LARGE_PAGES worth of decrease.
    if (after.mem_free >= before.mem_free) {
        t.failWithVal(
            "§5.3.3 mem_free did not decrease after commit",
            @intCast(before.mem_free),
            @intCast(after.mem_free),
        );
        syscall.shutdown();
    }
    const delta = before.mem_free - after.mem_free;
    if (delta < LARGE_PAGES / 2) {
        t.failWithVal(
            "§5.3.3 mem_free delta too small",
            @intCast(LARGE_PAGES / 2),
            @intCast(delta),
        );
        syscall.shutdown();
    }

    t.pass("§5.3.3");
    syscall.shutdown();
}
