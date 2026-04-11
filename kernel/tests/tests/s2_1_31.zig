const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const USER_END: u64 = 0xFFFF_8000_0000_0000;

/// §2.1.31 — User address space spans `[0, 0xFFFF_8000_0000_0000)`.
pub fn main(_: u64) void {
    const rw = perms.VmReservationRights{ .read = true, .write = true };

    // A reserve with no hint must land inside user space.
    const ok = syscall.mem_reserve(0, 4096, rw.bits());
    if (ok.val <= 0 or ok.val2 == 0 or ok.val2 >= USER_END) {
        t.fail("§2.1.31 default reservation outside user space");
        syscall.shutdown();
    }
    _ = syscall.revoke_perm(@bitCast(ok.val));

    // A reserve whose hint sits AT or BEYOND the user-space upper bound
    // must never succeed in producing a mapping at that hint. The kernel
    // may either reject the request outright or fall back to allocating
    // elsewhere in user space — but it must not map anything in the
    // kernel half.
    const at_bound = syscall.mem_reserve(USER_END, 4096, rw.bits());
    if (at_bound.val > 0) {
        // Allocated somewhere — must be strictly inside user space and
        // must NOT honour the out-of-range hint.
        if (at_bound.val2 >= USER_END or at_bound.val2 == USER_END) {
            t.fail("§2.1.31 reserve @ USER_END produced kernel-half mapping");
            syscall.shutdown();
        }
        if (at_bound.val2 == USER_END) {
            t.fail("§2.1.31 hint @ USER_END was honoured");
            syscall.shutdown();
        }
        _ = syscall.revoke_perm(@bitCast(at_bound.val));
    }

    const beyond = syscall.mem_reserve(USER_END + 0x1000, 4096, rw.bits());
    if (beyond.val > 0) {
        if (beyond.val2 >= USER_END) {
            t.fail("§2.1.31 reserve beyond USER_END produced kernel-half mapping");
            syscall.shutdown();
        }
        _ = syscall.revoke_perm(@bitCast(beyond.val));
    }

    t.pass("§2.1.31");
    syscall.shutdown();
}
