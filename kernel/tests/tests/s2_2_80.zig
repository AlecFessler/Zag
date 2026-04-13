const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

const E_INVAL: i64 = -1;

/// §2.2.80 — `thread_unpin` on a thread that is not currently pinned returns `E_INVAL`.
pub fn main(perm_view: u64) void {
    _ = perm_view;

    // The calling thread starts at normal priority (not pinned).
    const self_handle: u64 = @bitCast(syscall.thread_self());
    const ret = syscall.thread_unpin(self_handle);
    t.expectEqual("§2.2.80", E_INVAL, ret);

    syscall.shutdown();
}
