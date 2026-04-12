const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

const E_BADADDR: i64 = -7;

/// §2.2.42 — `thread_create` with invalid entry returns `E_BADADDR`.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    // Kernel address space — invalid for user thread entry.
    const bad_entry: *const fn () void = @ptrFromInt(0xFFFF_FFFF_8000_0000);
    const ret = syscall.thread_create(bad_entry, 0, 4);
    t.expectEqual("§2.2.42", E_BADADDR, ret);
    syscall.shutdown();
}
