const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

/// §5.2.9 — `getrandom` with `buf_ptr` not pointing to a writable region of `len` bytes returns `E_BADADDR`.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    // Pass a clearly invalid pointer (null / unmapped address)
    const rc = syscall.getrandom_raw(0, 32);
    t.expectEqual("§5.2.9", syscall.E_BADADDR, rc);
    syscall.shutdown();
}
