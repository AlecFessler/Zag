const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

/// §2.2.63 — `set_affinity` returns `E_OK` on success.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    const ret = syscall.set_affinity(0x1);
    t.expectEqual("§2.2.63", 0, ret);
    syscall.shutdown();
}
