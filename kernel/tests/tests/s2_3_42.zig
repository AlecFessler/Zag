const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

const E_BADHANDLE: i64 = -3;

/// §2.3.42 — `mem_unmap` with invalid or non-`vm_reservation` `vm_handle` returns `E_BADHANDLE`.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    const ret = syscall.mem_unmap(99999, 0, 4096);
    t.expectEqual("§2.3.42", E_BADHANDLE, ret);
    syscall.shutdown();
}
