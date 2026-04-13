const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

/// §2.4.25 — `irq_ack` with invalid or wrong-type `device_handle` returns `E_BADHANDLE`.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    const rc = syscall.irq_ack(t.BOGUS_HANDLE);
    t.expectEqual("§2.4.25", syscall.E_BADHANDLE, rc);
    syscall.shutdown();
}
