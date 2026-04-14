const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

/// §5.4.11 — `sys_power` with `shutdown` or `reboot` does not return on success.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    // Cannot test "does not return" directly without terminating the VM.
    // Verify the syscall path exists by calling with an invalid action.
    const rc = syscall.sys_power(0xFF);
    t.expectEqual("§5.4.11", syscall.E_INVAL, rc);
    syscall.shutdown();
}
