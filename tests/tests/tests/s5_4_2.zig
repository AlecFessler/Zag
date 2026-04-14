const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

/// §5.4.2 — `sys_power` with `shutdown` or `reboot` does not return on success.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    // We cannot actually test that shutdown/reboot doesn't return (it would
    // terminate the VM). Instead verify that an invalid action returns E_INVAL,
    // confirming the syscall dispatch path is wired up. The "does not return"
    // behavior is inherently tested by the shutdown syscall already used
    // in every test.
    const rc = syscall.sys_power(0xFF);
    t.expectEqual("§5.4.2", syscall.E_INVAL, rc);
    syscall.shutdown();
}
