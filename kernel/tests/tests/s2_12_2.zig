const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.12.2 — `ProcessHandleRights` bit 6 is `fault_handler`.
pub fn main(_: u64) void {
    // Verify that setting only the fault_handler field produces bit 6 (0x40).
    const rights = perms.ProcessHandleRights{ .fault_handler = true };
    const bits = rights.bits();
    if (bits == 0x40) {
        t.pass("§2.12.2");
    } else {
        t.failWithVal("§2.12.2", 0x40, @bitCast(bits));
    }
    syscall.shutdown();
}
