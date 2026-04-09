const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.12.1 — `ProcessRights` bit 8 is `fault_handler`.
pub fn main(_: u64) void {
    // Verify that setting only the fault_handler field produces bit 8 (0x100).
    const rights = perms.ProcessRights{ .fault_handler = true };
    const bits = rights.bits();
    if (bits == 0x100) {
        t.pass("§2.12.1");
    } else {
        t.failWithVal("§2.12.1", 0x100, @bitCast(bits));
    }
    syscall.shutdown();
}
