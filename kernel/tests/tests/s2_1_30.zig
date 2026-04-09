const lib = @import("lib");

const perm_view = lib.perm_view;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.1.30 — The initial thread receives the user view pointer via the `arg` register at launch.
pub fn main(pv: u64) void {
    // pv is the argument passed to main by start.zig from the arg register.
    // If we can read it as a valid user view, the arg was received correctly.
    if (pv != 0) {
        const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);
        if (view[0].entry_type == perm_view.ENTRY_TYPE_PROCESS) {
            t.pass("§2.1.30");
            syscall.shutdown();
        }
    }
    t.fail("§2.1.30");
    syscall.shutdown();
}
