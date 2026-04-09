const lib = @import("lib");

const perm_view = lib.perm_view;
const syscall = lib.syscall;
const t = lib.testing;

const U64_MAX: u64 = 0xFFFFFFFFFFFFFFFF;

/// §2.1.18 — Each entry's handle field is a monotonic u64 ID; empty slots have handle = `U64_MAX`.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);
    // Verify ALL empty slots have handle == U64_MAX, not just the first one.
    var checked: u32 = 0;
    var all_correct = true;
    for (0..128) |i| {
        if (view[i].entry_type == perm_view.ENTRY_TYPE_EMPTY) {
            checked += 1;
            if (view[i].handle != U64_MAX) {
                all_correct = false;
                break;
            }
        }
    }
    if (all_correct and checked > 0) {
        t.pass("§2.1.18");
    } else {
        t.fail("§2.1.18");
    }
    syscall.shutdown();
}
