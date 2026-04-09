const lib = @import("lib");

const perm_view = lib.perm_view;

/// Verifies the child boots with exactly the §4.10.2 starting set:
///   slot 0 = HANDLE_SELF (process), slot 1 = initial thread, all other slots empty.
/// Signals success by exiting normally and failure by null-derefing (parent
/// detects via processCrashReason). Does not print so it never collides with
/// the parent's [PASS]/[FAIL] line in the serial log.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);
    var count: u32 = 0;
    for (0..128) |i| {
        if (view[i].entry_type != perm_view.ENTRY_TYPE_EMPTY) {
            count += 1;
        }
    }
    const ok = count == 2 and
        view[0].handle == 0 and
        view[0].entry_type == perm_view.ENTRY_TYPE_PROCESS and
        view[1].entry_type == perm_view.ENTRY_TYPE_THREAD;
    if (!ok) {
        const np: *volatile u64 = @ptrFromInt(0xdead000);
        np.* = 0;
    }
}
