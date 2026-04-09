const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.1.35 — The first 4 KiB `[0, 0x1000)` is unmapped; accessing address 0 causes a fault.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);
    const child_rights = perms.ProcessRights{ .spawn_thread = true };
    const child_handle: u64 = @bitCast(@as(i64, syscall.proc_create(@intFromPtr(children.child_null_deref.ptr), children.child_null_deref.len, child_rights.bits())));

    // Wait for child to die from null dereference.
    var slot: usize = 0;
    for (0..128) |i| {
        if (view[i].handle == child_handle) {
            slot = i;
            break;
        }
    }
    var attempts: u32 = 0;
    while (attempts < 1000000) : (attempts += 1) {
        if (view[slot].entry_type == perm_view.ENTRY_TYPE_DEAD_PROCESS) break;
        syscall.thread_yield();
    }
    // Crash reason should be unmapped_access (6) since address 0 has no VMM node.
    const crash_reason = view[slot].processCrashReason();
    if (view[slot].entry_type == perm_view.ENTRY_TYPE_DEAD_PROCESS and crash_reason == .unmapped_access) {
        t.pass("§2.1.35");
    } else {
        t.fail("§2.1.35");
    }
    syscall.shutdown();
}
