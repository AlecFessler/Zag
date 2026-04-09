const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §4.10.2 — `proc_create` child starts with only `HANDLE_SELF`.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);
    // child_check_self_only inspects its perm_view: exactly 1 non-empty entry
    // (slot 0 = HANDLE_SELF, type process). It prints PASS/FAIL to serial.
    const child_rights = perms.ProcessRights{ .spawn_thread = true, .mem_reserve = true };
    const ch: u64 = @bitCast(@as(i64, syscall.proc_create(@intFromPtr(children.child_check_self_only.ptr), children.child_check_self_only.len, child_rights.bits())));
    // Wait for child to exit.
    var slot: usize = 0;
    for (0..128) |i| {
        if (view[i].handle == ch) {
            slot = i;
            break;
        }
    }
    var attempts: u32 = 0;
    while (attempts < 100000) : (attempts += 1) {
        if (view[slot].entry_type == perm_view.ENTRY_TYPE_DEAD_PROCESS) break;
        syscall.thread_yield();
    }
    // Verify child exited normally (didn't crash before reaching check).
    if (view[slot].entry_type == perm_view.ENTRY_TYPE_DEAD_PROCESS and view[slot].processCrashReason() == .normal_exit) {
        t.pass("§4.10.2");
    } else {
        t.fail("§4.10.2");
    }
    syscall.shutdown();
}
