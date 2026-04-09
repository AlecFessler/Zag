const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.1.13 — Root service is the sole source of all capabilities; all capabilities flow downward via process creation and message passing.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);
    // Root service should have device handles at boot — it's the sole capability source.
    var device_count: u32 = 0;
    for (0..128) |i| {
        if (view[i].entry_type == perm_view.ENTRY_TYPE_DEVICE_REGION) {
            device_count += 1;
        }
    }
    if (device_count == 0) {
        t.fail("§2.1.13");
        syscall.shutdown();
    }
    // Spawn child_check_self_only — it verifies it starts with ONLY HANDLE_SELF.
    // If child exits normally (not crash), its check passed.
    const child_rights = perms.ProcessRights{};
    const ch: u64 = @bitCast(@as(i64, syscall.proc_create(
        @intFromPtr(children.child_check_self_only.ptr),
        children.child_check_self_only.len,
        child_rights.bits(),
    )));
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
    // Child exiting normally means its self-check passed (only HANDLE_SELF).
    // Root has devices, child has none — capabilities only flow downward.
    if (view[slot].entry_type == perm_view.ENTRY_TYPE_DEAD_PROCESS and view[slot].processCrashReason() == .normal_exit) {
        t.pass("§2.1.13");
    } else {
        t.fail("§2.1.13");
    }
    syscall.shutdown();
}
