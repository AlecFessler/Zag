const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.1.23 — Data mappings persist across restart; content is reloaded from original ELF.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);
    // child_check_data_reload has an initialized .data variable (0xCAFE_BABE_DEAD_BEEF).
    // On first boot it corrupts it, then exits → restart.
    // On second boot it reads the value — if data was reloaded from ELF, it should
    // be back to the original value (0xCAFE_BABE_DEAD_BEEF), not the corrupted value.
    const child_rights = (perms.ProcessRights{ .restart = true }).bits();
    const child_handle: u64 = @bitCast(@as(i64, syscall.proc_create(
        @intFromPtr(children.child_check_data_reload.ptr),
        children.child_check_data_reload.len,
        child_rights,
    )));
    var slot: usize = 0;
    for (0..128) |i| {
        if (view[i].handle == child_handle) {
            slot = i;
            break;
        }
    }
    // Wait for restart.
    var attempts: u32 = 0;
    while (attempts < 500000) : (attempts += 1) {
        if (view[slot].processRestartCount() > 0) break;
        syscall.thread_yield();
    }
    if (view[slot].processRestartCount() == 0) {
        t.fail("§2.1.23");
        syscall.shutdown();
    }
    // Call child — it replies with its .data sentinel value.
    var reply: syscall.IpcMessage = .{};
    const rc = syscall.ipc_call(child_handle, &.{}, &reply);
    if (rc == 0 and reply.words[0] == 0xCAFE_BABE_DEAD_BEEF) {
        t.pass("§2.1.23");
    } else {
        t.failWithVal("§2.1.23", @bitCast(@as(u64, 0xCAFE_BABE_DEAD_BEEF)), @bitCast(reply.words[0]));
    }
    syscall.shutdown();
}
