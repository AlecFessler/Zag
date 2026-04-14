const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §3.3.23 — Process capability transfer inserts with `ProcessHandleRights` encoding.
///
/// Scans the entire perm view, asserts that exactly one new process entry
/// appeared (beyond `ch`) and that its rights match the expected
/// ProcessHandleRights mask sent by child_send_self.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    const child_rights = perms.ProcessRights{};
    const ch: u64 = @bitCast(@as(i64, syscall.proc_create(
        @intFromPtr(children.child_send_self.ptr),
        children.child_send_self.len,
        child_rights.bits(),
    )));

    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call(ch, &.{}, &reply);

    const expected_rights: u16 = @truncate((perms.ProcessHandleRights{
        .send_words = true,
        .send_shm = true,
        .send_process = true,
        .send_device = true,
        .kill = true,
        .grant = true,
    }).bits());

    var match_count: u32 = 0;
    var match_handle: u64 = 0;
    var match_rights: u16 = 0;
    for (0..128) |i| {
        if (view[i].entry_type != perm_view.ENTRY_TYPE_PROCESS) continue;
        if (view[i].handle == 0) continue; // HANDLE_SELF
        if (view[i].handle == ch) continue; // original child handle
        match_count += 1;
        match_handle = view[i].handle;
        match_rights = view[i].rights;
    }

    if (match_count != 1) {
        t.failWithVal("§3.3.23 match count", 1, @intCast(match_count));
        syscall.shutdown();
    }
    if (match_handle == ch) {
        t.fail("§3.3.23 inserted handle equals ch");
        syscall.shutdown();
    }
    if (match_rights != expected_rights) {
        t.failWithVal("§3.3.23 rights", @intCast(expected_rights), @intCast(match_rights));
        syscall.shutdown();
    }

    t.pass("§3.3.23");
    syscall.shutdown();
}
