const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const E_PERM: i64 = -2;

/// §4.17.4 — `call` without required rights returns `E_PERM`.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    // child_send_self_no_words: gives us a handle WITHOUT send_words right (only kill+grant).
    const child_rights = perms.ProcessRights{};
    const ch: u64 = @bitCast(@as(i64, syscall.proc_create(@intFromPtr(children.child_send_self_no_words.ptr), children.child_send_self_no_words.len, child_rights.bits())));
    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call(ch, &.{}, &reply);

    // Find the transferred handle (no send_words).
    var no_words_handle: u64 = 0;
    for (0..128) |i| {
        if (view[i].handle != 0 and view[i].handle != ch and view[i].entry_type == perm_view.ENTRY_TYPE_PROCESS) {
            no_words_handle = view[i].handle;
            break;
        }
    }
    if (no_words_handle == 0) {
        t.fail("§4.17.4");
        syscall.shutdown();
    }

    // Call via handle without send_words → E_PERM.
    var reply2: syscall.IpcMessage = .{};
    const rc = syscall.ipc_call(no_words_handle, &.{0x42}, &reply2);
    t.expectEqual("§4.17.4", E_PERM, rc);
    syscall.shutdown();
}
