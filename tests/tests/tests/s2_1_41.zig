const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const E_BADHANDLE: i64 = -3;

/// §2.1.41 — Non-parent holders' entries are lazily converted to `dead_process` on IPC attempt (`send`/`call` returns `E_BADHANDLE`).
/// Spawn child_send_self. Parent gets h1 (from proc_create, the parent handle) and
/// h2 (from cap transfer via HANDLE_SELF, a non-parent handle). When child exits,
/// h1 converts to dead_process immediately. h2 should remain as ENTRY_TYPE_PROCESS
/// until an IPC attempt, at which point it lazily converts.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    // Spawn child_send_self (non-restartable).
    const child_rights = perms.ProcessRights{ .spawn_thread = true };
    const h1: u64 = @bitCast(@as(i64, syscall.proc_create(@intFromPtr(children.child_send_self.ptr), children.child_send_self.len, child_rights.bits())));

    // Call child — it replies with HANDLE_SELF via cap transfer.
    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call(h1, &.{}, &reply);

    // Find h2 — the transferred handle (different from h1, but ENTRY_TYPE_PROCESS).
    var h2: u64 = 0;
    var h2_slot: usize = 0;
    for (0..128) |i| {
        if (view[i].handle != 0 and view[i].handle != h1 and view[i].entry_type == perm_view.ENTRY_TYPE_PROCESS) {
            h2 = view[i].handle;
            h2_slot = i;
            break;
        }
    }

    if (h2 == 0) {
        t.fail("§2.1.41");
        syscall.shutdown();
    }

    // Child exits after replying. Wait for h1 to become dead_process.
    var h1_slot: usize = 0;
    for (0..128) |i| {
        if (view[i].handle == h1) {
            h1_slot = i;
            break;
        }
    }

    var attempts: u32 = 0;
    while (attempts < 100000) : (attempts += 1) {
        if (view[h1_slot].entry_type == perm_view.ENTRY_TYPE_DEAD_PROCESS) break;
        syscall.thread_yield();
    }

    if (view[h1_slot].entry_type != perm_view.ENTRY_TYPE_DEAD_PROCESS) {
        t.fail("§2.1.41");
        syscall.shutdown();
    }

    // h2 may still appear as ENTRY_TYPE_PROCESS (lazy conversion).
    // Now attempt IPC on h2 — should get E_BADHANDLE and trigger lazy conversion.
    const rc = syscall.ipc_send(h2, &.{0});

    // After the IPC attempt, h2 should now be dead_process or empty.
    const h2_type = view[h2_slot].entry_type;
    const lazy_converted = (rc == E_BADHANDLE) and
        (h2_type == perm_view.ENTRY_TYPE_DEAD_PROCESS or h2_type == perm_view.ENTRY_TYPE_EMPTY);

    if (lazy_converted) {
        t.pass("§2.1.41");
    } else {
        t.fail("§2.1.41");
    }
    syscall.shutdown();
}
