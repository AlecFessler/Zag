const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.6.22 — All threads are removed on restart; only a fresh initial thread runs.
/// runs. Exercises *forced* thread removal: workers block in futex_wait
/// forever (never voluntarily exit), main thread faults to trigger restart,
/// and the restarted child counts thread entries in its own perm view and
/// reports the count. We assert exactly one thread entry survives.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    const child_rights = (perms.ProcessRights{ .restart = true, .spawn_thread = true }).bits();
    const child_handle: u64 = @bitCast(@as(i64, syscall.proc_create(
        @intFromPtr(children.child_parked_workers_then_fault.ptr),
        children.child_parked_workers_then_fault.len,
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
        t.fail("§2.6.22 no restart");
        syscall.shutdown();
    }

    // Ask the restarted child how many thread entries it sees.
    var reply: syscall.IpcMessage = .{};
    const rc = syscall.ipc_call(child_handle, &.{}, &reply);
    if (rc != 0) {
        t.fail("§2.6.22 ipc_call");
        syscall.shutdown();
    }

    if (reply.words[0] == 1) {
        t.pass("§2.6.22");
    } else {
        t.failWithVal("§2.6.22", 1, @intCast(reply.words[0]));
    }
    syscall.shutdown();
}
