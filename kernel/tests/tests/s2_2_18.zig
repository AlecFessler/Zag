const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const E_BUSY: i64 = -11;

var blocked_ready: u64 = 0;
var blocked_futex: u64 = 0;

fn blockedThreadFn() void {
    // Signal the parent we're about to block, then wait indefinitely on a
    // futex whose value won't change until the parent wakes us.
    const ready: *volatile u64 = @ptrCast(&blocked_ready);
    ready.* = 1;
    _ = syscall.futex_wait(@ptrCast(&blocked_futex), 0, @bitCast(@as(i64, -1)));
    syscall.thread_exit();
}

/// §2.2.18 — `thread_suspend` on a `.faulted` or `.blocked` thread returns `E_BUSY`.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    // Spawn a child that transfers fault_handler to us, then faults.
    const child_rights = (perms.ProcessRights{
        .spawn_thread = true,
        .fault_handler = true,
    }).bits();
    const child_handle: u64 = @bitCast(@as(i64, syscall.proc_create(
        @intFromPtr(children.child_fault_after_transfer.ptr),
        children.child_fault_after_transfer.len,
        child_rights,
    )));

    // Acquire fault_handler via cap transfer; the child returns from reply
    // and immediately faults. The kernel routes the fault to our box per
    // §2.12.10 and the faulting thread enters `.faulted` state.
    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call(child_handle, &.{}, &reply);

    // Block on fault_recv to make sure the fault has actually been delivered
    // (i.e., the thread is in `.faulted` and not still mid-fault).
    var fault_buf: [256]u8 align(8) = undefined;
    const token = syscall.fault_recv(@intFromPtr(&fault_buf), 1);
    if (token < 0) {
        t.fail("§2.2.18 fault_recv failed");
        syscall.shutdown();
    }

    // Find the child's thread handle in our perm_view.
    var thread_handle: u64 = 0;
    for (2..128) |i| {
        if (view[i].entry_type == perm_view.ENTRY_TYPE_THREAD) {
            thread_handle = view[i].handle;
            break;
        }
    }
    if (thread_handle == 0) {
        t.fail("§2.2.18 no thread handle found");
        syscall.shutdown();
    }

    // thread_suspend on a `.faulted` thread must return E_BUSY.
    const rc = syscall.thread_suspend(thread_handle);
    if (rc != E_BUSY) {
        t.failWithVal("§2.2.18 faulted", E_BUSY, rc);
        syscall.shutdown();
    }

    // Sub-scenario B: `.blocked` thread must also return E_BUSY. Spawn a
    // local thread that signals ready via SHM and then parks in futex_wait.
    const tret = syscall.thread_create(&blockedThreadFn, 0, 4);
    if (tret < 0) {
        t.fail("§2.2.18 thread_create failed");
        syscall.shutdown();
    }
    const blocked_handle: u64 = @bitCast(tret);

    // Wait until the child thread is actually parked in futex_wait. Yielding
    // gives the kernel a chance to dispatch it and run it up to the blocking
    // syscall.
    const ready: *volatile u64 = @ptrCast(&blocked_ready);
    while (ready.* == 0) syscall.thread_yield();
    for (0..10) |_| syscall.thread_yield();

    const rc_blocked = syscall.thread_suspend(blocked_handle);
    if (rc_blocked != E_BUSY) {
        t.failWithVal("§2.2.18 blocked", E_BUSY, rc_blocked);
        _ = syscall.futex_wake(@ptrCast(&blocked_futex), 1);
        syscall.shutdown();
    }

    // Wake the blocked thread so it can exit cleanly.
    _ = syscall.futex_wake(@ptrCast(&blocked_futex), 1);

    t.pass("§2.2.18");
    syscall.shutdown();
}
