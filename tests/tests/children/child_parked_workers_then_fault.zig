const lib = @import("lib");

const perms = lib.perms;
const pv = lib.perm_view;
const syscall = lib.syscall;

const MAX_PERMS = 128;

var parked_futex: u64 align(8) = 0;
var started_count: u64 align(8) = 0;

fn parker() void {
    _ = @atomicRmw(u64, &started_count, .Add, 1, .release);
    _ = syscall.futex_wake(@ptrCast(&started_count), 1);
    // Park forever — only the kernel can remove us (via restart thread teardown).
    _ = syscall.futex_wait(@ptrCast(&parked_futex), 0, @bitCast(@as(i64, -1)));
}

fn faultNow() void {
    const p: *allowzero volatile u64 = @ptrFromInt(0x0);
    p.* = 0xDEAD;
}

/// §2.6.22 helper. On first boot, spawn three parker threads that block in
/// futex_wait forever, wait for them to start, then fault in the main
/// thread to force a restart. Forcing restart with live workers is the
/// scenario the feedback asked for: voluntary exit doesn't cover forced
/// thread removal. On second boot, count thread entries in our own perm
/// view and reply with the count via IPC — the test asserts it equals 1
/// (just the fresh initial thread).
pub fn main(perm_view_addr: u64) void {
    const view: *const [MAX_PERMS]pv.UserViewEntry = @ptrFromInt(perm_view_addr);
    const restart_count = view[0].processRestartCount();

    if (restart_count == 0) {
        _ = syscall.thread_create(&parker, 0, 4);
        _ = syscall.thread_create(&parker, 0, 4);
        _ = syscall.thread_create(&parker, 0, 4);
        // Wait until all three parker threads are definitively parked.
        while (@atomicLoad(u64, &started_count, .acquire) < 3) {
            syscall.thread_yield();
        }
        // Fault — this kills the main thread, and since we have `.restart`,
        // the whole process restarts. Per §2.6.22, all threads (including
        // parkers) are removed; only a fresh initial thread runs after.
        faultNow();
        return;
    }

    // Second boot: count thread entries in our own perm view.
    var thread_entries: u64 = 0;
    for (view) |*entry| {
        if (entry.entry_type == pv.ENTRY_TYPE_THREAD) thread_entries += 1;
    }

    // Wait for the test parent's call, reply with the thread count.
    var msg: syscall.IpcMessage = .{};
    if (syscall.ipc_recv(true, &msg) != 0) return;
    _ = syscall.ipc_reply(&.{thread_entries});

    // Avoid unused const warnings.
    _ = perms;
}
