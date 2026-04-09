const lib = @import("lib");

const pv = lib.perm_view;
const syscall = lib.syscall;

const MAX_PERMS = 128;

var threads_started: u64 align(8) = 0;

fn worker() void {
    _ = @atomicRmw(u64, &threads_started, .Add, 1, .release);
    _ = syscall.futex_wake(@ptrCast(&threads_started), 1);
    // Exit immediately — thread_exit called by start.zig after return.
}

/// Spawns 3 extra threads (4 total), all exit quickly. On restart, only a fresh
/// initial thread should run (all old threads removed).
pub fn main(perm_view_addr: u64) void {
    const view: *const [MAX_PERMS]pv.UserViewEntry = @ptrFromInt(perm_view_addr);
    const restart_count = view[0].processRestartCount();

    if (restart_count == 0) {
        // First boot: spawn 3 threads, wait for them to start, then exit.
        _ = syscall.thread_create(&worker, 0, 4);
        _ = syscall.thread_create(&worker, 0, 4);
        _ = syscall.thread_create(&worker, 0, 4);
        // Wait for all 3 to start.
        while (@atomicLoad(u64, &threads_started, .acquire) < 3) {
            syscall.thread_yield();
        }
        // All workers exit quickly. Main thread returns → process exits → restart.
        return;
    }

    // Second boot: if we got here with only the initial thread running,
    // the kernel properly cleaned up old threads. Reply to parent via IPC.
    var msg: syscall.IpcMessage = .{};
    if (syscall.ipc_recv(true, &msg) != 0) return;
    _ = syscall.ipc_reply(&.{restart_count});
}
