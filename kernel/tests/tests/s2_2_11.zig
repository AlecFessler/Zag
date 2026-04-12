const lib = @import("lib");

const perm_view = lib.perm_view;
const syscall = lib.syscall;
const t = lib.testing;

var worker_self: u64 = 0;
var worker_done: u64 = 0;

fn workerThread() void {
    const s = syscall.thread_self();
    if (s > 0) worker_self = @bitCast(s);
    @atomicStore(u64, &worker_done, 1, .release);
    syscall.thread_exit();
}

/// §2.2.11 — `thread_self` returns the handle ID of the calling thread as it appears in the calling process's own permissions table.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    const main_self_ret = syscall.thread_self();
    if (main_self_ret <= 0) {
        t.failWithVal("§2.2.11 thread_self main", 1, main_self_ret);
        syscall.shutdown();
    }
    const main_self: u64 = @bitCast(main_self_ret);

    const worker_ret = syscall.thread_create(&workerThread, 0, 4);
    if (worker_ret <= 0) {
        t.failWithVal("§2.2.11 thread_create", 1, worker_ret);
        syscall.shutdown();
    }
    const worker_handle: u64 = @bitCast(worker_ret);

    // Wait for the worker to publish its thread_self result.
    var iters: u32 = 0;
    while (iters < 100000) : (iters += 1) {
        if (@atomicLoad(u64, &worker_done, .acquire) != 0) break;
        syscall.thread_yield();
    }
    if (@atomicLoad(u64, &worker_done, .acquire) == 0) {
        t.fail("§2.2.11 worker never ran");
        syscall.shutdown();
    }

    // Each thread's self-handle must be distinct.
    if (main_self == worker_self) {
        t.fail("§2.2.11 main and worker saw identical thread_self handles");
        syscall.shutdown();
    }

    // The worker's thread_self value must match the handle the kernel
    // returned from thread_create, and both must exist as THREAD entries
    // in our own perm view.
    if (worker_self != worker_handle) {
        t.fail("§2.2.11 worker thread_self != thread_create return");
        syscall.shutdown();
    }

    var saw_main = false;
    var saw_worker = false;
    for (0..128) |i| {
        if (view[i].entry_type == perm_view.ENTRY_TYPE_THREAD) {
            if (view[i].handle == main_self) saw_main = true;
            if (view[i].handle == worker_self) saw_worker = true;
        }
    }
    if (saw_main and saw_worker) {
        t.pass("§2.2.11");
    } else {
        t.fail("§2.2.11 thread handles not found in perm view");
    }
    syscall.shutdown();
}
