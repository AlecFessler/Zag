const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

var worker_counter: u64 = 0;
var worker_handle_pub: u64 = 0;

fn spinThread() void {
    // Pin ourselves to core 1 so the main thread stays on core 0 — this
    // guarantees the target is .running on a remote core when we suspend it.
    const self_ret = syscall.thread_self();
    if (self_ret > 0) {
        const h: u64 = @bitCast(self_ret);
        _ = syscall.set_affinity(0x2);
        @atomicStore(u64, &worker_handle_pub, h, .release);
    }
    while (true) {
        _ = @atomicRmw(u64, &worker_counter, .Add, 1, .monotonic);
    }
}

/// §2.2.16 — `thread_suspend` on a `.running` thread causes it to enter `.suspended` state; if running on a remote core, a scheduling IPI is issued to force the transition at the next scheduling point.
pub fn main(_: u64) void {
    // Keep main thread on core 0 so it can't possibly share a core with the
    // worker we pin to core 1.
    const main_self_ret = syscall.thread_self();
    if (main_self_ret <= 0) {
        t.fail("§2.2.16 thread_self main");
        syscall.shutdown();
    }
    _ = syscall.set_affinity(0x1);

    const ret = syscall.thread_create(&spinThread, 0, 4);
    if (ret < 0) {
        t.fail("§2.2.16 thread_create failed");
        syscall.shutdown();
    }
    const handle: u64 = @bitCast(ret);

    // Wait for the worker to publish its handle and actually start running:
    // observe the counter advancing so we know it's in .running state.
    var iters: u32 = 0;
    while (iters < 200000) : (iters += 1) {
        if (@atomicLoad(u64, &worker_handle_pub, .acquire) != 0) break;
        syscall.thread_yield();
    }
    if (@atomicLoad(u64, &worker_handle_pub, .acquire) == 0) {
        t.fail("§2.2.16 worker never published");
        syscall.shutdown();
    }

    const c0 = @atomicLoad(u64, &worker_counter, .monotonic);
    iters = 0;
    var observed_running = false;
    while (iters < 200000) : (iters += 1) {
        if (@atomicLoad(u64, &worker_counter, .monotonic) > c0) {
            observed_running = true;
            break;
        }
        syscall.thread_yield();
    }
    if (!observed_running) {
        t.fail("§2.2.16 worker counter never advanced");
        syscall.shutdown();
    }

    // Now suspend the definitively-running remote thread.
    const suspend_ret = syscall.thread_suspend(handle);
    if (suspend_ret != 0) {
        t.failWithVal("§2.2.16 thread_suspend", 0, suspend_ret);
        syscall.shutdown();
    }

    // Spec-visible signal: a second suspend on an already-.suspended thread
    // returns E_BUSY (§2.4.12) — confirms the first one actually landed.
    const suspend_again = syscall.thread_suspend(handle);
    if (suspend_again == 0) {
        t.fail("§2.2.16 second suspend returned success");
        syscall.shutdown();
    }

    _ = syscall.thread_kill(handle);
    t.pass("§2.2.16");
    syscall.shutdown();
}
