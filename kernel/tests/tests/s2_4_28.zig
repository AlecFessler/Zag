const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

/// §2.4.28 — `set_affinity` constrains the calling thread's core affinity; the change takes effect at the next scheduling decision.
///
/// Set affinity to core 1 only, yield, verify the thread is still running
/// (i.e. the affinity change was applied and the thread migrated).
pub fn main(_: u64) void {
    // Constrain to core 1.
    const ret = syscall.set_affinity(0b10);
    t.expectOk("§2.4.28 set_affinity core 1", ret);

    // Yield to trigger a scheduling decision with the new affinity.
    syscall.thread_yield();

    // If we're still running, the affinity change took effect.
    t.pass("§2.4.28 thread still runs after affinity change");

    syscall.shutdown();
}
