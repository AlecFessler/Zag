const lib = @import("lib");

const perm_view = lib.perm_view;
const syscall = lib.syscall;
const t = lib.testing;

const ENTRY_TYPE_CORE_PIN: u8 = 4;

var worker_counter: u64 align(8) = 0;

fn workerSpin() void {
    // Pin the worker to core 0 by affinity mask.
    _ = syscall.set_affinity(0x1);
    while (true) {
        _ = @atomicRmw(u64, &worker_counter, .Add, 1, .monotonic);
        syscall.thread_yield();
    }
}

/// §2.3.14 — Revoking a core pin unpins the thread, restores the thread's pre-pin affinity mask, drops the thread's priority to its pre-pin level, and clears the slot.
///
/// Plan:
///   1. Main thread set_affinity(core 0) and set_priority(PINNED) on core 0.
///   2. Spawn a worker thread also pinned to core 0 by affinity mask.
///   3. While the pin is held, §2.10.4 says only the pinned thread runs on
///      that core — the worker must starve. Yield main a handful of times
///      and confirm worker_counter remains 0.
///   4. Revoke the pin — scheduling on core 0 returns to preemptive,
///      and pre-pin affinity and priority are restored.
///   5. Yield main and confirm worker_counter advances.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    // Pin main to core 0.
    _ = syscall.set_affinity(0x1);

    // Take exclusive ownership of core 0.
    const pin_ret = syscall.set_priority(syscall.PRIORITY_PINNED);
    if (pin_ret < 0) {
        t.fail("§2.3.14 set_priority(PINNED) failed");
        syscall.shutdown();
    }
    const pin_handle: u64 = @bitCast(pin_ret);

    // Verify the pin slot is present.
    var pin_found = false;
    for (0..128) |i| {
        if (view[i].handle == pin_handle and view[i].entry_type == ENTRY_TYPE_CORE_PIN) {
            pin_found = true;
            break;
        }
    }
    if (!pin_found) {
        t.fail("§2.3.14 pin slot missing");
        syscall.shutdown();
    }

    // Spawn worker.
    const worker_ret = syscall.thread_create(&workerSpin, 0, 4);
    if (worker_ret < 0) {
        t.fail("§2.3.14 thread_create");
        syscall.shutdown();
    }

    // Under exclusive pin on core 0, the worker (also affined to core 0) cannot
    // run. Yield and check the counter stays at zero.
    var y: u32 = 0;
    while (y < 50) : (y += 1) syscall.thread_yield();
    const counter_during_pin = @atomicLoad(u64, &worker_counter, .monotonic);

    // Revoke the pin — pre-pin affinity and priority are restored.
    const revoke_ret = syscall.revoke_perm(pin_handle);
    if (revoke_ret != 0) {
        t.fail("§2.3.14 revoke");
        syscall.shutdown();
    }

    // Slot must be gone.
    var slot_gone = true;
    for (0..128) |i| {
        if (view[i].handle == pin_handle and view[i].entry_type == ENTRY_TYPE_CORE_PIN) {
            slot_gone = false;
            break;
        }
    }

    // Preemptive scheduling restored: the worker should now be able to run.
    var observed_progress = false;
    var attempts: u32 = 0;
    while (attempts < 200000) : (attempts += 1) {
        if (@atomicLoad(u64, &worker_counter, .monotonic) > counter_during_pin) {
            observed_progress = true;
            break;
        }
        syscall.thread_yield();
    }

    if (counter_during_pin == 0 and slot_gone and observed_progress) {
        t.pass("§2.3.14");
    } else {
        t.fail("§2.3.14");
    }
    syscall.shutdown();
}
