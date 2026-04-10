const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

const INF: u64 = @bitCast(@as(i64, -1));

var futex_val: u64 align(8) = 0;
var order: [3]u64 = .{ 0, 0, 0 };
var order_idx: u64 align(8) = 0;

// Step counter for serializing waiter entry into futex_wait.
var step: u64 align(8) = 0;

fn atomicInc(ptr: *u64) u64 {
    while (true) {
        const cur = ptr.*;
        if (@cmpxchgWeak(u64, ptr, cur, cur + 1, .seq_cst, .seq_cst) == null) return cur;
    }
}

fn waiterFn(my_turn: u64, id: u64, priority: u64) void {
    // Synchronize at default (normal) priority so main isn't starved.
    t.waitUntilAtLeast(&step, my_turn);
    // Signal main that we're about to enter futex_wait.
    step = my_turn + 1;
    _ = syscall.futex_wake(@ptrCast(&step), 10);
    // Set our priority level — the futex PQ will order us correctly.
    _ = syscall.set_priority(priority);
    // Enter the shared futex wait.
    _ = syscall.futex_wait(@ptrCast(&futex_val), 0, INF);
    // Record wake order.
    const idx = atomicInc(&order_idx);
    order[idx] = id;
    _ = syscall.futex_wake(@ptrCast(&order_idx), 1);
    // Exit cleanly so high-priority threads don't starve main.
    syscall.thread_exit();
}

// id=1 idle, id=2 normal, id=3 high
// Entered in order: idle first, then normal, then high.
// Expected wake order: high(3), normal(2), idle(1).
fn waiter_idle() void { waiterFn(0, 1, syscall.PRIORITY_IDLE); }
fn waiter_normal() void { waiterFn(2, 2, syscall.PRIORITY_NORMAL); }
fn waiter_high() void { waiterFn(4, 3, syscall.PRIORITY_HIGH); }

/// §2.5.7 — Futex waiters are woken in priority order (highest priority first), with FIFO ordering among waiters of the same priority level.
pub fn main(_: u64) void {
    _ = syscall.thread_create(&waiter_idle, 0, 4);
    _ = syscall.thread_create(&waiter_normal, 0, 4);
    _ = syscall.thread_create(&waiter_high, 0, 4);

    // Waiter idle: turn=0, signals step=1.
    t.waitUntilAtLeast(&step, 1);
    syscall.thread_yield();
    step = 2;
    _ = syscall.futex_wake(@ptrCast(&step), 10);

    // Waiter normal: turn=2, signals step=3.
    t.waitUntilAtLeast(&step, 3);
    syscall.thread_yield();
    step = 4;
    _ = syscall.futex_wake(@ptrCast(&step), 10);

    // Waiter high: turn=4, signals step=5.
    t.waitUntilAtLeast(&step, 5);
    syscall.thread_yield();

    // All 3 are now in futex_wait on futex_val.
    // Wake all at once — priority order should be: high(3), normal(2), idle(1).
    _ = syscall.futex_wake(@ptrCast(&futex_val), 3);
    t.waitUntilAtLeast(&order_idx, 3);

    if (order[0] == 3 and order[1] == 2 and order[2] == 1) {
        t.pass("§2.5.7");
    } else {
        t.fail("§2.5.7");
    }
    syscall.shutdown();
}
