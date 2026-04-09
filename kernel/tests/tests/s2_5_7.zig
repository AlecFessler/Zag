const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

const INF: u64 = @bitCast(@as(i64, -1));

var futex_val: u64 align(8) = 0;
var order: [3]u64 = .{ 0, 0, 0 };
var order_idx: u64 align(8) = 0;

// Step counter: main uses this to serialize waiter entry into futex_wait.
// Protocol per waiter:
//   1. Waiter waits for step == its_turn
//   2. Waiter sets step = its_turn + 1 (signals main it's about to enter futex_wait)
//   3. Waiter calls futex_wait on futex_val (the shared futex)
//   4. Main waits for step == its_turn + 1, then proceeds to next waiter
// There's a small window between step 2 and step 3. Main yields once after
// seeing the signal to let the waiter enter the kernel.
var step: u64 align(8) = 0;

fn atomicInc(ptr: *u64) u64 {
    while (true) {
        const cur = ptr.*;
        if (@cmpxchgWeak(u64, ptr, cur, cur + 1, .seq_cst, .seq_cst) == null) return cur;
    }
}

fn waiterFn(my_turn: u64, id: u64) void {
    // Wait for our turn.
    t.waitUntilAtLeast(&step, my_turn);
    // Signal main that we're about to enter futex_wait.
    step = my_turn + 1;
    _ = syscall.futex_wake(@ptrCast(&step), 10);
    // Enter the shared futex wait.
    _ = syscall.futex_wait(@ptrCast(&futex_val), 0, INF);
    // Record wake order.
    const idx = atomicInc(&order_idx);
    order[idx] = id;
    _ = syscall.futex_wake(@ptrCast(&order_idx), 1);
    while (true) syscall.thread_yield();
}

fn waiter1() void { waiterFn(0, 1); }
fn waiter2() void { waiterFn(2, 2); }
fn waiter3() void { waiterFn(4, 3); }

/// §2.5.7 — Futex waiters are woken in FIFO order.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    _ = syscall.thread_create(&waiter1, 0, 4);
    _ = syscall.thread_create(&waiter2, 0, 4);
    _ = syscall.thread_create(&waiter3, 0, 4);

    // Waiter1: turn=0, signals step=1. Main waits for step>=1, yields, sets step=2.
    t.waitUntilAtLeast(&step, 1);
    syscall.thread_yield(); // Let waiter1 enter futex_wait.
    step = 2;
    _ = syscall.futex_wake(@ptrCast(&step), 10);

    // Waiter2: turn=2, signals step=3.
    t.waitUntilAtLeast(&step, 3);
    syscall.thread_yield();
    step = 4;
    _ = syscall.futex_wake(@ptrCast(&step), 10);

    // Waiter3: turn=4, signals step=5.
    t.waitUntilAtLeast(&step, 5);
    syscall.thread_yield();

    // All 3 are now in futex_wait on futex_val, in order 1, 2, 3.
    // Wake one at a time and verify FIFO order.
    _ = syscall.futex_wake(@ptrCast(&futex_val), 1);
    t.waitUntilAtLeast(&order_idx, 1);
    _ = syscall.futex_wake(@ptrCast(&futex_val), 1);
    t.waitUntilAtLeast(&order_idx, 2);
    _ = syscall.futex_wake(@ptrCast(&futex_val), 1);
    t.waitUntilAtLeast(&order_idx, 3);

    if (order[0] == 1 and order[1] == 2 and order[2] == 3) {
        t.pass("§2.5.7");
    } else {
        t.fail("§2.5.7");
    }
    syscall.shutdown();
}
