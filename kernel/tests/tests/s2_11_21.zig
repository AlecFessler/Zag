const children = @import("embedded_children");
const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const PAGE: u64 = 4096;
const MAX_TIMEOUT: u64 = @bitCast(@as(i64, -1));

var child_h: u64 = 0;
var result1: u64 = 0;
var result2: u64 = 0;
var queued1: u64 align(8) = 0;
var queued2: u64 align(8) = 0;
var done1: u64 align(8) = 0;
var done2: u64 align(8) = 0;

fn caller1() void {
    @atomicStore(u64, &queued1, 1, .release);
    _ = syscall.futex_wake(@ptrCast(&queued1), 1);
    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call(@atomicLoad(u64, &child_h, .acquire), &.{0}, &reply);
    @atomicStore(u64, &result1, reply.words[0], .release);
    @atomicStore(u64, &done1, 1, .release);
    _ = syscall.futex_wake(@ptrCast(&done1), 1);
}

fn caller2() void {
    @atomicStore(u64, &queued2, 1, .release);
    _ = syscall.futex_wake(@ptrCast(&queued2), 1);
    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call(@atomicLoad(u64, &child_h, .acquire), &.{0}, &reply);
    @atomicStore(u64, &result2, reply.words[0], .release);
    @atomicStore(u64, &done2, 1, .release);
    _ = syscall.futex_wake(@ptrCast(&done2), 1);
}

/// §2.11.21 — The call wait queue is FIFO ordered.
///
/// Ordering strategy: the server is gated — it maps SHM and blocks on a
/// futex (buf[1]) until the parent has explicitly ordered caller1 into
/// the kernel wait queue BEFORE caller2 by:
///   1. spawning caller1 and waiting for caller1 to report it is about
///      to enter ipc_call (queued1 = 1), then yielding many times to
///      guarantee caller1 has actually entered the kernel wait queue,
///   2. spawning caller2 and doing the same,
///   3. waking the server, which then recvs + replies twice with a
///      monotonic counter.
/// FIFO order is proven by caller1 receiving counter==1 and caller2
/// receiving counter==2.
pub fn main(_: u64) void {
    const shm_rights = perms.SharedMemoryRights{ .read = true, .write = true, .grant = true };
    const shm: u64 = @bitCast(@as(i64, syscall.shm_create_with_rights(PAGE, shm_rights.bits())));
    const vm_rights = (perms.VmReservationRights{ .read = true, .write = true, .shareable = true }).bits();
    const vm = syscall.vm_reserve(0, PAGE, vm_rights);
    _ = syscall.shm_map(shm, @bitCast(vm.val), 0);
    const buf: [*]volatile u64 = @ptrFromInt(vm.val2);

    const child_rights = (perms.ProcessRights{ .mem_reserve = true, .spawn_thread = true }).bits();
    const h: u64 = @bitCast(@as(i64, syscall.proc_create(
        @intFromPtr(children.child_iter1_c_gated_counter.ptr),
        children.child_iter1_c_gated_counter.len,
        child_rights,
    )));
    @atomicStore(u64, &child_h, h, .release);

    var setup_reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call_cap(h, &.{ shm, shm_rights.bits() }, &setup_reply);

    // Wait for child ready.
    const b0: *u64 = @ptrCast(@volatileCast(&buf[0]));
    while (@atomicLoad(u64, b0, .acquire) != 1) {
        _ = syscall.futex_wait(b0, 0, MAX_TIMEOUT);
    }

    // Spawn caller1 first, wait for it to enter ipc_call, yield lots of
    // times to ensure it is actually in the kernel wait queue.
    _ = syscall.thread_create(&caller1, 0, 4);
    t.waitUntilNonZero(&queued1);
    for (0..2000) |_| syscall.thread_yield();

    // Then spawn caller2.
    _ = syscall.thread_create(&caller2, 0, 4);
    t.waitUntilNonZero(&queued2);
    for (0..2000) |_| syscall.thread_yield();

    // Now wake the server — it will dequeue in FIFO order.
    const b1: *u64 = @ptrCast(@volatileCast(&buf[1]));
    @atomicStore(u64, b1, 1, .release);
    _ = syscall.futex_wake(b1, 1);

    t.waitUntilNonZero(&done1);
    t.waitUntilNonZero(&done2);

    const r1 = @atomicLoad(u64, &result1, .acquire);
    const r2 = @atomicLoad(u64, &result2, .acquire);
    if (r1 == 1 and r2 == 2) {
        t.pass("§2.11.21");
    } else {
        t.failWithVal("§2.11.21", 1, @bitCast(r1));
    }
    syscall.shutdown();
}
