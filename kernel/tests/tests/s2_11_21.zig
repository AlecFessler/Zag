const children = @import("embedded_children");
const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const PAGE: u64 = 4096;
const MAX_TIMEOUT: u64 = @bitCast(@as(i64, -1));

var child_h: u64 = 0;
var result_idle: u64 = 0;
var result_high: u64 = 0;
var queued_idle: u64 align(8) = 0;
var queued_high: u64 align(8) = 0;
var done_idle: u64 align(8) = 0;
var done_high: u64 align(8) = 0;

fn caller_idle() void {
    // Set ourselves to idle priority before entering ipc_call.
    _ = syscall.set_priority(syscall.PRIORITY_IDLE);
    @atomicStore(u64, &queued_idle, 1, .release);
    _ = syscall.futex_wake(@ptrCast(&queued_idle), 1);
    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call(@atomicLoad(u64, &child_h, .acquire), &.{0}, &reply);
    @atomicStore(u64, &result_idle, reply.words[0], .release);
    @atomicStore(u64, &done_idle, 1, .release);
    _ = syscall.futex_wake(@ptrCast(&done_idle), 1);
}

fn caller_high() void {
    // Set ourselves to high priority before entering ipc_call.
    _ = syscall.set_priority(syscall.PRIORITY_HIGH);
    @atomicStore(u64, &queued_high, 1, .release);
    _ = syscall.futex_wake(@ptrCast(&queued_high), 1);
    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call(@atomicLoad(u64, &child_h, .acquire), &.{0}, &reply);
    @atomicStore(u64, &result_high, reply.words[0], .release);
    @atomicStore(u64, &done_high, 1, .release);
    _ = syscall.futex_wake(@ptrCast(&done_high), 1);
}

/// §2.11.21 — The call wait queue is priority ordered (highest priority first), with FIFO ordering among callers of the same priority level.
///
/// Ordering strategy: the server is gated — it maps SHM and blocks on a
/// futex (buf[1]) until the parent has explicitly ordered caller_idle into
/// the kernel wait queue BEFORE caller_high by:
///   1. spawning caller_idle (priority=idle) and waiting for it to report
///      it is about to enter ipc_call (queued_idle = 1), then yielding
///      many times to guarantee it has actually entered the kernel wait queue,
///   2. spawning caller_high (priority=high) and doing the same,
///   3. waking the server, which then recvs + replies twice with a
///      monotonic counter.
/// Priority ordering is proven by caller_high receiving counter==1
/// (served first) and caller_idle receiving counter==2 (served second),
/// despite caller_idle entering the queue first.
pub fn main(_: u64) void {
    const shm_rights = perms.SharedMemoryRights{ .read = true, .write = true, .grant = true };
    const shm: u64 = @bitCast(@as(i64, syscall.shm_create_with_rights(PAGE, shm_rights.bits())));
    const vm_rights = (perms.VmReservationRights{ .read = true, .write = true, .shareable = true }).bits();
    const vm = syscall.mem_reserve(0, PAGE, vm_rights);
    _ = syscall.mem_shm_map(shm, @bitCast(vm.val), 0);
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

    // Spawn idle caller first (lower priority), wait for it to enter ipc_call.
    _ = syscall.thread_create(&caller_idle, 0, 4);
    t.waitUntilNonZero(&queued_idle);
    for (0..2000) |_| syscall.thread_yield();

    // Then spawn high caller (higher priority).
    _ = syscall.thread_create(&caller_high, 0, 4);
    t.waitUntilNonZero(&queued_high);
    for (0..2000) |_| syscall.thread_yield();

    // Now wake the server — it will dequeue in priority order (high first).
    const b1: *u64 = @ptrCast(@volatileCast(&buf[1]));
    @atomicStore(u64, b1, 1, .release);
    _ = syscall.futex_wake(b1, 1);

    t.waitUntilNonZero(&done_idle);
    t.waitUntilNonZero(&done_high);

    const r_idle = @atomicLoad(u64, &result_idle, .acquire);
    const r_high = @atomicLoad(u64, &result_high, .acquire);
    // High priority caller should be served first (counter=1), idle second (counter=2).
    if (r_high == 1 and r_idle == 2) {
        t.pass("§2.11.21");
    } else {
        t.failWithVal("§2.11.21", 1, @bitCast(r_high));
    }
    syscall.shutdown();
}
