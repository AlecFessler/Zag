const children = @import("embedded_children");
const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const E_NOENT: i64 = -10;
const PAGE: u64 = 4096;
const MAX_TIMEOUT: u64 = @bitCast(@as(i64, -1));

var child_handle: u64 = 0;
var call_result_1: i64 = 0;
var call_result_2: i64 = 0;
var done_1: u64 align(8) = 0;
var done_2: u64 align(8) = 0;
var queued_1: u64 align(8) = 0;
var queued_2: u64 align(8) = 0;

fn caller1() void {
    @atomicStore(u64, &queued_1, 1, .release);
    _ = syscall.futex_wake(@ptrCast(&queued_1), 1);
    var reply: syscall.IpcMessage = .{};
    call_result_1 = syscall.ipc_call(@atomicLoad(u64, &child_handle, .acquire), &.{}, &reply);
    @atomicStore(u64, &done_1, 1, .release);
    _ = syscall.futex_wake(@ptrCast(&done_1), 1);
}

fn caller2() void {
    @atomicStore(u64, &queued_2, 1, .release);
    _ = syscall.futex_wake(@ptrCast(&queued_2), 1);
    var reply: syscall.IpcMessage = .{};
    call_result_2 = syscall.ipc_call(@atomicLoad(u64, &child_handle, .acquire), &.{}, &reply);
    @atomicStore(u64, &done_2, 1, .release);
    _ = syscall.futex_wake(@ptrCast(&done_2), 1);
}

/// §2.11.32 — When a process dies, queued callers in its wait queue are unblocked with `E_NOENT`.
///
/// Explicit handshake: the child sets a SHM "alive" flag once it has
/// consumed the setup message and is parked (not recv'ing). Parent waits
/// for both caller threads to signal they're entering ipc_call, then
/// yields many times to let them reach the kernel wait queue, then
/// revokes. Both callers should receive E_NOENT.
pub fn main(_: u64) void {
    const shm_rights = perms.SharedMemoryRights{ .read = true, .write = true, .grant = true };
    const shm: u64 = @bitCast(@as(i64, syscall.shm_create_with_rights(PAGE, shm_rights.bits())));
    const vm_rights = (perms.VmReservationRights{ .read = true, .write = true, .shareable = true }).bits();
    const vm = syscall.vm_reserve(0, PAGE, vm_rights);
    _ = syscall.shm_map(shm, @bitCast(vm.val), 0);
    const buf: [*]volatile u64 = @ptrFromInt(vm.val2);

    const child_rights = (perms.ProcessRights{ .mem_reserve = true, .spawn_thread = true }).bits();
    const h: u64 = @bitCast(@as(i64, syscall.proc_create(
        @intFromPtr(children.child_shm_ready_no_recv.ptr),
        children.child_shm_ready_no_recv.len,
        child_rights,
    )));
    @atomicStore(u64, &child_handle, h, .release);

    // Setup: cap-transfer SHM. After this reply, the child maps and parks.
    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call_cap(h, &.{ shm, shm_rights.bits() }, &reply);

    // Handshake: wait for child "alive" flag (buf[0] == 1).
    while (@atomicLoad(u64, @as(*u64, @ptrCast(@volatileCast(&buf[0]))), .acquire) != 1) {
        _ = syscall.futex_wait(@as(*u64, @ptrCast(@volatileCast(&buf[0]))), 0, MAX_TIMEOUT);
    }

    // Spawn both callers and wait until each has signaled it is entering
    // ipc_call. Then yield many times to ensure both have entered the
    // kernel wait queue before we revoke.
    _ = syscall.thread_create(&caller1, 0, 4);
    _ = syscall.thread_create(&caller2, 0, 4);
    t.waitUntilNonZero(&queued_1);
    t.waitUntilNonZero(&queued_2);
    for (0..2000) |_| syscall.thread_yield();

    // Kill child — both queued callers should get E_NOENT.
    _ = syscall.revoke_perm(h);

    t.waitUntilNonZero(&done_1);
    t.waitUntilNonZero(&done_2);
    const ok = (call_result_1 == E_NOENT) and (call_result_2 == E_NOENT);
    if (ok) t.pass("§2.11.32") else t.fail("§2.11.32");
    syscall.shutdown();
}
