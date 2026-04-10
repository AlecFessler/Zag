const children = @import("embedded_children");
const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const PAGE: u64 = 4096;
const MAX_TIMEOUT: u64 = @bitCast(@as(i64, -1));

var child_h: u64 = 0;
var call_done: u64 align(8) = 0;
var call_result: i64 = 0;
var reply_val: u64 = 0;

fn do_call() void {
    var reply: syscall.IpcMessage = .{};
    call_result = syscall.ipc_call(@atomicLoad(u64, &child_h, .acquire), &.{0x42}, &reply);
    reply_val = reply.words[0];
    @atomicStore(u64, &call_done, 1, .release);
    _ = syscall.futex_wake(@ptrCast(&call_done), 1);
}

/// §2.11.16 — `reply` to a `call` copies reply payload to the caller's registers and unblocks the caller.
///
/// Uses the same worker + SHM sentinel as §2.11.5 to distinguish "reply
/// actually unblocked a blocked caller" from "everything ran
/// straight-through". The server sets buf[0] = 1 right after recv, yields
/// many times, then replies. The parent asserts that call_done stays 0
/// while buf[0] == 1 (proving the caller was blocked waiting for reply),
/// then asserts the reply payload is delivered on unblock.
pub fn main(_: u64) void {
    const shm_rights = perms.SharedMemoryRights{ .read = true, .write = true, .grant = true };
    const shm: u64 = @bitCast(@as(i64, syscall.shm_create_with_rights(PAGE, shm_rights.bits())));
    const vm_rights = (perms.VmReservationRights{ .read = true, .write = true, .shareable = true }).bits();
    const vm = syscall.vm_reserve(0, PAGE, vm_rights);
    _ = syscall.shm_map(shm, @bitCast(vm.val), 0);
    const buf: [*]volatile u64 = @ptrFromInt(vm.val2);

    const child_rights = (perms.ProcessRights{ .mem_reserve = true, .spawn_thread = true }).bits();
    const h: u64 = @bitCast(@as(i64, syscall.proc_create(
        @intFromPtr(children.child_iter1_c_delay_server.ptr),
        children.child_iter1_c_delay_server.len,
        child_rights,
    )));
    @atomicStore(u64, &child_h, h, .release);

    var setup_reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call_cap(h, &.{ shm, shm_rights.bits() }, &setup_reply);

    _ = syscall.thread_create(&do_call, 0, 4);

    const b0: *u64 = @ptrCast(@volatileCast(&buf[0]));
    while (@atomicLoad(u64, b0, .acquire) != 1) {
        _ = syscall.futex_wait(b0, 0, MAX_TIMEOUT);
    }

    // Call must still be outstanding while the child delays before reply.
    var observed_blocked = false;
    var i: u32 = 0;
    while (i < 50) : (i += 1) {
        if (@atomicLoad(u64, &call_done, .acquire) == 0) {
            observed_blocked = true;
        } else {
            break;
        }
        syscall.thread_yield();
    }
    if (!observed_blocked) {
        t.fail("§2.11.16 call not observed blocked before reply");
        syscall.shutdown();
    }

    // Reply should unblock the caller and deliver the payload.
    t.waitUntilNonZero(&call_done);
    if (call_result == 0 and reply_val == 0x43) {
        t.pass("§2.11.16");
    } else {
        t.failWithVal("§2.11.16", 0, call_result);
    }
    syscall.shutdown();
}
