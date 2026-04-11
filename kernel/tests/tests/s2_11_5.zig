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

/// §2.11.5 — `call` blocks the caller until the receiver calls `reply`.
///
/// This test distinguishes "call actually blocked on reply" from "ran
/// end-to-end without scheduling". The server child explicitly sets a SHM
/// sentinel right after recv'ing the parent's call and before replying,
/// then yields many times. A worker thread issues the ipc_call. The parent
/// observes:
///   - buf[0] becomes 1 (server has the call and is sitting on reply)
///   - call_done stays 0 across many yield cycles AFTER buf[0] == 1
///     (proving the caller is still blocked inside ipc_call)
///   - call_done eventually flips to 1 with the expected reply payload.
pub fn main(_: u64) void {
    const shm_rights = perms.SharedMemoryRights{ .read = true, .write = true, .grant = true };
    const shm: u64 = @bitCast(@as(i64, syscall.shm_create_with_rights(PAGE, shm_rights.bits())));
    const vm_rights = (perms.VmReservationRights{ .read = true, .write = true, .shareable = true }).bits();
    const vm = syscall.mem_reserve(0, PAGE, vm_rights);
    _ = syscall.mem_shm_map(shm, @bitCast(vm.val), 0);
    const buf: [*]volatile u64 = @ptrFromInt(vm.val2);

    const child_rights = (perms.ProcessRights{ .mem_reserve = true, .spawn_thread = true }).bits();
    const h: u64 = @bitCast(@as(i64, syscall.proc_create(
        @intFromPtr(children.child_iter1_c_delay_server.ptr),
        children.child_iter1_c_delay_server.len,
        child_rights,
    )));
    @atomicStore(u64, &child_h, h, .release);

    // Setup: transfer SHM to child.
    var setup_reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call_cap(h, &.{ shm, shm_rights.bits() }, &setup_reply);

    // Worker thread issues the real call.
    _ = syscall.thread_create(&do_call, 0, 4);

    // Wait until the child has recv'd and set buf[0] = 1.
    const b0: *u64 = @ptrCast(@volatileCast(&buf[0]));
    while (@atomicLoad(u64, b0, .acquire) != 1) {
        _ = syscall.futex_wait(b0, 0, MAX_TIMEOUT);
    }

    // Now the child is about to yield many times before replying. The
    // worker must still be blocked inside ipc_call.
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
        t.fail("§2.11.5 call did not block after child observed message");
        syscall.shutdown();
    }

    // Eventually the child replies and the worker unblocks.
    t.waitUntilNonZero(&call_done);
    if (call_result == 0 and reply_val == 0x43) {
        t.pass("§2.11.5");
    } else {
        t.failWithVal("§2.11.5", 0, call_result);
    }
    syscall.shutdown();
}
