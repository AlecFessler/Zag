const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const PAGE: u64 = 4096;

/// §2.6.22 — All threads are removed on restart; only a fresh initial thread runs.
///
/// Uses child_iter1_b_parked_tids: first boot spawns 3 parker threads and
/// records the full set of pre-restart thread tids (main + 3 parkers,
/// captured via the child's own perm view) into an SHM, then faults to
/// force a restart. After restart, the child enumerates its THREAD perm
/// entries and records the post-restart count + the fresh initial
/// thread's tid into the same SHM.
///
/// We assert:
///   1. Exactly ONE thread perm entry exists after restart (mirrors the
///      old check).
///   2. The post-restart tid does NOT match ANY of the pre-restart tids
///      — i.e. every pre-restart thread id is gone, mirroring what
///      s2_6_35 does for the fault-handler variant.
pub fn main(pv_arg: u64) void {
    _ = pv_arg;

    const shm_rights = perms.SharedMemoryRights{ .read = true, .write = true, .grant = true };
    const shm_handle: u64 = @bitCast(@as(i64, syscall.shm_create_with_rights(PAGE, shm_rights.bits())));
    const vm_rw_s = perms.VmReservationRights{ .read = true, .write = true, .shareable = true };
    const vm = syscall.vm_reserve(0, PAGE, vm_rw_s.bits());
    const vm_handle: u64 = @bitCast(vm.val);
    _ = syscall.shm_map(shm_handle, vm_handle, 0);

    const base: u64 = vm.val2;
    const pre_count_ptr: *u64 = @ptrFromInt(base + 0);
    const post_count_ptr: *u64 = @ptrFromInt(base + 128);
    const post_tid_ptr: *u64 = @ptrFromInt(base + 136);
    const done_ptr: *u64 = @ptrFromInt(base + 144);
    pre_count_ptr.* = 0;
    post_count_ptr.* = 0;
    post_tid_ptr.* = 0;
    done_ptr.* = 0;

    const child_rights = (perms.ProcessRights{
        .restart = true,
        .spawn_thread = true,
        .mem_reserve = true,
        .shm_create = true,
    }).bits();
    const child_handle: u64 = @bitCast(@as(i64, syscall.proc_create(
        @intFromPtr(children.child_iter1_b_parked_tids.ptr),
        children.child_iter1_b_parked_tids.len,
        child_rights,
    )));

    // Transfer SHM on first boot.
    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call_cap(child_handle, &.{ shm_handle, shm_rights.bits() }, &reply);

    // Wait for the post-restart child to publish the result.
    t.waitUntilNonZero(done_ptr);

    const pre_count = pre_count_ptr.*;
    const post_count = post_count_ptr.*;
    const post_tid = post_tid_ptr.*;

    // 1. Exactly one fresh thread.
    if (post_count != 1) {
        t.failWithVal("§2.6.22 post_count", 1, @intCast(post_count));
        syscall.shutdown();
    }

    // 2. post_tid not in pre_tids.
    var tid_reused = false;
    var i: u64 = 0;
    while (i < pre_count) : (i += 1) {
        const pre_ptr: *u64 = @ptrFromInt(base + 8 + i * 8);
        if (pre_ptr.* == post_tid) {
            tid_reused = true;
            break;
        }
    }
    if (pre_count == 0 or tid_reused) {
        t.fail("§2.6.22 pre tid reused or missing");
        syscall.shutdown();
    }

    t.pass("§2.6.22");
    _ = perm_view;
    syscall.shutdown();
}
