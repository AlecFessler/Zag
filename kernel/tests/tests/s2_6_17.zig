const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const PAGE: u64 = 4096;

/// §2.6.17 — User permissions view (mapped read-only region) persists across restart.
///
/// Uses child_iter1_b_restart_probe: on first boot the child snapshots its
/// non-VM slots via its own perm view and exits. On restart it again reads
/// its own perm view — specifically view[0].processRestartCount() — and
/// publishes the value into SHM alongside a flag indicating it reached the
/// restart branch AT ALL (which is only possible if the view mapping is
/// still accessible on the second run). We assert both the flag is set
/// AND the reported restart count is nonzero.
pub fn main(pv_arg: u64) void {
    _ = pv_arg;

    const shm_rights = perms.SharedMemoryRights{ .read = true, .write = true, .grant = true };
    const shm_handle: u64 = @bitCast(@as(i64, syscall.shm_create_with_rights(PAGE, shm_rights.bits())));
    const vm_rw_s = perms.VmReservationRights{ .read = true, .write = true, .shareable = true };
    const vm = syscall.mem_reserve(0, PAGE, vm_rw_s.bits());
    const vm_handle: u64 = @bitCast(vm.val);
    _ = syscall.mem_shm_map(shm_handle, vm_handle, 0);

    const base: u64 = vm.val2;
    const result_ptr: *u64 = @ptrFromInt(base + 1000);
    const done_ptr: *u64 = @ptrFromInt(base + 1008);
    result_ptr.* = 0;
    done_ptr.* = 0;

    const child_rights = perms.ProcessRights{ .spawn_thread = true, .mem_reserve = true, .mem_shm_create = true, .restart = true };
    const child_handle: u64 = @bitCast(@as(i64, syscall.proc_create(
        @intFromPtr(children.child_iter1_b_restart_probe.ptr),
        children.child_iter1_b_restart_probe.len,
        child_rights.bits(),
    )));

    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call_cap(child_handle, &.{ shm_handle, shm_rights.bits() }, &reply);

    t.waitUntilNonZero(done_ptr);

    const result = result_ptr.*;
    const view_restart_count_nonzero = (result & 8) != 0;
    const child_restart_count: u32 = @truncate(result >> 32);
    if (view_restart_count_nonzero and child_restart_count > 0) {
        t.pass("§2.6.17");
    } else {
        t.fail("§2.6.17");
    }
    syscall.shutdown();
}
