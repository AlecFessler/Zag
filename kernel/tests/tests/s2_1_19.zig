const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const PAGE: u64 = 4096;

/// §2.1.19 — Permissions table persists across restart (except VM reservation entries).
///
/// Uses child_iter1_b_restart_probe: on first boot the child snapshots the
/// set of its non-VM perm-slot handle IDs into SHM, then voluntarily exits
/// (triggering restart). On restart the child re-enumerates and compares
/// every pre-restart handle against its current table. Bit 0 of the result
/// mask is set iff every recorded handle is still present — i.e. the
/// permissions table persisted across restart.
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

    // Transfer SHM to the child on first boot.
    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call_cap(child_handle, &.{ shm_handle, shm_rights.bits() }, &reply);

    // Block until the child (on its restart boot) publishes its result mask.
    t.waitUntilNonZero(done_ptr);

    const result = result_ptr.*;
    const perms_match = (result & 1) != 0;
    if (perms_match) {
        t.pass("§2.1.19");
    } else {
        t.fail("§2.1.19");
    }
    syscall.shutdown();
}
