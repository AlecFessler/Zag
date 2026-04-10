const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const PAGE: u64 = 4096;

/// §2.6.12 — SHM handle entries persist across restart.
///
/// Uses child_iter1_b_restart_probe: on first boot the child maps the SHM
/// and writes a MAGIC value. On restart it locates the SHM slot in its
/// persisted perm table (bit 1 of the result), re-maps the SHM, and reads
/// back the MAGIC value (bit 2 of the result). Both bits set => the SHM
/// handle slot persisted AND the mapping is still readable via the same
/// SHM handle.
pub fn main(pv_arg: u64) void {
    _ = pv_arg;

    const shm_rights = perms.SharedMemoryRights{ .read = true, .write = true, .grant = true };
    const shm_handle: u64 = @bitCast(@as(i64, syscall.shm_create_with_rights(PAGE, shm_rights.bits())));
    const vm_rw_s = perms.VmReservationRights{ .read = true, .write = true, .shareable = true };
    const vm = syscall.vm_reserve(0, PAGE, vm_rw_s.bits());
    const vm_handle: u64 = @bitCast(vm.val);
    _ = syscall.shm_map(shm_handle, vm_handle, 0);

    const base: u64 = vm.val2;
    const result_ptr: *u64 = @ptrFromInt(base + 1000);
    const done_ptr: *u64 = @ptrFromInt(base + 1008);
    result_ptr.* = 0;
    done_ptr.* = 0;

    const child_rights = perms.ProcessRights{ .spawn_thread = true, .mem_reserve = true, .shm_create = true, .restart = true };
    const child_handle: u64 = @bitCast(@as(i64, syscall.proc_create(
        @intFromPtr(children.child_iter1_b_restart_probe.ptr),
        children.child_iter1_b_restart_probe.len,
        child_rights.bits(),
    )));

    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call_cap(child_handle, &.{ shm_handle, shm_rights.bits() }, &reply);

    t.waitUntilNonZero(done_ptr);

    const result = result_ptr.*;
    const shm_slot_present = (result & 2) != 0;
    const shm_magic_readable = (result & 4) != 0;
    if (shm_slot_present and shm_magic_readable) {
        t.pass("§2.6.12");
    } else {
        t.fail("§2.6.12");
    }
    syscall.shutdown();
}
